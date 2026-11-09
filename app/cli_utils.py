"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""

import shlex
import sys
import subprocess
from typing import Iterable, List
from urllib.parse import urlparse

from app.hostsfile import normalize_hostname_alias
from db.entities.host import hostObj

def _normalize_import_target(raw_target: str) -> str:
    candidate = str(raw_target or "").strip()
    if not candidate or candidate.startswith("#"):
        return ""
    if "://" in candidate:
        try:
            parsed = urlparse(candidate)
            candidate = str(parsed.hostname or "").strip()
        except Exception:
            candidate = ""
    normalized = normalize_hostname_alias(candidate)
    return str(normalized or candidate or "").strip().rstrip(".")


_IMPORT_LOOKUP_CHUNK = 400  # each chunk is bound twice (ip and hostname): stay under SQLite's 999-parameter limit


def _existing_host_keys(session, targets: List[str]):
    """Look up which targets are already stored as a host ip or hostname (batched lookups).

    Returns (existing_keys, unchecked_targets): targets in a chunk whose lookup failed are reported as
    unchecked so the caller can skip just those, instead of the whole import.
    """
    existing = set()
    unchecked: List[str] = []
    for offset in range(0, len(targets), _IMPORT_LOOKUP_CHUNK):
        chunk = targets[offset:offset + _IMPORT_LOOKUP_CHUNK]
        try:
            rows = session.query(hostObj.ip, hostObj.hostname).filter(
                (hostObj.ip.in_(chunk)) | (hostObj.hostname.in_(chunk))
            ).all()
        except Exception as repo_exc:
            session.rollback()
            print(f"Warning: unable to check existing hosts for {len(chunk)} targets: {repo_exc}", file=sys.stderr)
            unchecked.extend(chunk)
            continue
        for ip_value, hostname_value in rows:
            existing.add(str(ip_value))
            existing.add(str(hostname_value))
    return existing, unchecked


def import_targets(session, hostRepository, targets: Iterable[str]) -> List[str]:
    """
    Import targets (hostnames, subnets, IPs, etc.) from an iterable into the database.
    Returns the list of newly-added targets.

    Existing hosts (matched by ip or hostname) are looked up in bulk through ``session`` and all new hosts are
    committed together. ``hostRepository`` is kept for API compatibility.
    """
    candidates: List[str] = []
    seen = set()
    for raw_target in list(targets or []):
        target = _normalize_import_target(raw_target)
        if not target or target in seen:
            continue
        seen.add(target)
        candidates.append(target)
    if not candidates:
        return []

    existing, unchecked = _existing_host_keys(session, candidates)
    skipped = set(unchecked)  # never add a target we could not check, to avoid duplicate hosts
    added_targets: List[str] = [target for target in candidates if target not in existing and target not in skipped]
    if not added_targets:
        return []
    def _new_host(target: str) -> hostObj:
        return hostObj(
            ip=target,
            ipv4=target,
            ipv6='',
            macaddr='',
            status='',
            hostname=target,
            vendor='',
            uptime='',
            lastboot='',
            distance='',
            state='',
            count='',
        )

    try:
        session.add_all([_new_host(target) for target in added_targets])
        session.commit()
    except Exception as batch_exc:
        session.rollback()
        # Fall back to one commit per target so a single bad row does not drop the whole batch.
        print(f"Warning: batch target import failed ({batch_exc}); retrying targets individually.", file=sys.stderr)
        imported: List[str] = []
        for target in added_targets:
            try:
                session.add(_new_host(target))
                session.commit()
                imported.append(target)
            except Exception as db_exc:
                session.rollback()
                print(f"Error importing target {target}: {db_exc}", file=sys.stderr)
        return imported
    return added_targets


def _row_to_dict(obj) -> dict:
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}


def build_hosts_export(database) -> List[dict]:
    """
    Build the per-host JSON export (host fields, ports with service/scripts, first note, CVEs).

    Uses one session and one query per table, grouping the rows in Python, instead of several queries per port.
    """
    from db.entities.cve import cve
    from db.entities.l1script import l1ScriptObj
    from db.entities.note import note
    from db.entities.port import portObj
    from db.entities.service import serviceObj

    session = database.session()
    try:
        hosts = session.query(hostObj).order_by(hostObj.id).all()
        services_by_id = {str(item.id): _row_to_dict(item) for item in session.query(serviceObj).all()}

        scripts_by_port = {}
        for script in session.query(l1ScriptObj).order_by(l1ScriptObj.id).all():
            if script.portId in (None, ''):
                continue
            scripts_by_port.setdefault(str(script.portId), []).append(_row_to_dict(script))

        ports_by_host = {}
        for port in session.query(portObj).order_by(portObj.id).all():
            port_dict = _row_to_dict(port)
            service = services_by_id.get(str(port.serviceId)) if port.serviceId not in (None, '') else None
            if service:
                port_dict['service'] = dict(service)
            port_dict['scripts'] = scripts_by_port.get(str(port.id), [])
            ports_by_host.setdefault(str(port.hostId), []).append(port_dict)

        note_by_host = {}
        for note_row in session.query(note).order_by(note.id).all():
            note_by_host.setdefault(str(note_row.hostId), note_row.text or "")

        cves_by_host = {}
        for cve_row in session.query(cve).order_by(cve.id).all():
            cves_by_host.setdefault(str(cve_row.hostId), []).append(_row_to_dict(cve_row))

        hosts_data = []
        for host in hosts:
            host_key = str(host.id)
            host_dict = _row_to_dict(host)
            host_dict['ports'] = ports_by_host.get(host_key, [])
            host_dict['note'] = note_by_host.get(host_key, "")
            host_dict['cves'] = cves_by_host.get(host_key, [])
            hosts_data.append(host_dict)
        return hosts_data
    finally:
        session.close()


def import_targets_from_textfile(session, hostRepository, filename):
    """
    Import targets (hostnames, subnets, IPs, etc.) from a text file into the database.
    Each line is treated as a target.
    """
    raw_targets = []
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw_targets.append(line)
    except FileNotFoundError:
        print(f"Error: input file '{filename}' not found.", file=sys.stderr)
        return 0
    except OSError as exc:
        print(f"Error opening input file '{filename}': {exc}", file=sys.stderr)
        return 0
    return len(import_targets(session, hostRepository, raw_targets))

def is_wsl():
    try:
        with open('/proc/version', 'r') as f:
            return 'Microsoft' in f.read()
    except Exception:
        return False

def to_windows_path(path):
    try:
        import subprocess
        return subprocess.check_output(['wslpath', '-w', path]).decode().strip()
    except Exception:
        # Fallback: naive conversion for /mnt/c/...
        if path.startswith('/mnt/'):
            drive = path[5]
            rest = path[6:]
            rest_win = rest.replace('/', '\\')
            return f"{drive.upper()}:\\{rest_win}"
        return path

class NmapStageError(RuntimeError):
    """A staged scan stopped part-way; `written` lists the XML reports of the stages that did complete."""

    def __init__(self, stage_name, written):
        super().__init__(f"nmap stage {stage_name} failed")
        self.stage_name = str(stage_name)
        self.written = list(written or [])


def run_nmap_scan(targets, output_prefix, discovery=True, staged=False, nmap_path="nmap", stage_specs=None,
                  nmap_args=""):
    """
    Run nmap against the given targets and return the XML reports written (a list of paths), or None on failure.
    A staged scan that fails after some stages completed raises NmapStageError carrying the reports written so far.
    - discovery: run a host-discovery sweep (-sn). With staged=False and discovery=True that is the whole scan.
    - staged: run the configured [StagedNmapSettings] stages (service detection per port group, NSE stage), each
      producing its own XML; when discovery is False the stages use -Pn.
    - neither: one -T4 -sV -O service scan (with -Pn).
    """
    from app.web.runtime_scan_planning import build_staged_scan_plan, os_detection_allowed

    def convert_if_needed(prefix):
        if is_wsl() and nmap_path.lower().endswith('.exe'):
            return to_windows_path(prefix)
        return prefix

    target_list = [item for item in str(targets or "").split() if item]
    try:
        extra_args = shlex.split(str(nmap_args or "")) if str(nmap_args or "").strip() else []
    except ValueError as exc:
        print(f"Error: invalid --nmap-args: {exc}", file=sys.stderr)
        return None

    if staged:
        # The planner converts the -oA argument for nmap.exe under WSL itself; xml_path stays a local path.
        plan = build_staged_scan_plan(
            nmap_path=nmap_path,
            targets=target_list,
            output_prefix=output_prefix,
            discovery=bool(discovery),
            extra_args=extra_args,
            stage_specs=list(stage_specs or []),
        )
        written = []
        for stage in plan["stages"]:
            try:
                subprocess.run(shlex.split(stage["command"]), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (subprocess.CalledProcessError, OSError) as exc:
                print(f"Error running nmap stage {stage['tool_name']}: {exc}", file=sys.stderr)
                raise NmapStageError(stage["tool_name"], written) from exc
            written.append(stage["xml_path"])
        return written

    cmd = [nmap_path]
    if discovery:
        cmd.append("-sn")
    else:
        cmd += ["-Pn", "-T4", "-sV"] + (["-O"] if os_detection_allowed(nmap_path) else [])
    cmd += extra_args + target_list + ["-oA", convert_if_needed(output_prefix)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"Error running nmap: {exc}", file=sys.stderr)
        return None
    return [output_prefix + ".xml"]
