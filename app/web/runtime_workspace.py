from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.device_categories import category_names, normalize_manual_device_categories
from app.device_categories import classify_device_categories
from app.device_categories import merge_effective_device_categories
from app.scheduler.insights import delete_host_ai_state
from app.scheduler.state import get_target_state, upsert_target_state
from app.scheduler.state import load_observed_service_inventory
from db.entities.cve import cve
from db.entities.l1script import l1ScriptObj


def host_is_down(status: Any) -> bool:
    return str(status or "").strip().lower() == "down"


def summary(runtime) -> Dict[str, int]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return {
            "hosts": 0,
            "open_ports": 0,
            "services": 0,
            "cves": 0,
            "running_processes": 0,
            "finished_processes": 0,
        }

    session = project.database.session()
    try:
        hosts_count = session.execute(text("SELECT COUNT(*) FROM hostObj")).scalar() or 0
        open_ports = session.execute(
            text("SELECT COUNT(*) FROM portObj WHERE state = 'open' OR state = 'open|filtered'")
        ).scalar() or 0
        services = session.execute(text("SELECT COUNT(*) FROM serviceObj")).scalar() or 0
        cves_count = session.execute(text("SELECT COUNT(*) FROM cve")).scalar() or 0
        running_processes = session.execute(
            text("SELECT COUNT(*) FROM process WHERE status IN ('Running', 'Waiting')")
        ).scalar() or 0
        finished_processes = session.execute(
            text("SELECT COUNT(*) FROM process WHERE status = 'Finished'")
        ).scalar() or 0
        return {
            "hosts": int(hosts_count),
            "open_ports": int(open_ports),
            "services": int(services),
            "cves": int(cves_count),
            "running_processes": int(running_processes),
            "finished_processes": int(finished_processes),
        }
    except Exception:
        return {
            "hosts": 0,
            "open_ports": 0,
            "services": 0,
            "cves": 0,
            "running_processes": 0,
            "finished_processes": 0,
        }
    finally:
        session.close()


def hosts(runtime, limit: Optional[int] = None, include_down: bool = False) -> List[Dict[str, Any]]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return []

    repo_container = project.repositoryContainer
    host_repo = repo_container.hostRepository
    port_repo = repo_container.portRepository
    service_repo = getattr(repo_container, "serviceRepository", None)

    host_rows = list(host_repo.getAllHostObjs())
    if not bool(include_down):
        host_rows = [host for host in host_rows if not host_is_down(getattr(host, "status", ""))]
    if limit is not None:
        try:
            normalized_limit = int(limit)
        except (TypeError, ValueError):
            normalized_limit = 0
        if normalized_limit > 0:
            host_rows = host_rows[:normalized_limit]
    return [build_workspace_host_row(runtime, host, port_repo, service_repo, project) for host in host_rows]


def get_workspace_overview(runtime) -> Dict[str, Any]:
    with runtime._lock:
        return {
            "project": runtime._project_metadata(),
            "summary": runtime._summary(),
            "scheduler": runtime._scheduler_preferences(),
            "scheduler_rationale_feed": runtime._scheduler_rationale_feed_locked(limit=12),
        }


def workspace_host_services(runtime, port_rows: List[Any], service_repo: Any) -> List[str]:
    services = []
    for port in list(port_rows or []):
        if str(getattr(port, "state", "") or "") not in {"open", "open|filtered"}:
            continue
        service_name = ""
        service_id = getattr(port, "serviceId", None)
        if service_id and service_repo is not None:
            try:
                service_obj = service_repo.getServiceById(service_id)
            except Exception:
                service_obj = None
            service_name = str(getattr(service_obj, "name", "") or "")
        if not service_name:
            service_name = str(getattr(port, "serviceName", "") or "")
        service_name = service_name.strip()
        if service_name:
            services.append(service_name)
    return sorted({item for item in services if item})


def resolve_host_device_categories(
        runtime,
        project: Any,
        host: Any,
        *,
        target_state: Optional[Dict[str, Any]] = None,
        service_inventory: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    state = dict(target_state or {})
    effective = list(state.get("device_categories", []) or [])
    manual = list(state.get("manual_device_categories", []) or [])
    override_auto = bool(state.get("device_category_override", False))
    if effective:
        return {
            "device_categories": list(effective),
            "manual_device_categories": list(manual),
            "device_category_override": override_auto,
        }
    resolved_inventory = list(service_inventory or state.get("service_inventory", []) or [])
    if not resolved_inventory:
        try:
            resolved_inventory = load_observed_service_inventory(project.database, int(getattr(host, "id", 0) or 0))
        except Exception:
            resolved_inventory = []
    manual = normalize_manual_device_categories(
        manual or (
            state.get("raw", {}).get("manual_device_categories", [])
            if isinstance(state.get("raw", {}), dict)
            else []
        )
    )
    override_auto = bool(
        state.get("device_category_override", False)
        or (
            state.get("raw", {}).get("device_category_override", False)
            if isinstance(state.get("raw", {}), dict)
            else False
        )
    )
    auto = classify_device_categories(
        {
            "hostname": str(getattr(host, "hostname", "") or state.get("hostname", "") or ""),
            "os_match": str(getattr(host, "osMatch", "") or state.get("os_match", "") or ""),
            "service_inventory": resolved_inventory,
            "technologies": list(state.get("technologies", []) or []),
            "findings": list(state.get("findings", []) or []),
        },
        custom_rules=runtime.scheduler_config.get_device_categories(),
    )
    return {
        "device_categories": merge_effective_device_categories(auto, manual, override_auto=override_auto),
        "manual_device_categories": manual,
        "device_category_override": override_auto,
    }


def build_workspace_host_row(runtime, host: Any, port_repo: Any, service_repo: Any, project: Any) -> Dict[str, Any]:
    ports = list(port_repo.getPortsByHostId(host.id) or [])
    open_ports = [p for p in ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}]
    services = workspace_host_services(runtime, ports, service_repo)
    target_state = get_target_state(project.database, int(getattr(host, "id", 0) or 0)) or {}
    category_state = resolve_host_device_categories(runtime, project, host, target_state=target_state)
    return {
        "id": int(host.id),
        "ip": str(getattr(host, "ip", "") or ""),
        "hostname": str(getattr(host, "hostname", "") or ""),
        "status": str(getattr(host, "status", "") or ""),
        "os": str(getattr(host, "osMatch", "") or ""),
        "open_ports": len(open_ports),
        "total_ports": len(ports),
        "services": services,
        "categories": category_names(category_state.get("device_categories", [])),
        "category_override": bool(category_state.get("device_category_override", False)),
    }


def get_workspace_hosts(
        runtime,
        limit: Optional[int] = None,
        include_down: bool = False,
        service: str = "",
        category: str = "",
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        repo_container = project.repositoryContainer
        host_repo = repo_container.hostRepository
        port_repo = repo_container.portRepository
        service_repo = getattr(repo_container, "serviceRepository", None)
        hosts = list(host_repo.getAllHostObjs())
        if not bool(include_down):
            hosts = [host for host in hosts if not host_is_down(getattr(host, "status", ""))]
        service_filter = str(service or "").strip().lower()
        category_filter = str(category or "").strip().lower()
        rows = [build_workspace_host_row(runtime, host, port_repo, service_repo, project) for host in hosts]
        if service_filter:
            rows = [
                row for row in rows
                if any(str(item or "").strip().lower() == service_filter for item in list(row.get("services", []) or []))
            ]
        if category_filter:
            rows = [
                row for row in rows
                if any(str(item or "").strip().lower() == category_filter for item in list(row.get("categories", []) or []))
            ]
        if limit is not None:
            try:
                normalized_limit = int(limit)
            except (TypeError, ValueError):
                normalized_limit = 0
            if normalized_limit > 0:
                rows = rows[:normalized_limit]
        return rows


def get_workspace_services(runtime, limit: int = 300, host_id: int = 0, category: str = "") -> List[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []
        repo_container = project.repositoryContainer
        host_repo = repo_container.hostRepository
        port_repo = repo_container.portRepository
        service_repo = getattr(repo_container, "serviceRepository", None)
        try:
            normalized_host_id = int(host_id or 0)
        except (TypeError, ValueError):
            normalized_host_id = 0
        category_filter = str(category or "").strip().lower()
        grouped: Dict[str, Dict[str, Any]] = {}
        for host in list(host_repo.getAllHostObjs() or []):
            current_host_id = int(getattr(host, "id", 0) or 0)
            if normalized_host_id > 0 and current_host_id != normalized_host_id:
                continue
            category_state = resolve_host_device_categories(runtime, project, host)
            host_categories = category_names(category_state.get("device_categories", []))
            if category_filter and not any(str(item or "").strip().lower() == category_filter for item in host_categories):
                continue
            for port in list(port_repo.getPortsByHostId(current_host_id) or []):
                if str(getattr(port, "state", "") or "") not in {"open", "open|filtered"}:
                    continue
                service_obj = None
                service_id = getattr(port, "serviceId", None)
                if service_id and service_repo is not None:
                    try:
                        service_obj = service_repo.getServiceById(service_id)
                    except Exception:
                        service_obj = None
                service_name = str(getattr(service_obj, "name", "") or getattr(port, "serviceName", "") or "unknown").strip() or "unknown"
                key = service_name.lower()
                row = grouped.setdefault(key, {
                    "service": service_name,
                    "port_count": 0,
                    "host_ids": set(),
                    "protocols": set(),
                    "categories": set(),
                })
                row["port_count"] += 1
                row["host_ids"].add(current_host_id)
                row["protocols"].add(str(getattr(port, "protocol", "") or "").strip().lower())
                for item in host_categories:
                    row["categories"].add(str(item or "").strip())
        rows = []
        for item in grouped.values():
            rows.append({
                "service": str(item.get("service", "") or ""),
                "port_count": int(item.get("port_count", 0) or 0),
                "host_count": len(item.get("host_ids", set()) or set()),
                "protocols": sorted([entry for entry in list(item.get("protocols", set()) or set()) if entry]),
                "categories": sorted([entry for entry in list(item.get("categories", set()) or set()) if entry]),
            })
        rows.sort(key=lambda row: (-int(row.get("host_count", 0) or 0), -int(row.get("port_count", 0) or 0), str(row.get("service", "") or "").lower()))
        return rows[: max(1, min(int(limit), 2000))]


def strip_nmap_preamble(output_text: str) -> str:
    text_value = str(output_text or "")
    if not text_value.strip():
        return ""
    filtered = []
    for raw_line in text_value.splitlines():
        line = str(raw_line or "")
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            if filtered:
                filtered.append("")
            continue
        if re.match(r"(?i)^Starting Nmap\b", stripped):
            continue
        if re.match(r"(?i)^Nmap scan report for\b", stripped):
            continue
        if re.match(r"(?i)^Host is up\b", stripped):
            continue
        if re.match(r"(?i)^Not shown:\b", stripped):
            continue
        if re.match(r"(?i)^All \d+ scanned ports\b", stripped):
            continue
        if re.match(r"(?i)^NSE:\s+(Loaded|Script Pre-scanning|Starting runlevel|Ending runlevel)\b", stripped):
            continue
        if re.match(r"(?i)^Service detection performed\b", stripped):
            continue
        if "nmap.org" in lowered and (
                lowered.startswith("starting nmap")
                or lowered.startswith("service detection performed")
                or lowered.startswith("read data files from")
                or lowered.startswith("please report")
        ):
            continue
        if re.match(r"(?i)^PORT\s+STATE\s+SERVICE\b", stripped):
            continue
        if re.match(r"(?i)^Nmap done:", stripped):
            continue
        filtered.append(line)
    cleaned = "\n".join(filtered).strip()
    return cleaned or text_value.strip()


def host_detail_script_preview(script_id: str, output_text: str, max_chars: int = 220) -> str:
    raw_output = str(output_text or "")
    display = raw_output
    lowered = " ".join([str(script_id or ""), raw_output[:400]]).lower()
    if "nmap" in lowered or "nse:" in lowered:
        display = strip_nmap_preamble(raw_output)
    display = re.sub(r"\s+", " ", str(display or "")).strip()
    if len(display) > int(max_chars or 220):
        return display[:max(0, int(max_chars or 220) - 1)].rstrip() + "..."
    return display


def get_target_state_view(runtime, host_id: int = 0, limit: int = 500) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        max_hosts = max(1, min(int(limit or 500), 5000))
        if int(host_id or 0) > 0:
            host = runtime._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_row = {
                "id": int(getattr(host, "id", 0) or 0),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(getattr(host, "osMatch", "") or ""),
            }
            return {
                "host": host_row,
                "target_state": get_target_state(project.database, int(host_id)) or {},
            }

        states = []
        for row in list(runtime._hosts(limit=max_hosts) or []):
            states.append({
                "host": dict(row),
                "target_state": get_target_state(project.database, int(row.get("id", 0) or 0)) or {},
            })
        return {
            "count": len(states),
            "states": states,
        }


def get_findings(
        runtime,
        host_id: int = 0,
        limit_hosts: int = 500,
        limit_findings: int = 1000,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        if int(host_id or 0) > 0:
            host = runtime._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            host_rows = [{
                "id": int(getattr(host, "id", 0) or 0),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(getattr(host, "osMatch", "") or ""),
            }]
        else:
            host_rows = list(runtime._hosts(limit=max(1, min(int(limit_hosts or 500), 5000))) or [])

        findings = []
        max_items = max(1, min(int(limit_findings or 1000), 5000))
        for row in host_rows:
            state = get_target_state(project.database, int(row.get("id", 0) or 0)) or {}
            for item in list(state.get("findings", []) or []):
                if not isinstance(item, dict):
                    continue
                findings.append({
                    "host": dict(row),
                    "title": str(item.get("title", "") or ""),
                    "severity": str(item.get("severity", "") or ""),
                    "confidence": item.get("confidence", 0.0),
                    "source_kind": str(item.get("source_kind", "") or "observed"),
                    "finding": dict(item),
                })
                if len(findings) >= max_items:
                    break
            if len(findings) >= max_items:
                break
        return {
            "count": len(findings),
            "host_scope_count": len(host_rows),
            "findings": findings,
        }


def get_host_workspace(runtime, host_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        repo_container = project.repositoryContainer
        port_repo = repo_container.portRepository
        service_repo = repo_container.serviceRepository
        script_repo = repo_container.scriptRepository
        note_repo = repo_container.noteRepository

        note_obj = note_repo.getNoteByHostId(host.id)
        note_text = str(getattr(note_obj, "text", "") or "")

        ports_data = []
        for port in port_repo.getPortsByHostId(host.id):
            service_obj = None
            if getattr(port, "serviceId", None):
                service_obj = service_repo.getServiceById(getattr(port, "serviceId", None))

            scripts = []
            for script in script_repo.getScriptsByPortId(port.id):
                script_id = str(getattr(script, "scriptId", "") or "")
                output = str(getattr(script, "output", "") or "")
                scripts.append({
                    "id": int(getattr(script, "id", 0) or 0),
                    "script_id": script_id,
                    "output": output,
                    "display_output": host_detail_script_preview(script_id, output),
                })

            ports_data.append({
                "id": int(getattr(port, "id", 0) or 0),
                "port": str(getattr(port, "portId", "") or ""),
                "protocol": str(getattr(port, "protocol", "") or ""),
                "state": str(getattr(port, "state", "") or ""),
                "service": {
                    "id": int(getattr(service_obj, "id", 0) or 0) if service_obj else 0,
                    "name": str(getattr(service_obj, "name", "") or "") if service_obj else "",
                    "product": str(getattr(service_obj, "product", "") or "") if service_obj else "",
                    "version": str(getattr(service_obj, "version", "") or "") if service_obj else "",
                    "extrainfo": str(getattr(service_obj, "extrainfo", "") or "") if service_obj else "",
                },
                "scripts": scripts,
            })

        cves = runtime._load_cves_for_host(project, int(host.id))
        screenshots = runtime._list_screenshots_for_host(project, str(getattr(host, "ip", "") or ""))
        ai_analysis = runtime._load_host_ai_analysis(project, int(host.id), str(getattr(host, "ip", "") or ""))
        inferred_urls = runtime._infer_host_urls(
            project,
            host_id=int(host.id),
            host_ip=str(getattr(host, "ip", "") or ""),
        )
        runtime._persist_shared_target_state(
            host_id=int(host.id),
            host_ip=str(getattr(host, "ip", "") or ""),
            hostname=str(getattr(host, "hostname", "") or ""),
            hostname_confidence=95.0 if str(getattr(host, "hostname", "") or "").strip() else 0.0,
            os_match=str(getattr(host, "osMatch", "") or ""),
            os_confidence=70.0 if str(getattr(host, "osMatch", "") or "").strip() else 0.0,
            technologies=ai_analysis.get("technologies", []) if isinstance(ai_analysis.get("technologies", []), list) else [],
            findings=ai_analysis.get("findings", []) if isinstance(ai_analysis.get("findings", []), list) else [],
            manual_tests=ai_analysis.get("manual_tests", []) if isinstance(ai_analysis.get("manual_tests", []), list) else [],
            next_phase=str(ai_analysis.get("next_phase", "") or ""),
            provider=str(ai_analysis.get("provider", "") or ""),
            goal_profile=str(ai_analysis.get("goal_profile", "") or ""),
            service_inventory=[
                {
                    "port": str(item.get("port", "") or ""),
                    "protocol": str(item.get("protocol", "") or ""),
                    "state": str(item.get("state", "") or ""),
                    "service": str((item.get("service", {}) or {}).get("name", "") or ""),
                    "service_product": str((item.get("service", {}) or {}).get("product", "") or ""),
                    "service_version": str((item.get("service", {}) or {}).get("version", "") or ""),
                    "service_extrainfo": str((item.get("service", {}) or {}).get("extrainfo", "") or ""),
                }
                for item in ports_data
                if isinstance(item, dict)
            ],
            urls=inferred_urls,
            screenshots=screenshots,
        )
        target_state = get_target_state(project.database, int(host.id)) or {}

        return {
            "host": {
                "id": int(host.id),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(getattr(host, "osMatch", "") or ""),
            },
            "note": note_text,
            "ports": ports_data,
            "cves": cves,
            "screenshots": screenshots,
            "ai_analysis": ai_analysis,
            "target_state": target_state,
        }


def update_host_note(runtime, host_id: int, text_value: str) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        ok = project.repositoryContainer.noteRepository.storeNotes(host.id, str(text_value or ""))
        return {
            "host_id": int(host.id),
            "saved": bool(ok),
        }


def update_host_categories(
        runtime,
        host_id: int,
        *,
        manual_categories: Any = None,
        override_auto: bool = False,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        updated_state = upsert_target_state(project.database, int(host.id), {
            "host_ip": str(getattr(host, "ip", "") or ""),
            "hostname": str(getattr(host, "hostname", "") or ""),
            "os_match": str(getattr(host, "osMatch", "") or ""),
            "manual_device_categories": normalize_manual_device_categories(manual_categories),
            "device_category_override": bool(override_auto),
        }, merge=True)
        return {
            "host_id": int(host.id),
            "device_categories": category_names(updated_state.get("device_categories", [])),
            "manual_device_categories": category_names(updated_state.get("manual_device_categories", [])),
            "device_category_override": bool(updated_state.get("device_category_override", False)),
        }


def delete_host_workspace(runtime, host_id: int) -> Dict[str, Any]:
    target_host_id = int(host_id)
    target_host_ip = ""

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(target_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        target_host_ip = str(getattr(host, "ip", "") or "").strip()

        runtime._ensure_process_tables()
        runtime._ensure_scheduler_table()
        runtime._ensure_scheduler_approval_store()

        session = project.database.session()
        try:
            running_process_ids = []
            if target_host_ip:
                result = session.execute(text(
                    "SELECT id FROM process "
                    "WHERE COALESCE(hostIp, '') = :host_ip "
                    "AND COALESCE(status, '') IN ('Running', 'Waiting')"
                ), {"host_ip": target_host_ip})
                running_process_ids = [
                    int(item[0]) for item in result.fetchall()
                    if item and item[0] is not None
                ]
        finally:
            session.close()

    for process_id in running_process_ids:
        try:
            runtime.kill_process(int(process_id))
        except Exception:
            pass

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(target_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        target_host_ip = str(getattr(host, "ip", "") or "").strip()
        host_id_text = str(int(getattr(host, "id", target_host_id) or target_host_id))

        session = project.database.session()
        deleted_counts = {
            "scripts": 0,
            "cves": 0,
            "notes": 0,
            "ports": 0,
            "hosts": 0,
            "process_output": 0,
            "processes": 0,
            "approvals": 0,
            "decisions": 0,
            "ai_analysis": 0,
        }

        try:
            script_delete = session.execute(text(
                "DELETE FROM l1ScriptObj "
                "WHERE CAST(hostId AS TEXT) = :host_id "
                "OR CAST(portId AS TEXT) IN ("
                "SELECT CAST(id AS TEXT) FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
                ")"
            ), {"host_id": host_id_text})
            deleted_counts["scripts"] = max(0, int(script_delete.rowcount or 0))

            cve_delete = session.execute(text(
                "DELETE FROM cve WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["cves"] = max(0, int(cve_delete.rowcount or 0))

            note_delete = session.execute(text(
                "DELETE FROM note WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["notes"] = max(0, int(note_delete.rowcount or 0))

            port_delete = session.execute(text(
                "DELETE FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["ports"] = max(0, int(port_delete.rowcount or 0))

            host_delete = session.execute(text(
                "DELETE FROM hostObj WHERE id = :host_id_int"
            ), {"host_id_int": int(host_id_text)})
            deleted_counts["hosts"] = max(0, int(host_delete.rowcount or 0))

            if target_host_ip:
                process_output_delete = session.execute(text(
                    "DELETE FROM process_output "
                    "WHERE processId IN (SELECT id FROM process WHERE COALESCE(hostIp, '') = :host_ip)"
                ), {"host_ip": target_host_ip})
                deleted_counts["process_output"] = max(0, int(process_output_delete.rowcount or 0))

                process_delete = session.execute(text(
                    "DELETE FROM process WHERE COALESCE(hostIp, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["processes"] = max(0, int(process_delete.rowcount or 0))

                approval_delete = session.execute(text(
                    "DELETE FROM scheduler_pending_approval WHERE COALESCE(host_ip, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["approvals"] = max(0, int(approval_delete.rowcount or 0))

                decision_delete = session.execute(text(
                    "DELETE FROM scheduler_decision_log WHERE COALESCE(host_ip, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["decisions"] = max(0, int(decision_delete.rowcount or 0))

            session.execute(text(
                "DELETE FROM serviceObj "
                "WHERE CAST(id AS TEXT) NOT IN ("
                "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj "
                "WHERE COALESCE(serviceId, '') <> ''"
                ")"
            ))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        deleted_counts["ai_analysis"] = int(delete_host_ai_state(project.database, int(host_id_text)) or 0)

        deleted_screenshots = 0
        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        if os.path.isdir(screenshot_dir) and target_host_ip:
            prefix = f"{target_host_ip}-"
            for filename in os.listdir(screenshot_dir):
                if not filename.startswith(prefix) or not filename.lower().endswith(".png"):
                    continue
                try:
                    os.remove(os.path.join(screenshot_dir, filename))
                    deleted_screenshots += 1
                except Exception:
                    continue

        return {
            "deleted": True,
            "host_id": int(target_host_id),
            "host_ip": target_host_ip,
            "counts": {
                **deleted_counts,
                "screenshots": int(deleted_screenshots),
            },
        }


def create_script_entry(
        runtime,
        host_id: int,
        port: str,
        protocol: str,
        script_id: str,
        output: str,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        port_obj = project.repositoryContainer.portRepository.getPortByHostIdAndPort(
            host.id,
            str(port),
            str(protocol or "tcp").lower(),
        )
        if port_obj is None:
            raise KeyError(f"Unknown port {port}/{protocol} for host {host.id}")

        session = project.database.session()
        try:
            script_row = l1ScriptObj(str(script_id), str(output or ""), str(port_obj.id), str(host.id))
            session.add(script_row)
            session.commit()
            return {
                "id": int(script_row.id),
                "script_id": str(script_row.scriptId),
                "port_id": int(port_obj.id),
            }
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def delete_script_entry(runtime, script_db_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.query(l1ScriptObj).filter_by(id=int(script_db_id)).first()
            if row is None:
                raise KeyError(f"Unknown script id: {script_db_id}")
            session.delete(row)
            session.commit()
            return {"deleted": True, "id": int(script_db_id)}
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def get_script_output(runtime, script_db_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
    offset_value = max(0, int(offset or 0))
    max_len = max(256, min(int(max_chars or 12000), 50000))
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            script_result = session.execute(text(
                "SELECT s.id AS script_db_id, "
                "COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS script_output, "
                "COALESCE(p.portId, '') AS port, "
                "LOWER(COALESCE(p.protocol, 'tcp')) AS protocol, "
                "COALESCE(h.ip, '') AS host_ip "
                "FROM l1ScriptObj AS s "
                "LEFT JOIN portObj AS p ON p.id = s.portId "
                "LEFT JOIN hostObj AS h ON h.id = s.hostId "
                "WHERE s.id = :id LIMIT 1"
            ), {"id": int(script_db_id)})
            script_row = script_result.fetchone()
            if script_row is None:
                raise KeyError(f"Unknown script id: {script_db_id}")
            script_data = dict(zip(script_result.keys(), script_row))

            process_result = session.execute(text(
                "SELECT p.id AS process_id, "
                "COALESCE(p.command, '') AS command, "
                "COALESCE(p.outputfile, '') AS outputfile, "
                "COALESCE(p.status, '') AS status, "
                "COALESCE(o.output, '') AS output "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE p.name = :tool_id "
                "AND COALESCE(p.hostIp, '') = :host_ip "
                "AND COALESCE(p.port, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "tool_id": str(script_data.get("script_id", "") or ""),
                "host_ip": str(script_data.get("host_ip", "") or ""),
                "port": str(script_data.get("port", "") or ""),
                "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
            })
            process_row = process_result.fetchone()
            process_data = dict(zip(process_result.keys(), process_row)) if process_row else {}
        finally:
            session.close()

    has_process = bool(process_data.get("process_id"))
    output_text = str(process_data.get("output", "") or "") if has_process else str(script_data.get("script_output", "") or "")
    output_length = len(output_text)
    chunk = ""
    if offset_value < output_length:
        chunk = output_text[offset_value:offset_value + max_len]
    next_offset = offset_value + len(chunk)
    status = str(process_data.get("status", "") or "")
    completed = status not in {"Running", "Waiting"} if has_process else True

    return {
        "script_db_id": int(script_data.get("script_db_id", 0) or 0),
        "script_id": str(script_data.get("script_id", "") or ""),
        "host_ip": str(script_data.get("host_ip", "") or ""),
        "port": str(script_data.get("port", "") or ""),
        "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
        "source": "process" if has_process else "script-row",
        "process_id": int(process_data.get("process_id", 0) or 0),
        "outputfile": str(process_data.get("outputfile", "") or ""),
        "command": runtime._redact_command_secrets(process_data.get("command", "")),
        "status": status if has_process else "Saved",
        "output": output_text,
        "output_chunk": chunk,
        "output_length": output_length,
        "offset": offset_value,
        "next_offset": next_offset,
        "completed": completed,
    }


def create_cve_entry(
        runtime,
        host_id: int,
        name: str,
        url: str = "",
        severity: str = "",
        source: str = "",
        product: str = "",
        version: str = "",
        exploit_id: int = 0,
        exploit: str = "",
        exploit_url: str = "",
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        session = project.database.session()
        try:
            existing = session.query(cve).filter_by(hostId=str(host.id), name=str(name)).first()
            if existing:
                return {
                    "id": int(existing.id),
                    "name": str(existing.name),
                    "host_id": int(host.id),
                    "created": False,
                }

            row = cve(
                str(name),
                str(url or ""),
                str(product or ""),
                str(host.id),
                severity=str(severity or ""),
                source=str(source or ""),
                version=str(version or ""),
                exploitId=int(exploit_id or 0),
                exploit=str(exploit or ""),
                exploitUrl=str(exploit_url or ""),
            )
            session.add(row)
            session.commit()
            return {
                "id": int(row.id),
                "name": str(row.name),
                "host_id": int(host.id),
                "created": True,
            }
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def delete_cve_entry(runtime, cve_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.query(cve).filter_by(id=int(cve_id)).first()
            if row is None:
                raise KeyError(f"Unknown cve id: {cve_id}")
            session.delete(row)
            session.commit()
            return {"deleted": True, "id": int(cve_id)}
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
