from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.device_categories import category_names, normalize_manual_device_categories
from app.device_categories import classify_device_categories
from app.device_categories import merge_effective_device_categories
from app.scheduler.state import get_target_state as load_target_state
from app.scheduler.state import load_observed_service_inventory


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


def hosts(
        runtime,
        limit: Optional[int] = None,
        include_down: bool = False,
        *,
        build_workspace_host_row_func=None,
) -> List[Dict[str, Any]]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return []

    repo_container = project.repositoryContainer
    host_repo = repo_container.hostRepository
    port_repo = repo_container.portRepository
    service_repo = getattr(repo_container, "serviceRepository", None)

    row_builder = build_workspace_host_row_func or build_workspace_host_row
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
    return [row_builder(runtime, host, port_repo, service_repo, project) for host in host_rows]


def resolve_host(runtime, host_id: int):
    project = runtime._require_active_project()
    session = project.database.session()
    try:
        result = session.execute(text("SELECT id FROM hostObj WHERE id = :id LIMIT 1"), {"id": int(host_id)}).fetchone()
        if not result:
            return None
    finally:
        session.close()
    hosts = project.repositoryContainer.hostRepository.getAllHostObjs()
    for host in hosts:
        if int(getattr(host, "id", 0) or 0) == int(host_id):
            return host
    return None


def load_cves_for_host(project, host_id: int) -> List[Dict[str, Any]]:
    session = project.database.session()
    try:
        result = session.execute(text(
            "SELECT id, name, severity, product, version, url, source, exploitId, exploit, exploitUrl "
            "FROM cve WHERE hostId = :host_id ORDER BY id DESC"
        ), {"host_id": str(host_id)})
        rows = result.fetchall()
        keys = result.keys()
        return [dict(zip(keys, row)) for row in rows]
    finally:
        session.close()


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


def hostname_for_ip(runtime, host_ip: str) -> str:
    try:
        project = runtime._require_active_project()
        host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
        host_obj = host_repo.getHostByIP(str(host_ip)) if host_repo else None
        return str(getattr(host_obj, "hostname", "") or "")
    except Exception:
        return ""


def service_name_for_target(runtime, host_ip: str, port: str, protocol: str) -> str:
    try:
        project = runtime._require_active_project()
        host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
        host_obj = host_repo.getHostByIP(str(host_ip)) if host_repo else None
        host_id = int(getattr(host_obj, "id", 0) or 0)
        if host_id <= 0:
            return ""

        session = project.database.session()
        try:
            result = session.execute(text(
                "SELECT COALESCE(s.name, '') "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "AND COALESCE(p.portId, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "host_id": host_id,
                "port": str(port or ""),
                "protocol": str(protocol or "tcp"),
            }).fetchone()
            return str(result[0] or "") if result else ""
        finally:
            session.close()
    except Exception:
        return ""


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


def build_workspace_host_row(
        runtime,
        host: Any,
        port_repo: Any,
        service_repo: Any,
        project: Any,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
    ports = list(port_repo.getPortsByHostId(host.id) or [])
    open_ports = [p for p in ports if str(getattr(p, "state", "")) in {"open", "open|filtered"}]
    services = workspace_host_services(runtime, ports, service_repo)
    target_state = target_state_getter(project.database, int(getattr(host, "id", 0) or 0)) or {}
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
        *,
        build_workspace_host_row_func=None,
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        repo_container = project.repositoryContainer
        host_repo = repo_container.hostRepository
        port_repo = repo_container.portRepository
        service_repo = getattr(repo_container, "serviceRepository", None)
        hosts = list(host_repo.getAllHostObjs())
        row_builder = build_workspace_host_row_func or build_workspace_host_row
        if not bool(include_down):
            hosts = [host for host in hosts if not host_is_down(getattr(host, "status", ""))]
        service_filter = str(service or "").strip().lower()
        category_filter = str(category or "").strip().lower()
        rows = [row_builder(runtime, host, port_repo, service_repo, project) for host in hosts]
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


def get_target_state_view(
        runtime,
        host_id: int = 0,
        limit: int = 500,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
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
                "target_state": target_state_getter(project.database, int(host_id)) or {},
            }

        states = []
        for row in list(runtime._hosts(limit=max_hosts) or []):
            states.append({
                "host": dict(row),
                "target_state": target_state_getter(project.database, int(row.get("id", 0) or 0)) or {},
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
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
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
            state = target_state_getter(project.database, int(row.get("id", 0) or 0)) or {}
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


def get_host_workspace(
        runtime,
        host_id: int,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
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
        target_state = target_state_getter(project.database, int(host.id)) or {}

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
