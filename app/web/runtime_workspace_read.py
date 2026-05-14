from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import text

from app.scheduler.state import get_target_state as load_target_state
from app.web import runtime_workspace_findings as web_runtime_workspace_findings
from app.web import runtime_workspace_services as web_runtime_workspace_services
from app.web import runtime_workspace_target_state as web_runtime_workspace_target_state
from app.web.runtime_workspace_identity import (
    _service_names_from_inventory,
    build_workspace_host_row,
    resolve_host_device_categories,
    resolve_host_os,
    workspace_host_service_inventory,
    workspace_host_services,
)
from app.web.runtime_workspace_host_detail import get_host_workspace


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
    prepared = []
    for host in host_rows:
        ports = list(port_repo.getPortsByHostId(host.id) or [])
        service_inventory = workspace_host_service_inventory(ports, service_repo)
        prepared.append((host, ports, service_inventory, _service_names_from_inventory(service_inventory)))
    target_states = _load_target_state_cache(project, [int(getattr(host, "id", 0) or 0) for host, *_ in prepared])
    return [
        row_builder(
            runtime,
            host,
            port_repo,
            service_repo,
            project,
            preloaded_ports=ports,
            preloaded_service_inventory=service_inventory,
            preloaded_services=services,
            preloaded_target_state=target_states.get(int(getattr(host, "id", 0) or 0), {}),
        )
        for host, ports, service_inventory, services in prepared
    ]


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


def _normalize_service_filters(values: Any) -> List[str]:
    raw_values: Iterable[Any]
    if isinstance(values, (list, tuple, set)):
        raw_values = values
    else:
        raw_values = [values]

    rows: List[str] = []
    seen = set()
    for value in raw_values:
        for token in str(value or "").split(","):
            normalized = token.strip().lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            rows.append(normalized)
    return rows


_load_target_state_cache = web_runtime_workspace_target_state.load_target_state_cache


def _host_matches_service_filters(row: Dict[str, Any], service_filters: List[str]) -> bool:
    if not service_filters:
        return True
    row_services = {
        str(item or "").strip().lower()
        for item in list(row.get("services", []) or [])
        if str(item or "").strip()
    }
    return any(service_name in row_services for service_name in service_filters)


def _services_match_filters(services: List[str], service_filters: List[str]) -> bool:
    if not service_filters:
        return True
    row_services = {
        str(item or "").strip().lower()
        for item in list(services or [])
        if str(item or "").strip()
    }
    return any(service_name in row_services for service_name in service_filters)


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
        service_filters = _normalize_service_filters(service)
        category_filter = str(category or "").strip().lower()
        prepared = []
        for host in hosts:
            ports = list(port_repo.getPortsByHostId(host.id) or [])
            service_inventory = workspace_host_service_inventory(ports, service_repo)
            services = _service_names_from_inventory(service_inventory)
            if service_filters and not _services_match_filters(services, service_filters):
                continue
            prepared.append((host, ports, service_inventory, services))
        target_states = _load_target_state_cache(project, [
            int(getattr(host, "id", 0) or 0)
            for host, *_ in prepared
        ])
        rows = []
        for host, ports, service_inventory, services in prepared:
            rows.append(row_builder(
                runtime,
                host,
                port_repo,
                service_repo,
                project,
                preloaded_ports=ports,
                preloaded_service_inventory=service_inventory,
                preloaded_services=services,
                preloaded_target_state=target_states.get(int(getattr(host, "id", 0) or 0), {}),
            ))
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
    return web_runtime_workspace_services.get_workspace_services(
        runtime,
        limit=limit,
        host_id=host_id,
        category=category,
        load_target_state_cache_func=_load_target_state_cache,
    )


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
    return web_runtime_workspace_findings.get_target_state_view(
        runtime,
        host_id=host_id,
        limit=limit,
        get_target_state_func=get_target_state_func,
    )


def get_findings(
        runtime,
        host_id: int = 0,
        limit_hosts: int = 500,
        limit_findings: int = 1000,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    return web_runtime_workspace_findings.get_findings(
        runtime,
        host_id=host_id,
        limit_hosts=limit_hosts,
        limit_findings=limit_findings,
        get_target_state_func=get_target_state_func,
    )
