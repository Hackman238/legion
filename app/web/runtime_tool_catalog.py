from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import text

from app.pipettes import find_pipette, list_pipettes
from app.scheduler.risk import classify_command_danger

_SCHEDULER_ONLY_LABELS = {
    "screenshooter": "Capture web screenshot",
}

_SUPPORTED_WORKSPACE_TOOL_IDS = {
    "curl-headers",
    "curl-options",
    "curl-robots",
    "dirsearch",
    "dnsmap",
    "enum4linux",
    "enum4linux-ng",
    "ffuf",
    "http-sqlmap",
    "httpx",
    "nbtscan",
    "nikto",
    "nmap",
    "nmap-vuln.nse",
    "nuclei-cves",
    "nuclei-exposures",
    "nuclei-web",
    "nuclei-wordpress",
    "rpcclient-enum",
    "screenshooter",
    "smbmap",
    "sqlmap",
    "sslscan",
    "testssl.sh",
    "wafw00f",
    "web-content-discovery",
    "whatweb",
    "whatweb-http",
    "whatweb-https",
    "wpscan",
}

_SUPPORTED_WORKSPACE_TOOL_PREFIXES = (
    "http-vuln-",
)


def _service_matches_scope(normalized_service: str, service_scope: List[str]) -> bool:
    if not normalized_service:
        return True
    if not service_scope:
        return True
    lowered = {item.lower() for item in service_scope}
    return "*" in lowered or normalized_service in lowered


def _normalize_port_value(value: Any) -> str:
    text_value = str(value or "").strip()
    try:
        parsed = int(text_value)
    except (TypeError, ValueError):
        return text_value
    return str(parsed) if 1 <= parsed <= 65535 else text_value


def _port_matches_scope(normalized_port: str, target_ports: List[str]) -> bool:
    if not normalized_port or not target_ports:
        return False
    normalized_targets = {_normalize_port_value(item) for item in target_ports}
    return "*" in normalized_targets or normalized_port in normalized_targets


def _pipette_matches_context(
        *,
        normalized_service: str,
        service_scope: List[str],
        normalized_port: str,
        target_ports: List[str],
) -> bool:
    if not normalized_service and not normalized_port:
        return True
    if normalized_service and _service_matches_scope(normalized_service, service_scope):
        return True
    return _port_matches_scope(normalized_port, target_ports)


def _is_supported_tool(tool_id: str) -> bool:
    normalized_tool = str(tool_id or "").strip().lower()
    if not normalized_tool:
        return False
    if find_pipette(normalized_tool) is not None:
        return True
    if normalized_tool in _SUPPORTED_WORKSPACE_TOOL_IDS:
        return True
    return any(normalized_tool.startswith(prefix) for prefix in _SUPPORTED_WORKSPACE_TOOL_PREFIXES)


def tool_run_stats(project) -> Dict[str, Dict[str, Any]]:
    session = project.database.session()
    try:
        result = session.execute(text(
            "SELECT p.name, COUNT(*) AS run_count, MAX(p.id) AS max_id "
            "FROM process AS p GROUP BY p.name"
        ))
        rows = result.fetchall()
        stats = {}
        for name, run_count, max_id in rows:
            name_key = str(name or "")
            last_status = ""
            last_start = ""
            if max_id:
                detail = session.execute(text(
                    "SELECT status, startTime FROM process WHERE id = :id LIMIT 1"
                ), {"id": int(max_id)}).fetchone()
                if detail:
                    last_status = str(detail[0] or "")
                    last_start = str(detail[1] or "")
            stats[name_key] = {
                "run_count": int(run_count or 0),
                "last_status": last_status,
                "last_start": last_start,
            }
        return stats
    except Exception:
        return {}
    finally:
        session.close()


def workspace_tools_rows(runtime, service: str = "", port: str = "", protocol: str = "tcp") -> List[Dict[str, Any]]:
    with runtime._lock:
        settings = runtime._get_settings()
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []

        normalized_service = str(service or "").strip().rstrip("?").lower()
        normalized_port = _normalize_port_value(port)
        normalized_protocol = str(protocol or "tcp").strip().lower() or "tcp"
        run_stats = runtime._tool_run_stats(project)
        dangerous_categories = runtime.scheduler_config.get_dangerous_categories()
        rows = []
        seen_tool_ids = set()

        for action in settings.portActions:
            label = str(action[0])
            tool_id = str(action[1])
            command_template = str(action[2])
            service_scope = runtime._split_csv(str(action[3] if len(action) > 3 else ""))

            if not _is_supported_tool(tool_id):
                continue
            if not _service_matches_scope(normalized_service, service_scope):
                continue

            stats = run_stats.get(tool_id, {})
            rows.append({
                "label": label,
                "tool_id": tool_id,
                "command_template": command_template,
                "service_scope": service_scope,
                "danger_categories": classify_command_danger(command_template, dangerous_categories),
                "run_count": int(stats.get("run_count", 0) or 0),
                "last_status": str(stats.get("last_status", "") or ""),
                "last_start": str(stats.get("last_start", "") or ""),
                "runnable": True,
            })
            seen_tool_ids.add(tool_id)

        for automated in settings.automatedAttacks:
            tool_id = str(automated[0] if len(automated) > 0 else "").strip()
            if not tool_id or tool_id in seen_tool_ids:
                continue
            if not _is_supported_tool(tool_id):
                continue
            service_scope = runtime._split_csv(str(automated[1] if len(automated) > 1 else ""))
            if not _service_matches_scope(normalized_service, service_scope):
                continue

            stats = run_stats.get(tool_id, {})
            rows.append({
                "label": _SCHEDULER_ONLY_LABELS.get(tool_id, tool_id),
                "tool_id": tool_id,
                "command_template": "",
                "service_scope": service_scope,
                "danger_categories": [],
                "run_count": int(stats.get("run_count", 0) or 0),
                "last_status": str(stats.get("last_status", "") or ""),
                "last_start": str(stats.get("last_start", "") or ""),
                "runnable": False,
            })
            seen_tool_ids.add(tool_id)

        for pipette in list_pipettes():
            tool_id = pipette.tool_id
            if tool_id in seen_tool_ids:
                continue
            service_scope = list(pipette.service_scope)
            target_ports = list(pipette.target_ports)
            protocol_scope = [str(item or "").strip().lower() for item in pipette.protocol_scope]
            if normalized_protocol and protocol_scope and "*" not in protocol_scope and normalized_protocol not in protocol_scope:
                continue
            if not _pipette_matches_context(
                    normalized_service=normalized_service,
                    service_scope=service_scope,
                    normalized_port=normalized_port,
                    target_ports=target_ports,
            ):
                continue

            stats = run_stats.get(tool_id, {})
            rows.append({
                "label": pipette.label,
                "tool_id": tool_id,
                "command_template": pipette.command_template,
                "service_scope": service_scope,
                "danger_categories": classify_command_danger(pipette.command_template, dangerous_categories),
                "run_count": int(stats.get("run_count", 0) or 0),
                "last_status": str(stats.get("last_status", "") or ""),
                "last_start": str(stats.get("last_start", "") or ""),
                "runnable": True,
                "pipette": True,
                "description": pipette.description,
                "required_tools": list(pipette.required_tools),
                "optional_tools": list(pipette.optional_tools),
                "risk_tags": list(pipette.risk_tags),
                "impact_level": pipette.impact_level,
                "noise_level": pipette.noise_level,
                "mode": pipette.mode,
                "default_timeout": int(pipette.default_timeout),
                "target_ports": target_ports,
                "parameters": [dict(item) for item in pipette.parameters],
            })
            seen_tool_ids.add(tool_id)

        rows.sort(key=lambda item: item["label"].lower())
        return rows


def get_workspace_tool_targets(
        runtime,
        *,
        host_id: int = 0,
        service: str = "",
        limit: int = 500,
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []
        session = project.database.session()
        try:
            try:
                normalized_host_id = int(host_id or 0)
            except (TypeError, ValueError):
                normalized_host_id = 0
            normalized_service = str(service or "").strip().rstrip("?").lower()
            resolved_limit = max(1, min(int(limit or 500), 5000))
            result = session.execute(text(
                "SELECT hosts.id AS host_id, "
                "COALESCE(hosts.ip, '') AS host_ip, "
                "COALESCE(hosts.hostname, '') AS hostname, "
                "COALESCE(ports.portId, '') AS port, "
                "LOWER(COALESCE(ports.protocol, 'tcp')) AS protocol, "
                "COALESCE(services.name, 'unknown') AS service, "
                "COALESCE(services.product, '') AS service_product, "
                "COALESCE(services.version, '') AS service_version "
                "FROM portObj AS ports "
                "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                "WHERE ports.state IN ('open', 'open|filtered') "
                "AND (:host_id <= 0 OR hosts.id = :host_id) "
                "AND (:service = '' OR LOWER(COALESCE(services.name, 'unknown')) = :service) "
                "ORDER BY hosts.ip ASC, ports.protocol ASC, ports.portId ASC "
                "LIMIT :limit"
            ), {
                "host_id": normalized_host_id,
                "service": normalized_service,
                "limit": resolved_limit,
            })
            rows = []
            for row in result.mappings():
                service_name = str(row.get("service", "") or "").strip()
                port_value = str(row.get("port", "") or "").strip()
                protocol = str(row.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
                host_ip = str(row.get("host_ip", "") or "").strip()
                hostname = str(row.get("hostname", "") or "").strip()
                label_parts = [host_ip]
                if hostname:
                    label_parts.append(hostname)
                if service_name:
                    label_parts.append(service_name)
                label_parts.append(f"{port_value}/{protocol}")
                rows.append({
                    "host_id": int(row.get("host_id", 0) or 0),
                    "host_ip": host_ip,
                    "hostname": hostname,
                    "port": port_value,
                    "protocol": protocol,
                    "service": service_name,
                    "service_product": str(row.get("service_product", "") or ""),
                    "service_version": str(row.get("service_version", "") or ""),
                    "label": " | ".join(part for part in label_parts if part),
                })
            rows.sort(key=lambda item: (
                str(item.get("host_ip", "") or ""),
                runtime._port_sort_key(item.get("port", "")),
                str(item.get("protocol", "") or ""),
                str(item.get("service", "") or ""),
            ))
            return rows
        finally:
            session.close()


def get_workspace_tools_page(
        runtime,
        service: str = "",
        port: str = "",
        protocol: str = "tcp",
        limit: int = 300,
        offset: int = 0,
) -> Dict[str, Any]:
    rows = workspace_tools_rows(runtime, service=service, port=port, protocol=protocol)
    total = len(rows)
    try:
        resolved_limit = int(limit)
    except (TypeError, ValueError):
        resolved_limit = 300
    try:
        resolved_offset = int(offset)
    except (TypeError, ValueError):
        resolved_offset = 0

    resolved_limit = max(1, min(resolved_limit, 500))
    resolved_offset = max(0, min(resolved_offset, total))
    page_rows = rows[resolved_offset:resolved_offset + resolved_limit]
    next_offset = resolved_offset + len(page_rows)
    has_more = next_offset < total
    return {
        "tools": page_rows,
        "offset": resolved_offset,
        "limit": resolved_limit,
        "total": total,
        "has_more": has_more,
        "next_offset": next_offset if has_more else None,
    }


def get_workspace_tools(
        runtime,
        service: str = "",
        port: str = "",
        protocol: str = "tcp",
        limit: int = 300,
        offset: int = 0,
) -> List[Dict[str, Any]]:
    return get_workspace_tools_page(
        runtime,
        service=service,
        port=port,
        protocol=protocol,
        limit=limit,
        offset=offset,
    ).get("tools", [])
