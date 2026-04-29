from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.planner import SchedulerPlanner
from app.scheduler.risk import classify_command_danger
from app.screenshot_targets import apply_preferred_target_placeholders
from app.settings import AppSettings, Settings
from app.timing import getTimestamp

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


def _is_supported_tool(tool_id: str) -> bool:
    normalized_tool = str(tool_id or "").strip().lower()
    if not normalized_tool:
        return False
    if normalized_tool in _SUPPORTED_WORKSPACE_TOOL_IDS:
        return True
    return any(normalized_tool.startswith(prefix) for prefix in _SUPPORTED_WORKSPACE_TOOL_PREFIXES)


def get_settings(runtime) -> Settings:
    return runtime.settings


def find_port_action(settings: Settings, tool_id: str):
    for action in settings.portActions:
        if str(action[1]) == str(tool_id):
            return action
    return None


def find_command_template_for_tool(runtime, settings: Settings, tool_id: str) -> str:
    action = find_port_action(settings, tool_id)
    if not action:
        return ""
    return str(action[2])


def runner_type_for_tool(runtime, tool_id: str, command_template: str = "") -> str:
    normalized_tool = str(tool_id or "").strip().lower()
    if not normalized_tool and not str(command_template or "").strip():
        return "local"
    try:
        registry = SchedulerPlanner.build_action_registry(runtime._get_settings(), dangerous_categories=[])
        spec = registry.get_by_tool_id(normalized_tool)
        if spec is not None and str(getattr(spec, "runner_type", "") or "").strip():
            return str(spec.runner_type).strip().lower()
    except Exception:
        pass
    if normalized_tool in {"screenshooter", "x11screen"}:
        return "browser"
    if normalized_tool in {"responder", "ntlmrelayx"}:
        return "manual"
    text = " ".join([normalized_tool, str(command_template or "")]).lower()
    if any(token in text for token in ("manual", "operator", "clipboard")):
        return "manual"
    return "local"


def runner_type_for_approval_item(runtime, item: Optional[Dict[str, Any]]) -> str:
    payload = item if isinstance(item, dict) else {}
    return runner_type_for_tool(
        runtime,
        str(payload.get("tool_id", "") or ""),
        str(payload.get("command_template", "") or ""),
    )


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


def build_command(
        runtime,
        template: str,
        host_ip: str,
        port: str,
        protocol: str,
        tool_id: str,
        service_name: str = "",
):
    project = runtime._require_active_project()
    running_folder = project.properties.runningFolder
    outputfile = os.path.join(running_folder, f"{getTimestamp()}-{tool_id}-{host_ip}-{port}")
    outputfile = os.path.normpath(outputfile).replace("\\", "/")

    command = str(template or "")
    normalized_tool = str(tool_id or "").strip().lower()
    scheduler_config = getattr(runtime, "scheduler_config", None)
    if scheduler_config is not None and hasattr(scheduler_config, "load"):
        scheduler_preferences = scheduler_config.load()
    else:
        scheduler_preferences = {}
    resolved_service_name = str(service_name or "").strip() or runtime._service_name_for_target(host_ip, port, protocol)
    if normalized_tool == "banner":
        command = AppSettings._ensure_banner_command(command)
    if normalized_tool == "nuclei-web":
        command = AppSettings._ensure_nuclei_auto_scan(command)
    elif "nuclei" in normalized_tool or "nuclei" in str(command).lower():
        command = AppSettings._ensure_nuclei_command(command, automatic_scan=False)
    if str(tool_id or "").strip().lower() == "web-content-discovery":
        command = AppSettings._ensure_web_content_discovery_command(command)
    if normalized_tool == "httpx":
        command = AppSettings._ensure_httpx_command(command)
    if normalized_tool == "nikto":
        command = AppSettings._ensure_nikto_command(command)
    if normalized_tool == "wpscan":
        command = AppSettings._ensure_wpscan_command(command)
    if "wapiti" in str(command).lower():
        normalized_tool = str(tool_id or "").strip().lower()
        scheme = "https" if "https-wapiti" in normalized_tool else "http"
        command = AppSettings._ensure_wapiti_command(command, scheme=scheme)
    command = AppSettings._canonicalize_web_target_placeholders(command)
    if "nmap" in str(command).lower():
        command = AppSettings._ensure_nmap_stats_every(command)
    hostname = runtime._hostname_for_ip(host_ip)
    command, target_host = apply_preferred_target_placeholders(
        command,
        hostname=hostname,
        ip=str(host_ip),
        port=str(port),
        output=outputfile,
        service_name=resolved_service_name,
        extra_placeholders=runtime._scheduler_command_placeholders(
            host_ip=str(host_ip),
            hostname=hostname,
            preferences=scheduler_preferences,
        ),
    )
    command = AppSettings._collapse_redundant_fallbacks(command)
    command = AppSettings._ensure_nmap_hostname_target_support(command, target_host)
    command = AppSettings._ensure_nmap_output_argument(command, outputfile)
    if "nmap" in command and str(protocol).lower() == "udp":
        command = command.replace("-sV", "-sVU")
    return command, outputfile


def start_tool_run_job(
        runtime,
        host_ip: str,
        port: str,
        protocol: str,
        tool_id: str,
        command_override: str = "",
        timeout: int = 300,
) -> Dict[str, Any]:
    resolved_host_ip = str(host_ip or "").strip()
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    resolved_tool_id = str(tool_id or "").strip()
    if not resolved_host_ip or not resolved_port or not resolved_tool_id:
        raise ValueError("host_ip, port and tool_id are required.")

    payload = {
        "host_ip": resolved_host_ip,
        "port": resolved_port,
        "protocol": resolved_protocol,
        "tool_id": resolved_tool_id,
        "timeout": int(timeout),
    }
    if command_override:
        payload["command_override"] = str(command_override)

    return runtime._start_job(
        "tool-run",
        lambda job_id: run_manual_tool(
            runtime,
            host_ip=resolved_host_ip,
            port=resolved_port,
            protocol=resolved_protocol,
            tool_id=resolved_tool_id,
            command_override=str(command_override or ""),
            timeout=int(timeout),
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )


def workspace_tools_rows(runtime, service: str = "") -> List[Dict[str, Any]]:
    with runtime._lock:
        settings = runtime._get_settings()
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []

        normalized_service = str(service or "").strip().rstrip("?").lower()
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

        # Show scheduler-only tool ids in the Tools table so the catalog reflects
        # what the scheduler can run even when there is no manual port action.
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
        limit: int = 300,
        offset: int = 0,
) -> Dict[str, Any]:
    rows = workspace_tools_rows(runtime, service=service)
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


def get_workspace_tools(runtime, service: str = "", limit: int = 300, offset: int = 0) -> List[Dict[str, Any]]:
    return get_workspace_tools_page(runtime, service=service, limit=limit, offset=offset).get("tools", [])


def run_manual_tool(
        runtime,
        host_ip: str,
        port: str,
        protocol: str,
        tool_id: str,
        command_override: str,
        timeout: int,
        job_id: int = 0,
):
    with runtime._lock:
        runtime._require_active_project()
        settings = runtime._get_settings()
        action = runtime._find_port_action(settings, tool_id)
        if action is None:
            raise KeyError(f"Unknown tool id: {tool_id}")

        label = str(action[0])
        template = str(command_override or action[2])
        command, outputfile = runtime._build_command(template, host_ip, port, protocol, tool_id)

    executed, reason, process_id = runtime._run_command_with_tracking(
        tool_name=tool_id,
        tab_title=f"{tool_id} ({port}/{protocol})",
        host_ip=host_ip,
        port=port,
        protocol=protocol,
        command=command,
        outputfile=outputfile,
        timeout=int(timeout),
        job_id=int(job_id or 0),
    )

    return {
        "tool_id": tool_id,
        "label": label,
        "host_ip": host_ip,
        "port": str(port),
        "protocol": str(protocol),
        "command": command,
        "outputfile": outputfile,
        "executed": bool(executed),
        "reason": reason,
        "process_id": process_id,
    }
