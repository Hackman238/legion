from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.pipettes import find_pipette
from app.scheduler.planner import SchedulerPlanner
from app.screenshot_targets import apply_preferred_target_placeholders
from app.settings import AppSettings, Settings
from app.timing import getTimestamp
from app.web.runtime_tool_catalog import (
    get_workspace_tool_targets,
    get_workspace_tools,
    get_workspace_tools_page,
    tool_run_stats,
    workspace_tools_rows,
)


def get_settings(runtime) -> Settings:
    return runtime.settings


def find_port_action(settings: Settings, tool_id: str):
    for action in settings.portActions:
        if str(action[1]) == str(tool_id):
            return action
    pipette = find_pipette(tool_id)
    if pipette is not None:
        return pipette.as_port_action()
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
        timeout: int = 300,
        parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_host_ip = str(host_ip or "").strip()
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    resolved_tool_id = str(tool_id or "").strip()
    if not resolved_host_ip or not resolved_port or not resolved_tool_id:
        raise ValueError("host_ip, port and tool_id are required.")
    pipette = find_pipette(resolved_tool_id)
    resolved_parameters = (
        pipette.validate_parameter_values(parameters)
        if pipette is not None
        else {}
    )

    payload = {
        "host_ip": resolved_host_ip,
        "port": resolved_port,
        "protocol": resolved_protocol,
        "tool_id": resolved_tool_id,
        "timeout": int(timeout),
    }
    if resolved_parameters:
        payload["parameters"] = dict(resolved_parameters)

    return runtime._start_job(
        "tool-run",
        lambda job_id: run_manual_tool(
            runtime,
            host_ip=resolved_host_ip,
            port=resolved_port,
            protocol=resolved_protocol,
            tool_id=resolved_tool_id,
            timeout=int(timeout),
            parameters=resolved_parameters,
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )


def run_manual_tool(
        runtime,
        host_ip: str,
        port: str,
        protocol: str,
        tool_id: str,
        timeout: int,
        parameters: Optional[Dict[str, Any]] = None,
        job_id: int = 0,
):
    with runtime._lock:
        runtime._require_active_project()
        settings = runtime._get_settings()
        action = runtime._find_port_action(settings, tool_id)
        if action is None:
            raise KeyError(f"Unknown tool id: {tool_id}")

        label = str(action[0])
        template = str(action[2])
        pipette = find_pipette(tool_id)
        if pipette is not None:
            template = pipette.command_template_for_values(parameters)
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
