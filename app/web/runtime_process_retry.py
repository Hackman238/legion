from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from app.settings import AppSettings
from app.timing import getTimestamp


def start_process_retry_job(runtime, process_id: int, timeout: int = 300) -> Dict[str, Any]:
    target_id = int(process_id)
    timeout_value = max(1, int(timeout or 300))
    return runtime._start_job(
        "process-retry",
        lambda job_id: retry_process(runtime, target_id, timeout=timeout_value, job_id=int(job_id or 0)),
        payload={"process_id": target_id, "timeout": timeout_value},
    )


def retry_process(runtime, process_id: int, timeout: int = 300, job_id: int = 0) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        runtime._ensure_process_tables()
        process_repo = project.repositoryContainer.processRepository
        details = process_repo.getProcessById(int(process_id))
        if not details:
            raise KeyError(f"Unknown process id: {process_id}")

        command = str(details.get("command", "") or "")
        if not command:
            raise ValueError(f"Process {process_id} has no command to retry.")

        host_ip = str(details.get("hostIp", "") or "")
        port = str(details.get("port", "") or "")
        protocol = str(details.get("protocol", "") or "tcp")
        tool_name = str(details.get("name", "") or "process")
        tab_title = str(details.get("tabTitle", "") or tool_name)
        outputfile = str(details.get("outputfile", "") or "")
        if not outputfile:
            outputfile = os.path.join(
                project.properties.runningFolder,
                f"{getTimestamp()}-{tool_name}-{host_ip}-{port}",
            )
            outputfile = os.path.normpath(outputfile).replace("\\", "/")
        retry_plan = build_process_retry_plan(
            runtime,
            tool_name=tool_name,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
        )
        if runtime._is_nmap_command(tool_name, command):
            command = AppSettings._ensure_nmap_stats_every(command)

    if retry_plan.get("mode") == "tool":
        tool_result = runtime._run_manual_tool(
            host_ip=str(retry_plan.get("host_ip", "") or ""),
            port=str(retry_plan.get("port", "") or ""),
            protocol=str(retry_plan.get("protocol", "tcp") or "tcp"),
            tool_id=str(retry_plan.get("tool_id", "") or ""),
            timeout=int(timeout),
            job_id=int(job_id or 0),
        )
        executed = bool(tool_result.get("executed", False))
        reason = str(tool_result.get("reason", "") or "")
        new_process_id = int(tool_result.get("process_id", 0) or 0)
        command = str(tool_result.get("command", "") or "")
        retry_mode = "intent"
        retry_intent = "tool-run"
    elif retry_plan.get("mode") == "nmap_scan":
        scan_result = runtime._run_nmap_scan_and_import(
            targets=list(retry_plan.get("targets", []) or []),
            discovery=bool(retry_plan.get("discovery", True)),
            staged=bool(retry_plan.get("staged", False)),
            run_actions=bool(retry_plan.get("run_actions", False)),
            nmap_path=str(retry_plan.get("nmap_path", "nmap") or "nmap"),
            nmap_args=str(retry_plan.get("nmap_args", "") or ""),
            scan_mode=str(retry_plan.get("scan_mode", "legacy") or "legacy"),
            scan_options=dict(retry_plan.get("scan_options", {}) or {}),
            job_id=int(job_id or 0),
        )
        stages = list(scan_result.get("stages", []) or [])
        last_stage = stages[-1] if stages else {}
        executed = True
        reason = "completed"
        new_process_id = int(last_stage.get("process_id", 0) or 0)
        command = str(last_stage.get("command", "") or "")
        retry_mode = "intent"
        retry_intent = "nmap_scan"
    else:
        executed, reason, new_process_id = runtime._run_command_with_tracking(
            tool_name=tool_name,
            tab_title=tab_title,
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            command=command,
            outputfile=outputfile,
            timeout=int(timeout),
            job_id=int(job_id or 0),
        )
        retry_mode = "command"
        retry_intent = "command-replay"
    return {
        "source_process_id": int(process_id),
        "process_id": int(new_process_id),
        "executed": bool(executed),
        "reason": str(reason),
        "command": command,
        "retry_mode": retry_mode,
        "retry_intent": retry_intent,
    }


def build_process_retry_plan(
        runtime,
        *,
        tool_name: str,
        host_ip: str,
        port: str,
        protocol: str,
) -> Dict[str, Any]:
    normalized_tool = str(tool_name or "").strip()
    normalized_host = str(host_ip or "").strip()
    normalized_port = str(port or "").strip()
    normalized_protocol = str(protocol or "tcp").strip().lower() or "tcp"

    settings = runtime._get_settings()
    if normalized_tool and normalized_host and normalized_port:
        action = runtime._find_port_action(settings, normalized_tool)
        if action is not None:
            return {
                "mode": "tool",
                "tool_id": normalized_tool,
                "host_ip": normalized_host,
                "port": normalized_port,
                "protocol": normalized_protocol,
            }

    normalized_targets = split_process_retry_targets(normalized_host)
    tool_token = normalized_tool.lower()
    if normalized_targets and tool_token in {"nmap-easy", "nmap-hard", "nmap-rfc1918_discovery"}:
        scan_mode = tool_token.split("nmap-", 1)[1]
        return {
            "mode": "nmap_scan",
            "targets": normalized_targets,
            "discovery": scan_mode != "hard",
            "staged": False,
            "run_actions": False,
            "nmap_path": "nmap",
            "nmap_args": "",
            "scan_mode": scan_mode,
            "scan_options": {},
        }

    return {"mode": "command"}


def split_process_retry_targets(value: str) -> List[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    tokens = [
        item.strip()
        for item in re.split(r"[\s,]+", raw)
        if item.strip()
    ]
    deduped: List[str] = []
    for item in tokens:
        if item not in deduped:
            deduped.append(item)
    return deduped
