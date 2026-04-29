from __future__ import annotations

import os
import re
import signal
import subprocess
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.config import (
    DEFAULT_TOOL_EXECUTION_PROFILES,
    normalize_tool_execution_profiles,
)
from app.settings import AppSettings
from app.timing import getTimestamp
from app.web import runtime_process_progress as web_runtime_process_progress


def register_job_process(runtime, job_id: int, process_id: int):
    resolved_job_id = int(job_id or 0)
    resolved_process_id = int(process_id or 0)
    if resolved_job_id <= 0 or resolved_process_id <= 0:
        return
    if not hasattr(runtime, "_job_process_ids"):
        runtime._job_process_ids = {}
    if not hasattr(runtime, "_process_job_id"):
        runtime._process_job_id = {}
    with runtime._process_runtime_lock:
        process_ids = runtime._job_process_ids.setdefault(resolved_job_id, set())
        process_ids.add(resolved_process_id)
        runtime._process_job_id[resolved_process_id] = resolved_job_id


def unregister_job_process(runtime, process_id: int):
    resolved_process_id = int(process_id or 0)
    if resolved_process_id <= 0:
        return
    if not hasattr(runtime, "_job_process_ids") or not hasattr(runtime, "_process_job_id"):
        return
    with runtime._process_runtime_lock:
        owner_job_id = runtime._process_job_id.pop(resolved_process_id, None)
        if owner_job_id is None:
            return
        process_ids = runtime._job_process_ids.get(int(owner_job_id))
        if not process_ids:
            return
        process_ids.discard(resolved_process_id)
        if not process_ids:
            runtime._job_process_ids.pop(int(owner_job_id), None)


def job_active_process_ids(runtime, job_id: int) -> List[int]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id <= 0:
        return []
    if not hasattr(runtime, "_job_process_ids"):
        return []
    with runtime._process_runtime_lock:
        process_ids = list(runtime._job_process_ids.get(resolved_job_id, set()))
    return sorted({int(item) for item in process_ids if int(item) > 0})


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
            command_override="",
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


def signal_process_tree(proc: Optional[subprocess.Popen], *, force: bool = False):
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            return
    except Exception:
        return

    used_group_signal = False
    if os.name != "nt" and hasattr(os, "killpg"):
        try:
            pgid = os.getpgid(int(proc.pid))
            if pgid > 0:
                sig = signal.SIGKILL if force else signal.SIGTERM
                os.killpg(pgid, sig)
                used_group_signal = True
        except Exception:
            used_group_signal = False

    if not used_group_signal:
        try:
            if force:
                proc.kill()
            else:
                proc.terminate()
        except Exception:
            pass


def kill_process(runtime, process_id: int) -> Dict[str, Any]:
    process_key = int(process_id)
    with runtime._process_runtime_lock:
        runtime._kill_requests.add(process_key)
        proc = runtime._active_processes.get(process_key)

    had_live_handle = proc is not None
    if proc is not None and proc.poll() is None:
        runtime._signal_process_tree(proc, force=False)
        try:
            proc.wait(timeout=2)
        except Exception:
            runtime._signal_process_tree(proc, force=True)
    else:
        with runtime._lock:
            project = runtime._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            pid = process_repo.getPIDByProcessId(str(process_key))
        try:
            if pid not in (None, "", "-1"):
                os.kill(int(pid), signal.SIGTERM)
        except Exception:
            pass

    with runtime._lock:
        project = runtime._require_active_project()
        process_repo = project.repositoryContainer.processRepository
        process_repo.storeProcessKillStatus(str(process_key))

    result = {
        "killed": True,
        "process_id": process_key,
        "had_live_handle": had_live_handle,
    }
    runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
    return result


def clear_processes(runtime, reset_all: bool = False) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        process_repo = project.repositoryContainer.processRepository
        process_repo.toggleProcessDisplayStatus(resetAll=bool(reset_all))
    result = {"cleared": True, "reset_all": bool(reset_all)}
    runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
    return result


def close_process(runtime, process_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        process_repo = project.repositoryContainer.processRepository
        status = str(process_repo.getStatusByProcessId(str(int(process_id))) or "")
        session = project.database.session()
        try:
            session.execute(text(
                "UPDATE process SET display = 'False', closed = 'True' WHERE id = :id"
            ), {"id": int(process_id)})
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()
        if status in {"Running", "Waiting"}:
            process_repo.storeProcessCancelStatus(str(int(process_id)))
    result = {"closed": True, "process_id": int(process_id)}
    runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
    return result


def get_process_output(runtime, process_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
    offset_value = max(0, int(offset or 0))
    max_len = max(256, min(int(max_chars or 12000), 50000))
    with runtime._lock:
        runtime._ensure_process_tables()
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            result = session.execute(text(
                "SELECT p.id, p.name, p.hostIp, p.port, p.protocol, p.command, p.status, p.startTime, p.endTime, "
                "COALESCE(p.percent, '') AS percent, "
                "p.estimatedRemaining AS estimatedRemaining, "
                "COALESCE(p.elapsed, 0) AS elapsed, "
                "COALESCE(p.progressMessage, '') AS progressMessage, "
                "COALESCE(p.progressSource, '') AS progressSource, "
                "COALESCE(p.progressUpdatedAt, '') AS progressUpdatedAt, "
                "COALESCE(o.output, '') AS output "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE p.id = :id LIMIT 1"
            ), {"id": int(process_id)})
            row = result.fetchone()
            if row is None:
                raise KeyError(f"Unknown process id: {process_id}")
            keys = result.keys()
            data = dict(zip(keys, row))
        finally:
            session.close()

    full_output = str(data.get("output", "") or "")
    output_length = len(full_output)
    chunk = ""
    if offset_value < output_length:
        chunk = full_output[offset_value:offset_value + max_len]
    next_offset = offset_value + len(chunk)
    status = str(data.get("status", "") or "")
    completed = status not in {"Running", "Waiting"}
    data["command"] = web_runtime_process_progress.redact_command_secrets(data.get("command", ""))
    data["output_chunk"] = chunk
    data["output_length"] = output_length
    data["offset"] = offset_value
    data["next_offset"] = next_offset
    data["completed"] = completed
    data["progress"] = web_runtime_process_progress.build_process_progress_payload(
        status=data.get("status", ""),
        percent=data.get("percent", ""),
        estimated_remaining=data.get("estimatedRemaining"),
        elapsed=data.get("elapsed", 0),
        progress_message=data.get("progressMessage", ""),
        progress_source=data.get("progressSource", ""),
        progress_updated_at=data.get("progressUpdatedAt", ""),
    )
    return data


def list_jobs(runtime, limit: int = 80) -> List[Dict[str, Any]]:
    return runtime.jobs.list_jobs(limit=limit)


def get_job(runtime, job_id: int) -> Dict[str, Any]:
    job = runtime.jobs.get_job(job_id)
    if job is None:
        raise KeyError(f"Unknown job id: {job_id}")
    return job


def stop_job(runtime, job_id: int) -> Dict[str, Any]:
    target_job_id = int(job_id)
    job = runtime.jobs.get_job(target_job_id)
    if job is None:
        raise KeyError(f"Unknown job id: {job_id}")

    status = str(job.get("status", "") or "").strip().lower()
    if status not in {"queued", "running"}:
        return {
            "stopped": False,
            "job": job,
            "killed_process_ids": [],
            "message": "Job is not running or queued.",
        }

    updated = runtime.jobs.cancel_job(target_job_id, reason="stopped by user")
    if updated is None:
        raise KeyError(f"Unknown job id: {job_id}")

    killed_process_ids = []
    for process_id in job_active_process_ids(runtime, target_job_id):
        try:
            runtime.kill_process(int(process_id))
            killed_process_ids.append(int(process_id))
        except Exception:
            continue

    final_job = runtime.jobs.get_job(target_job_id) or updated
    return {
        "stopped": True,
        "job": final_job,
        "killed_process_ids": killed_process_ids,
    }


def tool_execution_profile(runtime, tool_name: Any) -> Dict[str, Any]:
    tool_id = str(tool_name or "").strip().lower()
    profiles = normalize_tool_execution_profiles(DEFAULT_TOOL_EXECUTION_PROFILES)
    scheduler_config = getattr(runtime, "scheduler_config", None)
    if scheduler_config is not None and hasattr(scheduler_config, "load"):
        try:
            loaded = scheduler_config.load()
        except Exception:
            loaded = {}
        if isinstance(loaded, dict):
            profiles = normalize_tool_execution_profiles(loaded.get("tool_execution_profiles", profiles))
    return dict(profiles.get(tool_id, {}))


def resolve_process_timeout_policy(runtime, tool_name: Any, requested_timeout: Any) -> Dict[str, Any]:
    try:
        default_timeout = max(1, int(requested_timeout or 300))
    except (TypeError, ValueError):
        default_timeout = 300
    profile = tool_execution_profile(runtime, tool_name)
    quiet_long_running = bool(profile.get("quiet_long_running", False))
    if not quiet_long_running:
        return {
            "quiet_long_running": False,
            "inactivity_timeout_seconds": int(default_timeout),
            "hard_timeout_seconds": 0,
        }
    try:
        inactivity_timeout = int(profile.get("activity_timeout_seconds", default_timeout) or default_timeout)
    except (TypeError, ValueError):
        inactivity_timeout = default_timeout
    try:
        hard_timeout = int(profile.get("hard_timeout_seconds", 0) or 0)
    except (TypeError, ValueError):
        hard_timeout = 0
    return {
        "quiet_long_running": True,
        "inactivity_timeout_seconds": max(30, int(inactivity_timeout or 1800)),
        "hard_timeout_seconds": max(0, int(hard_timeout or 0)),
    }


def ensure_process_tables(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    session = project.database.session()
    try:
        def _ensure_column(table_name: str, column_name: str, column_type: str):
            rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            existing = {str(row[1]) for row in rows if len(row) > 1}
            if str(column_name) in existing:
                return
            session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))

        session.execute(text(
            "CREATE TABLE IF NOT EXISTS process ("
            "pid TEXT,"
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "display TEXT,"
            "name TEXT,"
            "tabTitle TEXT,"
            "hostIp TEXT,"
            "port TEXT,"
            "protocol TEXT,"
            "command TEXT,"
            "startTime TEXT,"
            "endTime TEXT,"
            "estimatedRemaining INTEGER,"
            "elapsed INTEGER,"
            "outputfile TEXT,"
            "status TEXT,"
            "closed TEXT,"
            "percent TEXT,"
            "progressMessage TEXT,"
            "progressSource TEXT,"
            "progressUpdatedAt TEXT"
            ")"
        ))
        session.execute(text(
            "CREATE TABLE IF NOT EXISTS process_output ("
            "processId INTEGER,"
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "output TEXT"
            ")"
        ))
        for column_name, column_type in (
                ("progressMessage", "TEXT"),
                ("progressSource", "TEXT"),
                ("progressUpdatedAt", "TEXT"),
        ):
            _ensure_column("process", column_name, column_type)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def count_running_or_waiting_processes(project) -> int:
    session = project.database.session()
    try:
        count = session.execute(
            text("SELECT COUNT(*) FROM process WHERE status IN ('Running', 'Waiting')")
        ).scalar()
        return int(count or 0)
    except Exception:
        return 0
    finally:
        session.close()
