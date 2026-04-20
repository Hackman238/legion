from __future__ import annotations

import datetime
import os
import re
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil
from sqlalchemy import text

from app.scheduler.config import (
    DEFAULT_TOOL_EXECUTION_PROFILES,
    normalize_tool_execution_profiles,
)
from app.settings import AppSettings
from app.timing import getTimestamp

_NMAP_PROGRESS_PERCENT_RE = re.compile(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_PAREN_RE = re.compile(r"\(([^)]*?)\s+remaining\)", flags=re.IGNORECASE)
_NMAP_PROGRESS_PERCENT_ATTR_RE = re.compile(r'percent=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_ATTR_RE = re.compile(r'remaining=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ELAPSED_RE = re.compile(r"^\[([0-9:]+)\]", flags=re.IGNORECASE)
_TSHARK_DURATION_RE = re.compile(r"\bduration:(\d+)\b", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_REQUESTS_RE = re.compile(
    r"Requests:\s*([0-9]+)\s*/\s*([0-9]+)(?:\s*\(([0-9]+(?:\.[0-9]+)?)%\))?",
    flags=re.IGNORECASE,
)
_NUCLEI_PROGRESS_RPS_RE = re.compile(r"RPS:\s*([0-9]+(?:\.[0-9]+)?)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_MATCHED_RE = re.compile(r"Matched:\s*([0-9]+)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ERRORS_RE = re.compile(r"Errors:\s*([0-9]+)", flags=re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


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
    data["command"] = runtime._redact_command_secrets(data.get("command", ""))
    data["output_chunk"] = chunk
    data["output_length"] = output_length
    data["offset"] = offset_value
    data["next_offset"] = next_offset
    data["completed"] = completed
    data["progress"] = build_process_progress_payload(
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


def sample_process_tree_activity(proc: Optional[subprocess.Popen]) -> Optional[Tuple[float, int]]:
    if proc is None or int(getattr(proc, "pid", 0) or 0) <= 0:
        return None
    try:
        root = psutil.Process(int(proc.pid))
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, ValueError):
        return None

    cpu_total = 0.0
    io_total = 0
    seen_pids = set()
    processes = [root]
    try:
        processes.extend(root.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        pass

    for current in processes:
        try:
            pid = int(current.pid)
        except Exception:
            continue
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        try:
            cpu_times = current.cpu_times()
            cpu_total += float(getattr(cpu_times, "user", 0.0) or 0.0)
            cpu_total += float(getattr(cpu_times, "system", 0.0) or 0.0)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
        try:
            io_counters = current.io_counters()
            if io_counters is not None:
                read_chars = getattr(io_counters, "read_chars", None)
                write_chars = getattr(io_counters, "write_chars", None)
                if read_chars is not None or write_chars is not None:
                    io_total += int(read_chars or 0) + int(write_chars or 0)
                else:
                    io_total += int(getattr(io_counters, "read_bytes", 0) or 0)
                    io_total += int(getattr(io_counters, "write_bytes", 0) or 0)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, AttributeError):
            pass
    return round(cpu_total, 4), int(io_total)


def process_tree_activity_changed(
        previous: Optional[Tuple[float, int]],
        current: Optional[Tuple[float, int]],
) -> bool:
    if previous is None or current is None:
        return False
    try:
        prev_cpu, prev_io = previous
        cur_cpu, cur_io = current
    except Exception:
        return False
    return (
        float(cur_cpu) > float(prev_cpu)
        or int(cur_io) > int(prev_io)
    )


def coerce_float(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def format_duration_label(total_seconds: Any) -> str:
    try:
        parsed = int(float(total_seconds))
    except (TypeError, ValueError):
        return ""
    if parsed <= 0:
        return ""
    hours = parsed // 3600
    minutes = (parsed % 3600) // 60
    seconds = parsed % 60
    if hours > 0:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds:02d}s"


def normalize_progress_source_label(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered == "nmap":
        return "Nmap"
    if lowered == "nuclei":
        return "Nuclei"
    if lowered == "tshark":
        return "TShark"
    return raw


def build_process_progress_payload(
        *,
        status: Any = "",
        percent: Any = "",
        estimated_remaining: Any = None,
        elapsed: Any = 0,
        progress_message: Any = "",
        progress_source: Any = "",
        progress_updated_at: Any = "",
) -> Dict[str, Any]:
    percent_numeric = coerce_float(percent)
    percent_display = f"{percent_numeric:.1f}%" if percent_numeric is not None else ""
    eta_seconds = None
    try:
        if estimated_remaining not in ("", None):
            eta_seconds = max(0, int(float(estimated_remaining)))
    except (TypeError, ValueError):
        eta_seconds = None
    elapsed_seconds = None
    try:
        if elapsed not in ("", None):
            elapsed_seconds = max(0, int(float(elapsed)))
    except (TypeError, ValueError):
        elapsed_seconds = None
    message_text = str(progress_message or "").strip()
    source_text = normalize_progress_source_label(progress_source)
    updated_at_text = str(progress_updated_at or "").strip()
    summary_parts = []
    if percent_display:
        summary_parts.append(percent_display)
    eta_label = format_duration_label(eta_seconds)
    if eta_label:
        summary_parts.append(f"ETA {eta_label}")
    if message_text:
        summary_parts.append(message_text)
    elif elapsed_seconds and str(status or "").strip().lower() == "running":
        elapsed_label = format_duration_label(elapsed_seconds)
        if elapsed_label:
            summary_parts.append(f"Elapsed {elapsed_label}")
    return {
        "active": bool(summary_parts or source_text or updated_at_text),
        "summary": " | ".join(summary_parts),
        "percent": f"{percent_numeric:.1f}" if percent_numeric is not None else "",
        "percent_display": percent_display,
        "estimated_remaining": eta_seconds,
        "estimated_remaining_display": eta_label,
        "elapsed": elapsed_seconds,
        "elapsed_display": format_duration_label(elapsed_seconds),
        "message": message_text,
        "source": source_text,
        "updated_at": updated_at_text,
    }


def process_progress_adapter_for_command(runtime_or_cls, tool_name: str, command: str) -> str:
    if runtime_or_cls._is_nmap_command(tool_name, command):
        return "nmap"
    if runtime_or_cls._is_nuclei_command(tool_name, command):
        return "nuclei"
    if runtime_or_cls._is_tshark_passive_capture_command(tool_name, command):
        return "tshark"
    return ""


def estimate_remaining_from_percent(runtime_seconds: float, percent: Optional[float]) -> Optional[int]:
    try:
        elapsed = max(0.0, float(runtime_seconds or 0.0))
    except (TypeError, ValueError):
        elapsed = 0.0
    if elapsed <= 0.0 or percent is None:
        return None
    bounded = max(0.0, min(float(percent), 100.0))
    if bounded <= 0.0 or bounded >= 100.0:
        return None
    fraction = bounded / 100.0
    total = elapsed / fraction
    return max(0, int(total - elapsed))


def extract_progress_line(text: str, predicate) -> str:
    cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
    for raw_line in reversed(cleaned.splitlines()):
        line = str(raw_line or "").strip()
        if line and predicate(line):
            return line[:240]
    return ""


def extract_nmap_progress_message(text: str) -> str:
    return extract_progress_line(
        text,
        lambda line: bool(
            _NMAP_PROGRESS_PERCENT_RE.search(line)
            or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(line)
            or _NMAP_PROGRESS_REMAINING_PAREN_RE.search(line)
            or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(line)
        ),
    )


def extract_nuclei_progress_from_text(
        text: str,
        runtime_seconds: float,
) -> Tuple[Optional[float], Optional[int], str]:
    cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
    if not cleaned:
        return None, None, ""

    for raw_line in reversed(cleaned.splitlines()):
        line = str(raw_line or "").strip()
        if not line or "requests:" not in line.lower():
            continue
        requests_match = _NUCLEI_PROGRESS_REQUESTS_RE.search(line)
        if not requests_match:
            continue
        try:
            completed = int(requests_match.group(1))
            total = int(requests_match.group(2))
        except Exception:
            continue
        percent = None
        percent_group = requests_match.group(3)
        if percent_group not in (None, ""):
            try:
                percent = float(percent_group)
            except Exception:
                percent = None
        if percent is None and total > 0:
            percent = max(0.0, min((float(completed) / float(total)) * 100.0, 100.0))

        elapsed_seconds = runtime_seconds
        elapsed_match = _NUCLEI_PROGRESS_ELAPSED_RE.search(line)
        if elapsed_match:
            parsed_elapsed = parse_duration_seconds(elapsed_match.group(1))
            if parsed_elapsed is not None:
                elapsed_seconds = float(parsed_elapsed)
        remaining = estimate_remaining_from_percent(elapsed_seconds, percent)

        parts = [f"Requests {completed}/{total}"]
        rps_match = _NUCLEI_PROGRESS_RPS_RE.search(line)
        if rps_match:
            parts.append(f"RPS {rps_match.group(1)}")
        matched_match = _NUCLEI_PROGRESS_MATCHED_RE.search(line)
        if matched_match:
            parts.append(f"Matches {matched_match.group(1)}")
        errors_match = _NUCLEI_PROGRESS_ERRORS_RE.search(line)
        if errors_match:
            parts.append(f"Errors {errors_match.group(1)}")
        return percent, remaining, " | ".join(parts)[:240]
    return None, None, ""


def extract_tshark_passive_progress(
        command: str,
        runtime_seconds: float,
) -> Tuple[Optional[float], Optional[int], str]:
    duration_match = _TSHARK_DURATION_RE.search(str(command or ""))
    if not duration_match:
        return None, None, ""
    try:
        total_seconds = max(1, int(duration_match.group(1)))
    except (TypeError, ValueError):
        return None, None, ""
    try:
        elapsed_seconds = max(0.0, float(runtime_seconds or 0.0))
    except (TypeError, ValueError):
        elapsed_seconds = 0.0
    bounded_elapsed = min(elapsed_seconds, float(total_seconds))
    percent = max(0.0, min((bounded_elapsed / float(total_seconds)) * 100.0, 100.0))
    remaining = max(0, int(round(float(total_seconds) - bounded_elapsed)))
    elapsed_label = format_duration_label(int(bounded_elapsed))
    message = f"Elapsed {elapsed_label}" if elapsed_label else ""
    return percent, remaining, message[:240]


def update_process_progress(
        runtime,
        process_repo,
        *,
        process_id: int,
        tool_name: str,
        command: str,
        text_chunk: str,
        runtime_seconds: float,
        state: Dict[str, Any],
):
    adapter = str(state.get("adapter", "") or "").strip().lower()
    if not adapter:
        return

    raw_chunk = str(text_chunk or "")
    percent = None
    remaining = None
    message = ""
    source = adapter
    clear_remaining_on_partial = False

    if adapter == "nmap":
        percent, remaining = extract_nmap_progress_from_text(raw_chunk)
        message = extract_nmap_progress_message(raw_chunk)
        clear_remaining_on_partial = bool(
            (_NMAP_PROGRESS_PERCENT_RE.search(raw_chunk) or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw_chunk))
            and not (_NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw_chunk) or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw_chunk))
        )
    elif adapter == "nuclei":
        percent, remaining, message = extract_nuclei_progress_from_text(
            raw_chunk,
            runtime_seconds=runtime_seconds,
        )
    elif adapter == "tshark":
        percent, remaining, message = extract_tshark_passive_progress(
            command,
            runtime_seconds=runtime_seconds,
        )
    else:
        return

    if percent is None and remaining is None and not message:
        return

    changed = False
    percent_value = state.get("percent")
    remaining_value = state.get("remaining")
    message_value = str(state.get("message", "") or "")
    source_value = str(state.get("source", "") or "")

    if percent is not None:
        bounded = max(0.0, min(float(percent), 100.0))
        if percent_value is None or abs(float(percent_value) - bounded) >= 0.1:
            percent_value = bounded
            state["percent"] = bounded
            changed = True

    if remaining is not None:
        bounded_remaining = max(0, int(remaining))
        if remaining_value is None or abs(int(remaining_value) - bounded_remaining) >= 5:
            remaining_value = bounded_remaining
            state["remaining"] = bounded_remaining
            changed = True
    elif clear_remaining_on_partial and remaining_value is not None:
        remaining_value = None
        state["remaining"] = None
        changed = True

    if message:
        if message != message_value:
            message_value = message
            state["message"] = message
            changed = True

    if source != source_value:
        source_value = source
        state["source"] = source
        changed = True

    now = time.monotonic()
    last_update = float(state.get("updated_at", 0.0) or 0.0)
    if not changed and (now - last_update) < 10.0:
        return

    try:
        process_repo.storeProcessProgress(
            str(int(process_id)),
            percent=f"{percent_value:.1f}" if percent_value is not None else None,
            estimated_remaining=remaining_value,
            progress_message=message_value,
            progress_source=source_value,
            progress_updated_at=getTimestamp(True),
        )
        state["updated_at"] = now
        runtime._emit_ui_invalidation("processes", throttle_seconds=5.0)
    except Exception:
        pass


def update_nmap_process_progress(
        runtime,
        process_repo,
        *,
        process_id: int,
        text_chunk: str,
        state: Dict[str, Any],
):
    percent, remaining = extract_nmap_progress_from_text(text_chunk)
    if percent is None and remaining is None:
        return

    changed = False
    percent_value = state.get("percent")
    remaining_value = state.get("remaining")
    if percent is not None:
        bounded = max(0.0, min(float(percent), 100.0))
        if percent_value is None or abs(float(percent_value) - bounded) >= 0.1:
            percent_value = bounded
            state["percent"] = bounded
            changed = True
    if remaining is not None:
        bounded_remaining = max(0, int(remaining))
        if remaining_value is None or int(remaining_value) != bounded_remaining:
            remaining_value = bounded_remaining
            state["remaining"] = bounded_remaining
            changed = True
    elif remaining_value is not None:
        remaining_value = None
        state["remaining"] = None
        changed = True

    now = time.monotonic()
    last_update = float(state.get("updated_at", 0.0) or 0.0)
    if not changed and (now - last_update) < 10.0:
        return

    process_repo.storeProcessProgress(
        str(int(process_id)),
        percent=f"{percent_value:.1f}" if percent_value is not None else None,
        estimated_remaining=remaining_value,
    )
    state["updated_at"] = now
    runtime._emit_ui_invalidation("processes", throttle_seconds=5.0)


def extract_nmap_progress_from_text(text: str) -> Tuple[Optional[float], Optional[int]]:
    raw = str(text or "")
    if not raw:
        return None, None

    percent = None
    remaining_seconds = None

    percent_match = _NMAP_PROGRESS_PERCENT_RE.search(raw)
    if percent_match:
        try:
            percent = float(percent_match.group(1))
        except Exception:
            percent = None

    if percent is None:
        percent_attr_match = _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw)
        if percent_attr_match:
            try:
                percent = float(percent_attr_match.group(1))
            except Exception:
                percent = None

    remaining_match = _NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw)
    if remaining_match:
        remaining_seconds = parse_duration_seconds(remaining_match.group(1))

    if remaining_seconds is None:
        remaining_attr_match = _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw)
        if remaining_attr_match:
            try:
                remaining_seconds = int(float(remaining_attr_match.group(1)))
            except Exception:
                remaining_seconds = None

    return percent, remaining_seconds


def parse_duration_seconds(raw: str) -> Optional[int]:
    text_value = str(raw or "").strip()
    if not text_value:
        return None

    if text_value.isdigit():
        return int(text_value)

    parts = text_value.split(":")
    if not all(part.isdigit() for part in parts):
        return None
    if len(parts) == 2:
        minutes, seconds = [int(part) for part in parts]
        return (minutes * 60) + seconds
    if len(parts) == 3:
        hours, minutes, seconds = [int(part) for part in parts]
        return (hours * 3600) + (minutes * 60) + seconds
    return None


def list_processes(runtime, limit: int = 75) -> List[Dict[str, Any]]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return []

    runtime._ensure_process_tables()
    process_repo = project.repositoryContainer.processRepository
    rows = process_repo.getProcesses({}, showProcesses='True', sort='desc', ncol='id')
    trimmed = rows[:limit]
    results = []

    for row in trimmed:
        status = str(row.get("status", "") or "")
        status_lower = status.strip().lower()
        terminal = status_lower in {"finished", "crashed", "problem", "cancelled", "killed", "failed"}
        estimated_remaining = row.get("estimatedRemaining")
        if terminal:
            estimated_remaining = None

        percent_value = str(row.get("percent", "") or "")
        if status_lower == "finished":
            numeric = coerce_float(percent_value)
            if numeric is None or numeric <= 0.0:
                percent_value = "100"

        elapsed_value = row.get("elapsed", 0)
        progress_message = row.get("progressMessage", "")
        progress_source = row.get("progressSource", "")
        progress_updated_at = row.get("progressUpdatedAt", "")

        results.append({
            "id": row.get("id", ""),
            "name": row.get("name", ""),
            "hostIp": row.get("hostIp", ""),
            "port": row.get("port", ""),
            "protocol": row.get("protocol", ""),
            "status": status,
            "startTime": row.get("startTime", ""),
            "elapsed": elapsed_value,
            "percent": percent_value,
            "estimatedRemaining": estimated_remaining,
            "progressMessage": progress_message,
            "progressSource": progress_source,
            "progressUpdatedAt": progress_updated_at,
            "progress": build_process_progress_payload(
                status=status,
                percent=percent_value,
                estimated_remaining=estimated_remaining,
                elapsed=elapsed_value,
                progress_message=progress_message,
                progress_source=progress_source,
                progress_updated_at=progress_updated_at,
            ),
        })
    return results


def process_history_records(
        project,
        limit: Optional[int] = None,
        *,
        redact_command=None,
) -> List[Dict[str, Any]]:
    if not project:
        return []

    session = project.database.session()
    try:
        query = (
            "SELECT "
            "process.id AS id, "
            "COALESCE(process.pid, '') AS pid, "
            "COALESCE(process.display, '') AS display, "
            "COALESCE(process.name, '') AS name, "
            "COALESCE(process.tabTitle, '') AS tabTitle, "
            "COALESCE(process.hostIp, '') AS hostIp, "
            "COALESCE(process.port, '') AS port, "
            "COALESCE(process.protocol, '') AS protocol, "
            "COALESCE(process.command, '') AS command, "
            "COALESCE(process.startTime, '') AS startTime, "
            "COALESCE(process.endTime, '') AS endTime, "
            "process.estimatedRemaining AS estimatedRemaining, "
            "COALESCE(process.elapsed, 0) AS elapsed, "
            "COALESCE(process.outputfile, '') AS outputfile, "
            "COALESCE(process.status, '') AS status, "
            "COALESCE(process.closed, '') AS closed, "
            "COALESCE(process.percent, '') AS percent, "
            "COALESCE(process.progressMessage, '') AS progressMessage, "
            "COALESCE(process.progressSource, '') AS progressSource, "
            "COALESCE(process.progressUpdatedAt, '') AS progressUpdatedAt, "
            "CASE "
            "WHEN EXISTS ("
            "    SELECT 1 FROM process_output AS output "
            "    WHERE output.processId = process.id "
            "    AND COALESCE(output.output, '') != ''"
            ") THEN 1 ELSE 0 END AS hasOutput "
            "FROM process AS process "
            "ORDER BY process.id DESC"
        )
        params: Dict[str, Any] = {}
        if limit is not None:
            resolved_limit = max(1, int(limit or 0))
            query = f"{query} LIMIT :limit"
            params["limit"] = resolved_limit
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        records: List[Dict[str, Any]] = []
        redact = redact_command or (lambda value: str(value or ""))
        for row in rows:
            item = dict(zip(keys, row))
            item["command"] = redact(item.get("command", ""))
            start_time_utc, end_time_utc, prefer_utc_naive = normalize_process_time_range_to_utc(
                item.get("startTime", ""),
                item.get("endTime", ""),
            )
            item["startTimeUtc"] = start_time_utc
            item["endTimeUtc"] = end_time_utc
            item["progressUpdatedAtUtc"] = normalize_process_timestamp_to_utc(
                item.get("progressUpdatedAt", ""),
                prefer_utc_naive=prefer_utc_naive,
            )
            records.append(item)
        return records
    finally:
        session.close()


def normalize_process_timestamp_to_utc(value: Any, *, prefer_utc_naive: bool = False) -> str:
    text_value = str(value or "").strip()
    if not text_value:
        return ""

    candidates = process_timestamp_utc_candidates(
        text_value,
        prefer_utc_naive=prefer_utc_naive,
    )
    if not candidates:
        return ""
    parsed = candidates[0][1]
    return parsed.astimezone(datetime.timezone.utc).isoformat()


def process_timestamp_utc_candidates(
        value: Any,
        *,
        prefer_utc_naive: bool = False,
) -> List[tuple]:
    text_value = str(value or "").strip()
    if not text_value:
        return []

    local_tz = datetime.datetime.now().astimezone().tzinfo or datetime.timezone.utc
    candidates: List[tuple] = []
    seen = set()

    def _append(candidate_dt: datetime.datetime, assumption: str):
        utc_dt = candidate_dt.astimezone(datetime.timezone.utc)
        normalized = utc_dt.isoformat()
        key = (normalized, assumption)
        if key in seen:
            return
        seen.add(key)
        candidates.append((normalized, utc_dt, assumption))

    try:
        iso_candidate = f"{text_value[:-1]}+00:00" if text_value.endswith("Z") else text_value
        parsed = datetime.datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is None:
            preferred_tz = datetime.timezone.utc if prefer_utc_naive else local_tz
            _append(parsed.replace(tzinfo=preferred_tz), "iso-naive-utc" if prefer_utc_naive else "iso-naive-local")
            alternate_tz = local_tz if prefer_utc_naive else datetime.timezone.utc
            _append(parsed.replace(tzinfo=alternate_tz), "iso-naive-local" if prefer_utc_naive else "iso-naive-utc")
        else:
            _append(parsed, "iso-aware")
    except ValueError:
        pass

    for fmt in ("%d %b %Y %H:%M:%S.%f", "%d %b %Y %H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(text_value, fmt)
        except ValueError:
            continue
        preferred_tz = datetime.timezone.utc if prefer_utc_naive else local_tz
        _append(parsed.replace(tzinfo=preferred_tz), "human-utc" if prefer_utc_naive else "human-local")
        alternate_tz = local_tz if prefer_utc_naive else datetime.timezone.utc
        _append(parsed.replace(tzinfo=alternate_tz), "human-local" if prefer_utc_naive else "human-utc")
        break

    return candidates


def normalize_process_time_range_to_utc(start_value: Any, end_value: Any) -> tuple:
    start_default = process_timestamp_utc_candidates(start_value, prefer_utc_naive=False)
    end_default = process_timestamp_utc_candidates(end_value, prefer_utc_naive=False)
    start_utc = start_default[0][0] if start_default else ""
    end_utc = end_default[0][0] if end_default else ""

    if not start_default or not end_default:
        return start_utc, end_utc, False

    default_start_dt = start_default[0][1]
    default_end_dt = end_default[0][1]
    if default_start_dt <= default_end_dt:
        prefer_utc_naive = any(candidate[2].endswith("-utc") for candidate in (start_default[0], end_default[0]))
        return start_utc, end_utc, prefer_utc_naive

    best_pair = None
    best_delta = None
    for start_candidate in start_default:
        for end_candidate in end_default:
            start_dt = start_candidate[1]
            end_dt = end_candidate[1]
            if start_dt > end_dt:
                continue
            delta_seconds = abs((end_dt - start_dt).total_seconds())
            if best_delta is None or delta_seconds < best_delta:
                best_delta = delta_seconds
                best_pair = (start_candidate, end_candidate)

    if best_pair is None:
        return start_utc, end_utc, False

    prefer_utc_naive = any(candidate[2].endswith("-utc") for candidate in best_pair)
    return best_pair[0][0], best_pair[1][0], prefer_utc_naive


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
