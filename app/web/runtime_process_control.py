from __future__ import annotations

import os
import signal
import subprocess
from typing import Any, Dict, Optional

from sqlalchemy import text

from app.web.runtime_process_jobs import (
    get_job,
    job_active_process_ids,
    list_jobs,
    register_job_process,
    stop_job,
    unregister_job_process,
)
from app.web.runtime_process_retry import (
    build_process_retry_plan,
    retry_process,
    split_process_retry_targets,
    start_process_retry_job,
)
from app.scheduler.config import (
    DEFAULT_TOOL_EXECUTION_PROFILES,
    normalize_tool_execution_profiles,
)
from app.web import runtime_process_parsing as web_runtime_process_parsing
from app.web import runtime_process_progress as web_runtime_process_progress


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
    data["command"] = web_runtime_process_parsing.redact_command_secrets(data.get("command", ""))
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
