from __future__ import annotations

import os
import signal
import subprocess
from typing import Any, Dict, Optional

from sqlalchemy import text

from app.scheduler.schema_cache import ensure_column, ensure_schema_once, is_schema_ensured

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
        proc = runtime._active_processes.get(process_key)

    had_live_handle = proc is not None
    killed = False
    if proc is not None:
        if proc.poll() is None:
            # Recorded only for a process that is still running: the runner reads it to report the exit as
            # "killed" whatever exit code the tool chooses (it may handle SIGTERM and exit 0). The runner
            # discards the entry when it unregisters the process.
            with runtime._process_runtime_lock:
                runtime._kill_requests.add(process_key)
            runtime._signal_process_tree(proc, force=False)
            try:
                proc.wait(timeout=2)
            except Exception:
                runtime._signal_process_tree(proc, force=True)
            killed = True
        if killed:
            with runtime._lock:
                project = runtime._require_active_project()
                process_repo = project.repositoryContainer.processRepository
                process_repo.storeProcessKillStatus(str(process_key))
    else:
        with runtime._lock:
            project = runtime._require_active_project()
            process_repo = project.repositoryContainer.processRepository
            if process_repo.getProcessById(process_key) is None:
                raise KeyError(f"Unknown process id: {process_key}")
            status = str(process_repo.getStatusByProcessId(str(process_key)) or "")
            # Without a live handle this process was not started by this session (a stale row left by a
            # crash/restart or a reopened/restored project), so its stored PID may now belong to an
            # unrelated process: never signal it, only record the kill.
            if status in {"Running", "Waiting"}:
                process_repo.storeProcessKillStatus(str(process_key))
                killed = True
                # A "Waiting" process is not started by its runner once marked Killed
                # (run_command_with_tracking checks the status right before launching).

    result = {
        "killed": killed,
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
        if process_repo.getProcessById(int(process_id)) is None:
            raise KeyError(f"Unknown process id: {process_id}")
        status = str(process_repo.getStatusByProcessId(str(int(process_id))) or "")
    if status in {"Running", "Waiting"}:
        # Hiding a live tool must stop it: otherwise it keeps running (and holding its port/interface) under a
        # row that is already marked closed, and a second instance can be started on top of it.
        kill_process(runtime, int(process_id))
    with runtime._lock:
        project = runtime._require_active_project()
        process_repo = project.repositoryContainer.processRepository
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
    result = {"closed": True, "process_id": int(process_id), "stopped": status in {"Running", "Waiting"}}
    runtime._emit_ui_invalidation("processes", "overview", throttle_seconds=0.1)
    return result


def get_process_output_tail(runtime, process_id: int, max_chars: int = 4000) -> str:
    """Return only the last max_chars of a process's stored output (sliced in SQL, not in Python)."""
    tail_chars = max(0, min(int(max_chars or 0), 200000))
    if tail_chars <= 0:
        return ""
    with runtime._lock:
        runtime._ensure_process_tables()
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.execute(text(
                "SELECT substr(COALESCE(output, ''), -:tail_chars), "
                "instr(CAST(COALESCE(output, '') AS BLOB), X'00') FROM process_output "
                "WHERE processId = :id LIMIT 1"
            ), {"id": int(process_id), "tail_chars": tail_chars}).fetchone()
        finally:
            session.close()
    if row is None:
        return ""
    if int(row[1] or 0) > 0:
        # SQLite's text functions stop at an embedded NUL; slice such (rare) output in Python instead.
        return get_process_output_text(runtime, process_id)[-tail_chars:]
    return str(row[0] or "")


def get_process_output_text(runtime, process_id: int) -> str:
    """Return a process's complete stored output, for callers that parse all of it (not for UI polling)."""
    with runtime._lock:
        runtime._ensure_process_tables()
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.execute(text(
                "SELECT COALESCE(output, '') FROM process_output WHERE processId = :id LIMIT 1"
            ), {"id": int(process_id)}).fetchone()
        finally:
            session.close()
    return str(row[0] or "") if row is not None else ""


def get_process_output(runtime, process_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
    """Return process metadata plus one output chunk; the full output is never loaded (it can be many MB)."""
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
                "length(COALESCE(o.output, '')) AS output_length, "
                "substr(COALESCE(o.output, ''), :chunk_start, :chunk_len) AS output_chunk, "
                "instr(CAST(COALESCE(o.output, '') AS BLOB), X'00') AS output_nul_at "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE p.id = :id LIMIT 1"
            ), {"id": int(process_id), "chunk_start": offset_value + 1, "chunk_len": max_len})
            row = result.fetchone()
            if row is None:
                raise KeyError(f"Unknown process id: {process_id}")
            keys = result.keys()
            data = dict(zip(keys, row))
        finally:
            session.close()

    output_length = int(data.pop("output_length", 0) or 0)
    chunk = str(data.pop("output_chunk", "") or "")
    if int(data.pop("output_nul_at", 0) or 0) > 0:
        # SQLite's text functions stop at an embedded NUL; slice such (rare) output in Python instead.
        full_output = get_process_output_text(runtime, process_id)
        output_length = len(full_output)
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
    # An explicit 0 (credential-capture listeners such as Responder) disables the inactivity timeout: these
    # tools legitimately print nothing for hours. None/'' keep the 300 s default.
    if isinstance(requested_timeout, (int, float)) and not isinstance(requested_timeout, bool) and requested_timeout <= 0:
        return {"quiet_long_running": False, "inactivity_timeout_seconds": 0, "hard_timeout_seconds": 0}
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


_PROCESS_TABLES_SCHEMA_KEY = "web_process_tables"


def _ensure_process_tables_uncached(session):
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
        ensure_column(session, "process", column_name, column_type)
    session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_process_output_processId ON process_output (processId)"
    ))


def _process_output_index_exists(session) -> bool:
    rows = session.execute(text("PRAGMA index_list(process_output)")).fetchall()
    return any(len(row) > 1 and str(row[1]) == "ix_process_output_processId" for row in rows)


def ensure_process_tables(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    if is_schema_ensured(getattr(project.database, "engine", None), _PROCESS_TABLES_SCHEMA_KEY):
        return
    session = project.database.session()
    try:
        # Runs the CREATE/PRAGMA/ALTER pass once per database engine (shared scheduler schema cache).
        ensure_schema_once(
            session,
            _PROCESS_TABLES_SCHEMA_KEY,
            _ensure_process_tables_uncached,
            ["process", "process_output"],
            is_complete=_process_output_index_exists,
        )
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
