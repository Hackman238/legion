from __future__ import annotations

import datetime
import os
import time
from typing import Any, Dict

from app.paths import get_legion_autosave_dir


def has_running_autosave_job(runtime) -> bool:
    jobs = runtime.jobs.list_jobs(limit=80)
    for job in jobs:
        if str(job.get("type", "") or "") != "project-autosave":
            continue
        status = str(job.get("status", "") or "").strip().lower()
        if status in {"queued", "running"}:
            return True
    return False


def get_autosave_interval_seconds(runtime) -> int:
    raw = getattr(runtime.settings, "general_notes_autosave_minutes", "2")
    try:
        minutes = float(str(raw).strip())
    except (TypeError, ValueError):
        minutes = 2.0
    if minutes <= 0:
        return 0
    return max(30, int(minutes * 60))


def resolve_autosave_target_path(project) -> str:
    project_name = str(getattr(project.properties, "projectName", "") or "").strip()
    if not project_name:
        return ""

    base_name = os.path.basename(project_name)
    stem, ext = os.path.splitext(base_name)
    if not ext:
        ext = ".legion"
    autosave_name = f"{stem}.autosave{ext}"

    if bool(getattr(project.properties, "isTemporary", False)):
        autosave_dir = get_legion_autosave_dir()
        os.makedirs(autosave_dir, exist_ok=True)
        return os.path.join(autosave_dir, autosave_name)

    folder = os.path.dirname(project_name) or os.getcwd()
    return os.path.join(folder, autosave_name)


def run_project_autosave(runtime, target_path: str) -> Dict[str, Any]:
    if not target_path:
        return {"saved": False, "reason": "autosave target path missing"}

    with runtime._autosave_lock:
        with runtime._lock:
            if runtime._save_in_progress:
                return {"saved": False, "reason": "save already in progress"}
            project = getattr(runtime.logic, "activeProject", None)
            if not project:
                return {"saved": False, "reason": "no active project"}
            if runtime._count_running_or_waiting_processes(project) > 0 or len(runtime._active_processes) > 0:
                return {"saved": False, "reason": "active scans/tools running"}
            runtime._save_in_progress = True

        try:
            project.database.verify_integrity()
            project.database.backup_to(str(target_path))
            saved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with runtime._lock:
                runtime._autosave_last_saved_at = saved_at
                runtime._autosave_last_path = str(target_path)
                runtime._autosave_last_error = ""
            return {
                "saved": True,
                "saved_at": saved_at,
                "path": str(target_path),
            }
        except Exception as exc:
            with runtime._lock:
                runtime._autosave_last_error = str(exc)
            return {
                "saved": False,
                "reason": str(exc),
                "path": str(target_path),
            }
        finally:
            with runtime._lock:
                runtime._save_in_progress = False


def maybe_schedule_autosave_locked(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        runtime._autosave_next_due_monotonic = 0.0
        return

    interval_seconds = runtime._get_autosave_interval_seconds()
    if interval_seconds <= 0:
        runtime._autosave_next_due_monotonic = 0.0
        return

    now = time.monotonic()
    if runtime._autosave_next_due_monotonic <= 0.0:
        runtime._autosave_next_due_monotonic = now + float(interval_seconds)
        return
    if now < runtime._autosave_next_due_monotonic:
        return
    if runtime._save_in_progress or runtime._has_running_autosave_job():
        runtime._autosave_next_due_monotonic = now + 20.0
        return
    if runtime._count_running_scan_jobs() > 0:
        runtime._autosave_next_due_monotonic = now + 30.0
        return
    if runtime._count_running_or_waiting_processes(project) > 0 or len(runtime._active_processes) > 0:
        runtime._autosave_next_due_monotonic = now + 30.0
        return

    target_path = runtime._resolve_autosave_target_path(project)
    if not target_path:
        runtime._autosave_next_due_monotonic = now + float(interval_seconds)
        return

    job = runtime._start_job(
        "project-autosave",
        lambda _job_id: run_project_autosave(runtime, target_path),
        payload={"path": str(target_path)},
        exclusive=True,
    )
    runtime._autosave_last_job_id = int(job.get("id", 0) or 0)
    runtime._autosave_next_due_monotonic = now + float(interval_seconds)
