from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List

from app.core.common import getTempFolder
from app.paths import get_legion_autosave_dir
from app.web import runtime_processes as web_runtime_processes
from app.web import runtime_project_autosave as web_runtime_project_autosave
from app.web import runtime_project_bundle as web_runtime_project_bundle


def is_temp_project(runtime) -> bool:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return False
    return bool(getattr(project.properties, "isTemporary", False))


def require_active_project(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if project is None:
        raise RuntimeError("No active project is loaded.")
    return project


def project_metadata(runtime) -> Dict[str, Any]:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return {
            "name": "",
            "output_folder": "",
            "running_folder": "",
            "is_temporary": False,
            "autosave": {
                "interval_minutes": 0,
                "last_saved_at": runtime._autosave_last_saved_at,
                "last_path": runtime._autosave_last_path,
                "last_error": runtime._autosave_last_error,
                "last_job_id": runtime._autosave_last_job_id,
            },
        }

    props = project.properties
    interval_seconds = runtime._get_autosave_interval_seconds()
    return {
        "name": str(getattr(props, "projectName", "")),
        "output_folder": str(getattr(props, "outputFolder", "")),
        "running_folder": str(getattr(props, "runningFolder", "")),
        "is_temporary": bool(getattr(props, "isTemporary", False)),
        "autosave": {
            "interval_minutes": int(interval_seconds / 60) if interval_seconds > 0 else 0,
            "last_saved_at": runtime._autosave_last_saved_at,
            "last_path": runtime._autosave_last_path,
            "last_error": runtime._autosave_last_error,
            "last_job_id": runtime._autosave_last_job_id,
        },
    }


def get_project_details(runtime) -> Dict[str, Any]:
    with runtime._lock:
        metadata = project_metadata(runtime)
        metadata["is_temporary"] = is_temp_project(runtime)
        return metadata


def project_listing_row(path: str, *, source: str, current_path: str = "") -> Dict[str, Any]:
    normalized_path = os.path.abspath(os.path.expanduser(str(path or "").strip()))
    modified_at = ""
    modified_at_epoch = 0.0
    try:
        modified_at_epoch = float(os.path.getmtime(normalized_path))
        modified_at = datetime.datetime.fromtimestamp(
            modified_at_epoch,
            tz=datetime.timezone.utc,
        ).isoformat()
    except Exception:
        modified_at = ""
        modified_at_epoch = 0.0
    return {
        "name": os.path.basename(normalized_path),
        "path": normalized_path,
        "source": str(source or "filesystem"),
        "is_current": bool(current_path and normalized_path == current_path),
        "exists": os.path.isfile(normalized_path),
        "modified_at": modified_at,
        "modified_at_epoch": modified_at_epoch,
    }


def list_projects(runtime, limit: int = 500) -> List[Dict[str, Any]]:
    with runtime._lock:
        current_name = str(project_metadata(runtime).get("name", "") or "").strip()
        current_path = (
            os.path.abspath(os.path.expanduser(current_name))
            if current_name else ""
        )
    max_items = max(1, min(int(limit or 500), 5000))
    roots = (
        ("temp", getTempFolder()),
        ("autosave", get_legion_autosave_dir()),
    )
    rows: List[Dict[str, Any]] = []
    seen = set()
    for source_name, root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in list(filenames or []):
                if not str(filename or "").strip().lower().endswith(".legion"):
                    continue
                path = os.path.abspath(os.path.join(dirpath, filename))
                if path in seen:
                    continue
                seen.add(path)
                rows.append(project_listing_row(path, source=source_name, current_path=current_path))
    if current_path and os.path.isfile(current_path) and current_path not in seen:
        rows.append(project_listing_row(current_path, source="active", current_path=current_path))
    rows.sort(
        key=lambda item: (
            not bool(item.get("is_current", False)),
            -float(item.get("modified_at_epoch", 0.0) or 0.0),
            str(item.get("path", "") or "").lower(),
        )
    )
    return rows[:max_items]


def create_new_temporary_project(runtime) -> Dict[str, Any]:
    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is in progress. Try again when it finishes.")
        active_jobs = count_running_scan_jobs(runtime, include_queued=True)
        if active_jobs > 0 or len(runtime._active_processes) > 0:
            raise RuntimeError(
                "Cannot create a new project while jobs/scans are active. "
                "Stop running jobs first."
            )
        close_active_project(runtime)
        runtime.logic.createNewTemporaryProject()
        runtime._ensure_scheduler_table()
        runtime._ensure_scheduler_approval_store()
        runtime._ensure_process_tables()
        return get_project_details(runtime)


def open_project(runtime, path: str) -> Dict[str, Any]:
    project_path = normalize_project_path(path)
    if not os.path.isfile(project_path):
        raise FileNotFoundError(f"Project file not found: {project_path}")

    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is in progress. Try again when it finishes.")
        active_jobs = count_running_scan_jobs(runtime, include_queued=True)
        if active_jobs > 0 or len(runtime._active_processes) > 0:
            raise RuntimeError(
                "Cannot open a project while jobs/scans are active. "
                "Stop running jobs first."
            )
        previous_project = getattr(runtime.logic, "activeProject", None)
        opened_project = None
        try:
            project_manager = getattr(runtime.logic, "projectManager", None)
            if project_manager is not None and hasattr(project_manager, "openExistingProject"):
                opened_project = project_manager.openExistingProject(project_path, projectType="legion")
            else:
                runtime.logic.openExistingProject(project_path, projectType="legion")
                opened_project = getattr(runtime.logic, "activeProject", None)
            if opened_project is None:
                raise RuntimeError("Project could not be opened.")

            runtime.logic.activeProject = opened_project
            runtime._ensure_scheduler_table()
            runtime._ensure_scheduler_approval_store()
            runtime._ensure_process_tables()
            details = get_project_details(runtime)
        except Exception:
            runtime.logic.activeProject = previous_project
            if opened_project is not None and opened_project is not previous_project:
                close_project_instance(runtime, opened_project)
            raise

        if previous_project is not None and previous_project is not opened_project:
            close_project_instance(runtime, previous_project)
        return details


def start_save_project_as_job(runtime, path: str, replace: bool = True) -> Dict[str, Any]:
    project_path = normalize_project_path(path)
    return runtime._start_job(
        "project-save-as",
        lambda _job_id: save_project_as_impl(runtime, project_path, bool(replace)),
        payload={"path": project_path, "replace": bool(replace)},
        queue_front=True,
        exclusive=True,
    )


def save_project_as(runtime, path: str, replace: bool = True) -> Dict[str, Any]:
    project_path = normalize_project_path(path)
    return save_project_as_impl(runtime, project_path, bool(replace))


def save_project_as_impl(runtime, project_path: str, replace: bool = True) -> Dict[str, Any]:
    source_project = None
    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is already in progress.")
        source_project = require_active_project(runtime)
        running_count = count_running_or_waiting_processes(source_project)
        active_subprocess_count = len(runtime._active_processes)
        active_jobs = count_running_scan_jobs(runtime, include_queued=False)
        if running_count > 0 or active_subprocess_count > 0 or active_jobs > 0:
            raise RuntimeError(
                "Cannot save while scans/tools are still active "
                f"(process-table={running_count}, subprocesses={active_subprocess_count}, jobs={active_jobs}). "
                "Wait for completion or stop active scans first."
            )
        runtime._save_in_progress = True

    try:
        saved_project = runtime.logic.projectManager.saveProjectAs(
            source_project,
            project_path,
            replace=1 if replace else 0,
            projectType="legion",
        )
        if not saved_project:
            raise RuntimeError("Save operation did not complete.")

        with runtime._lock:
            runtime.logic.activeProject = saved_project
            runtime._ensure_scheduler_table()
            runtime._ensure_scheduler_approval_store()
            runtime._ensure_process_tables()
            details = get_project_details(runtime)
        return {"project": details}
    finally:
        with runtime._lock:
            runtime._save_in_progress = False


def count_running_scan_jobs(runtime, include_queued: bool = True) -> int:
    running_types = {
        "nmap-scan",
        "import-nmap-xml",
        "scheduler-run",
        "scheduler-approval-execute",
        "scheduler-dig-deeper",
        "tool-run",
        "import-targets",
        "process-retry",
    }
    jobs = runtime.jobs.list_jobs(limit=200)
    count = 0
    for job in jobs:
        status = str(job.get("status", "") or "").strip().lower()
        valid_statuses = {"running"}
        if include_queued:
            valid_statuses.add("queued")
        if status not in valid_statuses:
            continue
        job_type = str(job.get("type", "") or "").strip()
        if job_type in running_types:
            count += 1
    return count


def count_running_or_waiting_processes(project) -> int:
    return web_runtime_processes.count_running_or_waiting_processes(project)


def close_active_project(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    close_project_instance(runtime, project)
    runtime.logic.activeProject = None


def close_project_instance(runtime, project) -> None:
    try:
        db = getattr(project, "database", None)
        if db and hasattr(db, "dispose"):
            db.dispose()
    except Exception:
        pass

    try:
        runtime.logic.projectManager.closeProject(project)
    except Exception:
        pass


def normalize_project_path(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate:
        raise ValueError("Project path is required.")
    normalized = os.path.abspath(os.path.expanduser(candidate))
    if not normalized.lower().endswith(".legion"):
        normalized = f"{normalized}.legion"
    return normalized


build_project_bundle_zip = web_runtime_project_bundle.build_project_bundle_zip
start_restore_project_zip_job = web_runtime_project_bundle.start_restore_project_zip_job
restore_project_bundle_zip = web_runtime_project_bundle.restore_project_bundle_zip
restore_project_bundle_zip_job = web_runtime_project_bundle.restore_project_bundle_zip_job
restore_project_bundle_zip_impl = web_runtime_project_bundle.restore_project_bundle_zip_impl
normalize_restore_compare_path = web_runtime_project_bundle.normalize_restore_compare_path
looks_like_absolute_path = web_runtime_project_bundle.looks_like_absolute_path
path_tail = web_runtime_project_bundle.path_tail
build_restore_root_mappings = web_runtime_project_bundle.build_restore_root_mappings
build_restore_text_replacements = web_runtime_project_bundle.build_restore_text_replacements
replace_restore_roots_in_text = web_runtime_project_bundle.replace_restore_roots_in_text
build_restore_basename_index = web_runtime_project_bundle.build_restore_basename_index
match_rebased_candidate = web_runtime_project_bundle.match_rebased_candidate
rebase_restored_file_reference = web_runtime_project_bundle.rebase_restored_file_reference
rewrite_restored_json_value = web_runtime_project_bundle.rewrite_restored_json_value
sqlite_table_columns = web_runtime_project_bundle.sqlite_table_columns
rewrite_restored_json_text = web_runtime_project_bundle.rewrite_restored_json_text
rewrite_sqlite_table_rows = web_runtime_project_bundle.rewrite_sqlite_table_rows
rebase_restored_project_paths = web_runtime_project_bundle.rebase_restored_project_paths
attach_restored_running_folder_locked = web_runtime_project_bundle.attach_restored_running_folder_locked
zip_add_file_if_exists = web_runtime_project_bundle.zip_add_file_if_exists
zip_add_dir_if_exists = web_runtime_project_bundle.zip_add_dir_if_exists
bundle_prefix = web_runtime_project_bundle.bundle_prefix
safe_bundle_filename = web_runtime_project_bundle.safe_bundle_filename
safe_bundle_relative_path = web_runtime_project_bundle.safe_bundle_relative_path
read_bundle_manifest = web_runtime_project_bundle.read_bundle_manifest
locate_bundle_session_member = web_runtime_project_bundle.locate_bundle_session_member
extract_zip_member_to_file = web_runtime_project_bundle.extract_zip_member_to_file
extract_zip_prefix_to_dir = web_runtime_project_bundle.extract_zip_prefix_to_dir
normalize_existing_file = web_runtime_project_bundle.normalize_existing_file

has_running_autosave_job = web_runtime_project_autosave.has_running_autosave_job
get_autosave_interval_seconds = web_runtime_project_autosave.get_autosave_interval_seconds
resolve_autosave_target_path = web_runtime_project_autosave.resolve_autosave_target_path
run_project_autosave = web_runtime_project_autosave.run_project_autosave
maybe_schedule_autosave_locked = web_runtime_project_autosave.maybe_schedule_autosave_locked
