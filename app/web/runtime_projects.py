from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from app.core.common import getTempFolder
from app.paths import get_legion_autosave_dir
from app.web import runtime_processes as web_runtime_processes


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
        metadata["is_temporary"] = runtime._is_temp_project()
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
        close_active_project(runtime)
        runtime.logic.openExistingProject(project_path, projectType="legion")
        runtime._ensure_scheduler_table()
        runtime._ensure_scheduler_approval_store()
        runtime._ensure_process_tables()
        return get_project_details(runtime)


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


def build_project_bundle_zip(runtime) -> Tuple[str, str]:
    with runtime._lock:
        project = runtime._require_active_project()
        runtime._ensure_process_tables()
        props = project.properties
        project_file = str(getattr(props, "projectName", "") or "")
        output_folder = str(getattr(props, "outputFolder", "") or "")
        running_folder = str(getattr(props, "runningFolder", "") or "")
    try:
        provider_logs = runtime.get_scheduler_provider_logs(limit=1000)
    except Exception:
        provider_logs = []
    try:
        process_history = runtime._process_history_records(project)
    except Exception:
        process_history = []
    try:
        credentials_payload = runtime.get_workspace_credential_captures(limit=5000)
    except Exception:
        credentials_payload = {"captures": [], "capture_count": 0, "unique_hash_count": 0, "deduped_hashes": []}
    try:
        credential_capture_state = runtime.get_credential_capture_state(include_captures=False)
    except Exception:
        credential_capture_state = {}

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    bundle_name = f"legion-session-{timestamp}.zip"
    root_name = f"legion-session-{timestamp}"
    tmp = tempfile.NamedTemporaryFile(prefix="legion-session-", suffix=".zip", delete=False)
    bundle_path = tmp.name
    tmp.close()

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        manifest = {
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "project_file": project_file,
            "output_folder": output_folder,
            "running_folder": running_folder,
            "provider_log_count": len(provider_logs) if isinstance(provider_logs, list) else 0,
            "process_history_count": len(process_history) if isinstance(process_history, list) else 0,
            "credential_capture_count": int(credentials_payload.get("capture_count", 0) or 0),
            "credential_unique_hash_count": int(credentials_payload.get("unique_hash_count", 0) or 0),
        }
        archive.writestr(
            f"{root_name}/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True),
        )
        zip_add_file_if_exists(
            archive,
            project_file,
            f"{root_name}/session/{os.path.basename(project_file or 'session.legion')}",
        )
        archive.writestr(
            f"{root_name}/provider-logs.json",
            json.dumps(list(provider_logs or []), indent=2, sort_keys=True),
        )
        archive.writestr(
            f"{root_name}/process-history.json",
            json.dumps(list(process_history or []), indent=2, sort_keys=True),
        )
        archive.writestr(
            f"{root_name}/credentials.json",
            json.dumps(dict(credentials_payload or {}), indent=2, sort_keys=True),
        )
        archive.writestr(
            f"{root_name}/credential-capture-state.json",
            json.dumps(dict(credential_capture_state or {}), indent=2, sort_keys=True),
        )
        zip_add_dir_if_exists(archive, output_folder, f"{root_name}/tool-output")
        zip_add_dir_if_exists(archive, running_folder, f"{root_name}/running")

    return bundle_path, bundle_name


def start_restore_project_zip_job(runtime, path: str) -> Dict[str, Any]:
    zip_path = normalize_existing_file(path)
    return runtime._start_job(
        "project-restore-zip",
        lambda _job_id: restore_project_bundle_zip_job(runtime, zip_path, cleanup_source=True),
        payload={"path": zip_path},
        queue_front=True,
        exclusive=True,
    )


def restore_project_bundle_zip(runtime, path: str) -> Dict[str, Any]:
    zip_path = normalize_existing_file(path)
    return restore_project_bundle_zip_job(runtime, zip_path, cleanup_source=False)


def restore_project_bundle_zip_job(runtime, zip_path: str, cleanup_source: bool) -> Dict[str, Any]:
    normalized = normalize_existing_file(zip_path)
    try:
        return restore_project_bundle_zip_impl(runtime, normalized)
    finally:
        if cleanup_source:
            try:
                if os.path.isfile(normalized):
                    os.remove(normalized)
            except Exception:
                pass


def restore_project_bundle_zip_impl(runtime, zip_path: str) -> Dict[str, Any]:
    normalized = normalize_existing_file(zip_path)
    if not zipfile.is_zipfile(normalized):
        raise ValueError(f"Invalid ZIP file: {normalized}")

    with zipfile.ZipFile(normalized, "r") as archive:
        manifest_name, root_prefix, manifest = read_bundle_manifest(archive)
        _ = manifest_name

        session_member = locate_bundle_session_member(
            archive,
            root_prefix=root_prefix,
            manifest=manifest,
        )
        if not session_member:
            raise ValueError("Bundle does not contain a session .legion file.")

        project_file_name = safe_bundle_filename(
            os.path.basename(str(session_member or "").strip()),
            fallback="restored.legion",
        )
        if not project_file_name.lower().endswith(".legion"):
            project_file_name = f"{project_file_name}.legion"
        project_stem = os.path.splitext(project_file_name)[0]

        restore_root = tempfile.mkdtemp(prefix="legion-restore-")
        project_path = os.path.join(restore_root, project_file_name)
        output_folder = os.path.join(restore_root, f"{project_stem}-tool-output")
        running_folder = os.path.join(restore_root, f"{project_stem}-running")

        os.makedirs(output_folder, exist_ok=True)
        os.makedirs(running_folder, exist_ok=True)

        extract_zip_member_to_file(archive, session_member, project_path)
        extract_zip_prefix_to_dir(
            archive,
            prefix=bundle_prefix(root_prefix, "tool-output"),
            destination_dir=output_folder,
        )
        extract_zip_prefix_to_dir(
            archive,
            prefix=bundle_prefix(root_prefix, "running"),
            destination_dir=running_folder,
        )

    rebase_restored_project_paths(
        project_path=project_path,
        manifest=manifest,
        output_folder=output_folder,
        running_folder=running_folder,
    )

    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is in progress. Try again when it finishes.")
        close_active_project(runtime)
        runtime.logic.openExistingProject(project_path, projectType="legion")
        attach_restored_running_folder_locked(runtime, running_folder)
        runtime._ensure_scheduler_table()
        runtime._ensure_scheduler_approval_store()
        runtime._ensure_process_tables()
        details = get_project_details(runtime)

    return {
        "project": details,
        "restored": {
            "restore_root": restore_root,
            "project_path": project_path,
            "output_folder": output_folder,
            "running_folder": running_folder,
            "manifest_project_file": str(manifest.get("project_file", "") or ""),
        },
    }


def save_project_as_impl(runtime, project_path: str, replace: bool = True) -> Dict[str, Any]:
    source_project = None
    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is already in progress.")
        source_project = runtime._require_active_project()
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
            if count_running_or_waiting_processes(project) > 0 or len(runtime._active_processes) > 0:
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

    interval_seconds = get_autosave_interval_seconds(runtime)
    if interval_seconds <= 0:
        runtime._autosave_next_due_monotonic = 0.0
        return

    now = time.monotonic()
    if runtime._autosave_next_due_monotonic <= 0.0:
        runtime._autosave_next_due_monotonic = now + float(interval_seconds)
        return
    if now < runtime._autosave_next_due_monotonic:
        return
    if runtime._save_in_progress or has_running_autosave_job(runtime):
        runtime._autosave_next_due_monotonic = now + 20.0
        return
    if count_running_scan_jobs(runtime) > 0:
        runtime._autosave_next_due_monotonic = now + 30.0
        return
    if count_running_or_waiting_processes(project) > 0 or len(runtime._active_processes) > 0:
        runtime._autosave_next_due_monotonic = now + 30.0
        return

    target_path = resolve_autosave_target_path(project)
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


def normalize_restore_compare_path(path: str) -> str:
    token = str(path or "").strip()
    if not token:
        return ""
    normalized = os.path.normpath(token.replace("\\", "/"))
    if normalized == ".":
        return ""
    return normalized.rstrip("/")


def looks_like_absolute_path(value: str) -> bool:
    token = normalize_restore_compare_path(value)
    if not token:
        return False
    return bool(token.startswith("/") or re.match(r"^[A-Za-z]:/", token))


def path_tail(path: str, depth: int = 2) -> str:
    token = normalize_restore_compare_path(path)
    if not token:
        return ""
    parts = [part for part in token.split("/") if part]
    return "/".join(parts[-max(1, int(depth or 2)):])


def build_restore_root_mappings(
        *,
        manifest: Dict[str, Any],
        project_path: str,
        output_folder: str,
        running_folder: str,
) -> List[Tuple[str, str]]:
    _ = project_path
    candidates: List[Tuple[str, str]] = []
    old_output_folder = str(manifest.get("output_folder", "") or "").strip()
    old_running_folder = str(manifest.get("running_folder", "") or "").strip()
    for old_root, new_root in (
            (old_output_folder, output_folder),
            (old_running_folder, running_folder),
    ):
        old_norm = normalize_restore_compare_path(old_root)
        new_norm = normalize_restore_compare_path(os.path.abspath(str(new_root or "").strip()))
        if not old_norm or not new_norm:
            continue
        candidates.append((old_norm, new_norm))

    deduped: List[Tuple[str, str]] = []
    seen = set()
    for old_root, new_root in sorted(candidates, key=lambda item: len(item[0]), reverse=True):
        key = (old_root, new_root)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((old_root, new_root))
    return deduped


def build_restore_text_replacements(root_mappings: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    replacements: List[Tuple[str, str]] = []
    seen = set()
    for old_root, new_root in list(root_mappings or []):
        paired_variants = [
            (str(old_root or "").strip(), str(new_root or "").strip()),
            (
                str(old_root or "").strip().replace("/", "\\"),
                str(new_root or "").strip().replace("/", "\\"),
            ),
        ]
        for old_variant, new_variant in paired_variants:
            pair = (old_variant, new_variant)
            if not old_variant or pair in seen:
                continue
            seen.add(pair)
            replacements.append(pair)
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    return replacements


def replace_restore_roots_in_text(value: str, text_replacements: List[Tuple[str, str]]) -> str:
    result = str(value or "")
    for old_root, new_root in list(text_replacements or []):
        if old_root and old_root in result:
            result = result.replace(old_root, new_root)
    return result


def build_restore_basename_index(roots: List[str]) -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = {}
    for root in list(roots or []):
        normalized_root = os.path.abspath(str(root or "").strip())
        if not normalized_root or not os.path.isdir(normalized_root):
            continue
        for base, _dirs, files in os.walk(normalized_root):
            for file_name in files:
                full_path = os.path.normpath(os.path.join(base, file_name)).replace("\\", "/")
                key = str(file_name or "").strip().lower()
                if not key:
                    continue
                index.setdefault(key, [])
                if full_path not in index[key]:
                    index[key].append(full_path)
    return index


def match_rebased_candidate(raw_value: str, candidates: List[str]) -> str:
    if not candidates:
        return str(raw_value or "")
    if len(candidates) == 1:
        return str(candidates[0])
    for depth in (3, 2):
        tail = path_tail(raw_value, depth=depth)
        if not tail:
            continue
        matches = [candidate for candidate in list(candidates) if path_tail(candidate, depth=depth) == tail]
        if len(matches) == 1:
            return str(matches[0])
    return str(raw_value or "")


def rebase_restored_file_reference(
        value: str,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> str:
    _ = root_mappings
    raw_value = str(value or "").strip()
    if not raw_value or raw_value.startswith("process_output:"):
        return raw_value
    if raw_value.startswith(("http://", "https://", "data:")):
        return raw_value

    replaced = replace_restore_roots_in_text(raw_value, text_replacements)
    replaced_norm = normalize_restore_compare_path(replaced)
    if replaced_norm and replaced != raw_value and looks_like_absolute_path(replaced_norm):
        return replaced_norm

    normalized_raw = normalize_restore_compare_path(raw_value)
    if not looks_like_absolute_path(normalized_raw):
        return replaced if replaced != raw_value else raw_value

    basename = os.path.basename(normalized_raw)
    if not basename:
        return replaced if replaced != raw_value else raw_value

    candidates = basename_index.get(str(basename or "").strip().lower(), [])
    matched = match_rebased_candidate(normalized_raw, candidates)
    return matched if matched != normalized_raw else (replaced if replaced != raw_value else raw_value)


def rewrite_restored_json_value(
        value: Any,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
        key_name: str = "",
) -> Any:
    if isinstance(value, dict):
        return {
            key: rewrite_restored_json_value(
                item,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
                key_name=str(key or ""),
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            rewrite_restored_json_value(
                item,
                root_mappings=root_mappings,
                text_replacements=text_replacements,
                basename_index=basename_index,
                key_name=str(key_name or ""),
            )
            for item in value
        ]
    if not isinstance(value, str):
        return value

    key_token = str(key_name or "").strip().lower()
    if key_token in {
        "artifact_ref",
        "ref",
        "stdout_ref",
        "stderr_ref",
        "source_ref",
        "outputfile",
        "path",
        "screenshot_path",
    }:
        return rebase_restored_file_reference(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
    if key_token in {"command", "command_template", "evidence_refs"}:
        return replace_restore_roots_in_text(value, text_replacements)

    replaced = replace_restore_roots_in_text(value, text_replacements)
    if replaced != value:
        replaced_norm = normalize_restore_compare_path(replaced)
        if replaced_norm and looks_like_absolute_path(replaced_norm):
            return replaced_norm
        return replaced
    if looks_like_absolute_path(value):
        return rebase_restored_file_reference(
            value,
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
    return value


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> List[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except Exception:
        return []
    return [str(row[1]) for row in rows if len(row) > 1]


def rewrite_restored_json_text(
        raw_json: Any,
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> Any:
    token = str(raw_json or "").strip()
    if not token:
        return str(raw_json or "")
    try:
        parsed = json.loads(token)
    except Exception:
        return replace_restore_roots_in_text(token, text_replacements)
    rewritten = rewrite_restored_json_value(
        parsed,
        root_mappings=root_mappings,
        text_replacements=text_replacements,
        basename_index=basename_index,
    )
    try:
        return json.dumps(rewritten, ensure_ascii=False)
    except Exception:
        return token


def rewrite_sqlite_table_rows(
        connection: sqlite3.Connection,
        table_name: str,
        column_modes: Dict[str, str],
        *,
        root_mappings: List[Tuple[str, str]],
        text_replacements: List[Tuple[str, str]],
        basename_index: Dict[str, List[str]],
) -> None:
    available_columns = set(sqlite_table_columns(connection, table_name))
    target_columns = [column for column in list(column_modes or {}) if column in available_columns]
    if not target_columns:
        return
    quoted_columns = ", ".join(f'"{column}"' for column in target_columns)
    try:
        rows = connection.execute(f'SELECT rowid, {quoted_columns} FROM "{table_name}"').fetchall()
    except Exception:
        return

    for row in rows:
        rowid = row[0]
        updates: Dict[str, Any] = {}
        for index, column_name in enumerate(target_columns, start=1):
            original = row[index]
            mode = str(column_modes.get(column_name, "text") or "text").strip().lower()
            if mode == "json":
                rewritten = rewrite_restored_json_text(
                    original,
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                )
            elif mode == "path":
                rewritten = rebase_restored_file_reference(
                    str(original or ""),
                    root_mappings=root_mappings,
                    text_replacements=text_replacements,
                    basename_index=basename_index,
                )
            else:
                rewritten = replace_restore_roots_in_text(str(original or ""), text_replacements)
            if rewritten != original:
                updates[column_name] = rewritten
        if not updates:
            continue
        assignments = ", ".join(f'"{column}" = ?' for column in updates)
        params = list(updates.values()) + [rowid]
        connection.execute(f'UPDATE "{table_name}" SET {assignments} WHERE rowid = ?', params)


def rebase_restored_project_paths(
        *,
        project_path: str,
        manifest: Dict[str, Any],
        output_folder: str,
        running_folder: str,
) -> None:
    root_mappings = build_restore_root_mappings(
        manifest=manifest,
        project_path=project_path,
        output_folder=output_folder,
        running_folder=running_folder,
    )
    if not root_mappings:
        return
    text_replacements = build_restore_text_replacements(root_mappings)
    basename_index = build_restore_basename_index([output_folder, running_folder])
    connection = sqlite3.connect(str(project_path))
    try:
        rewrite_sqlite_table_rows(
            connection,
            "process",
            {"outputfile": "path", "command": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_pending_approval",
            {"command_template": "text", "evidence_refs": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_execution_record",
            {
                "stdout_ref": "path",
                "stderr_ref": "path",
                "artifact_refs_json": "json",
                "observations_created_json": "json",
                "graph_mutations_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_target_state",
            {
                "technologies_json": "json",
                "findings_json": "json",
                "manual_tests_json": "json",
                "service_inventory_json": "json",
                "urls_json": "json",
                "coverage_gaps_json": "json",
                "attempted_actions_json": "json",
                "credentials_json": "json",
                "sessions_json": "json",
                "screenshots_json": "json",
                "artifacts_json": "json",
                "raw_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "scheduler_host_ai_state",
            {
                "technologies_json": "json",
                "findings_json": "json",
                "manual_tests_json": "json",
                "raw_json": "json",
            },
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_node",
            {"source_ref": "path", "properties_json": "json"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_edge",
            {"source_ref": "path", "properties_json": "json"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        rewrite_sqlite_table_rows(
            connection,
            "graph_evidence_ref",
            {"evidence_ref": "text"},
            root_mappings=root_mappings,
            text_replacements=text_replacements,
            basename_index=basename_index,
        )
        connection.commit()
    finally:
        connection.close()


def attach_restored_running_folder_locked(runtime, running_folder: str) -> None:
    project = getattr(runtime.logic, "activeProject", None)
    if project is None:
        return
    restored_running_folder = os.path.abspath(str(running_folder or "").strip())
    if not restored_running_folder:
        return
    os.makedirs(restored_running_folder, exist_ok=True)
    current_running_folder = str(getattr(project.properties, "runningFolder", "") or "").strip()
    if current_running_folder and os.path.abspath(current_running_folder) != restored_running_folder:
        try:
            shutil.rmtree(current_running_folder, ignore_errors=True)
        except Exception:
            pass
    if hasattr(project.properties, "_replace"):
        project.properties = project.properties._replace(runningFolder=restored_running_folder)


def count_running_or_waiting_processes(project) -> int:
    return web_runtime_processes.count_running_or_waiting_processes(project)


def zip_add_file_if_exists(archive: zipfile.ZipFile, src_path: str, arc_path: str):
    path = str(src_path or "").strip()
    if not path or not os.path.isfile(path):
        return
    archive.write(path, arcname=str(arc_path).replace("\\", "/"))


def zip_add_dir_if_exists(archive: zipfile.ZipFile, src_dir: str, arc_root: str):
    root = str(src_dir or "").strip()
    if not root or not os.path.isdir(root):
        return

    for base, _dirs, files in os.walk(root):
        for file_name in files:
            full_path = os.path.join(base, file_name)
            if not os.path.isfile(full_path):
                continue
            rel_path = os.path.relpath(full_path, root)
            arc_path = os.path.join(arc_root, rel_path).replace("\\", "/")
            try:
                archive.write(full_path, arcname=arc_path)
            except OSError:
                continue


def bundle_prefix(root_prefix: str, leaf: str) -> str:
    root = str(root_prefix or "").strip("/")
    suffix = str(leaf or "").strip("/")
    if not suffix:
        return f"{root}/" if root else ""
    return f"{root}/{suffix}/" if root else f"{suffix}/"


def safe_bundle_filename(name: str, fallback: str = "restored.legion") -> str:
    candidate = os.path.basename(str(name or "").strip())
    if not candidate:
        candidate = str(fallback or "restored.legion")
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate)
    candidate = candidate.strip("._")
    if not candidate:
        candidate = str(fallback or "restored.legion")
    return candidate


def safe_bundle_relative_path(path: str) -> str:
    raw = str(path or "").replace("\\", "/").strip()
    if not raw:
        return ""
    raw = raw.lstrip("/")
    parts = []
    for piece in raw.split("/"):
        token = str(piece or "").strip()
        if not token or token == ".":
            continue
        if token == "..":
            return ""
        parts.append(token)
    return "/".join(parts)


def read_bundle_manifest(archive: zipfile.ZipFile) -> Tuple[str, str, Dict[str, Any]]:
    names = [str(item or "") for item in archive.namelist()]
    manifest_name = ""
    for name in names:
        normalized = name.rstrip("/")
        if normalized.endswith("/manifest.json") or normalized == "manifest.json":
            manifest_name = normalized
            break
    if not manifest_name:
        raise ValueError("Bundle manifest.json is missing.")

    try:
        raw_manifest = archive.read(manifest_name)
    except KeyError as exc:
        raise ValueError("Bundle manifest.json is missing.") from exc

    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Bundle manifest.json is invalid.") from exc
    if not isinstance(manifest, dict):
        raise ValueError("Bundle manifest.json must be an object.")

    root_prefix = ""
    if manifest_name.endswith("/manifest.json"):
        root_prefix = manifest_name[:-len("/manifest.json")]

    return manifest_name, str(root_prefix or "").strip("/"), manifest


def locate_bundle_session_member(archive: zipfile.ZipFile, root_prefix: str, manifest: Dict[str, Any]) -> str:
    names = [str(item or "").rstrip("/") for item in archive.namelist()]
    name_set = set(names)

    manifest_project_name = os.path.basename(str(manifest.get("project_file", "") or "").strip())
    candidates = []

    session_prefix = bundle_prefix(root_prefix, "session")
    if manifest_project_name:
        explicit_name = f"{session_prefix}{manifest_project_name}" if session_prefix else manifest_project_name
        if explicit_name in name_set:
            candidates.append(explicit_name)

    if not candidates and session_prefix:
        for name in names:
            if not name.lower().endswith(".legion"):
                continue
            if name.startswith(session_prefix):
                candidates.append(name)

    if not candidates:
        for name in names:
            if name.lower().endswith(".legion"):
                candidates.append(name)

    if not candidates:
        return ""
    candidates.sort(key=lambda item: (len(item), item))
    return candidates[0]


def extract_zip_member_to_file(archive: zipfile.ZipFile, member_name: str, destination_path: str):
    target = os.path.abspath(str(destination_path or "").strip())
    if not target:
        raise ValueError("Destination path is required.")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    try:
        with archive.open(member_name, "r") as source, open(target, "wb") as handle:
            shutil.copyfileobj(source, handle)
    except KeyError as exc:
        raise ValueError(f"Bundle member is missing: {member_name}") from exc


def extract_zip_prefix_to_dir(archive: zipfile.ZipFile, prefix: str, destination_dir: str):
    clean_prefix = str(prefix or "").replace("\\", "/")
    if clean_prefix and not clean_prefix.endswith("/"):
        clean_prefix = f"{clean_prefix}/"

    dest_root = os.path.abspath(str(destination_dir or "").strip())
    if not dest_root:
        return
    os.makedirs(dest_root, exist_ok=True)

    names = [str(item or "") for item in archive.namelist()]
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.endswith("/"):
            continue
        if clean_prefix and not normalized.startswith(clean_prefix):
            continue
        relative = normalized[len(clean_prefix):] if clean_prefix else normalized
        safe_relative = safe_bundle_relative_path(relative)
        if not safe_relative:
            continue

        destination = os.path.abspath(os.path.join(dest_root, safe_relative))
        if not destination.startswith(f"{dest_root}{os.sep}") and destination != dest_root:
            continue

        os.makedirs(os.path.dirname(destination), exist_ok=True)
        try:
            with archive.open(name, "r") as source, open(destination, "wb") as handle:
                shutil.copyfileobj(source, handle)
        except Exception:
            continue


def close_active_project(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
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
    finally:
        runtime.logic.activeProject = None


def normalize_project_path(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate:
        raise ValueError("Project path is required.")
    normalized = os.path.abspath(os.path.expanduser(candidate))
    if not normalized.lower().endswith(".legion"):
        normalized = f"{normalized}.legion"
    return normalized


def normalize_existing_file(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate:
        raise ValueError("File path is required.")
    normalized = os.path.abspath(os.path.expanduser(candidate))
    if not os.path.isfile(normalized):
        raise FileNotFoundError(f"File not found: {normalized}")
    return normalized
