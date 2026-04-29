from __future__ import annotations

import os
import shutil
from typing import Any, Dict

from app.web import runtime_project_bundle_archive as web_runtime_project_bundle_archive
from app.web import runtime_project_bundle_rebase as web_runtime_project_bundle_rebase


def start_restore_project_zip_job(runtime, path: str) -> Dict[str, Any]:
    zip_path = web_runtime_project_bundle_archive.normalize_existing_file(path)
    return runtime._start_job(
        "project-restore-zip",
        lambda _job_id: restore_project_bundle_zip_job(runtime, zip_path, cleanup_source=True),
        payload={"path": zip_path},
        queue_front=True,
        exclusive=True,
    )


def restore_project_bundle_zip(runtime, path: str) -> Dict[str, Any]:
    zip_path = web_runtime_project_bundle_archive.normalize_existing_file(path)
    return restore_project_bundle_zip_job(runtime, zip_path, cleanup_source=False)


def restore_project_bundle_zip_job(runtime, zip_path: str, cleanup_source: bool) -> Dict[str, Any]:
    normalized = web_runtime_project_bundle_archive.normalize_existing_file(zip_path)
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
    normalized = web_runtime_project_bundle_archive.normalize_existing_file(zip_path)
    restored = web_runtime_project_bundle_archive.extract_project_bundle_zip(normalized)
    manifest = dict(restored.get("manifest") or {})
    restore_root = str(restored.get("restore_root", "") or "")
    project_path = str(restored.get("project_path", "") or "")
    output_folder = str(restored.get("output_folder", "") or "")
    running_folder = str(restored.get("running_folder", "") or "")

    web_runtime_project_bundle_rebase.rebase_restored_project_paths(
        project_path=project_path,
        manifest=manifest,
        output_folder=output_folder,
        running_folder=running_folder,
    )

    with runtime._lock:
        if runtime._save_in_progress:
            raise RuntimeError("Project save is in progress. Try again when it finishes.")
        previous_project = getattr(runtime.logic, "activeProject", None)
        restored_project = None
        try:
            project_manager = getattr(runtime.logic, "projectManager", None)
            if project_manager is not None and hasattr(project_manager, "openExistingProject"):
                restored_project = project_manager.openExistingProject(project_path, projectType="legion")
            else:
                runtime.logic.openExistingProject(project_path, projectType="legion")
                restored_project = getattr(runtime.logic, "activeProject", None)
            if restored_project is None:
                raise RuntimeError("Restored project could not be opened.")

            runtime.logic.activeProject = restored_project
            attach_restored_running_folder_locked(runtime, running_folder)
            runtime._ensure_scheduler_table()
            runtime._ensure_scheduler_approval_store()
            runtime._ensure_process_tables()
            details = runtime.get_project_details()
        except Exception:
            runtime.logic.activeProject = previous_project
            if restored_project is not None and restored_project is not previous_project:
                close_project_instance(runtime, restored_project)
            raise

        if previous_project is not None and previous_project is not restored_project:
            close_project_instance(runtime, previous_project)

    return {
        "project": details,
        "restored": {
            "restore_root": restore_root,
            "project_path": project_path,
            "output_folder": output_folder,
            "running_folder": running_folder,
            "manifest_project_file": str(manifest.get("project_file", "") or ""),
            "manifest_format": str(manifest.get("format", "") or ""),
        },
    }


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
