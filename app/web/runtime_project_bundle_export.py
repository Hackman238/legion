from __future__ import annotations

import datetime
import json
import os
import tempfile
import zipfile
from typing import List, Tuple


def build_project_bundle_zip(runtime) -> Tuple[str, str]:
    with runtime._lock:
        project = runtime._require_active_project()
        runtime._ensure_process_tables()
        props = project.properties
        project_file = str(getattr(props, "projectName", "") or "")
        output_folder = str(getattr(props, "outputFolder", "") or "")
        running_folder = str(getattr(props, "runningFolder", "") or "")
        database = getattr(project, "database", None)
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

    try:
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
            # Job workers may be mid-transaction: archive a consistent snapshot (SQLite backup API), not the
            # live file, which could be torn and fail the integrity check on restore.
            db_snapshot = _snapshot_database(database, project_file)
            try:
                zip_add_file_if_exists(
                    archive,
                    db_snapshot or project_file,
                    f"{root_name}/session/{os.path.basename(project_file or 'session.legion')}",
                )
            finally:
                if db_snapshot and os.path.isfile(db_snapshot):
                    try:
                        os.remove(db_snapshot)
                    except OSError:
                        pass
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
    except Exception:
        try:
            if os.path.isfile(bundle_path):
                os.remove(bundle_path)
        except Exception:
            pass
        raise

    return bundle_path, bundle_name


def _snapshot_database(database, project_file: str) -> str:
    """Path of a consistent copy of the project database, or '' when no backup API is available."""
    backup_to = getattr(database, "backup_to", None)
    if not callable(backup_to) or not project_file or not os.path.isfile(project_file):
        return ""
    handle = tempfile.NamedTemporaryFile(prefix="legion-bundle-db-", suffix=".legion", delete=False)
    snapshot_path = handle.name
    handle.close()
    try:
        backup_to(snapshot_path)
    except Exception:
        try:
            os.remove(snapshot_path)
        except OSError:
            pass
        raise
    return snapshot_path


def zip_add_file_if_exists(archive: zipfile.ZipFile, src_path: str, arc_path: str):
    path = str(src_path or "").strip()
    if not path or not os.path.isfile(path):
        return
    archive.write(path, arcname=str(arc_path).replace("\\", "/"))


def zip_add_dir_if_exists(archive: zipfile.ZipFile, src_dir: str, arc_root: str):
    root = str(src_dir or "").strip()
    if not root or not os.path.isdir(root):
        return []

    archive_errors: List[str] = []

    def _walk_error(exc):
        archive_errors.append(str(exc))

    for base, _dirs, files in os.walk(root, onerror=_walk_error):
        for file_name in files:
            full_path = os.path.join(base, file_name)
            if not os.path.isfile(full_path):
                continue
            rel_path = os.path.relpath(full_path, root)
            arc_path = os.path.join(arc_root, rel_path).replace("\\", "/")
            try:
                archive.write(full_path, arcname=arc_path)
            except OSError as exc:
                archive_errors.append(f"{full_path}: {exc}")

    if archive_errors:
        preview = "; ".join(archive_errors[:3])
        remaining = len(archive_errors) - min(len(archive_errors), 3)
        suffix = f"; +{remaining} more" if remaining > 0 else ""
        raise ValueError(f"Failed to add bundled artifacts from {root}: {preview}{suffix}")
    return []
