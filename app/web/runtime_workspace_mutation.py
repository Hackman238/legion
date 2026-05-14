from __future__ import annotations

import json
import os
from typing import Any, Dict

from sqlalchemy import text

from app.device_categories import category_names, normalize_manual_device_categories
from app.scheduler.insights import delete_host_ai_state
from app.scheduler.state import upsert_target_state as store_target_state
from app.web import runtime_workspace_entries as web_runtime_workspace_entries


create_script_entry = web_runtime_workspace_entries.create_script_entry
delete_script_entry = web_runtime_workspace_entries.delete_script_entry
get_script_output = web_runtime_workspace_entries.get_script_output
create_cve_entry = web_runtime_workspace_entries.create_cve_entry
delete_cve_entry = web_runtime_workspace_entries.delete_cve_entry


def ensure_workspace_settings_table(runtime) -> None:
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    session = project.database.session()
    try:
        session.execute(text(
            "CREATE TABLE IF NOT EXISTS workspace_setting ("
            "key TEXT PRIMARY KEY,"
            "value_json TEXT"
            ")"
        ))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_workspace_setting_locked(runtime, key: str, default: Any = None) -> Any:
    project = runtime._require_active_project()
    ensure_workspace_settings_table(runtime)
    session = project.database.session()
    try:
        row = session.execute(text(
            "SELECT value_json FROM workspace_setting WHERE key = :key LIMIT 1"
        ), {"key": str(key or "")}).fetchone()
        if not row or row[0] in (None, ""):
            return default
        try:
            return json.loads(str(row[0] or ""))
        except Exception:
            return default
    finally:
        session.close()


def set_workspace_setting_locked(runtime, key: str, value: Any) -> None:
    project = runtime._require_active_project()
    ensure_workspace_settings_table(runtime)
    session = project.database.session()
    try:
        encoded = json.dumps(value, sort_keys=True)
        session.execute(text(
            "INSERT INTO workspace_setting (key, value_json) VALUES (:key, :value_json) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json"
        ), {
            "key": str(key or ""),
            "value_json": encoded,
        })
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def update_host_note(runtime, host_id: int, text_value: str) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        ok = project.repositoryContainer.noteRepository.storeNotes(host.id, str(text_value or ""))
        return {
            "host_id": int(host.id),
            "saved": bool(ok),
        }


def update_host_categories(
        runtime,
        host_id: int,
        *,
        manual_categories: Any = None,
        override_auto: bool = False,
        upsert_target_state_func=None,
) -> Dict[str, Any]:
    target_state_upserter = upsert_target_state_func or store_target_state
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        updated_state = target_state_upserter(project.database, int(host.id), {
            "host_ip": str(getattr(host, "ip", "") or ""),
            "hostname": str(getattr(host, "hostname", "") or ""),
            "os_match": str(getattr(host, "osMatch", "") or ""),
            "manual_device_categories": normalize_manual_device_categories(manual_categories),
            "device_category_override": bool(override_auto),
        }, merge=True)
        return {
            "host_id": int(host.id),
            "device_categories": category_names(updated_state.get("device_categories", [])),
            "manual_device_categories": category_names(updated_state.get("manual_device_categories", [])),
            "device_category_override": bool(updated_state.get("device_category_override", False)),
        }


def delete_host_workspace(runtime, host_id: int) -> Dict[str, Any]:
    target_host_id = int(host_id)
    target_host_ip = ""

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(target_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        target_host_ip = str(getattr(host, "ip", "") or "").strip()

        runtime._ensure_process_tables()
        runtime._ensure_scheduler_table()
        runtime._ensure_scheduler_approval_store()

        session = project.database.session()
        try:
            running_process_ids = []
            if target_host_ip:
                result = session.execute(text(
                    "SELECT id FROM process "
                    "WHERE COALESCE(hostIp, '') = :host_ip "
                    "AND COALESCE(status, '') IN ('Running', 'Waiting')"
                ), {"host_ip": target_host_ip})
                running_process_ids = [
                    int(item[0]) for item in result.fetchall()
                    if item and item[0] is not None
                ]
        finally:
            session.close()

    for process_id in running_process_ids:
        try:
            runtime.kill_process(int(process_id))
        except Exception:
            pass

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(target_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        target_host_ip = str(getattr(host, "ip", "") or "").strip()
        host_id_text = str(int(getattr(host, "id", target_host_id) or target_host_id))

        session = project.database.session()
        deleted_counts = {
            "scripts": 0,
            "cves": 0,
            "notes": 0,
            "ports": 0,
            "hosts": 0,
            "process_output": 0,
            "processes": 0,
            "approvals": 0,
            "decisions": 0,
            "ai_analysis": 0,
        }

        try:
            script_delete = session.execute(text(
                "DELETE FROM l1ScriptObj "
                "WHERE CAST(hostId AS TEXT) = :host_id "
                "OR CAST(portId AS TEXT) IN ("
                "SELECT CAST(id AS TEXT) FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
                ")"
            ), {"host_id": host_id_text})
            deleted_counts["scripts"] = max(0, int(script_delete.rowcount or 0))

            cve_delete = session.execute(text(
                "DELETE FROM cve WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["cves"] = max(0, int(cve_delete.rowcount or 0))

            note_delete = session.execute(text(
                "DELETE FROM note WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["notes"] = max(0, int(note_delete.rowcount or 0))

            port_delete = session.execute(text(
                "DELETE FROM portObj WHERE CAST(hostId AS TEXT) = :host_id"
            ), {"host_id": host_id_text})
            deleted_counts["ports"] = max(0, int(port_delete.rowcount or 0))

            host_delete = session.execute(text(
                "DELETE FROM hostObj WHERE id = :host_id_int"
            ), {"host_id_int": int(host_id_text)})
            deleted_counts["hosts"] = max(0, int(host_delete.rowcount or 0))

            if target_host_ip:
                process_output_delete = session.execute(text(
                    "DELETE FROM process_output "
                    "WHERE processId IN (SELECT id FROM process WHERE COALESCE(hostIp, '') = :host_ip)"
                ), {"host_ip": target_host_ip})
                deleted_counts["process_output"] = max(0, int(process_output_delete.rowcount or 0))

                process_delete = session.execute(text(
                    "DELETE FROM process WHERE COALESCE(hostIp, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["processes"] = max(0, int(process_delete.rowcount or 0))

                approval_delete = session.execute(text(
                    "DELETE FROM scheduler_pending_approval WHERE COALESCE(host_ip, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["approvals"] = max(0, int(approval_delete.rowcount or 0))

                decision_delete = session.execute(text(
                    "DELETE FROM scheduler_decision_log WHERE COALESCE(host_ip, '') = :host_ip"
                ), {"host_ip": target_host_ip})
                deleted_counts["decisions"] = max(0, int(decision_delete.rowcount or 0))

            session.execute(text(
                "DELETE FROM serviceObj "
                "WHERE CAST(id AS TEXT) NOT IN ("
                "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj "
                "WHERE COALESCE(serviceId, '') <> ''"
                ")"
            ))

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        deleted_counts["ai_analysis"] = int(delete_host_ai_state(project.database, int(host_id_text)) or 0)

        deleted_screenshots = 0
        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        if os.path.isdir(screenshot_dir) and target_host_ip:
            prefix = f"{target_host_ip}-"
            for filename in os.listdir(screenshot_dir):
                if not filename.startswith(prefix) or not filename.lower().endswith(".png"):
                    continue
                try:
                    os.remove(os.path.join(screenshot_dir, filename))
                    deleted_screenshots += 1
                except Exception:
                    continue

        return {
            "deleted": True,
            "host_id": int(target_host_id),
            "host_ip": target_host_ip,
            "counts": {
                **deleted_counts,
                "screenshots": int(deleted_screenshots),
            },
        }
