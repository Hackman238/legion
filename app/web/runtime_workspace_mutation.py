from __future__ import annotations

import json
import os
from typing import Any, Dict

from sqlalchemy import text

from app.device_categories import category_names, normalize_manual_device_categories
from app.scheduler.insights import delete_host_ai_state
from app.scheduler.state import upsert_target_state as store_target_state
from app.web import runtime_processes as web_runtime_processes
from db.entities.cve import cve
from db.entities.l1script import l1ScriptObj


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


def create_script_entry(
        runtime,
        host_id: int,
        port: str,
        protocol: str,
        script_id: str,
        output: str,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        port_obj = project.repositoryContainer.portRepository.getPortByHostIdAndPort(
            host.id,
            str(port),
            str(protocol or "tcp").lower(),
        )
        if port_obj is None:
            raise KeyError(f"Unknown port {port}/{protocol} for host {host.id}")

        session = project.database.session()
        try:
            script_row = l1ScriptObj(str(script_id), str(output or ""), str(port_obj.id), str(host.id))
            session.add(script_row)
            session.commit()
            return {
                "id": int(script_row.id),
                "script_id": str(script_row.scriptId),
                "port_id": int(port_obj.id),
            }
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def delete_script_entry(runtime, script_db_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.query(l1ScriptObj).filter_by(id=int(script_db_id)).first()
            if row is None:
                raise KeyError(f"Unknown script id: {script_db_id}")
            session.delete(row)
            session.commit()
            return {"deleted": True, "id": int(script_db_id)}
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def get_script_output(runtime, script_db_id: int, offset: int = 0, max_chars: int = 12000) -> Dict[str, Any]:
    offset_value = max(0, int(offset or 0))
    max_len = max(256, min(int(max_chars or 12000), 50000))
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            script_result = session.execute(text(
                "SELECT s.id AS script_db_id, "
                "COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS script_output, "
                "COALESCE(p.portId, '') AS port, "
                "LOWER(COALESCE(p.protocol, 'tcp')) AS protocol, "
                "COALESCE(h.ip, '') AS host_ip "
                "FROM l1ScriptObj AS s "
                "LEFT JOIN portObj AS p ON p.id = s.portId "
                "LEFT JOIN hostObj AS h ON h.id = s.hostId "
                "WHERE s.id = :id LIMIT 1"
            ), {"id": int(script_db_id)})
            script_row = script_result.fetchone()
            if script_row is None:
                raise KeyError(f"Unknown script id: {script_db_id}")
            script_data = dict(zip(script_result.keys(), script_row))

            process_result = session.execute(text(
                "SELECT p.id AS process_id, "
                "COALESCE(p.command, '') AS command, "
                "COALESCE(p.outputfile, '') AS outputfile, "
                "COALESCE(p.status, '') AS status, "
                "COALESCE(o.output, '') AS output "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE p.name = :tool_id "
                "AND COALESCE(p.hostIp, '') = :host_ip "
                "AND COALESCE(p.port, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "tool_id": str(script_data.get("script_id", "") or ""),
                "host_ip": str(script_data.get("host_ip", "") or ""),
                "port": str(script_data.get("port", "") or ""),
                "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
            })
            process_row = process_result.fetchone()
            process_data = dict(zip(process_result.keys(), process_row)) if process_row else {}
        finally:
            session.close()

    has_process = bool(process_data.get("process_id"))
    output_text = str(process_data.get("output", "") or "") if has_process else str(script_data.get("script_output", "") or "")
    output_length = len(output_text)
    chunk = ""
    if offset_value < output_length:
        chunk = output_text[offset_value:offset_value + max_len]
    next_offset = offset_value + len(chunk)
    status = str(process_data.get("status", "") or "")
    completed = status not in {"Running", "Waiting"} if has_process else True

    return {
        "script_db_id": int(script_data.get("script_db_id", 0) or 0),
        "script_id": str(script_data.get("script_id", "") or ""),
        "host_ip": str(script_data.get("host_ip", "") or ""),
        "port": str(script_data.get("port", "") or ""),
        "protocol": str(script_data.get("protocol", "tcp") or "tcp"),
        "source": "process" if has_process else "script-row",
        "process_id": int(process_data.get("process_id", 0) or 0),
        "outputfile": str(process_data.get("outputfile", "") or ""),
        "command": web_runtime_processes.redact_command_secrets(process_data.get("command", "")),
        "status": status if has_process else "Saved",
        "output": output_text,
        "output_chunk": chunk,
        "output_length": output_length,
        "offset": offset_value,
        "next_offset": next_offset,
        "completed": completed,
    }


def create_cve_entry(
        runtime,
        host_id: int,
        name: str,
        url: str = "",
        severity: str = "",
        source: str = "",
        product: str = "",
        version: str = "",
        exploit_id: int = 0,
        exploit: str = "",
        exploit_url: str = "",
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        session = project.database.session()
        try:
            existing = session.query(cve).filter_by(hostId=str(host.id), name=str(name)).first()
            if existing:
                return {
                    "id": int(existing.id),
                    "name": str(existing.name),
                    "host_id": int(host.id),
                    "created": False,
                }

            row = cve(
                str(name),
                str(url or ""),
                str(product or ""),
                str(host.id),
                severity=str(severity or ""),
                source=str(source or ""),
                version=str(version or ""),
                exploitId=int(exploit_id or 0),
                exploit=str(exploit or ""),
                exploitUrl=str(exploit_url or ""),
            )
            session.add(row)
            session.commit()
            return {
                "id": int(row.id),
                "name": str(row.name),
                "host_id": int(host.id),
                "created": True,
            }
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def delete_cve_entry(runtime, cve_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            row = session.query(cve).filter_by(id=int(cve_id)).first()
            if row is None:
                raise KeyError(f"Unknown cve id: {cve_id}")
            session.delete(row)
            session.commit()
            return {"deleted": True, "id": int(cve_id)}
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
