from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import text

from app.web import runtime_processes as web_runtime_processes
from db.entities.cve import cve
from db.entities.l1script import l1ScriptObj


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
