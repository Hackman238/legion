from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import text


def load_scheduler_host_evidence(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str,
        protocol: str,
) -> Dict[str, Any]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return {}
        scheduler_preferences = runtime.scheduler_config.load()

        session = project.database.session()
        try:
            host_result = session.execute(text(
                "SELECT COALESCE(h.hostname, '') AS hostname, "
                "COALESCE(h.osMatch, '') AS os_match "
                "FROM hostObj AS h WHERE h.id = :host_id LIMIT 1"
            ), {"host_id": int(host_id or 0)}).fetchone()
            hostname = str(host_result[0] or "") if host_result else ""
            os_match = str(host_result[1] or "") if host_result else ""

            service_result = session.execute(text(
                "SELECT COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "AND COALESCE(p.portId, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "host_id": int(host_id or 0),
                "port": str(port or ""),
                "protocol": str(protocol or "tcp"),
            }).fetchone()
            service_name_db = str(service_result[0] or "") if service_result else ""
            service_product = str(service_result[1] or "") if service_result else ""
            service_version = str(service_result[2] or "") if service_result else ""
            service_extrainfo = str(service_result[3] or "") if service_result else ""

            host_port_rows = session.execute(text(
                "SELECT COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol, "
                "COALESCE(p.state, '') AS state, "
                "COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "ORDER BY p.id ASC LIMIT 280"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            script_rows = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output, "
                "COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM l1ScriptObj AS s "
                "LEFT JOIN portObj AS p ON p.id = s.portId "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 260"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            process_rows = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(p.status, '') AS status, "
                "COALESCE(p.command, '') AS command_text, "
                "COALESCE(o.output, '') AS output_text, "
                "COALESCE(p.port, '') AS port, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 180"
            ), {
                "host_ip": str(host_ip or ""),
            }).fetchall()
        finally:
            session.close()

    try:
        host_cves_raw = runtime._load_cves_for_host(project, int(host_id or 0))
    except Exception:
        host_cves_raw = []

    return {
        "project": project,
        "scheduler_preferences": scheduler_preferences,
        "hostname": hostname,
        "os_match": os_match,
        "service_name_db": service_name_db,
        "service_product": service_product,
        "service_version": service_version,
        "service_extrainfo": service_extrainfo,
        "host_port_rows": host_port_rows,
        "script_rows": script_rows,
        "process_rows": process_rows,
        "host_cves_raw": host_cves_raw,
    }
