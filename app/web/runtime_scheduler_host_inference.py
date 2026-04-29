from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.web import runtime_scheduler_observation_inference as web_runtime_scheduler_observation_inference


def infer_host_technologies(runtime, project, host_id: int, host_ip: str = "") -> List[Dict[str, str]]:
    session = project.database.session()
    service_rows = []
    script_rows = []
    process_rows = []
    analysis_output_chars = 2400
    try:
        service_result = session.execute(text(
            "SELECT COALESCE(p.portId, '') AS port_id, "
            "COALESCE(p.protocol, '') AS protocol, "
            "COALESCE(s.name, '') AS service_name, "
            "COALESCE(s.product, '') AS service_product, "
            "COALESCE(s.version, '') AS service_version, "
            "COALESCE(s.extrainfo, '') AS service_extrainfo "
            "FROM portObj AS p "
            "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
            "WHERE p.hostId = :host_id "
            "ORDER BY p.id ASC LIMIT 320"
        ), {"host_id": int(host_id)})
        service_rows = service_result.fetchall()

        script_result = session.execute(text(
            "SELECT COALESCE(s.scriptId, '') AS script_id, "
            "COALESCE(s.output, '') AS output "
            "FROM l1ScriptObj AS s "
            "WHERE s.hostId = :host_id "
            "ORDER BY s.id DESC LIMIT 320"
        ), {"host_id": int(host_id)})
        script_rows = script_result.fetchall()

        host_ip_text = str(host_ip or "").strip()
        if host_ip_text:
            process_result = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(o.output, '') AS output_text "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 180"
            ), {"host_ip": host_ip_text})
            process_rows = process_result.fetchall()
    except Exception:
        service_rows = []
        script_rows = []
        process_rows = []
    finally:
        session.close()

    service_records = []
    for row in service_rows:
        service_records.append({
            "port": str(row[0] or "").strip(),
            "protocol": str(row[1] or "").strip().lower(),
            "service_name": str(row[2] or "").strip(),
            "service_product": str(row[3] or "").strip(),
            "service_version": str(row[4] or "").strip(),
            "service_extrainfo": str(row[5] or "").strip(),
            "banner": "",
        })

    script_records = []
    for row in script_rows:
        script_records.append({
            "script_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        })

    process_records = []
    for row in process_rows:
        process_records.append({
            "tool_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        })

    return web_runtime_scheduler_observation_inference.infer_technologies_from_observations(
        runtime,
        service_records=service_records,
        script_records=script_records,
        process_records=process_records,
        limit=220,
    )


def infer_host_findings(
        runtime,
        project,
        *,
        host_id: int,
        host_ip: str,
        host_cves_raw: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    cves = host_cves_raw if isinstance(host_cves_raw, list) else runtime._load_cves_for_host(project, int(host_id or 0))

    session = project.database.session()
    script_rows = []
    process_rows = []
    analysis_output_chars = 2400
    try:
        script_result = session.execute(text(
            "SELECT COALESCE(s.scriptId, '') AS script_id, "
            "COALESCE(s.output, '') AS output "
            "FROM l1ScriptObj AS s "
            "WHERE s.hostId = :host_id "
            "ORDER BY s.id DESC LIMIT 360"
        ), {"host_id": int(host_id)})
        script_rows = script_result.fetchall()

        if str(host_ip or "").strip():
            process_result = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(o.output, '') AS output_text "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 220"
            ), {"host_ip": str(host_ip or "").strip()})
            process_rows = process_result.fetchall()
    except Exception:
        script_rows = []
        process_rows = []
    finally:
        session.close()

    script_records = [
        {
            "script_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        }
        for row in script_rows
    ]
    process_records = [
        {
            "tool_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        }
        for row in process_rows
    ]

    return web_runtime_scheduler_observation_inference.infer_findings_from_observations(
        runtime,
        host_cves_raw=cves,
        script_records=script_records,
        process_records=process_records,
        limit=220,
    )


def infer_host_urls(runtime, project, *, host_id: int, host_ip: str = "") -> List[Dict[str, Any]]:
    session = project.database.session()
    script_rows = []
    process_rows = []
    analysis_output_chars = 2400
    try:
        script_result = session.execute(text(
            "SELECT COALESCE(s.scriptId, '') AS script_id, "
            "COALESCE(s.output, '') AS output "
            "FROM l1ScriptObj AS s "
            "WHERE s.hostId = :host_id "
            "ORDER BY s.id DESC LIMIT 360"
        ), {"host_id": int(host_id)})
        script_rows = script_result.fetchall()

        if str(host_ip or "").strip():
            process_result = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(o.output, '') AS output_text "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 220"
            ), {"host_ip": str(host_ip or "").strip()})
            process_rows = process_result.fetchall()
    except Exception:
        script_rows = []
        process_rows = []
    finally:
        session.close()

    script_records = [
        {
            "script_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        }
        for row in script_rows
    ]
    process_records = [
        {
            "tool_id": str(row[0] or "").strip(),
            "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars)),
        }
        for row in process_rows
    ]
    return web_runtime_scheduler_observation_inference.infer_urls_from_observations(
        runtime,
        script_records=script_records,
        process_records=process_records,
        limit=160,
    )
