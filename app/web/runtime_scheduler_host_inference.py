from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.web import runtime_scheduler_observation_inference as web_runtime_scheduler_observation_inference


# The excerpt builders keep at most 400 non-empty lines of at most 260 chars, so only the head of a process
# output can ever reach an excerpt: reading more per row only holds the runtime lock longer. Output holding
# a NUL byte is read whole because SQLite's text functions stop at it.
PROCESS_OUTPUT_HEAD_CHARS = 120000
PROCESS_OUTPUT_HEAD_SQL = (
    "CASE WHEN instr(CAST(COALESCE(o.output, '') AS BLOB), X'00') > 0 THEN COALESCE(o.output, '') "
    f"ELSE substr(COALESCE(o.output, ''), 1, {int(PROCESS_OUTPUT_HEAD_CHARS)}) END"
)
_ANALYSIS_OUTPUT_CHARS = 2400

_observation_cache = threading.local()


@contextmanager
def host_observation_cache():
    """Share one host's script/process observations between the inference calls made for one request.

    Reentrant: a nested use keeps the cache already active on this thread.
    """
    previous = getattr(_observation_cache, "records", None)
    _observation_cache.records = {} if previous is None else previous
    try:
        yield
    finally:
        _observation_cache.records = previous


def load_host_observation_records(runtime, project, host_id: int, host_ip: str = "") -> Dict[str, List[Dict[str, str]]]:
    """Load (once per host_observation_cache scope) the script and process excerpt records of a host."""
    host_ip_text = str(host_ip or "").strip()
    cache_key = (int(host_id), host_ip_text)
    cache = getattr(_observation_cache, "records", None)
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    session = project.database.session()
    script_rows = []
    process_rows = []
    try:
        script_rows = session.execute(text(
            "SELECT COALESCE(s.scriptId, '') AS script_id, "
            "COALESCE(s.output, '') AS output "
            "FROM l1ScriptObj AS s "
            "WHERE s.hostId = :host_id "
            "ORDER BY s.id DESC LIMIT 360"
        ), {"host_id": int(host_id)}).fetchall()

        if host_ip_text:
            process_rows = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                f"{PROCESS_OUTPUT_HEAD_SQL} AS output_text "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 220"
            ), {"host_ip": host_ip_text}).fetchall()
    except Exception:
        script_rows = []
        process_rows = []
    finally:
        session.close()

    records = {
        "script_records": [
            {
                "script_id": str(row[0] or "").strip(),
                "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], _ANALYSIS_OUTPUT_CHARS),
            }
            for row in script_rows
        ],
        "process_records": [
            {
                "tool_id": str(row[0] or "").strip(),
                "analysis_excerpt": runtime._build_scheduler_analysis_excerpt(row[1], _ANALYSIS_OUTPUT_CHARS),
            }
            for row in process_rows
        ],
    }
    if cache is not None:
        cache[cache_key] = records
    return records


def infer_host_technologies(runtime, project, host_id: int, host_ip: str = "") -> List[Dict[str, str]]:
    session = project.database.session()
    service_rows = []
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
    except Exception:
        service_rows = []
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

    observations = load_host_observation_records(runtime, project, int(host_id), host_ip)
    return web_runtime_scheduler_observation_inference.infer_technologies_from_observations(
        runtime,
        service_records=service_records,
        script_records=observations["script_records"][:320],
        process_records=observations["process_records"][:180],
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
    observations = load_host_observation_records(runtime, project, int(host_id), host_ip)
    return web_runtime_scheduler_observation_inference.infer_findings_from_observations(
        runtime,
        host_cves_raw=cves,
        script_records=observations["script_records"],
        process_records=observations["process_records"],
        limit=220,
    )


def infer_host_urls(runtime, project, *, host_id: int, host_ip: str = "") -> List[Dict[str, Any]]:
    observations = load_host_observation_records(runtime, project, int(host_id), host_ip)
    return web_runtime_scheduler_observation_inference.infer_urls_from_observations(
        runtime,
        script_records=observations["script_records"],
        process_records=observations["process_records"],
        limit=160,
    )
