from __future__ import annotations

from sqlalchemy import text

from app.hostsfile import add_temporary_host_alias
from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_nmap_scripts,
    infer_os_from_service_inventory,
    is_unknown_hostname,
    is_unknown_os_match,
)
from app.web import runtime_scheduler_inference as web_runtime_scheduler_inference
from db.entities.host import hostObj


AI_HOST_UPDATE_MIN_CONFIDENCE = web_runtime_scheduler_inference.AI_HOST_UPDATE_MIN_CONFIDENCE


def apply_ai_host_updates(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        hostname: str,
        hostname_confidence: float,
        os_match: str,
        os_confidence: float,
):
    alias_to_add = ""
    safe_hostname = runtime._sanitize_ai_hostname(hostname)
    safe_os_match = str(os_match or "").strip()[:120]
    hostname_conf = runtime._ai_confidence_value(hostname_confidence)
    os_conf = runtime._ai_confidence_value(os_confidence)

    if not safe_hostname and not safe_os_match:
        return

    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return

        session = project.database.session()
        try:
            row = session.query(hostObj).filter_by(id=int(host_id)).first()
            if row is None and str(host_ip or "").strip():
                row = session.query(hostObj).filter_by(ip=str(host_ip or "").strip()).first()
            if row is None:
                return

            changed = False
            current_hostname = str(getattr(row, "hostname", "") or "")
            current_os = str(getattr(row, "osMatch", "") or "")

            if (
                    safe_hostname
                    and hostname_conf >= AI_HOST_UPDATE_MIN_CONFIDENCE
                    and is_unknown_hostname(current_hostname)
                    and safe_hostname != current_hostname
            ):
                row.hostname = safe_hostname
                alias_to_add = safe_hostname
                changed = True

            if (
                    safe_os_match
                    and os_conf >= AI_HOST_UPDATE_MIN_CONFIDENCE
                    and is_unknown_os_match(current_os)
                    and safe_os_match != current_os
            ):
                row.osMatch = safe_os_match
                row.osAccuracy = str(int(round(os_conf)))
                changed = True

            if changed:
                session.add(row)
                session.commit()
            else:
                session.rollback()
        except Exception:
            session.rollback()
        finally:
            session.close()

    if alias_to_add:
        try:
            add_temporary_host_alias(str(host_ip or ""), alias_to_add)
        except Exception:
            pass


def enrich_host_from_observed_results(runtime, *, host_ip: str, port: str, protocol: str):
    _ = port, protocol
    alias_to_add = ""
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return

        session = project.database.session()
        try:
            row = session.query(hostObj).filter_by(ip=str(host_ip or "")).first()
            if row is None:
                return

            need_hostname = is_unknown_hostname(str(getattr(row, "hostname", "") or ""))
            need_os = is_unknown_os_match(str(getattr(row, "osMatch", "") or ""))
            if not need_hostname and not need_os:
                return

            script_records = []
            script_result = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output "
                "FROM l1ScriptObj AS s "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 240"
            ), {"host_id": int(getattr(row, "id", 0) or 0)})
            for item in script_result.fetchall():
                script_id = str(item[0] or "").strip()
                output = runtime._truncate_scheduler_text(item[1], 1400)
                if script_id and output:
                    script_records.append((script_id, output))

            process_result = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(o.output, '') AS output "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 120"
            ), {
                "host_ip": str(host_ip or ""),
            })
            for item in process_result.fetchall():
                tool_id = str(item[0] or "").strip()
                output = runtime._truncate_scheduler_text(item[1], 1400)
                if tool_id and output:
                    script_records.append((tool_id, output))

            service_records = []
            service_result = session.execute(text(
                "SELECT COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS product, "
                "COALESCE(s.version, '') AS version, "
                "COALESCE(s.extrainfo, '') AS extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "ORDER BY p.id DESC LIMIT 260"
            ), {"host_id": int(getattr(row, "id", 0) or 0)})
            for item in service_result.fetchall():
                service_records.append((
                    str(item[0] or ""),
                    str(item[1] or ""),
                    str(item[2] or ""),
                    str(item[3] or ""),
                ))

            changed = False
            if need_hostname:
                inferred_hostname = infer_hostname_from_nmap_data(
                    str(getattr(row, "hostname", "") or ""),
                    script_records,
                )
                if inferred_hostname and is_unknown_hostname(str(getattr(row, "hostname", "") or "")):
                    row.hostname = inferred_hostname
                    alias_to_add = inferred_hostname
                    changed = True

            if need_os:
                inferred_os = infer_os_from_nmap_scripts(script_records)
                if not inferred_os:
                    inferred_os = infer_os_from_service_inventory(service_records)
                if inferred_os and is_unknown_os_match(str(getattr(row, "osMatch", "") or "")):
                    row.osMatch = inferred_os
                    if not str(getattr(row, "osAccuracy", "") or "").strip():
                        row.osAccuracy = "80"
                    changed = True

            if changed:
                session.add(row)
                session.commit()
            else:
                session.rollback()
        except Exception:
            session.rollback()
        finally:
            session.close()

    if alias_to_add:
        try:
            add_temporary_host_alias(str(host_ip or ""), alias_to_add)
        except Exception:
            pass
