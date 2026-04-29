from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy import text

from app.hostsfile import add_temporary_host_alias
from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_nmap_scripts,
    infer_os_from_service_inventory,
    is_unknown_hostname,
    is_unknown_os_match,
)
from app.scheduler.insights import ensure_scheduler_ai_state_table, get_host_ai_state, upsert_host_ai_state
from app.timing import getTimestamp
from app.web import runtime_scheduler_inference as web_runtime_scheduler_inference
from db.entities.host import hostObj


AI_HOST_UPDATE_MIN_CONFIDENCE = web_runtime_scheduler_inference.AI_HOST_UPDATE_MIN_CONFIDENCE

def persist_scheduler_ai_analysis(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        goal_profile: str,
        provider_payload: Optional[Dict[str, Any]],
):
    payload = provider_payload if isinstance(provider_payload, dict) else {}

    host_updates_raw = payload.get("host_updates", {})
    if not isinstance(host_updates_raw, dict):
        host_updates_raw = {}

    provider_technologies = runtime._normalize_ai_technologies(
        host_updates_raw.get("technologies", [])
        or payload.get("technologies", [])
    )
    findings = runtime._normalize_ai_findings(payload.get("findings", []))
    manual_tests = runtime._normalize_ai_manual_tests(payload.get("manual_tests", []))

    hostname_candidate = runtime._sanitize_ai_hostname(host_updates_raw.get("hostname", ""))
    hostname_confidence = runtime._ai_confidence_value(host_updates_raw.get("hostname_confidence", 0.0))
    os_candidate = str(host_updates_raw.get("os", "")).strip()[:120]
    os_confidence = runtime._ai_confidence_value(host_updates_raw.get("os_confidence", 0.0))
    next_phase = str(payload.get("next_phase", "")).strip()[:80]

    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return
        try:
            host_cves_raw = runtime._load_cves_for_host(project, int(host_id or 0))
        except Exception:
            host_cves_raw = []
        inferred_technologies = runtime._infer_host_technologies(project, int(host_id), str(host_ip or ""))
        technologies = runtime._merge_technologies(
            existing=inferred_technologies,
            incoming=provider_technologies,
            limit=220,
        )
        inferred_findings = runtime._infer_host_findings(
            project,
            host_id=int(host_id),
            host_ip=str(host_ip or ""),
            host_cves_raw=host_cves_raw,
        )
        findings_combined = runtime._merge_ai_items(
            existing=inferred_findings,
            incoming=findings,
            key_fields=["title", "cve", "severity"],
            limit=260,
        )
        if not any([
            technologies,
            findings_combined,
            manual_tests,
            hostname_candidate,
            os_candidate,
            next_phase,
        ]):
            return
        ensure_scheduler_ai_state_table(project.database)
        existing = get_host_ai_state(project.database, int(host_id)) or {}
        existing_raw = existing.get("raw", {}) if isinstance(existing.get("raw", {}), dict) else {}
        existing_findings = runtime._normalize_ai_findings(existing.get("findings", []))

        merged_technologies = runtime._merge_technologies(
            existing=existing.get("technologies", []) if isinstance(existing.get("technologies", []), list) else [],
            incoming=technologies,
            limit=220,
        )
        merged_findings = runtime._merge_ai_items(
            existing=existing_findings,
            incoming=findings_combined,
            key_fields=["title", "cve", "severity"],
            limit=260,
        )
        merged_manual = runtime._merge_ai_items(
            existing=existing.get("manual_tests", []) if isinstance(existing.get("manual_tests", []), list) else [],
            incoming=manual_tests,
            key_fields=["command"],
            limit=200,
        )

        existing_hostname = runtime._sanitize_ai_hostname(existing.get("hostname", ""))
        existing_hostname_conf = runtime._ai_confidence_value(existing.get("hostname_confidence", 0.0))
        if hostname_candidate and hostname_confidence >= existing_hostname_conf:
            selected_hostname = hostname_candidate
            selected_hostname_conf = hostname_confidence
        else:
            selected_hostname = existing_hostname
            selected_hostname_conf = existing_hostname_conf

        existing_os = str(existing.get("os_match", "")).strip()[:120]
        existing_os_conf = runtime._ai_confidence_value(existing.get("os_confidence", 0.0))
        if os_candidate and os_confidence >= existing_os_conf:
            selected_os = os_candidate
            selected_os_conf = os_confidence
        else:
            selected_os = existing_os
            selected_os_conf = existing_os_conf

        raw_payload = dict(existing_raw)
        raw_payload.update(payload)
        if isinstance(existing_raw.get("reflection", {}), dict) and "reflection" not in raw_payload:
            raw_payload["reflection"] = dict(existing_raw.get("reflection", {}))

        state_payload = {
            "host_id": int(host_id),
            "host_ip": str(host_ip or ""),
            "_sync_target_state": False,
            "provider": str(payload.get("provider", "") or existing.get("provider", "")),
            "goal_profile": str(goal_profile or existing.get("goal_profile", "")),
            "last_port": str(port or existing.get("last_port", "")),
            "last_protocol": str(protocol or existing.get("last_protocol", "")),
            "last_service": str(service_name or existing.get("last_service", "")),
            "hostname": selected_hostname,
            "hostname_confidence": selected_hostname_conf,
            "os_match": selected_os,
            "os_confidence": selected_os_conf,
            "next_phase": str(next_phase or existing.get("next_phase", "")),
            "technologies": merged_technologies,
            "findings": merged_findings,
            "manual_tests": merged_manual,
            "raw": raw_payload,
        }
        upsert_host_ai_state(project.database, int(host_id), state_payload)
        runtime._persist_shared_target_state(
            host_id=int(host_id),
            host_ip=str(host_ip or ""),
            port=str(port or ""),
            protocol=str(protocol or "tcp"),
            service_name=str(service_name or ""),
            scheduler_mode="ai",
            goal_profile=str(goal_profile or existing.get("goal_profile", "")),
            engagement_preset=str(existing.get("engagement_preset", "") or ""),
            provider=str(payload.get("provider", "") or existing.get("provider", "")),
            hostname=selected_hostname,
            hostname_confidence=selected_hostname_conf,
            os_match=selected_os,
            os_confidence=selected_os_conf,
            next_phase=str(next_phase or existing.get("next_phase", "")),
            technologies=provider_technologies or None,
            findings=findings or None,
            manual_tests=manual_tests or None,
            raw=raw_payload,
        )

    runtime._apply_ai_host_updates(
        host_id=int(host_id),
        host_ip=str(host_ip or ""),
        hostname=hostname_candidate,
        hostname_confidence=hostname_confidence,
        os_match=os_candidate,
        os_confidence=os_confidence,
    )


def persist_scheduler_reflection_analysis(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        goal_profile: str,
        reflection_payload: Optional[Dict[str, Any]],
):
    payload = reflection_payload if isinstance(reflection_payload, dict) else {}
    reflection_state = str(payload.get("state", "") or "").strip().lower()
    reason = runtime._truncate_scheduler_text(payload.get("reason", ""), 320)
    priority_shift = str(payload.get("priority_shift", "") or "").strip().lower()[:64]
    trigger_reason = str(payload.get("trigger_reason", "") or "").strip().lower()[:64]
    trigger_context_raw = payload.get("trigger_context", {}) if isinstance(payload.get("trigger_context", {}), dict) else {}
    trigger_context = {}
    for key in ("round_number", "current_phase", "previous_phase", "window_size", "repeated_selection_count"):
        value = trigger_context_raw.get(key, "")
        if value in ("", None):
            continue
        trigger_context[str(key)] = value
    trigger_recent_failures = [
        runtime._truncate_scheduler_text(item, 120)
        for item in list(trigger_context_raw.get("recent_failures", []) or [])[:6]
        if runtime._truncate_scheduler_text(item, 120)
    ]
    if trigger_recent_failures:
        trigger_context["recent_failures"] = trigger_recent_failures
    promote_tool_ids = [
        str(item or "").strip().lower()[:120]
        for item in list(payload.get("promote_tool_ids", []) or [])[:16]
        if str(item or "").strip()
    ]
    suppress_tool_ids = [
        str(item or "").strip().lower()[:120]
        for item in list(payload.get("suppress_tool_ids", []) or [])[:16]
        if str(item or "").strip()
    ]
    manual_tests = runtime._normalize_ai_manual_tests(payload.get("manual_tests", []))

    if not any([reflection_state, reason, priority_shift, trigger_reason, trigger_context, promote_tool_ids, suppress_tool_ids, manual_tests]):
        return

    reflection_record = {
        "state": reflection_state or "continue",
        "reason": reason,
        "priority_shift": priority_shift,
        "trigger_reason": trigger_reason,
        "trigger_context": trigger_context,
        "promote_tool_ids": promote_tool_ids,
        "suppress_tool_ids": suppress_tool_ids,
        "manual_tests": manual_tests,
        "provider": str(payload.get("provider", "") or ""),
        "prompt_version": str(payload.get("prompt_version", "") or ""),
        "prompt_type": str(payload.get("prompt_type", "") or "reflection"),
        "reflected_at": getTimestamp(True),
    }

    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return
        ensure_scheduler_ai_state_table(project.database)
        existing = get_host_ai_state(project.database, int(host_id)) or {}
        existing_raw = existing.get("raw", {}) if isinstance(existing.get("raw", {}), dict) else {}
        existing_technologies = runtime._normalize_ai_technologies(existing.get("technologies", []))
        existing_findings = runtime._normalize_ai_findings(existing.get("findings", []))
        merged_manual = runtime._merge_ai_items(
            existing=existing.get("manual_tests", []) if isinstance(existing.get("manual_tests", []), list) else [],
            incoming=manual_tests,
            key_fields=["command"],
            limit=200,
        )
        raw_payload = dict(existing_raw)
        raw_payload["reflection"] = reflection_record

        state_payload = {
            "host_id": int(host_id),
            "host_ip": str(host_ip or existing.get("host_ip", "")),
            "_sync_target_state": False,
            "provider": str(payload.get("provider", "") or existing.get("provider", "")),
            "goal_profile": str(goal_profile or existing.get("goal_profile", "")),
            "last_port": str(port or existing.get("last_port", "")),
            "last_protocol": str(protocol or existing.get("last_protocol", "")),
            "last_service": str(service_name or existing.get("last_service", "")),
            "hostname": runtime._sanitize_ai_hostname(existing.get("hostname", "")),
            "hostname_confidence": runtime._ai_confidence_value(existing.get("hostname_confidence", 0.0)),
            "os_match": str(existing.get("os_match", "") or ""),
            "os_confidence": runtime._ai_confidence_value(existing.get("os_confidence", 0.0)),
            "next_phase": str(existing.get("next_phase", "") or ""),
            "technologies": existing_technologies,
            "findings": existing_findings,
            "manual_tests": merged_manual,
            "raw": raw_payload,
        }
        upsert_host_ai_state(project.database, int(host_id), state_payload)
        runtime._persist_shared_target_state(
            host_id=int(host_id),
            host_ip=str(host_ip or existing.get("host_ip", "")),
            port=str(port or existing.get("last_port", "")),
            protocol=str(existing.get("last_protocol", "tcp") or "tcp"),
            service_name=str(service_name or existing.get("last_service", "")),
            scheduler_mode="ai",
            goal_profile=str(goal_profile or existing.get("goal_profile", "")),
            engagement_preset=str(existing.get("engagement_preset", "") or ""),
            provider=str(payload.get("provider", "") or existing.get("provider", "")),
            hostname=runtime._sanitize_ai_hostname(existing.get("hostname", "")),
            hostname_confidence=runtime._ai_confidence_value(existing.get("hostname_confidence", 0.0)),
            os_match=str(existing.get("os_match", "") or ""),
            os_confidence=runtime._ai_confidence_value(existing.get("os_confidence", 0.0)),
            next_phase=str(existing.get("next_phase", "") or ""),
            technologies=None,
            findings=None,
            manual_tests=manual_tests or None,
            raw=raw_payload,
        )


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
