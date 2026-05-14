from __future__ import annotations

from typing import Any, Dict, Optional

from app.scheduler.insights import ensure_scheduler_ai_state_table, get_host_ai_state, upsert_host_ai_state
from app.timing import getTimestamp
from app.web import runtime_scheduler_ai_host_updates as web_runtime_scheduler_ai_host_updates


AI_HOST_UPDATE_MIN_CONFIDENCE = web_runtime_scheduler_ai_host_updates.AI_HOST_UPDATE_MIN_CONFIDENCE
apply_ai_host_updates = web_runtime_scheduler_ai_host_updates.apply_ai_host_updates
enrich_host_from_observed_results = web_runtime_scheduler_ai_host_updates.enrich_host_from_observed_results

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
