from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt


def build_host_ai_context_state(
        runtime,
        *,
        ai_state: Dict[str, Any],
        inferred_technologies: List[Dict[str, Any]],
        signals: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    context_state = {}
    updated_signals = dict(signals or {})
    if isinstance(ai_state, dict) and ai_state:
        host_updates = ai_state.get("host_updates", {}) if isinstance(ai_state.get("host_updates", {}), dict) else {}

        ai_tech = []
        for item in ai_state.get("technologies", [])[:24]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()[:120]
            version = str(item.get("version", "")).strip()[:120]
            cpe = str(item.get("cpe", "")).strip()[:220]
            evidence = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("evidence", ""), 260)
            if not name and not cpe:
                continue
            ai_tech.append({
                "name": name,
                "version": version,
                "cpe": cpe,
                "evidence": evidence,
            })

        ai_findings = []
        for item in ai_state.get("findings", [])[:24]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()[:240]
            severity = str(item.get("severity", "")).strip().lower()[:16]
            cve_id = str(item.get("cve", "")).strip()[:64]
            evidence = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("evidence", ""), 260)
            if not title and not cve_id:
                continue
            ai_findings.append({
                "title": title,
                "severity": severity,
                "cve": cve_id,
                "evidence": evidence,
            })

        ai_manual_tests = []
        for item in ai_state.get("manual_tests", [])[:16]:
            if not isinstance(item, dict):
                continue
            command = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("command", ""), 260)
            why = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("why", ""), 180)
            if not command and not why:
                continue
            ai_manual_tests.append({
                "command": command,
                "why": why,
                "scope_note": web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("scope_note", ""), 160),
            })

        merged_context_tech = runtime._merge_technologies(
            existing=inferred_technologies,
            incoming=ai_tech,
            limit=64,
        )

        context_state = {
            "updated_at": str(ai_state.get("updated_at", "") or ""),
            "provider": str(ai_state.get("provider", "") or ""),
            "goal_profile": str(ai_state.get("goal_profile", "") or ""),
            "next_phase": str(ai_state.get("next_phase", "") or ""),
            "host_updates": {
                "hostname": str(host_updates.get("hostname", "") or ""),
                "hostname_confidence": runtime._ai_confidence_value(host_updates.get("hostname_confidence", 0.0)),
                "os": str(host_updates.get("os", "") or ""),
                "os_confidence": runtime._ai_confidence_value(host_updates.get("os_confidence", 0.0)),
            },
            "technologies": merged_context_tech,
            "findings": ai_findings,
            "manual_tests": ai_manual_tests,
        }
        reflection = ai_state.get("reflection", {}) if isinstance(ai_state.get("reflection", {}), dict) else {}
        if reflection:
            context_state["reflection"] = {
                "state": str(reflection.get("state", "") or "")[:24],
                "priority_shift": str(reflection.get("priority_shift", "") or "")[:64],
                "reason": web_runtime_scheduler_excerpt.truncate_scheduler_text(reflection.get("reason", ""), 220),
                "promote_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("promote_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
                "suppress_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("suppress_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
            }

        updated_signals = merge_observed_technology_signals(
            updated_signals,
            [
                str(item.get("name", "")).strip().lower()
                for item in merged_context_tech
                if isinstance(item, dict) and str(item.get("name", "")).strip()
            ],
        )
    elif inferred_technologies:
        context_state = {
            "updated_at": "",
            "provider": "",
            "goal_profile": "",
            "next_phase": "",
            "host_updates": {
                "hostname": "",
                "hostname_confidence": 0.0,
                "os": "",
                "os_confidence": 0.0,
            },
            "technologies": inferred_technologies,
            "findings": [],
            "manual_tests": [],
        }
        updated_signals = merge_observed_technology_signals(
            updated_signals,
            [
                str(item.get("name", "")).strip().lower()
                for item in inferred_technologies
                if isinstance(item, dict) and str(item.get("name", "")).strip()
            ],
        )

    return context_state, updated_signals


def merge_observed_technology_signals(signals: Dict[str, Any], observed_technologies: List[str]) -> Dict[str, Any]:
    if not observed_technologies:
        return signals
    updated = dict(signals or {})
    existing_observed = updated.get("observed_technologies", [])
    if not isinstance(existing_observed, list):
        existing_observed = []
    merged_observed = []
    seen_observed = set()
    for marker in existing_observed + list(observed_technologies or []):
        token = str(marker or "").strip().lower()
        if not token or token in seen_observed:
            continue
        seen_observed.add(token)
        merged_observed.append(token)
    if merged_observed:
        updated["observed_technologies"] = merged_observed[:24]
    return updated
