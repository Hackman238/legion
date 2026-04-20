from __future__ import annotations

import datetime
import importlib
import json
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.planner import ScheduledAction
from app.timing import getTimestamp


def _web_runtime_module():
    return importlib.import_module("app.web.runtime")


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
    runtime_module = _web_runtime_module()
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
        runtime_module.ensure_scheduler_ai_state_table(project.database)
        existing = runtime_module.get_host_ai_state(project.database, int(host_id)) or {}
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
        runtime_module.upsert_host_ai_state(project.database, int(host_id), state_payload)
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
    runtime_module = _web_runtime_module()
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
        runtime_module.ensure_scheduler_ai_state_table(project.database)
        existing = runtime_module.get_host_ai_state(project.database, int(host_id)) or {}
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
        runtime_module.upsert_host_ai_state(project.database, int(host_id), state_payload)
        runtime._persist_shared_target_state(
            host_id=int(host_id),
            host_ip=str(host_ip or existing.get("host_ip", "")),
            port=str(port or existing.get("last_port", "")),
            protocol=str(protocol or existing.get("last_protocol", "tcp") or "tcp"),
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
    runtime_module = _web_runtime_module()
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
            row = session.query(runtime_module.hostObj).filter_by(id=int(host_id)).first()
            if row is None and str(host_ip or "").strip():
                row = session.query(runtime_module.hostObj).filter_by(ip=str(host_ip or "").strip()).first()
            if row is None:
                return

            changed = False
            current_hostname = str(getattr(row, "hostname", "") or "")
            current_os = str(getattr(row, "osMatch", "") or "")

            if (
                    safe_hostname
                    and hostname_conf >= runtime_module._AI_HOST_UPDATE_MIN_CONFIDENCE
                    and runtime_module.is_unknown_hostname(current_hostname)
                    and safe_hostname != current_hostname
            ):
                row.hostname = safe_hostname
                alias_to_add = safe_hostname
                changed = True

            if (
                    safe_os_match
                    and os_conf >= runtime_module._AI_HOST_UPDATE_MIN_CONFIDENCE
                    and runtime_module.is_unknown_os_match(current_os)
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
            runtime_module.add_temporary_host_alias(str(host_ip or ""), alias_to_add)
        except Exception:
            pass


def enrich_host_from_observed_results(runtime, *, host_ip: str, port: str, protocol: str):
    runtime_module = _web_runtime_module()
    _ = port, protocol
    alias_to_add = ""
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return

        session = project.database.session()
        try:
            row = session.query(runtime_module.hostObj).filter_by(ip=str(host_ip or "")).first()
            if row is None:
                return

            need_hostname = runtime_module.is_unknown_hostname(str(getattr(row, "hostname", "") or ""))
            need_os = runtime_module.is_unknown_os_match(str(getattr(row, "osMatch", "") or ""))
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
                inferred_hostname = runtime_module.infer_hostname_from_nmap_data(
                    str(getattr(row, "hostname", "") or ""),
                    script_records,
                )
                if inferred_hostname and runtime_module.is_unknown_hostname(str(getattr(row, "hostname", "") or "")):
                    row.hostname = inferred_hostname
                    alias_to_add = inferred_hostname
                    changed = True

            if need_os:
                inferred_os = runtime_module.infer_os_from_nmap_scripts(script_records)
                if not inferred_os:
                    inferred_os = runtime_module.infer_os_from_service_inventory(service_records)
                if inferred_os and runtime_module.is_unknown_os_match(str(getattr(row, "osMatch", "") or "")):
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
            runtime_module.add_temporary_host_alias(str(host_ip or ""), alias_to_add)
        except Exception:
            pass


def queue_scheduler_approval(
        runtime,
        decision: ScheduledAction,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        command_template: str,
) -> int:
    runtime_module = _web_runtime_module()
    with runtime._lock:
        project = runtime._require_active_project()
        runtime_module.ensure_scheduler_approval_table(project.database)
        approval_id = runtime_module.queue_pending_approval(project.database, {
            "status": "pending",
            "host_ip": str(host_ip),
            "port": str(port),
            "protocol": str(protocol),
            "service": str(service_name),
            "tool_id": str(decision.tool_id),
            "label": str(decision.label),
            "command_template": str(command_template or ""),
            "command_family_id": str(decision.family_id),
            "danger_categories": ",".join(decision.danger_categories),
            "risk_tags": ",".join(decision.risk_tags),
            "scheduler_mode": str(decision.mode),
            "goal_profile": str(decision.goal_profile),
            "engagement_preset": str(decision.engagement_preset),
            "rationale": str(decision.rationale),
            "policy_decision": str(decision.policy_decision),
            "policy_reason": str(decision.policy_reason),
            "risk_summary": str(decision.risk_summary),
            "safer_alternative": str(decision.safer_alternative),
            "family_policy_state": str(decision.family_policy_state),
            "evidence_refs": ",".join(str(item) for item in list(decision.linked_evidence_refs or []) if str(item).strip()),
            "decision_reason": "pending approval",
            "execution_job_id": "",
        })
    runtime._emit_ui_invalidation("approvals", "overview")
    return approval_id


def record_scheduler_decision(
        runtime,
        decision: ScheduledAction,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        *,
        approved: bool,
        executed: bool,
        reason: str,
        approval_id: Optional[int] = None,
):
    runtime_module = _web_runtime_module()
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return
        runtime_module.log_scheduler_decision(project.database, {
            "timestamp": getTimestamp(True),
            "host_ip": str(host_ip),
            "port": str(port),
            "protocol": str(protocol),
            "service": str(service_name),
            "scheduler_mode": str(decision.mode),
            "goal_profile": str(decision.goal_profile),
            "engagement_preset": str(decision.engagement_preset),
            "tool_id": str(decision.tool_id),
            "label": str(decision.label),
            "command_family_id": str(decision.family_id),
            "danger_categories": ",".join(decision.danger_categories),
            "risk_tags": ",".join(decision.risk_tags),
            "requires_approval": "True" if decision.requires_approval else "False",
            "policy_decision": str(decision.policy_decision),
            "policy_reason": str(decision.policy_reason),
            "risk_summary": str(decision.risk_summary),
            "safer_alternative": str(decision.safer_alternative),
            "family_policy_state": str(decision.family_policy_state),
            "approved": "True" if approved else "False",
            "executed": "True" if executed else "False",
            "reason": str(reason),
            "rationale": str(decision.rationale),
            "approval_id": str(approval_id or ""),
        })
    runtime._emit_ui_invalidation("decisions")


def build_scheduler_credential_row(cls, tool_name: str, capture: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    _ = tool_name
    if not isinstance(capture, dict):
        return None
    details = str(capture.get("details", "") or "").strip()
    username_raw = str(capture.get("username", "") or "").strip()
    hash_value = str(capture.get("hash_value", "") or "").strip()
    realm, username = cls._split_credential_principal(username_raw)
    secret_ref = ""
    cred_type = ""
    if hash_value:
        secret_ref = hash_value[:240]
        cred_type = "ntlm_hash"
    else:
        cleartext = cls._extract_cleartext_password(details)
        if cleartext:
            secret_ref = cleartext[:240]
            cred_type = "cleartext_password"
    if not username and not secret_ref:
        return None
    if not cred_type:
        cred_type = "captured_credential"
    return {
        "username": username,
        "realm": realm,
        "secret_ref": secret_ref,
        "type": cred_type,
        "evidence": details[:280],
        "confidence": 88.0 if secret_ref else 72.0,
        "source_kind": "observed",
        "observed": True,
    }


def build_scheduler_session_row(cls, tool_name: str, capture: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    runtime_module = _web_runtime_module()
    if not isinstance(capture, dict):
        return None
    lowered_tool = str(tool_name or "").strip().lower()
    details = str(capture.get("details", "") or "").strip()
    if lowered_tool not in {"ntlmrelay", "ntlmrelayx"} or "authenticating against" not in details.lower():
        return None
    target = str(capture.get("source", "") or "").strip()
    target_host = cls._normalize_credential_capture_source(target)
    realm, username = cls._split_credential_principal(capture.get("username", ""))
    port = ""
    protocol = "tcp"
    try:
        parsed = runtime_module.urlparse(target)
        scheme = str(parsed.scheme or "").strip().lower()
        if scheme == "smb":
            port = str(parsed.port or 445)
        elif scheme in {"ldap", "ldaps", "http", "https"}:
            port = str(parsed.port or "")
    except Exception:
        pass
    if not username and not target_host:
        return None
    return {
        "session_type": "ntlm_relay_auth",
        "username": username,
        "host": target_host,
        "port": port,
        "protocol": protocol,
        "evidence": details[:280],
        "obtained_at": getTimestamp(True),
        "confidence": 82.0,
        "source_kind": "observed",
        "observed": True,
        "realm": realm,
    }


def extract_credential_capture_entries(
        cls,
        tool_name: str,
        line: Any,
        *,
        default_source: str = "",
        context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    stripped = str(line or "").strip()
    if not stripped:
        return []
    lowered_tool = str(tool_name or "").strip().lower()
    default_source_value = str(default_source or "").strip()
    state = context if isinstance(context, dict) else {}
    captures: List[Dict[str, Any]] = []

    if lowered_tool in {"ntlmrelay", "ntlmrelayx"}:
        auth_match = re.search(
            r"Authenticating against\s+(?P<target>\S+)\s+as\s+(?P<account>[^\s]+)\s+"
            r"(?P<result>SUCCEED|SUCCESS|SUCCEEDED|FAILED|FAIL(?:ED)?)\b",
            stripped,
            flags=re.IGNORECASE,
        )
        if auth_match:
            result = str(auth_match.group("result") or "").strip().lower()
            if result.startswith("suc"):
                captures.append({
                    "source": str(auth_match.group("target") or "").strip() or default_source_value,
                    "details": stripped,
                    "username": str(auth_match.group("account") or "").strip(),
                    "hash_value": "",
                })
                return captures

        sam_match = re.match(
            r"^(?P<account>[^:\s]+):(?P<rid>\d+):(?P<lm>[A-Fa-f0-9]{32}):(?P<nt>[A-Fa-f0-9]{32})(?:::.*)?$",
            stripped,
        )
        if sam_match:
            captures.append({
                "source": default_source_value,
                "details": stripped,
                "username": str(sam_match.group("account") or "").strip(),
                "hash_value": f"{sam_match.group('lm')}:{sam_match.group('nt')}",
            })
            return captures
        return []

    if lowered_tool == "responder":
        client_match = re.search(r"\bclient\s*:\s*(?P<source>\S+)", stripped, flags=re.IGNORECASE)
        if client_match:
            state["source"] = str(client_match.group("source") or "").strip()
            return []

        user_match = re.search(r"\busername\s*:\s*(?P<username>.+)$", stripped, flags=re.IGNORECASE)
        if user_match:
            state["username"] = str(user_match.group("username") or "").strip()
            return []

        hash_match = re.search(r"\bhash\s*:\s*(?P<hash>.+)$", stripped, flags=re.IGNORECASE)
        if hash_match:
            raw_hash = str(hash_match.group("hash") or "").strip()
            username, hash_value = cls._extract_credential_data(raw_hash)
            captures.append({
                "source": state.get("source", "") or default_source_value,
                "details": stripped,
                "username": state.get("username", "") or username,
                "hash_value": hash_value or raw_hash,
            })
            return captures

        cleartext_match = re.search(r"\bclear\s+text\s+password\s*:\s*(?P<password>.+)$", stripped, flags=re.IGNORECASE)
        if cleartext_match:
            captures.append({
                "source": state.get("source", "") or default_source_value,
                "details": stripped,
                "username": state.get("username", ""),
                "hash_value": "",
            })
            return captures

        if "::" in stripped:
            username, hash_value = cls._extract_credential_data(stripped)
            captures.append({
                "source": state.get("source", "") or default_source_value,
                "details": stripped,
                "username": state.get("username", "") or username,
                "hash_value": hash_value,
            })
            return captures
        return captures

    interests = ("ntlm", "hash", "relay", "captured", "credential")
    if (
            not any(keyword in stripped.lower() for keyword in interests)
            and "::" not in stripped
            and not re.search(r"from\s+[^:]+:\s*.+", stripped, re.IGNORECASE)
    ):
        return []
    username, hash_value = cls._extract_credential_data(stripped)
    captures.append({
        "source": default_source_value,
        "details": stripped,
        "username": username,
        "hash_value": hash_value,
    })
    return captures


def persist_credential_captures_to_scheduler(
        runtime,
        captures: List[Dict[str, Any]],
        *,
        tool_name: str = "",
        default_source: str = "",
):
    runtime_module = _web_runtime_module()
    if not isinstance(captures, list) or not captures:
        return
    project = getattr(runtime.logic, "activeProject", None)
    if project is None:
        return
    database = getattr(project, "database", None)
    host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
    if database is None or host_repo is None:
        return
    runtime_module.ensure_scheduler_target_state_table(database)
    default_source_token = runtime._normalize_credential_capture_source(default_source)
    grouped: Dict[int, Dict[str, Any]] = {}

    for capture in captures:
        if not isinstance(capture, dict):
            continue
        source_token = runtime._normalize_credential_capture_source(capture.get("source", "") or default_source_token)
        host_obj = None
        if source_token:
            host_obj = host_repo.getHostByIP(source_token) or host_repo.getHostByHostname(source_token)
        if host_obj is None and default_source_token:
            host_obj = host_repo.getHostByIP(default_source_token) or host_repo.getHostByHostname(default_source_token)
        if host_obj is None:
            continue
        host_id = int(getattr(host_obj, "id", 0) or 0)
        host_ip = str(getattr(host_obj, "ip", "") or source_token or default_source_token).strip()
        if host_id <= 0 or not host_ip:
            continue
        bucket = grouped.setdefault(host_id, {
            "host_ip": host_ip,
            "credentials": [],
            "sessions": [],
        })
        credential_row = runtime._build_scheduler_credential_row(tool_name, capture)
        if credential_row:
            bucket["credentials"].append(credential_row)
        session_row = runtime._build_scheduler_session_row(tool_name, capture)
        if session_row:
            bucket["sessions"].append(session_row)

    updated_at = getTimestamp(True)
    normalized_tool = str(tool_name or "").strip().lower()
    for host_id, payload in grouped.items():
        runtime_module.upsert_target_state(database, int(host_id), {
            "host_ip": str(payload.get("host_ip", "") or ""),
            "updated_at": updated_at,
            "credentials": list(payload.get("credentials", []) or []),
            "sessions": list(payload.get("sessions", []) or []),
            "raw": {
                "credential_capture_tools": [normalized_tool] if normalized_tool else [],
            },
        }, merge=True)


def persist_credential_capture_output(runtime, *, tool_name: str, output_text: str, default_source: str = ""):
    project = getattr(runtime.logic, "activeProject", None)
    if project is None:
        return
    repo = getattr(getattr(project, "repositoryContainer", None), "credentialRepository", None)
    if repo is None:
        return
    output_lines = str(output_text or "").splitlines()
    seen = set()
    capture_context: Dict[str, Any] = {}
    scheduler_captures: List[Dict[str, Any]] = []
    for line in output_lines:
        stripped = str(line or "").strip()
        if not stripped:
            continue
        captures = runtime._extract_credential_capture_entries(
            tool_name,
            stripped,
            default_source=str(default_source or ""),
            context=capture_context,
        )
        for capture in captures:
            dedupe_key = (
                str(capture.get("source", "") or ""),
                str(capture.get("username", "") or ""),
                str(capture.get("hash_value", "") or ""),
                str(capture.get("details", "") or ""),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            repo.storeCapture(
                str(tool_name or ""),
                capture.get("source", "") or "",
                capture.get("details", "") or stripped,
                username=capture.get("username", "") or "",
                hash_value=capture.get("hash_value", "") or "",
            )
            scheduler_captures.append(dict(capture))
    runtime._persist_credential_captures_to_scheduler(
        scheduler_captures,
        tool_name=str(tool_name or ""),
        default_source=str(default_source or ""),
    )


def is_placeholder_scheduler_text(value: Any) -> bool:
    token = str(value or "").strip().lower()
    if not token:
        return False
    if token in {"true", "false", "null", "none", "nil", "truncated", "...", "[truncated]", "...[truncated]"}:
        return True
    if "[truncated]" in token:
        trimmed = token.replace("...[truncated]", "").replace("[truncated]", "").strip(" .:-")
        return not trimmed or trimmed == "truncated"
    return token.endswith("...")


def infer_technologies_from_observations(
        runtime,
        *,
        service_records: List[Dict[str, Any]],
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 180,
) -> List[Dict[str, str]]:
    runtime_module = _web_runtime_module()
    rows: List[Dict[str, str]] = []
    seen = set()

    def _add(name: Any, version: Any, cpe: Any, evidence: Any):
        tech_name = str(name or "").strip()[:120]
        tech_cpe = runtime._normalize_cpe_token(cpe)
        tech_evidence = runtime._truncate_scheduler_text(evidence, 520)
        tech_version = runtime._sanitize_technology_version_for_tech(
            name=tech_name,
            version=version,
            cpe=tech_cpe,
            evidence=tech_evidence,
        )

        if not tech_name and tech_cpe:
            tech_name = runtime._name_from_cpe(tech_cpe)
        if not tech_version and tech_cpe:
            cpe_version = runtime._sanitize_technology_version_for_tech(
                name=tech_name,
                version=runtime._version_from_cpe(tech_cpe),
                cpe=tech_cpe,
                evidence=tech_evidence,
            )
            if cpe_version:
                tech_version = cpe_version
            else:
                tech_cpe = runtime._cpe_base(tech_cpe)

        if not tech_cpe:
            hinted_name, hinted_cpe = runtime._guess_technology_hint(tech_name, tech_version)
            if hinted_name and not tech_name:
                tech_name = hinted_name
            if hinted_cpe:
                tech_cpe = runtime._normalize_cpe_token(hinted_cpe)
                if tech_cpe and not tech_version:
                    tech_version = runtime._version_from_cpe(tech_cpe)

        if not tech_name and not tech_cpe:
            return
        if runtime._is_weak_technology_name(tech_name) and not tech_cpe:
            if not any(marker in tech_evidence.lower() for marker in runtime_module._TECH_STRONG_EVIDENCE_MARKERS):
                return

        quality = runtime._technology_quality_score(
            name=tech_name,
            version=tech_version,
            cpe=tech_cpe,
            evidence=tech_evidence,
        )
        if quality < 20:
            return
        key = "|".join([tech_name.lower(), tech_version.lower(), tech_cpe.lower()])
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "name": tech_name,
            "version": tech_version,
            "cpe": tech_cpe,
            "evidence": tech_evidence,
        })

    for record in service_records[:320]:
        if not isinstance(record, dict):
            continue
        service_name = str(record.get("service_name", "") or "").strip()
        product = str(record.get("service_product", "") or "").strip()
        version = str(record.get("service_version", "") or "").strip()
        extrainfo = str(record.get("service_extrainfo", "") or "").strip()
        banner = str(record.get("banner", "") or "").strip()
        port = str(record.get("port", "") or "").strip()
        protocol = str(record.get("protocol", "") or "").strip().lower()

        evidence_blob = " ".join([
            service_name,
            product,
            version,
            extrainfo,
            banner,
        ])
        cpes = runtime._extract_cpe_tokens(evidence_blob, limit=3)
        hinted_rows = runtime._guess_technology_hints(evidence_blob, version_hint=version)

        primary_name = product
        if not primary_name:
            service_token = service_name.lower()
            has_strong_context = bool(version or cpes or hinted_rows or banner or extrainfo)
            if (
                    service_name
                    and service_token not in runtime_module._GENERIC_TECH_NAME_TOKENS
                    and not runtime._is_weak_technology_name(service_name)
                    and has_strong_context
            ):
                primary_name = service_name
        if primary_name and primary_name.lower() not in {"unknown", "generic"}:
            _add(
                primary_name,
                version,
                cpes[0] if cpes else "",
                f"service {port}/{protocol} {service_name} {product} {version} {extrainfo}".strip(),
            )
        for hinted_name, hinted_cpe in hinted_rows:
            hinted_version = runtime._version_from_cpe(hinted_cpe) or version
            _add(
                hinted_name or primary_name,
                hinted_version,
                hinted_cpe or (cpes[0] if cpes else ""),
                f"service fingerprint {port}/{protocol}",
            )
        for token in cpes:
            _add("", "", token, f"service CPE {port}/{protocol}")
        if len(rows) >= int(limit):
            break

    for record in (script_records[:320] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
        output = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not output:
            continue
        analysis_output = runtime._technology_hint_source_text(source_id, output)
        parsed = extract_tool_observations(
            source_id,
            output,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("technologies", []) or [])[:24]:
            if not isinstance(item, dict):
                continue
            _add(
                item.get("name", ""),
                item.get("version", ""),
                item.get("cpe", ""),
                item.get("evidence", "") or f"{source_id} parsed output",
            )
        cpes = runtime._extract_cpe_tokens(analysis_output or output, limit=4)
        for token in cpes:
            _add("", "", token, f"{source_id} output CPE")
        hinted_rows = runtime._guess_technology_hints(analysis_output or output, version_hint=analysis_output or output)
        for hinted_name, hinted_cpe in hinted_rows:
            version = runtime._version_from_cpe(hinted_cpe)
            if not version:
                version = runtime._extract_version_near_tokens(analysis_output or output, [hinted_name])
            _add(
                hinted_name,
                version,
                hinted_cpe,
                f"{source_id} output fingerprint",
            )
        if len(rows) >= int(limit):
            break

    return normalize_ai_technologies(runtime, rows[:int(limit)])


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

    return infer_technologies_from_observations(
        runtime,
        service_records=service_records,
        script_records=script_records,
        process_records=process_records,
        limit=220,
    )


def normalize_ai_technologies(runtime, items: Any) -> List[Dict[str, str]]:
    runtime_module = _web_runtime_module()
    if not isinstance(items, list):
        return []
    best_rows: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()[:120]
        cpe = runtime._normalize_cpe_token(item.get("cpe", ""))
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 520)
        version = runtime._sanitize_technology_version_for_tech(
            name=name,
            version=item.get("version", ""),
            cpe=cpe,
            evidence=evidence,
        )
        if is_placeholder_scheduler_text(name) and not cpe:
            continue
        if is_placeholder_scheduler_text(version):
            version = ""
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not name and not cpe:
            continue
        if not name and cpe:
            name = runtime._name_from_cpe(cpe)
        if str(name or "").strip().lower() in runtime_module._PSEUDO_TECH_NAME_TOKENS and not cpe:
            continue
        if not version and cpe:
            cpe_version = runtime._sanitize_technology_version_for_tech(
                name=name,
                version=runtime._version_from_cpe(cpe),
                cpe=cpe,
                evidence=evidence,
            )
            if cpe_version:
                version = cpe_version
            else:
                cpe = runtime._cpe_base(cpe)
        if not cpe and name:
            hinted_name, hinted_cpe = runtime._guess_technology_hint(name, version)
            if hinted_name and not name:
                name = hinted_name
            if hinted_cpe:
                cpe = runtime._normalize_cpe_token(hinted_cpe)
                if cpe and not version:
                    version = runtime._version_from_cpe(cpe)

        if runtime._is_weak_technology_name(name) and not cpe:
            if not any(marker in evidence.lower() for marker in runtime_module._TECH_STRONG_EVIDENCE_MARKERS):
                continue

        quality = runtime._technology_quality_score(
            name=name,
            version=version,
            cpe=cpe,
            evidence=evidence,
        )
        if quality < 20:
            continue

        canonical = runtime._technology_canonical_key(name, cpe) or "|".join([name.lower(), version.lower(), cpe.lower()])
        candidate = {
            "name": name,
            "version": version,
            "cpe": cpe,
            "evidence": evidence,
            "_quality": quality,
        }
        current = best_rows.get(canonical)
        if current is None:
            best_rows[canonical] = candidate
            continue

        if int(candidate["_quality"]) > int(current.get("_quality", 0)):
            best_rows[canonical] = candidate
            continue
        if int(candidate["_quality"]) == int(current.get("_quality", 0)):
            current_version = str(current.get("version", "") or "")
            if len(version) > len(current_version):
                best_rows[canonical] = candidate
                continue
            if cpe and not str(current.get("cpe", "") or ""):
                best_rows[canonical] = candidate

    rows = sorted(
        list(best_rows.values()),
        key=lambda row: (
            -int(row.get("_quality", 0) or 0),
            str(row.get("name", "") or "").lower(),
            str(row.get("version", "") or "").lower(),
            str(row.get("cpe", "") or "").lower(),
        ),
    )
    trimmed: List[Dict[str, str]] = []
    for row in rows:
        trimmed.append({
            "name": str(row.get("name", "") or "")[:120],
            "version": str(row.get("version", "") or "")[:120],
            "cpe": str(row.get("cpe", "") or "")[:220],
            "evidence": runtime._truncate_scheduler_text(row.get("evidence", ""), 520),
        })
        if len(trimmed) >= 180:
            break
    return trimmed


def merge_technologies(
        runtime,
        *,
        existing: Any,
        incoming: Any,
        limit: int = 220,
) -> List[Dict[str, str]]:
    combined: List[Dict[str, Any]] = []
    if isinstance(incoming, list):
        for item in incoming:
            if isinstance(item, dict):
                combined.append(dict(item))
    if isinstance(existing, list):
        for item in existing:
            if isinstance(item, dict):
                combined.append(dict(item))
    rows = normalize_ai_technologies(runtime, combined)
    return rows[:int(limit)]


def infer_findings_from_observations(
        runtime,
        *,
        host_cves_raw: List[Dict[str, Any]],
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 220,
) -> List[Dict[str, Any]]:
    runtime_module = _web_runtime_module()
    rows: List[Dict[str, Any]] = []
    cve_index: Dict[str, Dict[str, Any]] = {}

    for row in host_cves_raw[:240]:
        if not isinstance(row, dict):
            continue
        cve_name = str(row.get("name", "") or "").strip().upper()
        matched = runtime_module._CVE_TOKEN_RE.search(cve_name)
        cve_id = matched.group(0).upper() if matched else ""
        severity = runtime._severity_from_text(row.get("severity", ""))
        product = str(row.get("product", "") or "").strip()
        version = str(row.get("version", "") or "").strip()
        url = str(row.get("url", "") or "").strip()
        title = cve_id or cve_name or f"Potential vulnerability in {product or 'service'}"
        evidence = " | ".join(part for part in [
            f"product={product}" if product else "",
            f"version={version}" if version else "",
            f"url={url}" if url else "",
        ] if part)
        rows.append({
            "title": title,
            "severity": severity,
            "cvss": 0.0,
            "cve": cve_id,
            "evidence": evidence or title,
        })
        if cve_id:
            cve_index[cve_id] = {
                "severity": severity,
                "evidence": evidence or title,
            }

    for record in (script_records[:360] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()[:80]
        excerpt = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not excerpt:
            continue
        cleaned_excerpt = runtime._observation_text_for_analysis(source_id, excerpt)
        parsed = extract_tool_observations(
            source_id,
            cleaned_excerpt or excerpt,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("findings", []) or [])[:32]:
            if not isinstance(item, dict):
                continue
            rows.append({
                "title": str(item.get("title", "") or ""),
                "severity": runtime._severity_from_text(item.get("severity", "info")),
                "cvss": 0.0,
                "cve": str(item.get("cve", "") or "").upper(),
                "evidence": runtime._truncate_scheduler_text(item.get("evidence", "") or cleaned_excerpt or excerpt, 420),
            })
        suppressed_cves = {
            str(item.get("cve", "") or "").strip().upper()
            for item in list(parsed.get("finding_quality_events", []) or [])
            if isinstance(item, dict) and str(item.get("action", "") or "").strip().lower() == "suppressed"
        }
        for cve_id, evidence_line in runtime._cve_evidence_lines(source_id, cleaned_excerpt or excerpt):
            if cve_id in suppressed_cves:
                continue
            mapped = cve_index.get(cve_id, {})
            severity = str(mapped.get("severity", "info") or "info")
            evidence = runtime._truncate_scheduler_text(
                f"{source_id}: {evidence_line}",
                420,
            )
            rows.append({
                "title": cve_id,
                "severity": severity,
                "cvss": 0.0,
                "cve": cve_id,
                "evidence": evidence,
            })

    normalized = normalize_ai_findings(runtime, rows)
    return normalized[:int(limit)]


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

    return infer_findings_from_observations(
        runtime,
        host_cves_raw=cves,
        script_records=script_records,
        process_records=process_records,
        limit=220,
    )


def infer_urls_from_observations(
        runtime,
        *,
        script_records: List[Dict[str, Any]],
        process_records: List[Dict[str, Any]],
        limit: int = 160,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for record in (script_records[:320] + process_records[:220]):
        if not isinstance(record, dict):
            continue
        source_id = str(record.get("script_id", "") or record.get("tool_id", "")).strip()
        output = str(
            record.get("analysis_excerpt", "")
            or record.get("excerpt", "")
            or record.get("output_excerpt", "")
        ).strip()
        if not output:
            continue
        parsed = extract_tool_observations(
            source_id,
            output,
            port=str(record.get("port", "") or ""),
            protocol=str(record.get("protocol", "tcp") or "tcp"),
            service=str(record.get("service", "") or ""),
            artifact_refs=list(record.get("artifact_refs", []) or []),
            host_ip=str(record.get("host_ip", "") or ""),
            hostname=str(record.get("hostname", "") or ""),
        )
        for item in list(parsed.get("urls", []) or [])[:32]:
            if not isinstance(item, dict):
                continue
            rows.append({
                "url": str(item.get("url", "") or ""),
                "port": str(item.get("port", "") or record.get("port", "") or ""),
                "protocol": str(item.get("protocol", "tcp") or record.get("protocol", "tcp") or "tcp"),
                "service": str(item.get("service", "") or record.get("service", "") or ""),
                "label": str(item.get("label", "") or source_id),
                "confidence": float(item.get("confidence", 90.0) or 90.0),
                "source_kind": str(item.get("source_kind", "observed") or "observed"),
                "observed": bool(item.get("observed", True)),
            })
        if len(rows) >= int(limit):
            break
    return rows[:int(limit)]


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
    return infer_urls_from_observations(
        runtime,
        script_records=script_records,
        process_records=process_records,
        limit=160,
    )


def normalize_ai_findings(runtime, items: Any) -> List[Dict[str, Any]]:
    runtime_module = _web_runtime_module()
    if not isinstance(items, list):
        return []
    allowed = {"critical", "high", "medium", "low", "info"}
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()[:260]
        severity = str(item.get("severity", "info")).strip().lower()
        if severity not in allowed:
            severity = "info"
        cve_id = str(item.get("cve", "")).strip()[:64]
        cvss_value = runtime._ai_confidence_value(item.get("cvss"))
        if cvss_value > 10.0:
            cvss_value = 10.0
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 640)
        if is_placeholder_scheduler_text(title) and not cve_id:
            continue
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not title and not cve_id:
            continue
        evidence_lower = str(evidence or "").strip().lower()
        if runtime_module._REFERENCE_ONLY_FINDING_RE.match(title) or evidence_lower in {"previous scan result", "previous tls scan result"}:
            continue
        key = "|".join([title.lower(), cve_id.lower(), severity])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "title": title or cve_id,
            "severity": severity,
            "cvss": cvss_value,
            "cve": cve_id,
            "evidence": evidence or title or cve_id,
        })
        if len(rows) >= 220:
            break
    rows.sort(key=lambda row: runtime._finding_sort_key(row), reverse=True)
    return rows


def normalize_ai_manual_tests(runtime, items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        why = runtime._truncate_scheduler_text(item.get("why", ""), 320)
        command = runtime._truncate_scheduler_text(item.get("command", ""), 520)
        scope_note = runtime._truncate_scheduler_text(item.get("scope_note", ""), 280)
        if not command and not why:
            continue
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "why": why,
            "command": command,
            "scope_note": scope_note,
        })
        if len(rows) >= 160:
            break
    return rows


def merge_ai_items(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for source in (incoming, existing):
        for item in source:
            if not isinstance(item, dict):
                continue
            key_parts = [str(item.get(field, "")).strip().lower() for field in key_fields]
            key = "|".join(key_parts)
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
            if len(merged) >= int(limit):
                return merged
    return merged


def coverage_gaps_from_summary(coverage: Any) -> List[Dict[str, Any]]:
    if not isinstance(coverage, dict):
        return []
    missing = coverage.get("missing", [])
    if not isinstance(missing, list):
        return []
    recommended = coverage.get("recommended_tool_ids", [])
    if not isinstance(recommended, list):
        recommended = []
    rows = []
    for gap_id in missing[:32]:
        token = str(gap_id or "").strip().lower()
        if not token:
            continue
        rows.append({
            "gap_id": token,
            "description": token.replace("_", " "),
            "recommended_tool_ids": list(recommended[:16]),
            "analysis_mode": str(coverage.get("analysis_mode", "") or "").strip().lower(),
            "stage": str(coverage.get("stage", "") or "").strip().lower(),
            "host_cve_count": int(coverage.get("host_cve_count", 0) or 0),
            "source_kind": "inferred",
            "observed": False,
        })
    return rows


def persist_shared_target_state(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str = "",
        protocol: str = "tcp",
        service_name: str = "",
        scheduler_mode: str = "",
        goal_profile: str = "",
        engagement_preset: str = "",
        provider: str = "",
        hostname: str = "",
        hostname_confidence: float = 0.0,
        os_match: str = "",
        os_confidence: float = 0.0,
        next_phase: str = "",
        technologies: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        manual_tests: Optional[List[Dict[str, Any]]] = None,
        service_inventory: Optional[List[Dict[str, Any]]] = None,
        urls: Optional[List[Dict[str, Any]]] = None,
        coverage: Optional[Dict[str, Any]] = None,
        attempted_action: Optional[Dict[str, Any]] = None,
        artifact_refs: Optional[List[str]] = None,
        screenshots: Optional[List[Dict[str, Any]]] = None,
        raw: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    runtime_module = _web_runtime_module()
    if int(host_id or 0) <= 0:
        return {}

    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return {}
        runtime_module.ensure_scheduler_target_state_table(project.database)
        host_obj = runtime._resolve_host(int(host_id))
        resolved_host_ip = str(host_ip or getattr(host_obj, "ip", "") or "")
        resolved_hostname = str(hostname or getattr(host_obj, "hostname", "") or "")
        resolved_os = str(os_match or getattr(host_obj, "osMatch", "") or "")
        if service_inventory is None:
            try:
                resolved_service_inventory = runtime_module.load_observed_service_inventory(project.database, int(host_id))
            except Exception:
                resolved_service_inventory = []
        else:
            resolved_service_inventory = list(service_inventory or [])
        resolved_urls = runtime_module.build_target_urls(resolved_host_ip, resolved_hostname, resolved_service_inventory)
        for item in list(urls or []):
            if isinstance(item, dict):
                resolved_urls.append(dict(item))
        coverage_gaps = coverage_gaps_from_summary(coverage)
        attempted_actions = [attempted_action] if isinstance(attempted_action, dict) and attempted_action else []
        artifact_entries = runtime_module.build_artifact_entries(
            list(artifact_refs or []),
            tool_id=str((attempted_action or {}).get("tool_id", "") or ""),
            port=str(port or ""),
            protocol=str(protocol or "tcp"),
        )
        screenshot_rows = []
        for item in list(screenshots or []):
            if not isinstance(item, dict):
                continue
            row = runtime_module.build_screenshot_state_row(
                artifact_ref=str(item.get("artifact_ref", "") or item.get("url", "") or "").strip(),
                metadata=item,
                port=str(item.get("port", "") or port or "").strip(),
                protocol=str(item.get("protocol", "") or protocol or "tcp").strip().lower(),
            )
            if row:
                screenshot_rows.append(row)
        for artifact in artifact_entries:
            if str(artifact.get("kind", "") or "").strip().lower() != "screenshot":
                continue
            artifact_ref = str(artifact.get("ref", "") or "").strip()
            row = runtime_module.build_screenshot_state_row(
                screenshot_path=artifact_ref,
                artifact_ref=artifact_ref,
                metadata=runtime_module.load_screenshot_metadata(artifact_ref),
                port=str(port or artifact.get("port", "") or "").strip(),
                protocol=str(protocol or artifact.get("protocol", "tcp") or "tcp").strip().lower(),
            )
            if row:
                screenshot_rows.append(row)

        payload = {
            "host_ip": resolved_host_ip,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "last_mode": str(scheduler_mode or ""),
            "provider": str(provider or ""),
            "goal_profile": str(goal_profile or ""),
            "engagement_preset": str(engagement_preset or ""),
            "last_port": str(port or ""),
            "last_protocol": str(protocol or "tcp"),
            "last_service": str(service_name or ""),
            "hostname": resolved_hostname,
            "hostname_confidence": float(hostname_confidence or 0.0),
            "hostname_source_kind": "observed" if resolved_hostname else "",
            "os_match": resolved_os,
            "os_confidence": float(os_confidence or 0.0),
            "os_source_kind": "observed" if resolved_os else "",
            "next_phase": str(next_phase or ""),
            "service_inventory": resolved_service_inventory,
            "urls": resolved_urls,
            "coverage_gaps": coverage_gaps,
            "attempted_actions": attempted_actions,
            "screenshots": screenshot_rows,
            "artifacts": [{"artifact_ref": row.get("ref", ""), **row} for row in artifact_entries],
            "raw": raw if isinstance(raw, dict) else {},
        }
        if technologies is not None:
            payload["technologies"] = list(technologies or [])
        if findings is not None:
            payload["findings"] = list(findings or [])
        if manual_tests is not None:
            payload["manual_tests"] = list(manual_tests or [])
        return runtime_module.upsert_target_state(project.database, int(host_id), payload, merge=True)


def load_host_ai_analysis(runtime, project, host_id: int, host_ip: str) -> Dict[str, Any]:
    runtime_module = _web_runtime_module()
    runtime_module.ensure_scheduler_ai_state_table(project.database)
    row = runtime_module.get_host_ai_state(project.database, int(host_id)) or {}
    raw = row.get("raw", {}) if isinstance(row.get("raw", {}), dict) else {}
    stored_technologies = row.get("technologies", [])
    stored_findings = row.get("findings", [])
    manual_tests = row.get("manual_tests", [])
    reflection = raw.get("reflection", {}) if isinstance(raw.get("reflection", {}), dict) else {}
    if not isinstance(stored_technologies, list):
        stored_technologies = []
    if not isinstance(stored_findings, list):
        stored_findings = []
    if not isinstance(manual_tests, list):
        manual_tests = []
    host_cves_raw = runtime._load_cves_for_host(project, int(host_id or 0))
    inferred_technologies = runtime._infer_host_technologies(project, int(host_id), str(host_ip or ""))
    inferred_findings = runtime._infer_host_findings(
        project,
        host_id=int(host_id),
        host_ip=str(host_ip or ""),
        host_cves_raw=host_cves_raw,
    )
    technologies = runtime._merge_technologies(
        existing=inferred_technologies,
        incoming=runtime._normalize_ai_technologies(stored_technologies),
        limit=240,
    )
    findings = runtime._merge_ai_items(
        existing=inferred_findings,
        incoming=runtime._normalize_ai_findings(stored_findings),
        key_fields=["title", "cve", "severity"],
        limit=260,
    )
    return {
        "host_id": int(host_id),
        "host_ip": str(row.get("host_ip", "") or host_ip or ""),
        "updated_at": str(row.get("updated_at", "") or ""),
        "provider": str(row.get("provider", "") or ""),
        "goal_profile": str(row.get("goal_profile", "") or ""),
        "last_target": {
            "port": str(row.get("last_port", "") or ""),
            "protocol": str(row.get("last_protocol", "") or ""),
            "service": str(row.get("last_service", "") or ""),
        },
        "host_updates": {
            "hostname": str(row.get("hostname", "") or ""),
            "hostname_confidence": runtime._ai_confidence_value(row.get("hostname_confidence", 0.0)),
            "os": str(row.get("os_match", "") or ""),
            "os_confidence": runtime._ai_confidence_value(row.get("os_confidence", 0.0)),
        },
        "next_phase": str(row.get("next_phase", "") or ""),
        "technologies": technologies,
        "findings": findings,
        "manual_tests": manual_tests,
        "reflection": reflection,
    }


def scan_history_targets(record: Dict[str, Any]) -> List[str]:
    if isinstance(record.get("targets"), list):
        values = [str(item or "").strip() for item in list(record.get("targets", [])) if str(item or "").strip()]
        if values:
            return values
    raw_targets = str(record.get("targets_json", "") or "").strip()
    if raw_targets:
        try:
            parsed = json.loads(raw_targets)
        except Exception:
            parsed = []
        if isinstance(parsed, list):
            values = [str(item or "").strip() for item in parsed if str(item or "").strip()]
            if values:
                return values
    fallback: List[str] = []
    for source in (record.get("scope_summary", ""), record.get("target_summary", "")):
        for token in re.findall(r"[A-Za-z0-9./:-]+", str(source or "")):
            cleaned = str(token or "").strip(",:")
            if cleaned and cleaned not in fallback:
                fallback.append(cleaned)
    return fallback
