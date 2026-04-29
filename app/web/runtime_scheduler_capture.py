from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.scheduler.approvals import ensure_scheduler_approval_table, queue_pending_approval
from app.scheduler.audit import log_scheduler_decision
from app.scheduler.planner import ScheduledAction
from app.scheduler.state import ensure_scheduler_target_state_table, upsert_target_state
from app.timing import getTimestamp


def queue_scheduler_approval(
        runtime,
        decision: ScheduledAction,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        command_template: str,
) -> int:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_approval_table(project.database)
        approval_id = queue_pending_approval(project.database, {
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
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return
        log_scheduler_decision(project.database, {
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
        parsed = urlparse(target)
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
    if not isinstance(captures, list) or not captures:
        return
    project = getattr(runtime.logic, "activeProject", None)
    if project is None:
        return
    database = getattr(project, "database", None)
    host_repo = getattr(getattr(project, "repositoryContainer", None), "hostRepository", None)
    if database is None or host_repo is None:
        return
    ensure_scheduler_target_state_table(database)
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
        upsert_target_state(database, int(host_id), {
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
