import datetime
import json
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.policy import preset_from_legacy_goal_profile
from app.url_normalization import normalize_discovered_url


WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}
TARGET_SOURCE_KINDS = {"observed", "inferred", "ai_suggested", "user_entered"}
_REFERENCE_ONLY_FINDING_RE = re.compile(
    r"^(?:https?://|//|bid:\d+\s+cve:cve-\d{4}-\d+|cve:cve-\d{4}-\d+)",
    flags=re.IGNORECASE,
)
_LOW_SIGNAL_FINDING_EVIDENCE = {
    "previous scan result",
    "previous tls scan result",
}
_FINDING_QUALITY_ACTIONS = {"suppressed", "downgraded"}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _ensure_target_state_table(session):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS scheduler_target_state ("
        "host_id INTEGER PRIMARY KEY,"
        "host_ip TEXT,"
        "updated_at TEXT,"
        "state_version INTEGER,"
        "last_mode TEXT,"
        "provider TEXT,"
        "goal_profile TEXT,"
        "engagement_preset TEXT,"
        "last_port TEXT,"
        "last_protocol TEXT,"
        "last_service TEXT,"
        "hostname TEXT,"
        "hostname_confidence REAL,"
        "hostname_source_kind TEXT,"
        "os_match TEXT,"
        "os_confidence REAL,"
        "os_source_kind TEXT,"
        "next_phase TEXT,"
        "technologies_json TEXT,"
        "findings_json TEXT,"
        "manual_tests_json TEXT,"
        "service_inventory_json TEXT,"
        "urls_json TEXT,"
        "coverage_gaps_json TEXT,"
        "attempted_actions_json TEXT,"
        "credentials_json TEXT,"
        "sessions_json TEXT,"
        "screenshots_json TEXT,"
        "artifacts_json TEXT,"
        "raw_json TEXT"
        ")"
    ))
    _ensure_column(session, "scheduler_target_state", "host_ip", "TEXT")
    _ensure_column(session, "scheduler_target_state", "updated_at", "TEXT")
    _ensure_column(session, "scheduler_target_state", "state_version", "INTEGER")
    _ensure_column(session, "scheduler_target_state", "last_mode", "TEXT")
    _ensure_column(session, "scheduler_target_state", "provider", "TEXT")
    _ensure_column(session, "scheduler_target_state", "goal_profile", "TEXT")
    _ensure_column(session, "scheduler_target_state", "engagement_preset", "TEXT")
    _ensure_column(session, "scheduler_target_state", "last_port", "TEXT")
    _ensure_column(session, "scheduler_target_state", "last_protocol", "TEXT")
    _ensure_column(session, "scheduler_target_state", "last_service", "TEXT")
    _ensure_column(session, "scheduler_target_state", "hostname", "TEXT")
    _ensure_column(session, "scheduler_target_state", "hostname_confidence", "REAL")
    _ensure_column(session, "scheduler_target_state", "hostname_source_kind", "TEXT")
    _ensure_column(session, "scheduler_target_state", "os_match", "TEXT")
    _ensure_column(session, "scheduler_target_state", "os_confidence", "REAL")
    _ensure_column(session, "scheduler_target_state", "os_source_kind", "TEXT")
    _ensure_column(session, "scheduler_target_state", "next_phase", "TEXT")
    _ensure_column(session, "scheduler_target_state", "technologies_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "findings_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "manual_tests_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "service_inventory_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "urls_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "coverage_gaps_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "attempted_actions_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "credentials_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "sessions_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "screenshots_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "artifacts_json", "TEXT")
    _ensure_column(session, "scheduler_target_state", "raw_json", "TEXT")


def _as_json(value: Any, fallback: Any) -> str:
    try:
        return json.dumps(value if value is not None else fallback, ensure_ascii=False)
    except Exception:
        return json.dumps(fallback, ensure_ascii=False)


def _from_json(value: Any, fallback: Any):
    raw = str(value or "").strip()
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


def _safe_float(value: Any, default: float = 0.0, minimum: float = 0.0, maximum: float = 100.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = float(default)
    if parsed < minimum:
        return float(minimum)
    if parsed > maximum:
        return float(maximum)
    return float(parsed)


def _normalize_source_kind(value: Any, default: str = "observed") -> str:
    token = str(value or default or "observed").strip().lower()
    if token not in TARGET_SOURCE_KINDS:
        return str(default or "observed")
    return token


def _merge_rows(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for source in (incoming, existing):
        for item in list(source or []):
            if not isinstance(item, dict):
                continue
            key = "|".join(str(item.get(field, "")).strip().lower() for field in key_fields)
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
            if len(merged) >= int(limit):
                return merged
    return merged


def _normalize_technologies(items: Any, default_source: str = "observed") -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()[:120]
        version = str(item.get("version", "") or "").strip()[:80]
        cpe = str(item.get("cpe", "") or "").strip()[:180]
        evidence = str(item.get("evidence", "") or "").strip()[:280]
        if not name and not cpe:
            continue
        rows.append({
            "name": name,
            "version": version,
            "cpe": cpe,
            "evidence": evidence,
            "confidence": _safe_float(item.get("confidence", 82.0 if cpe else 68.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", default_source), default_source),
            "observed": bool(item.get("observed", _normalize_source_kind(item.get("source_kind", default_source), default_source) == "observed")),
        })
    return _merge_rows([], rows, key_fields=["name", "version", "cpe"], limit=240)


def _normalize_findings(items: Any, default_source: str = "observed") -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "") or "").strip()[:220]
        severity = str(item.get("severity", "info") or "info").strip().lower()[:16]
        cve = str(item.get("cve", "") or "").strip()[:64]
        evidence = str(item.get("evidence", "") or "").strip()[:320]
        if not title and not cve:
            continue
        if _REFERENCE_ONLY_FINDING_RE.match(title) or str(evidence or "").strip().lower() in _LOW_SIGNAL_FINDING_EVIDENCE:
            continue
        try:
            cvss_value = float(item.get("cvss", 0.0) or 0.0)
        except (TypeError, ValueError):
            cvss_value = 0.0
        evidence_items = [
            str(token or "").strip()[:160]
            for token in list(item.get("evidence_items", []) or [])
            if str(token or "").strip()
        ][:16]
        row = {
            "title": title,
            "severity": severity,
            "cvss": cvss_value,
            "cve": cve,
            "evidence": evidence,
            "confidence": _safe_float(item.get("confidence", 88.0 if cve else 72.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", default_source), default_source),
            "observed": bool(item.get("observed", _normalize_source_kind(item.get("source_kind", default_source), default_source) == "observed")),
        }
        if evidence_items:
            row["evidence_items"] = evidence_items
        quality_action = str(item.get("quality_action", "") or "").strip().lower()[:16]
        quality_reason = str(item.get("quality_reason", "") or "").strip().lower()[:96]
        if quality_action in _FINDING_QUALITY_ACTIONS and quality_reason:
            row["quality_action"] = quality_action
            row["quality_reason"] = quality_reason
            severity_before = str(item.get("severity_before", "") or "").strip().lower()[:16]
            if quality_action == "downgraded" and severity_before:
                row["severity_before"] = severity_before
        rows.append(row)
    return _merge_rows([], rows, key_fields=["title", "cve", "severity"], limit=260)


def _normalize_finding_quality_events(items: Any, default_source: str = "observed") -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", item.get("quality_action", "")) or "").strip().lower()[:16]
        reason = str(item.get("reason", item.get("quality_reason", "")) or "").strip().lower()[:96]
        title = str(item.get("title", "") or "").strip()[:220]
        cve = str(item.get("cve", "") or "").strip()[:64]
        evidence = str(item.get("evidence", "") or "").strip()[:320]
        matched_url = normalize_discovered_url(item.get("matched_url", ""))[:320]
        if action not in _FINDING_QUALITY_ACTIONS or not reason:
            continue
        if not any([title, cve, evidence, matched_url]):
            continue
        row = {
            "title": title,
            "cve": cve,
            "action": action,
            "reason": reason,
            "severity_before": str(item.get("severity_before", "") or "").strip().lower()[:16],
            "severity_after": str(item.get("severity_after", "") or "").strip().lower()[:16],
            "evidence": evidence,
            "matched_url": matched_url,
            "confidence": _safe_float(item.get("confidence", 82.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", default_source), default_source),
            "observed": bool(item.get("observed", _normalize_source_kind(item.get("source_kind", default_source), default_source) == "observed")),
        }
        rows.append(row)
    return _merge_rows([], rows, key_fields=["title", "cve", "action", "reason", "evidence", "matched_url"], limit=260)


def _normalize_manual_tests(items: Any, default_source: str = "ai_suggested") -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        why = str(item.get("why", "") or "").strip()[:220]
        command = str(item.get("command", "") or "").strip()[:520]
        scope_note = str(item.get("scope_note", "") or "").strip()[:220]
        if not command and not why:
            continue
        rows.append({
            "why": why,
            "command": command,
            "scope_note": scope_note,
            "confidence": _safe_float(item.get("confidence", 65.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", default_source), default_source),
            "observed": bool(item.get("observed", False)),
        })
    return _merge_rows([], rows, key_fields=["command", "why"], limit=200)


def _normalize_service_inventory(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rows.append({
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "tcp") or "tcp").strip().lower()[:12],
            "state": str(item.get("state", "") or "").strip().lower()[:32],
            "service": str(item.get("service", "") or item.get("service_name", "") or "").strip()[:64],
            "service_product": str(item.get("service_product", "") or "").strip()[:120],
            "service_version": str(item.get("service_version", "") or "").strip()[:80],
            "service_extrainfo": str(item.get("service_extrainfo", "") or "").strip()[:120],
            "banner": str(item.get("banner", "") or "").strip()[:280],
            "confidence": _safe_float(item.get("confidence", 95.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    return _merge_rows([], rows, key_fields=["port", "protocol", "service"], limit=320)


def _normalize_urls(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = normalize_discovered_url(item.get("url", ""))
        if not url:
            continue
        rows.append({
            "url": url[:320],
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "tcp") or "tcp").strip().lower()[:12],
            "service": str(item.get("service", "") or "").strip()[:64],
            "label": str(item.get("label", "") or "").strip()[:120],
            "confidence": _safe_float(item.get("confidence", 90.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    rows.sort(key=lambda item: (
        0 if str(item.get("port", "") or "").strip() else 1,
        0 if str(item.get("service", "") or "").strip() else 1,
        -float(item.get("confidence", 0.0) or 0.0),
        str(item.get("url", "") or ""),
    ))
    return _merge_rows([], rows, key_fields=["url"], limit=240)


def _normalize_coverage_gaps(items: Any) -> List[Dict[str, Any]]:
    rows = []
    if isinstance(items, dict):
        missing = items.get("missing", [])
        recommended = items.get("recommended_tool_ids", [])
        analysis_mode = str(items.get("analysis_mode", "") or "").strip().lower()[:24]
        stage = str(items.get("stage", "") or "").strip().lower()[:32]
        host_cve_count = int(items.get("host_cve_count", 0) or 0)
        items = [
            {
                "gap_id": str(gap or "").strip().lower(),
                "description": str(gap or "").strip().replace("_", " "),
                "recommended_tool_ids": list(recommended or []),
                "analysis_mode": analysis_mode,
                "stage": stage,
                "host_cve_count": host_cve_count,
            }
            for gap in list(missing or [])
            if str(gap or "").strip()
        ]
    if not isinstance(items, list):
        return []
    for item in items:
        if isinstance(item, str):
            item = {"gap_id": str(item).strip().lower(), "description": str(item).strip().replace("_", " ")}
        if not isinstance(item, dict):
            continue
        gap_id = str(item.get("gap_id", "") or "").strip().lower()[:96]
        if not gap_id:
            continue
        recommended = [
            str(token or "").strip().lower()[:80]
            for token in list(item.get("recommended_tool_ids", []) or [])
            if str(token or "").strip()
        ]
        rows.append({
            "gap_id": gap_id,
            "description": str(item.get("description", "") or gap_id.replace("_", " ")).strip()[:220],
            "recommended_tool_ids": recommended[:16],
            "analysis_mode": str(item.get("analysis_mode", "") or "").strip().lower()[:24],
            "stage": str(item.get("stage", "") or "").strip().lower()[:32],
            "host_cve_count": int(item.get("host_cve_count", 0) or 0),
            "confidence": _safe_float(item.get("confidence", 72.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "inferred"), "inferred"),
            "observed": bool(item.get("observed", False)),
        })
    return _merge_rows([], rows, key_fields=["gap_id"], limit=64)


def _normalize_attempted_actions(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id", "") or "").strip()[:96]
        if not tool_id:
            continue
        rows.append({
            "tool_id": tool_id,
            "label": str(item.get("label", "") or tool_id).strip()[:140],
            "action_id": str(item.get("action_id", "") or tool_id).strip()[:120],
            "family_id": str(item.get("family_id", "") or "").strip()[:160],
            "command_signature": str(item.get("command_signature", "") or "").strip()[:160],
            "status": str(item.get("status", "") or "").strip().lower()[:32],
            "attempted_at": str(item.get("attempted_at", "") or _utc_now()).strip()[:64],
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "tcp") or "tcp").strip().lower()[:12],
            "service": str(item.get("service", "") or "").strip()[:64],
            "origin_mode": str(item.get("origin_mode", "") or "").strip().lower()[:24],
            "approval_state": str(item.get("approval_state", "") or "").strip().lower()[:32],
            "reason": str(item.get("reason", "") or "").strip()[:320],
            "coverage_gap": str(item.get("coverage_gap", "") or "").strip().lower()[:96],
            "pack_ids": [
                str(token or "").strip().lower()[:64]
                for token in list(item.get("pack_ids", []) or [])
                if str(token or "").strip()
            ][:8],
            "artifact_refs": [
                str(token or "").strip()[:320]
                for token in list(item.get("artifact_refs", []) or [])
                if str(token or "").strip()
            ][:12],
            "confidence": _safe_float(item.get("confidence", 94.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    return _merge_rows([], rows, key_fields=["tool_id", "status", "port", "protocol", "attempted_at"], limit=360)


def _normalize_credentials(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username", "") or "").strip()[:160]
        secret_ref = str(item.get("secret_ref", "") or "").strip()[:240]
        realm = str(item.get("realm", "") or "").strip()[:160]
        if not username and not secret_ref:
            continue
        rows.append({
            "username": username,
            "secret_ref": secret_ref,
            "realm": realm,
            "type": str(item.get("type", "") or "").strip()[:64],
            "evidence": str(item.get("evidence", "") or "").strip()[:280],
            "confidence": _safe_float(item.get("confidence", 75.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    return _merge_rows([], rows, key_fields=["username", "realm", "type", "secret_ref"], limit=160)


def _normalize_sessions(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        session_type = str(item.get("session_type", "") or "").strip()[:64]
        username = str(item.get("username", "") or "").strip()[:160]
        host = str(item.get("host", "") or "").strip()[:160]
        if not any([session_type, username, host]):
            continue
        rows.append({
            "session_type": session_type,
            "username": username,
            "host": host,
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "") or "").strip().lower()[:12],
            "evidence": str(item.get("evidence", "") or "").strip()[:280],
            "obtained_at": str(item.get("obtained_at", "") or "").strip()[:64],
            "confidence": _safe_float(item.get("confidence", 78.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    return _merge_rows([], rows, key_fields=["session_type", "username", "host", "port", "protocol"], limit=160)


def _normalize_screenshots(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        artifact_ref = str(item.get("artifact_ref", "") or item.get("ref", "") or item.get("url", "") or "").strip()[:320]
        filename = str(item.get("filename", "") or "").strip()[:200]
        if not artifact_ref and not filename:
            continue
        row = {
            "artifact_ref": artifact_ref,
            "filename": filename,
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "tcp") or "tcp").strip().lower()[:12],
            "confidence": _safe_float(item.get("confidence", 96.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        }
        optional_fields = {
            "target_url": 320,
            "capture_engine": 80,
            "capture_reason": 160,
            "captured_at": 64,
            "service_name": 64,
            "hostname": 160,
        }
        for field, limit in optional_fields.items():
            value = str(item.get(field, "") or "").strip()[:limit]
            if value:
                row[field] = value
        rows.append(row)
    return _merge_rows([], rows, key_fields=["artifact_ref", "filename", "port", "protocol"], limit=160)


def _normalize_artifacts(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ref = str(item.get("ref", "") or item.get("artifact_ref", "") or "").strip()[:320]
        if not ref:
            continue
        rows.append({
            "ref": ref,
            "kind": str(item.get("kind", "") or "").strip().lower()[:64],
            "tool_id": str(item.get("tool_id", "") or "").strip()[:96],
            "port": str(item.get("port", "") or "").strip()[:20],
            "protocol": str(item.get("protocol", "tcp") or "tcp").strip().lower()[:12],
            "confidence": _safe_float(item.get("confidence", 90.0)),
            "source_kind": _normalize_source_kind(item.get("source_kind", "observed"), "observed"),
            "observed": bool(item.get("observed", True)),
        })
    return _merge_rows([], rows, key_fields=["ref", "kind", "tool_id", "port", "protocol"], limit=240)


def build_target_urls(host_ip: str, hostname: str, service_inventory: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    preferred_hosts = []
    for token in [str(hostname or "").strip(), str(host_ip or "").strip()]:
        if token and token not in preferred_hosts:
            preferred_hosts.append(token)
    for item in list(service_inventory or []):
        if not isinstance(item, dict):
            continue
        service_name = str(item.get("service", "") or "").strip().lower()
        if service_name not in WEB_SERVICE_IDS:
            continue
        port = str(item.get("port", "") or "").strip()
        protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower()
        scheme = "https" if service_name in {"https", "ssl", "https-alt"} else "http"
        for host in preferred_hosts[:2]:
            url = f"{scheme}://{host}"
            if port and port not in {"80", "443"}:
                url = f"{url}:{port}"
            candidates.append({
                "url": url,
                "port": port,
                "protocol": protocol,
                "service": service_name,
                "label": f"{service_name} base URL",
                "source_kind": "observed",
                "observed": True,
            })
    return _normalize_urls(candidates)


def load_observed_service_inventory(database, host_id: int) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_target_state_table(session)
        result = session.execute(text(
            "SELECT COALESCE(p.portId, '') AS port, "
            "COALESCE(p.protocol, 'tcp') AS protocol, "
            "COALESCE(p.state, '') AS state, "
            "COALESCE(s.name, '') AS service, "
            "COALESCE(s.product, '') AS service_product, "
            "COALESCE(s.version, '') AS service_version, "
            "COALESCE(s.extrainfo, '') AS service_extrainfo "
            "FROM portObj AS p "
            "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
            "WHERE p.hostId = :host_id "
            "ORDER BY p.id ASC"
        ), {"host_id": int(host_id or 0)})
        rows = result.fetchall()
        keys = result.keys()
        return _normalize_service_inventory([dict(zip(keys, row)) for row in rows])
    finally:
        session.close()


def build_attempted_action_entry(
        *,
        decision,
        status: str,
        reason: str,
        attempted_at: str,
        port: str,
        protocol: str,
        service: str,
        family_id: str = "",
        command_signature: str = "",
        artifact_refs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "tool_id": str(getattr(decision, "tool_id", "") or ""),
        "label": str(getattr(decision, "label", "") or getattr(decision, "tool_id", "") or ""),
        "action_id": str(getattr(decision, "action_id", "") or getattr(decision, "tool_id", "") or ""),
        "family_id": str(family_id or getattr(decision, "family_id", "") or ""),
        "command_signature": str(command_signature or ""),
        "status": str(status or "").strip().lower(),
        "attempted_at": str(attempted_at or _utc_now()),
        "port": str(port or ""),
        "protocol": str(protocol or "tcp"),
        "service": str(service or ""),
        "origin_mode": str(getattr(decision, "mode", "") or ""),
        "approval_state": str(getattr(decision, "approval_state", "") or ""),
        "reason": str(reason or ""),
        "coverage_gap": str(getattr(decision, "coverage_gap", "") or ""),
        "pack_ids": list(getattr(decision, "pack_ids", []) or []),
        "artifact_refs": list(artifact_refs or []),
        "source_kind": "observed",
        "observed": True,
    }


def build_artifact_entries(
        artifact_refs: List[str],
        *,
        tool_id: str,
        port: str,
        protocol: str,
) -> List[Dict[str, Any]]:
    rows = []
    for ref in list(artifact_refs or []):
        token = str(ref or "").strip()
        if not token:
            continue
        kind = "screenshot" if token.lower().endswith(".png") else "artifact"
        rows.append({
            "ref": token,
            "kind": kind,
            "tool_id": str(tool_id or ""),
            "port": str(port or ""),
            "protocol": str(protocol or "tcp"),
            "source_kind": "observed",
            "observed": True,
        })
    return _normalize_artifacts(rows)


def ensure_scheduler_target_state_table(database):
    session = database.session()
    try:
        _ensure_target_state_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def _fetch_target_state_row(database, host_id: int) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_target_state_table(session)
        result = session.execute(text(
            "SELECT host_id, host_ip, updated_at, state_version, last_mode, provider, goal_profile, engagement_preset, "
            "last_port, last_protocol, last_service, hostname, hostname_confidence, hostname_source_kind, "
            "os_match, os_confidence, os_source_kind, next_phase, technologies_json, findings_json, manual_tests_json, "
            "service_inventory_json, urls_json, coverage_gaps_json, attempted_actions_json, credentials_json, "
            "sessions_json, screenshots_json, artifacts_json, raw_json "
            "FROM scheduler_target_state WHERE host_id = :host_id LIMIT 1"
        ), {"host_id": int(host_id or 0)})
        row = result.fetchone()
        if row is None:
            return None
        payload = dict(zip(result.keys(), row))
        payload["technologies"] = _from_json(payload.get("technologies_json"), [])
        payload["findings"] = _from_json(payload.get("findings_json"), [])
        payload["manual_tests"] = _from_json(payload.get("manual_tests_json"), [])
        payload["service_inventory"] = _from_json(payload.get("service_inventory_json"), [])
        payload["urls"] = _from_json(payload.get("urls_json"), [])
        payload["coverage_gaps"] = _from_json(payload.get("coverage_gaps_json"), [])
        payload["attempted_actions"] = _from_json(payload.get("attempted_actions_json"), [])
        payload["credentials"] = _from_json(payload.get("credentials_json"), [])
        payload["sessions"] = _from_json(payload.get("sessions_json"), [])
        payload["screenshots"] = _from_json(payload.get("screenshots_json"), [])
        payload["artifacts"] = _from_json(payload.get("artifacts_json"), [])
        payload["raw"] = _from_json(payload.get("raw_json"), {})
        raw_quality_events = payload["raw"].get("finding_quality_events", []) if isinstance(payload.get("raw", {}), dict) else []
        payload["finding_quality_events"] = _normalize_finding_quality_events(raw_quality_events, default_source="observed")
        return payload
    finally:
        session.close()


def target_state_to_legacy_ai_state(target_state: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(target_state, dict) or not target_state:
        return None
    return {
        "host_id": int(target_state.get("host_id", 0) or 0),
        "host_ip": str(target_state.get("host_ip", "") or ""),
        "updated_at": str(target_state.get("updated_at", "") or ""),
        "provider": str(target_state.get("provider", "") or ""),
        "goal_profile": str(target_state.get("goal_profile", "") or ""),
        "last_port": str(target_state.get("last_port", "") or ""),
        "last_protocol": str(target_state.get("last_protocol", "") or ""),
        "last_service": str(target_state.get("last_service", "") or ""),
        "hostname": str(target_state.get("hostname", "") or ""),
        "hostname_confidence": _safe_float(target_state.get("hostname_confidence", 0.0)),
        "os_match": str(target_state.get("os_match", "") or ""),
        "os_confidence": _safe_float(target_state.get("os_confidence", 0.0)),
        "next_phase": str(target_state.get("next_phase", "") or ""),
        "technologies": _normalize_technologies(target_state.get("technologies", []), default_source="observed"),
        "findings": _normalize_findings(target_state.get("findings", []), default_source="observed"),
        "finding_quality_events": _normalize_finding_quality_events(target_state.get("finding_quality_events", []), default_source="observed"),
        "manual_tests": _normalize_manual_tests(target_state.get("manual_tests", []), default_source="ai_suggested"),
        "raw": target_state.get("raw", {}) if isinstance(target_state.get("raw", {}), dict) else {},
    }


def legacy_ai_payload_to_target_state(host_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    goal_profile = str(payload.get("goal_profile", "") or "").strip()
    engagement_preset = str(payload.get("engagement_preset", "") or "").strip().lower()
    provider = str(payload.get("provider", "") or "").strip()
    explicit_mode = str(payload.get("last_mode", "") or "").strip().lower()
    resolved_mode = explicit_mode or ("ai" if provider else "deterministic")
    default_source = "ai_suggested" if resolved_mode == "ai" else "observed"
    if not engagement_preset and goal_profile:
        try:
            engagement_preset = preset_from_legacy_goal_profile(goal_profile)
        except Exception:
            engagement_preset = ""
    raw_payload = payload.get("raw", {}) if isinstance(payload.get("raw", {}), dict) else {}
    finding_quality_events = _normalize_finding_quality_events(
        payload.get("finding_quality_events", raw_payload.get("finding_quality_events", [])),
        default_source=default_source,
    )
    if finding_quality_events:
        raw_payload = dict(raw_payload)
        raw_payload["finding_quality_events"] = finding_quality_events
    return {
        "host_id": int(host_id or 0),
        "host_ip": str(payload.get("host_ip", "") or ""),
        "updated_at": str(payload.get("updated_at", "") or _utc_now()),
        "state_version": 1,
        "last_mode": resolved_mode,
        "provider": provider,
        "goal_profile": goal_profile,
        "engagement_preset": engagement_preset,
        "last_port": str(payload.get("last_port", "") or ""),
        "last_protocol": str(payload.get("last_protocol", "") or ""),
        "last_service": str(payload.get("last_service", "") or ""),
        "hostname": str(payload.get("hostname", "") or ""),
        "hostname_confidence": _safe_float(payload.get("hostname_confidence", 0.0)),
        "hostname_source_kind": _normalize_source_kind(
            payload.get("hostname_source_kind", default_source),
            default_source,
        ) if str(payload.get("hostname", "") or "").strip() else "",
        "os_match": str(payload.get("os_match", "") or ""),
        "os_confidence": _safe_float(payload.get("os_confidence", 0.0)),
        "os_source_kind": _normalize_source_kind(
            payload.get("os_source_kind", default_source),
            default_source,
        ) if str(payload.get("os_match", "") or "").strip() else "",
        "next_phase": str(payload.get("next_phase", "") or ""),
        "technologies": _normalize_technologies(payload.get("technologies", []), default_source=default_source),
        "findings": _normalize_findings(payload.get("findings", []), default_source=default_source),
        "manual_tests": _normalize_manual_tests(payload.get("manual_tests", []), default_source=default_source),
        "service_inventory": _normalize_service_inventory(payload.get("service_inventory", [])),
        "urls": _normalize_urls(payload.get("urls", [])),
        "coverage_gaps": _normalize_coverage_gaps(payload.get("coverage_gaps", [])),
        "attempted_actions": _normalize_attempted_actions(payload.get("attempted_actions", [])),
        "credentials": _normalize_credentials(payload.get("credentials", [])),
        "sessions": _normalize_sessions(payload.get("sessions", [])),
        "screenshots": _normalize_screenshots(payload.get("screenshots", [])),
        "artifacts": _normalize_artifacts(payload.get("artifacts", [])),
        "raw": raw_payload,
    }


def migrate_legacy_ai_state_to_target_state(database, host_id: Optional[int] = None) -> int:
    session = database.session()
    migrated = 0
    migrated_host_ids: List[int] = []
    try:
        _ensure_target_state_table(session)
        session.execute(text(
            "CREATE TABLE IF NOT EXISTS scheduler_host_ai_state ("
            "host_id INTEGER PRIMARY KEY,"
            "host_ip TEXT,"
            "updated_at TEXT,"
            "provider TEXT,"
            "goal_profile TEXT,"
            "last_port TEXT,"
            "last_protocol TEXT,"
            "last_service TEXT,"
            "hostname TEXT,"
            "hostname_confidence REAL,"
            "os_match TEXT,"
            "os_confidence REAL,"
            "next_phase TEXT,"
            "technologies_json TEXT,"
            "findings_json TEXT,"
            "manual_tests_json TEXT,"
            "raw_json TEXT"
            ")"
        ))
        query = (
            "SELECT host_id, host_ip, updated_at, provider, goal_profile, last_port, last_protocol, last_service, "
            "hostname, hostname_confidence, os_match, os_confidence, next_phase, technologies_json, findings_json, "
            "manual_tests_json, raw_json "
            "FROM scheduler_host_ai_state"
        )
        params: Dict[str, Any] = {}
        if host_id is not None:
            query += " WHERE host_id = :host_id"
            params["host_id"] = int(host_id or 0)
        rows = session.execute(text(query), params).fetchall()
        for row in rows:
            payload = dict(zip(
                [
                    "host_id", "host_ip", "updated_at", "provider", "goal_profile", "last_port", "last_protocol",
                    "last_service", "hostname", "hostname_confidence", "os_match", "os_confidence", "next_phase",
                    "technologies_json", "findings_json", "manual_tests_json", "raw_json",
                ],
                row,
            ))
            existing = session.execute(text(
                "SELECT host_id FROM scheduler_target_state WHERE host_id = :host_id LIMIT 1"
            ), {"host_id": int(payload.get("host_id", 0) or 0)}).fetchone()
            if existing is not None:
                continue
            target_payload = legacy_ai_payload_to_target_state(int(payload.get("host_id", 0) or 0), {
                "host_ip": payload.get("host_ip", ""),
                "updated_at": payload.get("updated_at", ""),
                "provider": payload.get("provider", ""),
                "goal_profile": payload.get("goal_profile", ""),
                "last_port": payload.get("last_port", ""),
                "last_protocol": payload.get("last_protocol", ""),
                "last_service": payload.get("last_service", ""),
                "hostname": payload.get("hostname", ""),
                "hostname_confidence": payload.get("hostname_confidence", 0.0),
                "os_match": payload.get("os_match", ""),
                "os_confidence": payload.get("os_confidence", 0.0),
                "next_phase": payload.get("next_phase", ""),
                "technologies": _from_json(payload.get("technologies_json"), []),
                "findings": _from_json(payload.get("findings_json"), []),
                "manual_tests": _from_json(payload.get("manual_tests_json"), []),
                "raw": _from_json(payload.get("raw_json"), {}),
            })
            session.execute(text(
                "INSERT INTO scheduler_target_state ("
                "host_id, host_ip, updated_at, state_version, last_mode, provider, goal_profile, engagement_preset, "
                "last_port, last_protocol, last_service, hostname, hostname_confidence, hostname_source_kind, "
                "os_match, os_confidence, os_source_kind, next_phase, technologies_json, findings_json, manual_tests_json, "
                "service_inventory_json, urls_json, coverage_gaps_json, attempted_actions_json, credentials_json, "
                "sessions_json, screenshots_json, artifacts_json, raw_json"
                ") VALUES ("
                ":host_id, :host_ip, :updated_at, :state_version, :last_mode, :provider, :goal_profile, :engagement_preset, "
                ":last_port, :last_protocol, :last_service, :hostname, :hostname_confidence, :hostname_source_kind, "
                ":os_match, :os_confidence, :os_source_kind, :next_phase, :technologies_json, :findings_json, :manual_tests_json, "
                ":service_inventory_json, :urls_json, :coverage_gaps_json, :attempted_actions_json, :credentials_json, "
                ":sessions_json, :screenshots_json, :artifacts_json, :raw_json"
                ")"
            ), {
                "host_id": int(target_payload.get("host_id", 0) or 0),
                "host_ip": str(target_payload.get("host_ip", "") or ""),
                "updated_at": str(target_payload.get("updated_at", "") or _utc_now()),
                "state_version": int(target_payload.get("state_version", 1) or 1),
                "last_mode": str(target_payload.get("last_mode", "") or ""),
                "provider": str(target_payload.get("provider", "") or ""),
                "goal_profile": str(target_payload.get("goal_profile", "") or ""),
                "engagement_preset": str(target_payload.get("engagement_preset", "") or ""),
                "last_port": str(target_payload.get("last_port", "") or ""),
                "last_protocol": str(target_payload.get("last_protocol", "") or ""),
                "last_service": str(target_payload.get("last_service", "") or ""),
                "hostname": str(target_payload.get("hostname", "") or ""),
                "hostname_confidence": float(target_payload.get("hostname_confidence", 0.0) or 0.0),
                "hostname_source_kind": str(target_payload.get("hostname_source_kind", "") or ""),
                "os_match": str(target_payload.get("os_match", "") or ""),
                "os_confidence": float(target_payload.get("os_confidence", 0.0) or 0.0),
                "os_source_kind": str(target_payload.get("os_source_kind", "") or ""),
                "next_phase": str(target_payload.get("next_phase", "") or ""),
                "technologies_json": _as_json(target_payload.get("technologies", []), []),
                "findings_json": _as_json(target_payload.get("findings", []), []),
                "manual_tests_json": _as_json(target_payload.get("manual_tests", []), []),
                "service_inventory_json": _as_json(target_payload.get("service_inventory", []), []),
                "urls_json": _as_json(target_payload.get("urls", []), []),
                "coverage_gaps_json": _as_json(target_payload.get("coverage_gaps", []), []),
                "attempted_actions_json": _as_json(target_payload.get("attempted_actions", []), []),
                "credentials_json": _as_json(target_payload.get("credentials", []), []),
                "sessions_json": _as_json(target_payload.get("sessions", []), []),
                "screenshots_json": _as_json(target_payload.get("screenshots", []), []),
                "artifacts_json": _as_json(target_payload.get("artifacts", []), []),
                "raw_json": _as_json(target_payload.get("raw", {}), {}),
            })
            migrated += 1
            migrated_host_ids.append(int(target_payload.get("host_id", 0) or 0))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    if migrated_host_ids:
        try:
            from app.scheduler.graph import sync_target_state_to_evidence_graph
            for migrated_host_id in list(dict.fromkeys(migrated_host_ids)):
                if int(migrated_host_id or 0) > 0:
                    sync_target_state_to_evidence_graph(database, host_id=int(migrated_host_id))
        except Exception:
            pass
    return migrated


def get_target_state(database, host_id: int) -> Optional[Dict[str, Any]]:
    payload = _fetch_target_state_row(database, int(host_id or 0))
    if payload is not None:
        return payload
    migrated = migrate_legacy_ai_state_to_target_state(database, host_id=int(host_id or 0))
    if migrated <= 0:
        return None
    return _fetch_target_state_row(database, int(host_id or 0))


def upsert_target_state(database, host_id: int, payload: Dict[str, Any], *, merge: bool = True) -> Dict[str, Any]:
    ensure_scheduler_target_state_table(database)
    existing = get_target_state(database, int(host_id or 0)) if merge else None
    normalized = legacy_ai_payload_to_target_state(int(host_id or 0), payload)
    merged = dict(existing or {})
    merged.update({
        "host_id": int(host_id or 0),
        "host_ip": str(normalized.get("host_ip", "") or merged.get("host_ip", "")),
        "updated_at": str(normalized.get("updated_at", "") or _utc_now()),
        "state_version": 1,
        "last_mode": str(normalized.get("last_mode", "") or merged.get("last_mode", "")),
        "provider": str(normalized.get("provider", "") or merged.get("provider", "")),
        "goal_profile": str(normalized.get("goal_profile", "") or merged.get("goal_profile", "")),
        "engagement_preset": str(normalized.get("engagement_preset", "") or merged.get("engagement_preset", "")),
        "last_port": str(normalized.get("last_port", "") or merged.get("last_port", "")),
        "last_protocol": str(normalized.get("last_protocol", "") or merged.get("last_protocol", "")),
        "last_service": str(normalized.get("last_service", "") or merged.get("last_service", "")),
        "hostname": str(normalized.get("hostname", "") or merged.get("hostname", "")),
        "hostname_confidence": max(
            _safe_float(merged.get("hostname_confidence", 0.0)),
            _safe_float(normalized.get("hostname_confidence", 0.0)),
        ) if str(normalized.get("hostname", "") or "").strip() else _safe_float(merged.get("hostname_confidence", 0.0)),
        "hostname_source_kind": str(normalized.get("hostname_source_kind", "") or merged.get("hostname_source_kind", "")),
        "os_match": str(normalized.get("os_match", "") or merged.get("os_match", "")),
        "os_confidence": max(
            _safe_float(merged.get("os_confidence", 0.0)),
            _safe_float(normalized.get("os_confidence", 0.0)),
        ) if str(normalized.get("os_match", "") or "").strip() else _safe_float(merged.get("os_confidence", 0.0)),
        "os_source_kind": str(normalized.get("os_source_kind", "") or merged.get("os_source_kind", "")),
        "next_phase": str(normalized.get("next_phase", "") or merged.get("next_phase", "")),
    })
    merged["technologies"] = _merge_rows(
        _normalize_technologies(merged.get("technologies", []), default_source="observed"),
        _normalize_technologies(normalized.get("technologies", []), default_source="observed"),
        key_fields=["name", "version", "cpe"],
        limit=240,
    )
    merged["findings"] = _merge_rows(
        _normalize_findings(merged.get("findings", []), default_source="observed"),
        _normalize_findings(normalized.get("findings", []), default_source="observed"),
        key_fields=["title", "cve", "severity"],
        limit=260,
    )
    merged["manual_tests"] = _merge_rows(
        _normalize_manual_tests(merged.get("manual_tests", []), default_source="ai_suggested"),
        _normalize_manual_tests(normalized.get("manual_tests", []), default_source="ai_suggested"),
        key_fields=["command", "why"],
        limit=200,
    )
    merged["attempted_actions"] = _merge_rows(
        _normalize_attempted_actions(merged.get("attempted_actions", [])),
        _normalize_attempted_actions(normalized.get("attempted_actions", [])),
        key_fields=["tool_id", "status", "port", "protocol", "attempted_at"],
        limit=360,
    )
    merged["credentials"] = _merge_rows(
        _normalize_credentials(merged.get("credentials", [])),
        _normalize_credentials(normalized.get("credentials", [])),
        key_fields=["username", "realm", "type", "secret_ref"],
        limit=160,
    )
    merged["sessions"] = _merge_rows(
        _normalize_sessions(merged.get("sessions", [])),
        _normalize_sessions(normalized.get("sessions", [])),
        key_fields=["session_type", "username", "host", "port", "protocol"],
        limit=160,
    )
    merged["screenshots"] = _merge_rows(
        _normalize_screenshots(merged.get("screenshots", [])),
        _normalize_screenshots(normalized.get("screenshots", [])),
        key_fields=["artifact_ref", "filename", "port", "protocol"],
        limit=160,
    )
    merged["artifacts"] = _merge_rows(
        _normalize_artifacts(merged.get("artifacts", [])),
        _normalize_artifacts(normalized.get("artifacts", [])),
        key_fields=["ref", "kind", "tool_id", "port", "protocol"],
        limit=240,
    )

    incoming_services = _normalize_service_inventory(normalized.get("service_inventory", []))
    merged["service_inventory"] = incoming_services or _normalize_service_inventory(merged.get("service_inventory", []))
    incoming_urls = _normalize_urls(normalized.get("urls", []))
    merged["urls"] = incoming_urls or _normalize_urls(merged.get("urls", []))
    incoming_gaps = _normalize_coverage_gaps(normalized.get("coverage_gaps", []))
    merged["coverage_gaps"] = incoming_gaps or _normalize_coverage_gaps(merged.get("coverage_gaps", []))
    existing_raw = merged.get("raw", {}) if isinstance(merged.get("raw", {}), dict) else {}
    incoming_raw = normalized.get("raw", {}) if isinstance(normalized.get("raw", {}), dict) else {}
    merged_raw = dict(existing_raw)
    for key, value in incoming_raw.items():
        if str(key or "") == "finding_quality_events":
            continue
        merged_raw[str(key)] = value
    merged_quality_events = _merge_rows(
        _normalize_finding_quality_events(existing_raw.get("finding_quality_events", []), default_source="observed"),
        _normalize_finding_quality_events(incoming_raw.get("finding_quality_events", []), default_source="observed"),
        key_fields=["title", "cve", "action", "reason", "evidence", "matched_url"],
        limit=260,
    )
    if merged_quality_events:
        merged_raw["finding_quality_events"] = merged_quality_events
    elif "finding_quality_events" in merged_raw:
        merged_raw.pop("finding_quality_events", None)
    merged["raw"] = merged_raw
    merged["finding_quality_events"] = merged_quality_events

    session = database.session()
    try:
        _ensure_target_state_table(session)
        existing_row = session.execute(text(
            "SELECT host_id FROM scheduler_target_state WHERE host_id = :host_id LIMIT 1"
        ), {"host_id": int(host_id or 0)}).fetchone()
        row_payload = {
            "host_id": int(host_id or 0),
            "host_ip": str(merged.get("host_ip", "") or ""),
            "updated_at": str(merged.get("updated_at", "") or _utc_now()),
            "state_version": 1,
            "last_mode": str(merged.get("last_mode", "") or ""),
            "provider": str(merged.get("provider", "") or ""),
            "goal_profile": str(merged.get("goal_profile", "") or ""),
            "engagement_preset": str(merged.get("engagement_preset", "") or ""),
            "last_port": str(merged.get("last_port", "") or ""),
            "last_protocol": str(merged.get("last_protocol", "") or ""),
            "last_service": str(merged.get("last_service", "") or ""),
            "hostname": str(merged.get("hostname", "") or ""),
            "hostname_confidence": _safe_float(merged.get("hostname_confidence", 0.0)),
            "hostname_source_kind": str(merged.get("hostname_source_kind", "") or ""),
            "os_match": str(merged.get("os_match", "") or ""),
            "os_confidence": _safe_float(merged.get("os_confidence", 0.0)),
            "os_source_kind": str(merged.get("os_source_kind", "") or ""),
            "next_phase": str(merged.get("next_phase", "") or ""),
            "technologies_json": _as_json(merged.get("technologies", []), []),
            "findings_json": _as_json(merged.get("findings", []), []),
            "manual_tests_json": _as_json(merged.get("manual_tests", []), []),
            "service_inventory_json": _as_json(merged.get("service_inventory", []), []),
            "urls_json": _as_json(merged.get("urls", []), []),
            "coverage_gaps_json": _as_json(merged.get("coverage_gaps", []), []),
            "attempted_actions_json": _as_json(merged.get("attempted_actions", []), []),
            "credentials_json": _as_json(merged.get("credentials", []), []),
            "sessions_json": _as_json(merged.get("sessions", []), []),
            "screenshots_json": _as_json(merged.get("screenshots", []), []),
            "artifacts_json": _as_json(merged.get("artifacts", []), []),
            "raw_json": _as_json(merged.get("raw", {}), {}),
        }
        if existing_row is None:
            session.execute(text(
                "INSERT INTO scheduler_target_state ("
                "host_id, host_ip, updated_at, state_version, last_mode, provider, goal_profile, engagement_preset, "
                "last_port, last_protocol, last_service, hostname, hostname_confidence, hostname_source_kind, "
                "os_match, os_confidence, os_source_kind, next_phase, technologies_json, findings_json, manual_tests_json, "
                "service_inventory_json, urls_json, coverage_gaps_json, attempted_actions_json, credentials_json, "
                "sessions_json, screenshots_json, artifacts_json, raw_json"
                ") VALUES ("
                ":host_id, :host_ip, :updated_at, :state_version, :last_mode, :provider, :goal_profile, :engagement_preset, "
                ":last_port, :last_protocol, :last_service, :hostname, :hostname_confidence, :hostname_source_kind, "
                ":os_match, :os_confidence, :os_source_kind, :next_phase, :technologies_json, :findings_json, :manual_tests_json, "
                ":service_inventory_json, :urls_json, :coverage_gaps_json, :attempted_actions_json, :credentials_json, "
                ":sessions_json, :screenshots_json, :artifacts_json, :raw_json"
                ")"
            ), row_payload)
        else:
            session.execute(text(
                "UPDATE scheduler_target_state SET "
                "host_ip = :host_ip, updated_at = :updated_at, state_version = :state_version, "
                "last_mode = :last_mode, provider = :provider, goal_profile = :goal_profile, engagement_preset = :engagement_preset, "
                "last_port = :last_port, last_protocol = :last_protocol, last_service = :last_service, "
                "hostname = :hostname, hostname_confidence = :hostname_confidence, hostname_source_kind = :hostname_source_kind, "
                "os_match = :os_match, os_confidence = :os_confidence, os_source_kind = :os_source_kind, "
                "next_phase = :next_phase, technologies_json = :technologies_json, findings_json = :findings_json, "
                "manual_tests_json = :manual_tests_json, service_inventory_json = :service_inventory_json, urls_json = :urls_json, "
                "coverage_gaps_json = :coverage_gaps_json, attempted_actions_json = :attempted_actions_json, credentials_json = :credentials_json, "
                "sessions_json = :sessions_json, screenshots_json = :screenshots_json, artifacts_json = :artifacts_json, raw_json = :raw_json "
                "WHERE host_id = :host_id"
            ), row_payload)
        session.commit()
        merged["updated_at"] = row_payload["updated_at"]
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    try:
        from app.scheduler.graph import sync_target_state_to_evidence_graph
        sync_target_state_to_evidence_graph(database, host_id=int(host_id or 0), target_state=merged)
    except Exception:
        pass
    return merged


def delete_target_state(database, host_id: int) -> int:
    session = database.session()
    try:
        _ensure_target_state_table(session)
        result = session.execute(text(
            "DELETE FROM scheduler_target_state WHERE host_id = :host_id"
        ), {"host_id": int(host_id or 0)})
        session.commit()
        return max(0, int(result.rowcount or 0))
    except Exception:
        session.rollback()
        return 0
    finally:
        session.close()
