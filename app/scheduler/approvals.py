import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text


APPROVAL_COLUMNS = (
    "id",
    "created_at",
    "updated_at",
    "status",
    "host_ip",
    "port",
    "protocol",
    "service",
    "tool_id",
    "label",
    "command_template",
    "command_family_id",
    "danger_categories",
    "risk_tags",
    "scheduler_mode",
    "goal_profile",
    "engagement_preset",
    "rationale",
    "policy_decision",
    "policy_reason",
    "risk_summary",
    "safer_alternative",
    "family_policy_state",
    "evidence_refs",
    "decision_reason",
    "execution_job_id",
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    ))


def _ensure_table(session):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS scheduler_pending_approval ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "created_at TEXT,"
        "updated_at TEXT,"
        "status TEXT,"
        "host_ip TEXT,"
        "port TEXT,"
        "protocol TEXT,"
        "service TEXT,"
        "tool_id TEXT,"
        "label TEXT,"
        "command_template TEXT,"
        "command_family_id TEXT,"
        "danger_categories TEXT,"
        "risk_tags TEXT,"
        "scheduler_mode TEXT,"
        "goal_profile TEXT,"
        "engagement_preset TEXT,"
        "rationale TEXT,"
        "policy_decision TEXT,"
        "policy_reason TEXT,"
        "risk_summary TEXT,"
        "safer_alternative TEXT,"
        "family_policy_state TEXT,"
        "evidence_refs TEXT,"
        "decision_reason TEXT,"
        "execution_job_id TEXT"
        ")"
    ))
    _ensure_column(session, "scheduler_pending_approval", "risk_tags", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "engagement_preset", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "policy_decision", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "policy_reason", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "risk_summary", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "safer_alternative", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "family_policy_state", "TEXT")
    _ensure_column(session, "scheduler_pending_approval", "evidence_refs", "TEXT")


def _select_columns() -> str:
    return ", ".join(APPROVAL_COLUMNS)


def _row_to_dict(result, row) -> Dict[str, Any]:
    keys = result.keys()
    return dict(zip(keys, row))


def ensure_scheduler_approval_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def queue_pending_approval(database, record: Dict[str, Any]) -> int:
    session = database.session()
    try:
        _ensure_table(session)
        now = _utc_now()
        result = session.execute(text(
            "INSERT INTO scheduler_pending_approval ("
            "created_at, updated_at, status, host_ip, port, protocol, service, tool_id, label, "
            "command_template, command_family_id, danger_categories, risk_tags, scheduler_mode, goal_profile, "
            "engagement_preset, rationale, policy_decision, policy_reason, risk_summary, safer_alternative, "
            "family_policy_state, evidence_refs, decision_reason, execution_job_id"
            ") VALUES ("
            ":created_at, :updated_at, :status, :host_ip, :port, :protocol, :service, :tool_id, :label, "
            ":command_template, :command_family_id, :danger_categories, :risk_tags, :scheduler_mode, :goal_profile, "
            ":engagement_preset, :rationale, :policy_decision, :policy_reason, :risk_summary, :safer_alternative, "
            ":family_policy_state, :evidence_refs, :decision_reason, :execution_job_id"
            ")"
        ), {
            "created_at": now,
            "updated_at": now,
            "status": str(record.get("status", "pending")),
            "host_ip": str(record.get("host_ip", "")),
            "port": str(record.get("port", "")),
            "protocol": str(record.get("protocol", "")),
            "service": str(record.get("service", "")),
            "tool_id": str(record.get("tool_id", "")),
            "label": str(record.get("label", "")),
            "command_template": str(record.get("command_template", "")),
            "command_family_id": str(record.get("command_family_id", "")),
            "danger_categories": str(record.get("danger_categories", "")),
            "risk_tags": str(record.get("risk_tags", "")),
            "scheduler_mode": str(record.get("scheduler_mode", "")),
            "goal_profile": str(record.get("goal_profile", "")),
            "engagement_preset": str(record.get("engagement_preset", "")),
            "rationale": str(record.get("rationale", "")),
            "policy_decision": str(record.get("policy_decision", "")),
            "policy_reason": str(record.get("policy_reason", "")),
            "risk_summary": str(record.get("risk_summary", "")),
            "safer_alternative": str(record.get("safer_alternative", "")),
            "family_policy_state": str(record.get("family_policy_state", "")),
            "evidence_refs": str(record.get("evidence_refs", "")),
            "decision_reason": str(record.get("decision_reason", "")),
            "execution_job_id": str(record.get("execution_job_id", "")),
        })
        session.commit()
        return int(result.lastrowid or 0)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_pending_approvals(database, limit: int = 200, status: Optional[str] = None) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        query = f"SELECT {_select_columns()} FROM scheduler_pending_approval"
        params: Dict[str, Any] = {"limit": max(1, min(int(limit), 1000))}
        if status:
            query += " WHERE status = :status"
            params["status"] = str(status)
        query += " ORDER BY id DESC LIMIT :limit"
        result = session.execute(text(query), params)
        rows = result.fetchall()
        return [_row_to_dict(result, row) for row in rows]
    finally:
        session.close()


def get_pending_approval(database, approval_id: int) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            f"SELECT {_select_columns()} FROM scheduler_pending_approval WHERE id = :id LIMIT 1"
        ), {"id": int(approval_id)})
        row = result.fetchone()
        if row is None:
            return None
        return _row_to_dict(result, row)
    finally:
        session.close()


def update_pending_approval(
        database,
        approval_id: int,
        *,
        status: Optional[str] = None,
        decision_reason: Optional[str] = None,
        execution_job_id: Optional[str] = None,
        family_policy_state: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        existing = session.execute(text(
            "SELECT id FROM scheduler_pending_approval WHERE id = :id LIMIT 1"
        ), {"id": int(approval_id)}).fetchone()
        if existing is None:
            return None

        clauses = ["updated_at = :updated_at"]
        params: Dict[str, Any] = {"id": int(approval_id), "updated_at": _utc_now()}
        if status is not None:
            clauses.append("status = :status")
            params["status"] = str(status)
        if decision_reason is not None:
            clauses.append("decision_reason = :decision_reason")
            params["decision_reason"] = str(decision_reason)
        if execution_job_id is not None:
            clauses.append("execution_job_id = :execution_job_id")
            params["execution_job_id"] = str(execution_job_id)
        if family_policy_state is not None:
            clauses.append("family_policy_state = :family_policy_state")
            params["family_policy_state"] = str(family_policy_state)

        session.execute(text(
            f"UPDATE scheduler_pending_approval SET {', '.join(clauses)} WHERE id = :id"
        ), params)
        session.commit()

        result = session.execute(text(
            f"SELECT {_select_columns()} FROM scheduler_pending_approval WHERE id = :id LIMIT 1"
        ), {"id": int(approval_id)})
        row = result.fetchone()
        if row is None:
            return None
        return _row_to_dict(result, row)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
