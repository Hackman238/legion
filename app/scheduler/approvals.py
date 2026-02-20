import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import text


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


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
        "scheduler_mode TEXT,"
        "goal_profile TEXT,"
        "rationale TEXT,"
        "decision_reason TEXT,"
        "execution_job_id TEXT"
        ")"
    ))


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
            "command_template, command_family_id, danger_categories, scheduler_mode, goal_profile, "
            "rationale, decision_reason, execution_job_id"
            ") VALUES ("
            ":created_at, :updated_at, :status, :host_ip, :port, :protocol, :service, :tool_id, :label, "
            ":command_template, :command_family_id, :danger_categories, :scheduler_mode, :goal_profile, "
            ":rationale, :decision_reason, :execution_job_id"
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
            "scheduler_mode": str(record.get("scheduler_mode", "")),
            "goal_profile": str(record.get("goal_profile", "")),
            "rationale": str(record.get("rationale", "")),
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
        query = (
            "SELECT id, created_at, updated_at, status, host_ip, port, protocol, service, tool_id, label, "
            "command_template, command_family_id, danger_categories, scheduler_mode, goal_profile, rationale, "
            "decision_reason, execution_job_id "
            "FROM scheduler_pending_approval"
        )
        params: Dict[str, Any] = {"limit": max(1, min(int(limit), 1000))}
        if status:
            query += " WHERE status = :status"
            params["status"] = str(status)
        query += " ORDER BY id DESC LIMIT :limit"
        result = session.execute(text(query), params)
        rows = result.fetchall()
        keys = result.keys()
        return [dict(zip(keys, row)) for row in rows]
    finally:
        session.close()


def get_pending_approval(database, approval_id: int) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            "SELECT id, created_at, updated_at, status, host_ip, port, protocol, service, tool_id, label, "
            "command_template, command_family_id, danger_categories, scheduler_mode, goal_profile, rationale, "
            "decision_reason, execution_job_id "
            "FROM scheduler_pending_approval WHERE id = :id LIMIT 1"
        ), {"id": int(approval_id)})
        row = result.fetchone()
        if row is None:
            return None
        keys = result.keys()
        return dict(zip(keys, row))
    finally:
        session.close()


def update_pending_approval(
        database,
        approval_id: int,
        *,
        status: Optional[str] = None,
        decision_reason: Optional[str] = None,
        execution_job_id: Optional[str] = None
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

        session.execute(text(
            f"UPDATE scheduler_pending_approval SET {', '.join(clauses)} WHERE id = :id"
        ), params)
        session.commit()

        result = session.execute(text(
            "SELECT id, created_at, updated_at, status, host_ip, port, protocol, service, tool_id, label, "
            "command_template, command_family_id, danger_categories, scheduler_mode, goal_profile, rationale, "
            "decision_reason, execution_job_id "
            "FROM scheduler_pending_approval WHERE id = :id LIMIT 1"
        ), {"id": int(approval_id)})
        row = result.fetchone()
        if row is None:
            return None
        keys = result.keys()
        return dict(zip(keys, row))
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
