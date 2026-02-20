from typing import Dict

from sqlalchemy import text


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
        "CREATE TABLE IF NOT EXISTS scheduler_decision_log ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp TEXT,"
        "host_ip TEXT,"
        "port TEXT,"
        "protocol TEXT,"
        "service TEXT,"
        "scheduler_mode TEXT,"
        "goal_profile TEXT,"
        "tool_id TEXT,"
        "label TEXT,"
        "command_family_id TEXT,"
        "danger_categories TEXT,"
        "requires_approval TEXT,"
        "approved TEXT,"
        "executed TEXT,"
        "reason TEXT,"
        "rationale TEXT,"
        "approval_id TEXT"
        ")"
    ))
    _ensure_column(session, "scheduler_decision_log", "approval_id", "TEXT")


def log_scheduler_decision(database, record: Dict[str, str]):
    session = database.session()
    try:
        _ensure_table(session)
        payload = dict(record or {})
        payload.setdefault("approval_id", "")
        session.execute(text(
            "INSERT INTO scheduler_decision_log ("
            "timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, "
            "tool_id, label, command_family_id, danger_categories, requires_approval, "
            "approved, executed, reason, rationale, approval_id"
            ") VALUES ("
            ":timestamp, :host_ip, :port, :protocol, :service, :scheduler_mode, :goal_profile, "
            ":tool_id, :label, :command_family_id, :danger_categories, :requires_approval, "
            ":approved, :executed, :reason, :rationale, :approval_id"
            ")"
        ), payload)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def ensure_scheduler_audit_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def update_scheduler_decision_for_approval(
        database,
        approval_id: int,
        *,
        approved=None,
        executed=None,
        reason: str = None,
):
    session = database.session()
    try:
        _ensure_table(session)
        approval_key = str(approval_id or "").strip()
        if not approval_key:
            return None

        row = session.execute(text(
            "SELECT id FROM scheduler_decision_log "
            "WHERE approval_id = :approval_id ORDER BY id DESC LIMIT 1"
        ), {"approval_id": approval_key}).fetchone()
        if row is None:
            row = session.execute(text(
                "SELECT id FROM scheduler_decision_log "
                "WHERE reason LIKE :needle ORDER BY id DESC LIMIT 1"
            ), {"needle": f"%approval #{approval_key}%"}).fetchone()
        if row is None:
            return None

        clauses = []
        params = {"id": int(row[0])}

        if approved is not None:
            clauses.append("approved = :approved")
            params["approved"] = "True" if bool(approved) else "False"
        if executed is not None:
            clauses.append("executed = :executed")
            params["executed"] = "True" if bool(executed) else "False"
        if reason is not None:
            clauses.append("reason = :reason")
            params["reason"] = str(reason)

        if not clauses:
            return None

        session.execute(text(
            f"UPDATE scheduler_decision_log SET {', '.join(clauses)} WHERE id = :id"
        ), params)
        session.commit()

        result = session.execute(text(
            "SELECT id, timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, "
            "tool_id, label, command_family_id, danger_categories, requires_approval, "
            "approved, executed, reason, rationale, approval_id "
            "FROM scheduler_decision_log WHERE id = :id LIMIT 1"
        ), {"id": int(row[0])})
        updated_row = result.fetchone()
        if updated_row is None:
            return None
        keys = result.keys()
        return dict(zip(keys, updated_row))
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()
