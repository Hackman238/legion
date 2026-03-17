from typing import Dict

from sqlalchemy import text


AUDIT_COLUMNS = (
    "id",
    "timestamp",
    "host_ip",
    "port",
    "protocol",
    "service",
    "scheduler_mode",
    "goal_profile",
    "engagement_preset",
    "tool_id",
    "label",
    "command_family_id",
    "danger_categories",
    "risk_tags",
    "requires_approval",
    "policy_decision",
    "policy_reason",
    "risk_summary",
    "safer_alternative",
    "family_policy_state",
    "approved",
    "executed",
    "reason",
    "rationale",
    "approval_id",
)


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
        "engagement_preset TEXT,"
        "tool_id TEXT,"
        "label TEXT,"
        "command_family_id TEXT,"
        "danger_categories TEXT,"
        "risk_tags TEXT,"
        "requires_approval TEXT,"
        "policy_decision TEXT,"
        "policy_reason TEXT,"
        "risk_summary TEXT,"
        "safer_alternative TEXT,"
        "family_policy_state TEXT,"
        "approved TEXT,"
        "executed TEXT,"
        "reason TEXT,"
        "rationale TEXT,"
        "approval_id TEXT"
        ")"
    ))
    _ensure_column(session, "scheduler_decision_log", "approval_id", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "engagement_preset", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "risk_tags", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "policy_decision", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "policy_reason", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "risk_summary", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "safer_alternative", "TEXT")
    _ensure_column(session, "scheduler_decision_log", "family_policy_state", "TEXT")


def _select_columns() -> str:
    return ", ".join(AUDIT_COLUMNS)


def _row_to_dict(result, row):
    keys = result.keys()
    return dict(zip(keys, row))


def log_scheduler_decision(database, record: Dict[str, str]):
    session = database.session()
    try:
        _ensure_table(session)
        payload = dict(record or {})
        payload.setdefault("approval_id", "")
        payload.setdefault("engagement_preset", "")
        payload.setdefault("risk_tags", "")
        payload.setdefault("policy_decision", "")
        payload.setdefault("policy_reason", "")
        payload.setdefault("risk_summary", "")
        payload.setdefault("safer_alternative", "")
        payload.setdefault("family_policy_state", "")
        session.execute(text(
            "INSERT INTO scheduler_decision_log ("
            "timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, engagement_preset, "
            "tool_id, label, command_family_id, danger_categories, risk_tags, requires_approval, "
            "policy_decision, policy_reason, risk_summary, safer_alternative, family_policy_state, "
            "approved, executed, reason, rationale, approval_id"
            ") VALUES ("
            ":timestamp, :host_ip, :port, :protocol, :service, :scheduler_mode, :goal_profile, :engagement_preset, "
            ":tool_id, :label, :command_family_id, :danger_categories, :risk_tags, :requires_approval, "
            ":policy_decision, :policy_reason, :risk_summary, :safer_alternative, :family_policy_state, "
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
            f"SELECT {_select_columns()} FROM scheduler_decision_log WHERE id = :id LIMIT 1"
        ), {"id": int(row[0])})
        updated_row = result.fetchone()
        if updated_row is None:
            return None
        return _row_to_dict(result, updated_row)
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()
