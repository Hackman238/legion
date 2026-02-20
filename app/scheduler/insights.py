import datetime
import json
from typing import Any, Dict, Optional

from sqlalchemy import text


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _ensure_table(session):
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
    _ensure_column(session, "scheduler_host_ai_state", "host_ip", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "updated_at", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "provider", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "goal_profile", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "last_port", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "last_protocol", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "last_service", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "hostname", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "hostname_confidence", "REAL")
    _ensure_column(session, "scheduler_host_ai_state", "os_match", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "os_confidence", "REAL")
    _ensure_column(session, "scheduler_host_ai_state", "next_phase", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "technologies_json", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "findings_json", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "manual_tests_json", "TEXT")
    _ensure_column(session, "scheduler_host_ai_state", "raw_json", "TEXT")


def _as_json(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else [], ensure_ascii=False)
    except Exception:
        return "[]"


def _from_json(value: Any, fallback):
    raw = str(value or "").strip()
    if not raw:
        return fallback
    try:
        parsed = json.loads(raw)
    except Exception:
        return fallback
    return parsed


def ensure_scheduler_ai_state_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def get_host_ai_state(database, host_id: int) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            "SELECT host_id, host_ip, updated_at, provider, goal_profile, last_port, last_protocol, last_service, "
            "hostname, hostname_confidence, os_match, os_confidence, next_phase, technologies_json, findings_json, "
            "manual_tests_json, raw_json "
            "FROM scheduler_host_ai_state WHERE host_id = :host_id LIMIT 1"
        ), {"host_id": int(host_id)})
        row = result.fetchone()
        if row is None:
            return None
        keys = result.keys()
        payload = dict(zip(keys, row))
        payload["technologies"] = _from_json(payload.get("technologies_json"), [])
        payload["findings"] = _from_json(payload.get("findings_json"), [])
        payload["manual_tests"] = _from_json(payload.get("manual_tests_json"), [])
        payload["raw"] = _from_json(payload.get("raw_json"), {})
        return payload
    finally:
        session.close()


def upsert_host_ai_state(database, host_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_table(session)
        now = _utc_now()
        row_payload = {
            "host_id": int(host_id),
            "host_ip": str(payload.get("host_ip", "")),
            "updated_at": str(payload.get("updated_at", now) or now),
            "provider": str(payload.get("provider", "")),
            "goal_profile": str(payload.get("goal_profile", "")),
            "last_port": str(payload.get("last_port", "")),
            "last_protocol": str(payload.get("last_protocol", "")),
            "last_service": str(payload.get("last_service", "")),
            "hostname": str(payload.get("hostname", "")),
            "hostname_confidence": float(payload.get("hostname_confidence", 0.0) or 0.0),
            "os_match": str(payload.get("os_match", "")),
            "os_confidence": float(payload.get("os_confidence", 0.0) or 0.0),
            "next_phase": str(payload.get("next_phase", "")),
            "technologies_json": _as_json(payload.get("technologies", [])),
            "findings_json": _as_json(payload.get("findings", [])),
            "manual_tests_json": _as_json(payload.get("manual_tests", [])),
            "raw_json": _as_json(payload.get("raw", {})),
        }

        existing = session.execute(text(
            "SELECT host_id FROM scheduler_host_ai_state WHERE host_id = :host_id LIMIT 1"
        ), {"host_id": int(host_id)}).fetchone()

        if existing is None:
            session.execute(text(
                "INSERT INTO scheduler_host_ai_state ("
                "host_id, host_ip, updated_at, provider, goal_profile, last_port, last_protocol, last_service, "
                "hostname, hostname_confidence, os_match, os_confidence, next_phase, technologies_json, findings_json, "
                "manual_tests_json, raw_json"
                ") VALUES ("
                ":host_id, :host_ip, :updated_at, :provider, :goal_profile, :last_port, :last_protocol, :last_service, "
                ":hostname, :hostname_confidence, :os_match, :os_confidence, :next_phase, :technologies_json, "
                ":findings_json, :manual_tests_json, :raw_json"
                ")"
            ), row_payload)
        else:
            session.execute(text(
                "UPDATE scheduler_host_ai_state SET "
                "host_ip = :host_ip, "
                "updated_at = :updated_at, "
                "provider = :provider, "
                "goal_profile = :goal_profile, "
                "last_port = :last_port, "
                "last_protocol = :last_protocol, "
                "last_service = :last_service, "
                "hostname = :hostname, "
                "hostname_confidence = :hostname_confidence, "
                "os_match = :os_match, "
                "os_confidence = :os_confidence, "
                "next_phase = :next_phase, "
                "technologies_json = :technologies_json, "
                "findings_json = :findings_json, "
                "manual_tests_json = :manual_tests_json, "
                "raw_json = :raw_json "
                "WHERE host_id = :host_id"
            ), row_payload)

        session.commit()
        return row_payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def delete_host_ai_state(database, host_id: int) -> int:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            "DELETE FROM scheduler_host_ai_state WHERE host_id = :host_id"
        ), {"host_id": int(host_id)})
        session.commit()
        return max(0, int(result.rowcount or 0))
    except Exception:
        session.rollback()
        return 0
    finally:
        session.close()
