import datetime
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import text


SCAN_HISTORY_COLUMNS = (
    "id",
    "created_at",
    "updated_at",
    "job_id",
    "submission_kind",
    "status",
    "target_summary",
    "scope_summary",
    "targets_json",
    "source_path",
    "scan_mode",
    "discovery",
    "staged",
    "run_actions",
    "nmap_path",
    "nmap_args",
    "scan_options_json",
    "result_summary",
)


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
        "CREATE TABLE IF NOT EXISTS scheduler_scan_submission ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "created_at TEXT,"
        "updated_at TEXT,"
        "job_id TEXT,"
        "submission_kind TEXT,"
        "status TEXT,"
        "target_summary TEXT,"
        "scope_summary TEXT,"
        "targets_json TEXT,"
        "source_path TEXT,"
        "scan_mode TEXT,"
        "discovery TEXT,"
        "staged TEXT,"
        "run_actions TEXT,"
        "nmap_path TEXT,"
        "nmap_args TEXT,"
        "scan_options_json TEXT,"
        "result_summary TEXT"
        ")"
    ))
    for column_name, column_type in (
            ("created_at", "TEXT"),
            ("updated_at", "TEXT"),
            ("job_id", "TEXT"),
            ("submission_kind", "TEXT"),
            ("status", "TEXT"),
            ("target_summary", "TEXT"),
            ("scope_summary", "TEXT"),
            ("targets_json", "TEXT"),
            ("source_path", "TEXT"),
            ("scan_mode", "TEXT"),
            ("discovery", "TEXT"),
            ("staged", "TEXT"),
            ("run_actions", "TEXT"),
            ("nmap_path", "TEXT"),
            ("nmap_args", "TEXT"),
            ("scan_options_json", "TEXT"),
            ("result_summary", "TEXT"),
    ):
        _ensure_column(session, "scheduler_scan_submission", column_name, column_type)


def _to_json(value: Any, fallback: Any) -> str:
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


def ensure_scan_submission_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def record_scan_submission(database, record: Dict[str, Any]) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_table(session)
        now = _utc_now()
        payload = {
            "created_at": str(record.get("created_at", now) or now),
            "updated_at": str(record.get("updated_at", now) or now),
            "job_id": str(record.get("job_id", "") or ""),
            "submission_kind": str(record.get("submission_kind", "") or ""),
            "status": str(record.get("status", "submitted") or "submitted"),
            "target_summary": str(record.get("target_summary", "") or ""),
            "scope_summary": str(record.get("scope_summary", "") or ""),
            "targets_json": _to_json(record.get("targets", []), []),
            "source_path": str(record.get("source_path", "") or ""),
            "scan_mode": str(record.get("scan_mode", "") or ""),
            "discovery": "True" if bool(record.get("discovery", False)) else "False",
            "staged": "True" if bool(record.get("staged", False)) else "False",
            "run_actions": "True" if bool(record.get("run_actions", False)) else "False",
            "nmap_path": str(record.get("nmap_path", "") or ""),
            "nmap_args": str(record.get("nmap_args", "") or ""),
            "scan_options_json": _to_json(record.get("scan_options", {}), {}),
            "result_summary": str(record.get("result_summary", "") or ""),
        }
        result = session.execute(text(
            "INSERT INTO scheduler_scan_submission ("
            "created_at, updated_at, job_id, submission_kind, status, target_summary, scope_summary, targets_json, "
            "source_path, scan_mode, discovery, staged, run_actions, nmap_path, nmap_args, scan_options_json, "
            "result_summary"
            ") VALUES ("
            ":created_at, :updated_at, :job_id, :submission_kind, :status, :target_summary, :scope_summary, :targets_json, "
            ":source_path, :scan_mode, :discovery, :staged, :run_actions, :nmap_path, :nmap_args, :scan_options_json, "
            ":result_summary"
            ")"
        ), payload)
        session.commit()
        payload["id"] = int(result.lastrowid or 0)
        payload["targets"] = _from_json(payload.get("targets_json", "[]"), [])
        payload["scan_options"] = _from_json(payload.get("scan_options_json", "{}"), {})
        return payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def update_scan_submission(
        database,
        *,
        submission_id: int = 0,
        job_id: int = 0,
        status: Optional[str] = None,
        result_summary: Optional[str] = None,
        target_summary: Optional[str] = None,
        scope_summary: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        if int(submission_id or 0) > 0:
            row = session.execute(text(
                "SELECT id FROM scheduler_scan_submission WHERE id = :id LIMIT 1"
            ), {"id": int(submission_id or 0)}).fetchone()
        else:
            row = session.execute(text(
                "SELECT id FROM scheduler_scan_submission WHERE job_id = :job_id ORDER BY id DESC LIMIT 1"
            ), {"job_id": str(int(job_id or 0) or "")}).fetchone()
        if row is None:
            return None

        clauses = ["updated_at = :updated_at"]
        params: Dict[str, Any] = {"id": int(row[0]), "updated_at": _utc_now()}
        if status is not None:
            clauses.append("status = :status")
            params["status"] = str(status or "")
        if result_summary is not None:
            clauses.append("result_summary = :result_summary")
            params["result_summary"] = str(result_summary or "")
        if target_summary is not None:
            clauses.append("target_summary = :target_summary")
            params["target_summary"] = str(target_summary or "")
        if scope_summary is not None:
            clauses.append("scope_summary = :scope_summary")
            params["scope_summary"] = str(scope_summary or "")

        session.execute(text(
            f"UPDATE scheduler_scan_submission SET {', '.join(clauses)} WHERE id = :id"
        ), params)
        session.commit()

        result = session.execute(text(
            "SELECT " + ", ".join(SCAN_HISTORY_COLUMNS) + " "
            "FROM scheduler_scan_submission WHERE id = :id LIMIT 1"
        ), {"id": int(row[0])})
        updated_row = result.fetchone()
        if updated_row is None:
            return None
        payload = dict(zip(result.keys(), updated_row))
        payload["targets"] = _from_json(payload.get("targets_json"), [])
        payload["scan_options"] = _from_json(payload.get("scan_options_json"), {})
        return payload
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()


def list_scan_submissions(database, limit: int = 200) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        safe_limit = max(1, min(int(limit or 200), 2000))
        result = session.execute(text(
            "SELECT " + ", ".join(SCAN_HISTORY_COLUMNS) + " "
            "FROM scheduler_scan_submission ORDER BY id DESC LIMIT :limit"
        ), {"limit": safe_limit})
        rows = result.fetchall()
        payload: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(zip(result.keys(), row))
            item["targets"] = _from_json(item.get("targets_json"), [])
            item["scan_options"] = _from_json(item.get("scan_options_json"), {})
            payload.append(item)
        return payload
    finally:
        session.close()
