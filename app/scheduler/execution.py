import json
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.models import ExecutionRecord, PlanStep


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _ensure_table(session):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS scheduler_execution_record ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "execution_id TEXT UNIQUE,"
        "step_id TEXT,"
        "action_id TEXT,"
        "tool_id TEXT,"
        "label TEXT,"
        "scheduler_mode TEXT,"
        "goal_profile TEXT,"
        "host_ip TEXT,"
        "port TEXT,"
        "protocol TEXT,"
        "service TEXT,"
        "started_at TEXT,"
        "finished_at TEXT,"
        "runner_type TEXT,"
        "exit_status TEXT,"
        "stdout_ref TEXT,"
        "stderr_ref TEXT,"
        "artifact_refs_json TEXT,"
        "approval_id TEXT,"
        "observations_created_json TEXT,"
        "graph_mutations_json TEXT,"
        "operator_notes TEXT"
        ")"
    ))
    for column_name, column_type in (
            ("execution_id", "TEXT"),
            ("step_id", "TEXT"),
            ("action_id", "TEXT"),
            ("tool_id", "TEXT"),
            ("label", "TEXT"),
            ("scheduler_mode", "TEXT"),
            ("goal_profile", "TEXT"),
            ("host_ip", "TEXT"),
            ("port", "TEXT"),
            ("protocol", "TEXT"),
            ("service", "TEXT"),
            ("started_at", "TEXT"),
            ("finished_at", "TEXT"),
            ("runner_type", "TEXT"),
            ("exit_status", "TEXT"),
            ("stdout_ref", "TEXT"),
            ("stderr_ref", "TEXT"),
            ("artifact_refs_json", "TEXT"),
            ("approval_id", "TEXT"),
            ("observations_created_json", "TEXT"),
            ("graph_mutations_json", "TEXT"),
            ("operator_notes", "TEXT"),
    ):
        _ensure_column(session, "scheduler_execution_record", column_name, column_type)


def _to_json(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else [], ensure_ascii=False)
    except Exception:
        return "[]"


def _from_json(value: Any) -> List[Any]:
    raw = str(value or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def ensure_scheduler_execution_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def store_execution_record(
        database,
        record: ExecutionRecord,
        *,
        step: Optional[PlanStep] = None,
        host_ip: str = "",
        port: str = "",
        protocol: str = "",
        service: str = "",
) -> Dict[str, Any]:
    session = database.session()
    try:
        _ensure_table(session)
        action = step.action if isinstance(step, PlanStep) else None
        payload = {
            "execution_id": str(record.execution_id),
            "step_id": str(record.step_id),
            "action_id": str(action.action_id if action else ""),
            "tool_id": str(action.tool_id if action else ""),
            "label": str(action.label if action else ""),
            "scheduler_mode": str(step.origin_mode if isinstance(step, PlanStep) else ""),
            "goal_profile": str(step.goal_profile if isinstance(step, PlanStep) else ""),
            "host_ip": str(host_ip or ""),
            "port": str(port or ""),
            "protocol": str(protocol or ""),
            "service": str(service or ""),
            "started_at": str(record.started_at or ""),
            "finished_at": str(record.finished_at or ""),
            "runner_type": str(record.runner_type or ""),
            "exit_status": str(record.exit_status or ""),
            "stdout_ref": str(record.stdout_ref or ""),
            "stderr_ref": str(record.stderr_ref or ""),
            "artifact_refs_json": _to_json(record.artifact_refs),
            "approval_id": str(record.approval_id or ""),
            "observations_created_json": _to_json(record.observations_created),
            "graph_mutations_json": _to_json(record.graph_mutations),
            "operator_notes": str(record.operator_notes or ""),
        }

        existing = session.execute(text(
            "SELECT id FROM scheduler_execution_record WHERE execution_id = :execution_id LIMIT 1"
        ), {"execution_id": payload["execution_id"]}).fetchone()

        if existing is None:
            session.execute(text(
                "INSERT INTO scheduler_execution_record ("
                "execution_id, step_id, action_id, tool_id, label, scheduler_mode, goal_profile, "
                "host_ip, port, protocol, service, started_at, finished_at, runner_type, exit_status, "
                "stdout_ref, stderr_ref, artifact_refs_json, approval_id, observations_created_json, "
                "graph_mutations_json, operator_notes"
                ") VALUES ("
                ":execution_id, :step_id, :action_id, :tool_id, :label, :scheduler_mode, :goal_profile, "
                ":host_ip, :port, :protocol, :service, :started_at, :finished_at, :runner_type, :exit_status, "
                ":stdout_ref, :stderr_ref, :artifact_refs_json, :approval_id, :observations_created_json, "
                ":graph_mutations_json, :operator_notes"
                ")"
            ), payload)
        else:
            session.execute(text(
                "UPDATE scheduler_execution_record SET "
                "step_id = :step_id, "
                "action_id = :action_id, "
                "tool_id = :tool_id, "
                "label = :label, "
                "scheduler_mode = :scheduler_mode, "
                "goal_profile = :goal_profile, "
                "host_ip = :host_ip, "
                "port = :port, "
                "protocol = :protocol, "
                "service = :service, "
                "started_at = :started_at, "
                "finished_at = :finished_at, "
                "runner_type = :runner_type, "
                "exit_status = :exit_status, "
                "stdout_ref = :stdout_ref, "
                "stderr_ref = :stderr_ref, "
                "artifact_refs_json = :artifact_refs_json, "
                "approval_id = :approval_id, "
                "observations_created_json = :observations_created_json, "
                "graph_mutations_json = :graph_mutations_json, "
                "operator_notes = :operator_notes "
                "WHERE execution_id = :execution_id"
            ), payload)

        session.commit()
        return payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_execution_records(database, limit: int = 200) -> List[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        max_items = max(1, min(int(limit), 1000))
        result = session.execute(text(
            "SELECT execution_id, step_id, action_id, tool_id, label, scheduler_mode, goal_profile, "
            "host_ip, port, protocol, service, started_at, finished_at, runner_type, exit_status, "
            "stdout_ref, stderr_ref, artifact_refs_json, approval_id, observations_created_json, "
            "graph_mutations_json, operator_notes "
            "FROM scheduler_execution_record ORDER BY id DESC LIMIT :limit"
        ), {"limit": max_items})
        rows = result.fetchall()
        keys = result.keys()
        payload = []
        for row in rows:
            item = dict(zip(keys, row))
            item["artifact_refs"] = _from_json(item.get("artifact_refs_json"))
            item["observations_created"] = _from_json(item.get("observations_created_json"))
            item["graph_mutations"] = _from_json(item.get("graph_mutations_json"))
            payload.append(item)
        return payload
    finally:
        session.close()


def get_execution_record(database, execution_id: str) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            "SELECT execution_id, step_id, action_id, tool_id, label, scheduler_mode, goal_profile, "
            "host_ip, port, protocol, service, started_at, finished_at, runner_type, exit_status, "
            "stdout_ref, stderr_ref, artifact_refs_json, approval_id, observations_created_json, "
            "graph_mutations_json, operator_notes "
            "FROM scheduler_execution_record WHERE execution_id = :execution_id LIMIT 1"
        ), {"execution_id": str(execution_id or "")})
        row = result.fetchone()
        if row is None:
            return None
        keys = result.keys()
        item = dict(zip(keys, row))
        item["artifact_refs"] = _from_json(item.get("artifact_refs_json"))
        item["observations_created"] = _from_json(item.get("observations_created_json"))
        item["graph_mutations"] = _from_json(item.get("graph_mutations_json"))
        return item
    finally:
        session.close()
