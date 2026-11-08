import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.models import ExecutionRecord, PlanStep
from app.scheduler.schema_cache import ensure_schema_once, ensure_column

logger = logging.getLogger(__name__)


_ensure_column = ensure_column


def _ensure_table(session):
    ensure_schema_once(session, "execution_record", _ensure_table_uncached, ["scheduler_execution_record"])


def _ensure_table_uncached(session):
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
    payload: Dict[str, Any] = {}
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
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    try:
        from app.scheduler.graph import sync_execution_record_to_evidence_graph

        mutations = sync_execution_record_to_evidence_graph(
            database,
            execution_record=record,
            step=step,
            host_ip=str(host_ip or ""),
            port=str(port or ""),
            protocol=str(protocol or ""),
            service=str(service or ""),
        )
        if mutations:
            record.graph_mutations = list(mutations)
            payload["graph_mutations_json"] = _to_json(mutations)
            payload["graph_mutations"] = list(mutations)
            patch_session = database.session()
            try:
                _ensure_table(patch_session)
                patch_session.execute(text(
                    "UPDATE scheduler_execution_record SET graph_mutations_json = :graph_mutations_json "
                    "WHERE execution_id = :execution_id"
                ), {
                    "graph_mutations_json": payload["graph_mutations_json"],
                    "execution_id": payload["execution_id"],
                })
                patch_session.commit()
            except Exception:
                patch_session.rollback()
                logger.warning(
                    "Failed to store graph mutations for execution %s.", payload.get("execution_id", ""),
                    exc_info=True,
                )
            finally:
                patch_session.close()
    except Exception:
        logger.warning(
            "Failed to sync execution %s to evidence graph.", payload.get("execution_id", ""),
            exc_info=True,
        )
    return payload


def list_execution_records(
        database,
        limit: int = 200,
        host_ip: Optional[str] = None,
        tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Newest execution records first; host_ip / tool_id filters are applied before the limit."""
    session = database.session()
    try:
        _ensure_table(session)
        max_items = max(1, min(int(limit), 1000))
        params: Dict[str, Any] = {"limit": max_items}
        clauses = []
        if host_ip is not None:
            clauses.append("TRIM(COALESCE(host_ip, '')) = :host_ip")
            params["host_ip"] = str(host_ip or "").strip()
        if tool_id is not None:
            clauses.append("LOWER(TRIM(COALESCE(tool_id, ''))) = :tool_id")
            params["tool_id"] = str(tool_id or "").strip().lower()
        where_clause = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        result = session.execute(text(
            "SELECT execution_id, step_id, action_id, tool_id, label, scheduler_mode, goal_profile, "
            "host_ip, port, protocol, service, started_at, finished_at, runner_type, exit_status, "
            "stdout_ref, stderr_ref, artifact_refs_json, approval_id, observations_created_json, "
            "graph_mutations_json, operator_notes "
            "FROM scheduler_execution_record "
            f"{where_clause}"
            "ORDER BY id DESC LIMIT :limit"
        ), params)
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
