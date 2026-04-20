from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.scheduler_service import SchedulerService

scheduler_bp = Blueprint("scheduler_api", __name__)


def _scheduler_service() -> SchedulerService:
    return SchedulerService(runtime_from_app())


@scheduler_bp.post("/api/scheduler/run")
def scheduler_run():
    service = _scheduler_service()
    try:
        body, status_code = service.start_run()
        return jsonify(body), status_code
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/preferences")
def scheduler_preferences():
    service = _scheduler_service()
    return jsonify(service.get_preferences())


@scheduler_bp.post("/api/scheduler/preferences")
def scheduler_preferences_update():
    service = _scheduler_service()
    try:
        return jsonify(service.update_preferences(request.get_json(silent=True) or {}))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.post("/api/scheduler/provider/test")
def scheduler_provider_test():
    service = _scheduler_service()
    try:
        return jsonify(service.test_provider(request.get_json(silent=True) or {}))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/engagement-policy")
def engagement_policy_get():
    service = _scheduler_service()
    return jsonify(service.get_engagement_policy())


@scheduler_bp.post("/api/engagement-policy")
def engagement_policy_update():
    service = _scheduler_service()
    try:
        return jsonify(service.update_engagement_policy(request.get_json(silent=True) or {}))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/provider/logs")
def scheduler_provider_logs():
    service = _scheduler_service()
    try:
        return jsonify(service.get_provider_logs(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.post("/api/scheduler/approve-family")
def scheduler_approve_family():
    service = _scheduler_service()
    try:
        return jsonify(service.approve_family(request.get_json(silent=True) or {}))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/decisions")
def scheduler_decisions():
    service = _scheduler_service()
    try:
        return jsonify(service.get_decisions(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/plan-preview")
def scheduler_plan_preview():
    service = _scheduler_service()
    try:
        return jsonify(service.get_plan_preview(request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/approvals")
def scheduler_approvals():
    service = _scheduler_service()
    try:
        return jsonify(service.list_approvals(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.post("/api/scheduler/approvals/<int:approval_id>/approve")
def scheduler_approval_approve(approval_id: int):
    service = _scheduler_service()
    try:
        body, status_code = service.approve_approval(approval_id, request.get_json(silent=True) or {})
        return jsonify(body), status_code
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.post("/api/scheduler/approvals/<int:approval_id>/reject")
def scheduler_approval_reject(approval_id: int):
    service = _scheduler_service()
    try:
        return jsonify(service.reject_approval(approval_id, request.get_json(silent=True) or {}))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/executions")
def scheduler_execution_traces():
    service = _scheduler_service()
    try:
        return jsonify(service.list_executions(request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@scheduler_bp.get("/api/scheduler/executions/<string:execution_id>")
def scheduler_execution_trace(execution_id: str):
    service = _scheduler_service()
    try:
        return jsonify(service.get_execution_trace(execution_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)
