from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.runtime_service import RuntimeService

runtime_bp = Blueprint("runtime_api", __name__)


def _runtime_service() -> RuntimeService:
    return RuntimeService(runtime_from_app())


@runtime_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@runtime_bp.get("/api/snapshot")
def snapshot():
    service = _runtime_service()
    try:
        return jsonify(service.get_snapshot())
    except Exception as exc:
        return json_error(str(exc), 500)


@runtime_bp.get("/api/jobs")
def jobs():
    service = _runtime_service()
    try:
        return jsonify(service.list_jobs(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@runtime_bp.get("/api/processes")
def processes():
    service = _runtime_service()
    try:
        return jsonify(service.list_processes(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@runtime_bp.get("/api/jobs/<int:job_id>")
def job_details(job_id):
    service = _runtime_service()
    try:
        return jsonify(service.get_job(job_id))
    except KeyError:
        return json_error(f"Unknown job id: {job_id}", 404)


@runtime_bp.post("/api/jobs/<int:job_id>/stop")
def job_stop(job_id):
    service = _runtime_service()
    try:
        return jsonify({"status": "ok", **service.stop_job(job_id)})
    except KeyError:
        return json_error(f"Unknown job id: {job_id}", 404)
    except Exception as exc:
        return json_error(str(exc), 500)
