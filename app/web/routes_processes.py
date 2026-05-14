from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.process_service import ProcessService

processes_bp = Blueprint("processes_api", __name__)


def _process_service() -> ProcessService:
    return ProcessService(runtime_from_app())


@processes_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@processes_bp.post("/api/processes/<int:process_id>/kill")
def process_kill(process_id):
    service = _process_service()
    try:
        return jsonify({"status": "ok", **service.kill_process(process_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@processes_bp.post("/api/processes/<int:process_id>/retry")
def process_retry(process_id):
    service = _process_service()
    try:
        return jsonify(service.retry_process(process_id, request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@processes_bp.post("/api/processes/<int:process_id>/close")
def process_close(process_id):
    service = _process_service()
    try:
        return jsonify({"status": "ok", **service.close_process(process_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@processes_bp.post("/api/processes/clear")
def process_clear():
    service = _process_service()
    try:
        return jsonify({"status": "ok", **service.clear_processes(request.get_json(silent=True) or {})})
    except Exception as exc:
        return json_error(str(exc), 500)


@processes_bp.get("/api/processes/<int:process_id>/output")
def process_output(process_id):
    service = _process_service()
    try:
        return jsonify(service.get_process_output(process_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)
