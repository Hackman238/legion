from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.host_action_service import HostActionService

host_actions_bp = Blueprint("host_actions_api", __name__)


def _host_action_service() -> HostActionService:
    return HostActionService(runtime_from_app())


@host_actions_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@host_actions_bp.post("/api/workspace/ports/delete")
def workspace_port_delete():
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.delete_workspace_port(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/services/delete")
def workspace_service_delete():
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.delete_workspace_service(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/hosts/<int:host_id>/note")
def workspace_host_note(host_id):
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.update_host_note(host_id, request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/hosts/<int:host_id>/categories")
def workspace_host_categories(host_id):
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.update_host_categories(host_id, request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/hosts/<int:host_id>/scripts")
def workspace_host_script_create(host_id):
    service = _host_action_service()
    try:
        return jsonify(service.create_script_entry(host_id, request.get_json(silent=True) or {}))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.delete("/api/workspace/scripts/<int:script_id>")
def workspace_host_script_delete(script_id):
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.delete_script_entry(script_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.get("/api/workspace/scripts/<int:script_id>/output")
def workspace_host_script_output(script_id):
    service = _host_action_service()
    try:
        return jsonify(service.get_script_output(script_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/hosts/<int:host_id>/cves")
def workspace_host_cve_create(host_id):
    service = _host_action_service()
    try:
        return jsonify(service.create_cve_entry(host_id, request.get_json(silent=True) or {}))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.delete("/api/workspace/cves/<int:cve_id>")
def workspace_host_cve_delete(cve_id):
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.delete_cve_entry(cve_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.post("/api/workspace/hosts/<int:host_id>/dig-deeper")
def workspace_host_dig_deeper(host_id):
    service = _host_action_service()
    try:
        return jsonify(service.start_host_dig_deeper(host_id)), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@host_actions_bp.delete("/api/workspace/hosts/<int:host_id>")
def workspace_host_remove(host_id):
    service = _host_action_service()
    try:
        return jsonify({"status": "ok", **service.delete_host_workspace(host_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)
