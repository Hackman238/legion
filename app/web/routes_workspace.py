from __future__ import annotations

import io

from flask import Blueprint, jsonify, request, send_file

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.workspace_service import WorkspaceService

workspace_bp = Blueprint("workspace_api", __name__)


def _workspace_service() -> WorkspaceService:
    return WorkspaceService(runtime_from_app())


@workspace_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@workspace_bp.get("/api/export/hosts-csv")
def export_hosts_csv():
    service = _workspace_service()
    try:
        payload = service.export_workspace_hosts_csv(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/export/hosts-json")
def export_hosts_json():
    service = _workspace_service()
    try:
        payload = service.export_workspace_hosts_json(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts")
def workspace_hosts():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_hosts(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/overview")
def workspace_overview():
    service = _workspace_service()
    try:
        return jsonify(service.get_workspace_overview())
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/services")
def workspace_services():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_services(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts/<int:host_id>")
def workspace_host_detail(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_host_workspace(host_id))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts/<int:host_id>/target-state")
def workspace_host_target_state(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_host_target_state(host_id))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/findings")
def workspace_findings():
    service = _workspace_service()
    try:
        return jsonify(service.list_findings(request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)

