from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.tool_service import ToolService

tools_bp = Blueprint("tools_api", __name__)


def _tool_service() -> ToolService:
    return ToolService(runtime_from_app())


@tools_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@tools_bp.get("/api/workspace/tools")
def workspace_tools():
    service = _tool_service()
    try:
        return jsonify(service.list_workspace_tools(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@tools_bp.get("/api/workspace/tool-targets")
def workspace_tool_targets():
    service = _tool_service()
    try:
        return jsonify(service.list_workspace_tool_targets(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@tools_bp.post("/api/workspace/tools/run")
def workspace_tool_run():
    service = _tool_service()
    try:
        return jsonify(service.start_tool_run(request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
