from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.settings_service import SettingsService

settings_bp = Blueprint("settings_api", __name__)


def _settings_service() -> SettingsService:
    return SettingsService(runtime_from_app())


@settings_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@settings_bp.get("/api/settings/legion-conf")
def settings_legion_conf_get():
    service = _settings_service()
    try:
        return jsonify(service.get_legion_conf())
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.post("/api/settings/legion-conf")
def settings_legion_conf_save():
    service = _settings_service()
    try:
        return jsonify(service.save_legion_conf(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.get("/api/settings/display")
def settings_display_get():
    service = _settings_service()
    try:
        return jsonify(service.get_display_settings())
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.post("/api/settings/display")
def settings_display_save():
    service = _settings_service()
    try:
        payload = service.save_display_settings(request.get_json(silent=True) or {})
        current_app.config["LEGION_COLORFUL_ASCII_BACKGROUND"] = bool(
            payload.get("colorful_ascii_background", False)
        )
        return jsonify(payload)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.get("/api/settings/tool-audit")
def settings_tool_audit():
    service = _settings_service()
    try:
        return jsonify(service.get_tool_audit())
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.get("/api/settings/tool-audit/install-plan")
def settings_tool_audit_install_plan():
    service = _settings_service()
    try:
        return jsonify(service.get_tool_install_plan(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@settings_bp.post("/api/settings/tool-audit/install")
def settings_tool_audit_install():
    service = _settings_service()
    try:
        return jsonify(service.start_tool_install(request.get_json(silent=True) or {})), 202
    except NotImplementedError as exc:
        return json_error(str(exc), 501)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
