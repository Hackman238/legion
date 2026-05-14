from __future__ import annotations

import os

from flask import Blueprint, jsonify, request, send_from_directory

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.screenshot_service import ScreenshotService

screenshots_bp = Blueprint("screenshots_api", __name__)


def _screenshot_service() -> ScreenshotService:
    return ScreenshotService(runtime_from_app())


@screenshots_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@screenshots_bp.get("/api/screenshots/<path:filename>")
def workspace_screenshot(filename):
    service = _screenshot_service()
    try:
        file_path = service.get_screenshot_file(filename)
    except FileNotFoundError:
        return json_error("Screenshot not found.", 404)
    except Exception as exc:
        return json_error(str(exc), 400)
    directory = os.path.dirname(file_path)
    basename = os.path.basename(file_path)
    return send_from_directory(directory, basename, as_attachment=False)


@screenshots_bp.post("/api/workspace/hosts/<int:host_id>/refresh-screenshots")
def workspace_host_refresh_screenshots(host_id):
    service = _screenshot_service()
    try:
        return jsonify(service.refresh_host_screenshots(host_id)), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@screenshots_bp.post("/api/workspace/screenshots/refresh")
def workspace_graph_screenshot_refresh():
    service = _screenshot_service()
    try:
        return jsonify(service.refresh_graph_screenshot(request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@screenshots_bp.post("/api/workspace/screenshots/delete")
def workspace_graph_screenshot_delete():
    service = _screenshot_service()
    try:
        return jsonify({"status": "ok", **service.delete_graph_screenshot(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
