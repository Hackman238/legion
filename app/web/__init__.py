from typing import TYPE_CHECKING

from flask import Flask, jsonify, request

from app.ApplicationInfo import applicationInfo

try:
    from flask_sock import Sock
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    Sock = None

from app.web.routes_graph import graph_bp
from app.web.routes_credentials import credentials_bp
from app.web.routes_host_actions import host_actions_bp
from app.web.routes_processes import processes_bp
from app.web.routes_reports import reports_bp
from app.web.routes import web_bp
from app.web.routes_projects import projects_bp
from app.web.routes_runtime import runtime_bp
from app.web.routes_scans import scans_bp
from app.web.routes_scheduler import scheduler_bp
from app.web.routes_screenshots import screenshots_bp
from app.web.routes_settings import settings_bp
from app.web.routes_tools import tools_bp
from app.web.routes_workspace import workspace_bp
from app.web.ws import register_websocket_routes

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from app.web.runtime import WebRuntime


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _request_host_name(host_header: str) -> str:
    value = str(host_header or "").strip().lower()
    if value.startswith("["):
        return value.split("]", 1)[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def request_is_cross_site(method: str, headers, request_host: str) -> bool:
    """True for a state-changing request that a browser sent from another origin.

    A hostile page can auto-submit a form (or a multipart fetch) at the local Legion port; browsers always add
    Origin and Sec-Fetch-Site to such requests, while same-origin page scripts and non-browser clients (curl,
    scripts) either send a matching Origin or none at all.
    """
    if str(method or "").upper() not in _STATE_CHANGING_METHODS:
        return False
    fetch_site = str(headers.get("Sec-Fetch-Site", "") or "").strip().lower()
    if fetch_site in {"cross-site", "same-site"}:
        return True
    origin = str(headers.get("Origin", "") or "").strip().lower()
    if not origin or origin == "null":
        return bool(origin)  # "null" origin (sandboxed frame / file page) is never same-origin
    origin_host = origin.split("://", 1)[-1].split("/", 1)[0]
    return _request_host_name(origin_host) != _request_host_name(request_host)


def request_host_is_rebound(bind_host: str, request_host: str) -> bool:
    """DNS rebinding check: a loopback-only server must only be addressed as localhost."""
    if str(bind_host or "").strip() not in {"127.0.0.1", "localhost", "::1"}:
        return False
    return _request_host_name(request_host) not in _LOOPBACK_HOSTS


def install_request_guards(app: Flask) -> None:
    @app.before_request
    def _reject_cross_site_requests():
        bind_host = str(app.config.get("LEGION_WEB_BIND_HOST", "127.0.0.1") or "127.0.0.1")
        if request_host_is_rebound(bind_host, request.host):
            return jsonify({"status": "error", "error": "Host header does not match the local interface."}), 403
        if request_is_cross_site(request.method, request.headers, request.host):
            return jsonify({"status": "error", "error": "Cross-site requests are not accepted."}), 403
        return None

    def _json_http_error(error):
        if request.path.startswith("/api/") or request.path.startswith("/ws/"):
            code = int(getattr(error, "code", 500) or 500)
            message = str(getattr(error, "description", "") or getattr(error, "name", "") or "Request failed.")
            if code == 413:
                message = "Upload too large."
            return jsonify({"status": "error", "error": message}), code
        return error

    for status_code in (404, 405, 413, 500):
        app.register_error_handler(status_code, _json_http_error)


def create_app(runtime: "WebRuntime") -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["LEGION_WS_EVENT_HEARTBEAT_SECONDS"] = 30.0
    app.config["LEGION_AUTH_ENABLED"] = False
    app.config["LEGION_WEB_BIND_HOST"] = "127.0.0.1"
    app.config["LEGION_WEB_BIND_LABEL"] = "Localhost only"
    app.config["LEGION_UI_OPAQUE"] = True
    app.config["LEGION_COLORFUL_ASCII_BACKGROUND"] = False
    app.extensions["legion_runtime"] = runtime
    # Project bundles (ZIP with screenshots/tool output) can be large, but not unbounded: a runaway upload must
    # not fill the temp partition before the restore job even starts.
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024
    install_request_guards(app)

    @app.context_processor
    def inject_legion_runtime_flags():
        return {
            "legion_web_bind_host": app.config.get("LEGION_WEB_BIND_HOST", "127.0.0.1"),
            "legion_web_bind_label": app.config.get("LEGION_WEB_BIND_LABEL", "Localhost only"),
            "legion_ui_opaque": bool(app.config.get("LEGION_UI_OPAQUE", False)),
            "legion_colorful_ascii_background": bool(app.config.get("LEGION_COLORFUL_ASCII_BACKGROUND", False)),
            "legion_version_label": f"v{applicationInfo.get('version', '0.0.0')}",
        }

    app.register_blueprint(web_bp)
    app.register_blueprint(runtime_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(workspace_bp)
    app.register_blueprint(credentials_bp)
    app.register_blueprint(screenshots_bp)
    app.register_blueprint(host_actions_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(processes_bp)
    app.register_blueprint(scheduler_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(reports_bp)

    if Sock is not None:
        sock = Sock(app)
        register_websocket_routes(sock)
        app.config["LEGION_WEBSOCKETS_ENABLED"] = True
    else:
        app.config["LEGION_WEBSOCKETS_ENABLED"] = False
    return app
