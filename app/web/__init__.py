from typing import TYPE_CHECKING

from flask import Flask

from app.ApplicationInfo import applicationInfo

try:
    from flask_sock import Sock
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    Sock = None

from app.web.routes import web_bp
from app.web.ws import register_websocket_routes

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from app.web.runtime import WebRuntime


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
    app.config["LEGION_UI_OPAQUE"] = False
    app.extensions["legion_runtime"] = runtime

    @app.context_processor
    def inject_legion_runtime_flags():
        return {
            "legion_web_bind_host": app.config.get("LEGION_WEB_BIND_HOST", "127.0.0.1"),
            "legion_web_bind_label": app.config.get("LEGION_WEB_BIND_LABEL", "Localhost only"),
            "legion_ui_opaque": bool(app.config.get("LEGION_UI_OPAQUE", False)),
            "legion_version_label": f"v{applicationInfo.get('version', '0.0.0')}",
        }

    app.register_blueprint(web_bp)

    if Sock is not None:
        sock = Sock(app)
        register_websocket_routes(sock)
        app.config["LEGION_WEBSOCKETS_ENABLED"] = True
    else:
        app.config["LEGION_WEBSOCKETS_ENABLED"] = False
    return app
