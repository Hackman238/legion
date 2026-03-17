from typing import TYPE_CHECKING

from flask import Flask

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
    app.config["LEGION_WS_SNAPSHOT_INTERVAL_SECONDS"] = 1.0
    app.config["LEGION_AUTH_ENABLED"] = False
    app.config["LEGION_WEB_BIND_HOST"] = "127.0.0.1"
    app.config["LEGION_WEB_BIND_LABEL"] = "Localhost only"
    app.extensions["legion_runtime"] = runtime

    @app.context_processor
    def inject_legion_runtime_flags():
        return {
            "legion_web_bind_host": app.config.get("LEGION_WEB_BIND_HOST", "127.0.0.1"),
            "legion_web_bind_label": app.config.get("LEGION_WEB_BIND_LABEL", "Localhost only"),
        }

    app.register_blueprint(web_bp)

    if Sock is not None:
        sock = Sock(app)
        register_websocket_routes(sock)
        app.config["LEGION_WEBSOCKETS_ENABLED"] = True
    else:
        app.config["LEGION_WEBSOCKETS_ENABLED"] = False
    return app
