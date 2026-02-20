from flask import Flask

try:
    from flask_sock import Sock
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    Sock = None

from app.web.routes import web_bp
from app.web.runtime import WebRuntime
from app.web.ws import register_websocket_routes


def create_app(runtime: WebRuntime) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["LEGION_WS_SNAPSHOT_INTERVAL_SECONDS"] = 1.0
    app.config["LEGION_AUTH_ENABLED"] = False
    app.extensions["legion_runtime"] = runtime

    app.register_blueprint(web_bp)

    if Sock is not None:
        sock = Sock(app)
        register_websocket_routes(sock)
        app.config["LEGION_WEBSOCKETS_ENABLED"] = True
    else:
        app.config["LEGION_WEBSOCKETS_ENABLED"] = False
    return app
