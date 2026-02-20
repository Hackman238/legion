import json
import time

from flask import current_app


def register_websocket_routes(sock):
    @sock.route("/ws/snapshot")
    def snapshot_feed(ws):
        runtime = current_app.extensions["legion_runtime"]
        delay_seconds = float(current_app.config.get("LEGION_WS_SNAPSHOT_INTERVAL_SECONDS", 1.0))
        while True:
            try:
                payload = runtime.get_snapshot()
                ws.send(json.dumps(payload))
                time.sleep(delay_seconds)
            except Exception:
                break
