import json

from flask import current_app


def register_websocket_routes(sock):
    @sock.route("/ws/snapshot")
    def snapshot_feed(ws):
        runtime = current_app.extensions["legion_runtime"]
        cursor = 0
        timeout_seconds = float(current_app.config.get("LEGION_WS_EVENT_HEARTBEAT_SECONDS", 30.0))
        while True:
            try:
                payload = runtime.wait_for_ui_event(after_seq=cursor, timeout_seconds=timeout_seconds)
                cursor = max(cursor, int(payload.get("seq", cursor) or cursor))
                ws.send(json.dumps(payload))
            except Exception:
                break
