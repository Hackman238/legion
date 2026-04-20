from __future__ import annotations

from flask import current_app, jsonify


def as_bool(value, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def clamp_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        resolved = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        resolved = int(default)
    return max(int(minimum), min(int(maximum), resolved))


def json_error(message: str, status_code: int = 400):
    return jsonify({"status": "error", "error": str(message)}), int(status_code)


def runtime_from_app():
    return current_app.extensions["legion_runtime"]
