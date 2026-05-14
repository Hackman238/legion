from __future__ import annotations

import io

from flask import Blueprint, jsonify, request, send_file

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.credential_service import CredentialService

credentials_bp = Blueprint("credentials_api", __name__)


def _credential_service() -> CredentialService:
    return CredentialService(runtime_from_app())


@credentials_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@credentials_bp.get("/api/workspace/credential-capture")
def workspace_credential_capture_state():
    service = _credential_service()
    try:
        return jsonify(service.get_credential_capture_state())
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.post("/api/workspace/credential-capture/config")
def workspace_credential_capture_config_save():
    service = _credential_service()
    try:
        return jsonify(service.save_credential_capture_config(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.post("/api/workspace/credential-capture/start")
def workspace_credential_capture_start():
    service = _credential_service()
    try:
        return jsonify(service.start_credential_capture(request.get_json(silent=True) or {})), 202
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.post("/api/workspace/credential-capture/stop")
def workspace_credential_capture_stop():
    service = _credential_service()
    try:
        return jsonify(service.stop_credential_capture(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.get("/api/workspace/credential-capture/log")
def workspace_credential_capture_log_download():
    service = _credential_service()
    try:
        payload = service.download_credential_capture_log(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.get("/api/workspace/credentials")
def workspace_credentials():
    service = _credential_service()
    try:
        return jsonify(service.list_credentials(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@credentials_bp.get("/api/workspace/credentials/download")
def workspace_credentials_download():
    service = _credential_service()
    try:
        payload = service.download_credentials(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
