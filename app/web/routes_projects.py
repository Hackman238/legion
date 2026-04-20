from __future__ import annotations

import os
import tempfile

from flask import Blueprint, after_this_request, jsonify, request, send_file

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.project_service import ProjectService

projects_bp = Blueprint("projects_api", __name__)


def _project_service() -> ProjectService:
    return ProjectService(runtime_from_app())


@projects_bp.get("/api/project")
def project_details():
    return jsonify(_project_service().get_details())


@projects_bp.get("/api/projects")
def project_list():
    service = _project_service()
    try:
        return jsonify(service.list_projects(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@projects_bp.post("/api/project/new-temp")
def project_new_temp():
    service = _project_service()
    try:
        return jsonify(service.create_new_temp())
    except RuntimeError as exc:
        return json_error(str(exc), 409)
    except Exception as exc:
        return json_error(str(exc), 500)


@projects_bp.post("/api/project/open")
def project_open():
    service = _project_service()
    try:
        return jsonify(service.open_project(request.get_json(silent=True) or {}))
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except RuntimeError as exc:
        return json_error(str(exc), 409)
    except Exception as exc:
        return json_error(str(exc), 500)


@projects_bp.post("/api/project/save-as")
def project_save_as():
    service = _project_service()
    try:
        body, status_code = service.save_project_as(request.get_json(silent=True) or {})
        return jsonify(body), status_code
    except ValueError as exc:
        return json_error(str(exc), 400)
    except RuntimeError as exc:
        return json_error(str(exc), 409)
    except Exception as exc:
        return json_error(str(exc), 500)


@projects_bp.get("/api/project/download-zip")
def project_download_zip():
    runtime = runtime_from_app()
    try:
        bundle_path, bundle_name = runtime.build_project_bundle_zip()
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)

    @after_this_request
    def _cleanup(response):
        try:
            if os.path.isfile(bundle_path):
                os.remove(bundle_path)
        except Exception:
            pass
        return response

    return send_file(
        bundle_path,
        as_attachment=True,
        download_name=bundle_name,
        mimetype="application/zip",
        max_age=0,
    )


@projects_bp.post("/api/project/restore-zip")
def project_restore_zip():
    runtime = runtime_from_app()
    uploaded = request.files.get("bundle")
    if uploaded is None:
        return json_error("Field 'bundle' is required.", 400)

    filename = str(getattr(uploaded, "filename", "") or "").strip()
    if not filename:
        return json_error("Uploaded bundle filename is required.", 400)

    temp_file = tempfile.NamedTemporaryFile(prefix="legion-restore-upload-", suffix=".zip", delete=False)
    temp_path = temp_file.name
    temp_file.close()

    def _remove_temp_upload():
        try:
            if os.path.isfile(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

    try:
        uploaded.save(temp_path)
    except Exception as exc:
        _remove_temp_upload()
        return json_error(f"Failed to save uploaded ZIP: {exc}", 400)

    try:
        if hasattr(runtime, "start_restore_project_zip_job"):
            job = runtime.start_restore_project_zip_job(temp_path)
            return jsonify({"status": "accepted", "job": job}), 202

        if hasattr(runtime, "restore_project_bundle_zip"):
            result = runtime.restore_project_bundle_zip(temp_path)
            _remove_temp_upload()
            return jsonify({"status": "ok", "project": result.get("project", {}), "result": result}), 200

        _remove_temp_upload()
        return json_error("Runtime does not support ZIP restore.", 501)
    except FileNotFoundError as exc:
        _remove_temp_upload()
        return json_error(str(exc), 404)
    except ValueError as exc:
        _remove_temp_upload()
        return json_error(str(exc), 400)
    except RuntimeError as exc:
        _remove_temp_upload()
        return json_error(str(exc), 409)
    except Exception as exc:
        _remove_temp_upload()
        return json_error(str(exc), 500)
