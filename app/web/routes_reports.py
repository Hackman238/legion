from __future__ import annotations

import os

from flask import Blueprint, after_this_request, current_app, jsonify, request, send_file

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.report_service import ReportService

reports_bp = Blueprint("reports_api", __name__)


def _report_service() -> ReportService:
    return ReportService(runtime_from_app())


def _download_response(payload):
    response = current_app.response_class(payload["body"], mimetype=payload["mimetype"])
    response.headers["Content-Disposition"] = f'attachment; filename="{payload["filename"]}"'
    return response


@reports_bp.get("/api/workspace/hosts/<int:host_id>/ai-report")
def workspace_host_ai_report(host_id: int):
    service = _report_service()
    try:
        return _download_response(service.export_host_ai_report(host_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@reports_bp.get("/api/workspace/hosts/<int:host_id>/report")
def workspace_host_report(host_id: int):
    service = _report_service()
    try:
        return _download_response(service.export_host_report(host_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@reports_bp.get("/api/workspace/ai-reports/download-zip")
def workspace_ai_reports_download_zip():
    service = _report_service()
    try:
        bundle_path, bundle_name = service.build_host_ai_reports_zip()
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


@reports_bp.get("/api/workspace/project-ai-report")
def workspace_project_ai_report():
    service = _report_service()
    try:
        return _download_response(service.export_project_ai_report(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@reports_bp.get("/api/workspace/project-report")
def workspace_project_report():
    service = _report_service()
    try:
        return _download_response(service.export_project_report(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@reports_bp.post("/api/workspace/project-ai-report/push")
def workspace_project_ai_report_push():
    service = _report_service()
    try:
        body, status_code = service.push_project_ai_report(request.get_json(silent=True) or {})
        return jsonify(body), status_code
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@reports_bp.post("/api/workspace/project-report/push")
def workspace_project_report_push():
    service = _report_service()
    try:
        body, status_code = service.push_project_report(request.get_json(silent=True) or {})
        return jsonify(body), status_code
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
