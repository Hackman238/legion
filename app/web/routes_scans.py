from __future__ import annotations

import os
import re
import tempfile

from flask import Blueprint, jsonify, request

from app.web.http_utils import as_bool, json_error, runtime_from_app
from app.web.services.scan_service import ScanService

scans_bp = Blueprint("scans_api", __name__)


def _scan_service() -> ScanService:
    return ScanService(runtime_from_app())


@scans_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    return response


@scans_bp.post("/api/targets/import-file")
def import_targets():
    service = _scan_service()
    try:
        return jsonify(service.import_targets(request.get_json(silent=True) or {})), 202
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


def _save_upload(field: str, *, suffix: str, prefix: str):
    """Store an uploaded file next to the project's running folder (falls back to the temp dir); returns its path."""
    uploaded = request.files.get(field)
    if uploaded is None:
        raise ValueError(f"Field '{field}' (multipart file) is required.")
    original = os.path.basename(str(getattr(uploaded, "filename", "") or "").strip()) or f"upload{suffix}"
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", original)[:120]
    runtime = runtime_from_app()
    target_dir = ""
    try:
        project = getattr(runtime.logic, "activeProject", None)
        target_dir = str(getattr(getattr(project, "properties", None), "runningFolder", "") or "")
    except Exception:
        target_dir = ""
    if not target_dir or not os.path.isdir(target_dir):
        target_dir = tempfile.gettempdir()
    handle = tempfile.NamedTemporaryFile(prefix=f"{prefix}-", suffix=f"-{safe_name}", dir=target_dir, delete=False)
    path = handle.name
    handle.close()
    uploaded.save(path)
    return path


@scans_bp.post("/api/nmap/import-xml-upload")
def import_nmap_xml_upload():
    """Multipart variant of /api/nmap/import-xml for operators whose browser is not on the Legion host."""
    service = _scan_service()
    try:
        path = _save_upload("file", suffix=".xml", prefix="uploaded-nmap")
        run_actions = as_bool(request.form.get("run_actions", "false"), default=False)
        return jsonify(service.import_nmap_xml({"path": path, "run_actions": run_actions})), 202
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/targets/import-upload")
def import_targets_upload():
    service = _scan_service()
    try:
        path = _save_upload("file", suffix=".txt", prefix="uploaded-targets")
        return jsonify(service.import_targets({"path": path})), 202
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/nmap/import-xml")
def import_nmap_xml():
    service = _scan_service()
    try:
        return jsonify(service.import_nmap_xml(request.get_json(silent=True) or {})), 202
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/nmap/scan")
def nmap_scan():
    service = _scan_service()
    try:
        return jsonify(service.nmap_scan(request.get_json(silent=True) or {})), 202
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.get("/api/network/interfaces")
def network_interfaces():
    service = _scan_service()
    try:
        return jsonify(service.get_network_interfaces())
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/scan/passive-capture")
def passive_capture_scan():
    service = _scan_service()
    try:
        return jsonify(service.passive_capture(request.get_json(silent=True) or {})), 202
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/workspace/hosts/<int:host_id>/rescan")
def workspace_host_rescan(host_id):
    service = _scan_service()
    try:
        return jsonify(service.host_rescan(host_id)), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.post("/api/workspace/subnets/rescan")
def workspace_subnet_rescan():
    service = _scan_service()
    try:
        return jsonify(service.subnet_rescan(request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@scans_bp.get("/api/scans/history")
def scan_history():
    service = _scan_service()
    try:
        return jsonify(service.scan_history(request.args.get("limit", 100)))
    except Exception as exc:
        return json_error(str(exc), 500)
