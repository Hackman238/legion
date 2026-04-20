from __future__ import annotations

import io
import os

from flask import Blueprint, jsonify, request, send_file, send_from_directory

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.workspace_service import WorkspaceService

workspace_bp = Blueprint("workspace_api", __name__)


def _workspace_service() -> WorkspaceService:
    return WorkspaceService(runtime_from_app())


@workspace_bp.after_request
def _disable_cache(response):
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@workspace_bp.get("/api/workspace/credential-capture")
def workspace_credential_capture_state():
    service = _workspace_service()
    try:
        return jsonify(service.get_credential_capture_state())
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/credential-capture/config")
def workspace_credential_capture_config_save():
    service = _workspace_service()
    try:
        return jsonify(service.save_credential_capture_config(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/credential-capture/start")
def workspace_credential_capture_start():
    service = _workspace_service()
    try:
        return jsonify(service.start_credential_capture(request.get_json(silent=True) or {})), 202
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/credential-capture/stop")
def workspace_credential_capture_stop():
    service = _workspace_service()
    try:
        return jsonify(service.stop_credential_capture(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/credential-capture/log")
def workspace_credential_capture_log_download():
    service = _workspace_service()
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


@workspace_bp.get("/api/workspace/credentials")
def workspace_credentials():
    service = _workspace_service()
    try:
        return jsonify(service.list_credentials(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/credentials/download")
def workspace_credentials_download():
    service = _workspace_service()
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


@workspace_bp.get("/api/export/hosts-csv")
def export_hosts_csv():
    service = _workspace_service()
    try:
        payload = service.export_workspace_hosts_csv(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/export/hosts-json")
def export_hosts_json():
    service = _workspace_service()
    try:
        payload = service.export_workspace_hosts_json(request.args)
        buffer = io.BytesIO(payload["body"])
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype=payload["mimetype"],
            as_attachment=True,
            download_name=payload["filename"],
        )
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts")
def workspace_hosts():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_hosts(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/overview")
def workspace_overview():
    service = _workspace_service()
    try:
        return jsonify(service.get_workspace_overview())
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/services")
def workspace_services():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_services(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/tools")
def workspace_tools():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_tools(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/tool-targets")
def workspace_tool_targets():
    service = _workspace_service()
    try:
        return jsonify(service.list_workspace_tool_targets(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts/<int:host_id>")
def workspace_host_detail(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_host_workspace(host_id))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/hosts/<int:host_id>/target-state")
def workspace_host_target_state(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_host_target_state(host_id))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/findings")
def workspace_findings():
    service = _workspace_service()
    try:
        return jsonify(service.list_findings(request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/screenshots/<path:filename>")
def workspace_screenshot(filename):
    service = _workspace_service()
    try:
        file_path = service.get_screenshot_file(filename)
    except FileNotFoundError:
        return json_error("Screenshot not found.", 404)
    except Exception as exc:
        return json_error(str(exc), 400)
    directory = os.path.dirname(file_path)
    basename = os.path.basename(file_path)
    return send_from_directory(directory, basename, as_attachment=False)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/refresh-screenshots")
def workspace_host_refresh_screenshots(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.refresh_host_screenshots(host_id)), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/screenshots/refresh")
def workspace_graph_screenshot_refresh():
    service = _workspace_service()
    try:
        return jsonify(service.refresh_graph_screenshot(request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/screenshots/delete")
def workspace_graph_screenshot_delete():
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_graph_screenshot(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/ports/delete")
def workspace_port_delete():
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_workspace_port(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/services/delete")
def workspace_service_delete():
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_workspace_service(request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/note")
def workspace_host_note(host_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.update_host_note(host_id, request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/categories")
def workspace_host_categories(host_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.update_host_categories(host_id, request.get_json(silent=True) or {})})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/scripts")
def workspace_host_script_create(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.create_script_entry(host_id, request.get_json(silent=True) or {}))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.delete("/api/workspace/scripts/<int:script_id>")
def workspace_host_script_delete(script_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_script_entry(script_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/workspace/scripts/<int:script_id>/output")
def workspace_host_script_output(script_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_script_output(script_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/cves")
def workspace_host_cve_create(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.create_cve_entry(host_id, request.get_json(silent=True) or {}))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.delete("/api/workspace/cves/<int:cve_id>")
def workspace_host_cve_delete(cve_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_cve_entry(cve_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/hosts/<int:host_id>/dig-deeper")
def workspace_host_dig_deeper(host_id):
    service = _workspace_service()
    try:
        return jsonify(service.start_host_dig_deeper(host_id)), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.delete("/api/workspace/hosts/<int:host_id>")
def workspace_host_remove(host_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.delete_host_workspace(host_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/workspace/tools/run")
def workspace_tool_run():
    service = _workspace_service()
    try:
        return jsonify(service.start_tool_run(request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/processes/<int:process_id>/kill")
def workspace_process_kill(process_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.kill_process(process_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/processes/<int:process_id>/retry")
def workspace_process_retry(process_id):
    service = _workspace_service()
    try:
        return jsonify(service.retry_process(process_id, request.get_json(silent=True) or {})), 202
    except KeyError as exc:
        return json_error(str(exc), 404)
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/processes/<int:process_id>/close")
def workspace_process_close(process_id):
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.close_process(process_id)})
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.post("/api/processes/clear")
def workspace_process_clear():
    service = _workspace_service()
    try:
        return jsonify({"status": "ok", **service.clear_processes(request.get_json(silent=True) or {})})
    except Exception as exc:
        return json_error(str(exc), 500)


@workspace_bp.get("/api/processes/<int:process_id>/output")
def workspace_process_output(process_id):
    service = _workspace_service()
    try:
        return jsonify(service.get_process_output(process_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)
