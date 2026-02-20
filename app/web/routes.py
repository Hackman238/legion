import csv
import datetime
import io
import json
import os
import re
import tempfile

from flask import (
    Blueprint,
    after_this_request,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory,
)

from app.ApplicationInfo import getConsoleLogo
from app.settings import AppSettings, Settings

web_bp = Blueprint("web", __name__)
_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _as_bool(value, default=False):
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


def _json_error(message: str, status_code: int = 400):
    return jsonify({"status": "error", "error": str(message)}), int(status_code)


def _get_sanitized_console_logo() -> str:
    try:
        raw = str(getConsoleLogo() or "")
    except Exception:
        return ""
    cleaned = _ANSI_ESCAPE_RE.sub("", raw)
    lines = [line.rstrip() for line in cleaned.splitlines()]
    return "\n".join(lines).strip("\n")


def _build_csv_export(snapshot):
    output = io.StringIO()
    writer = csv.writer(output)

    def write_key_value_section(title, data):
        writer.writerow([title])
        writer.writerow(["key", "value"])
        for key, value in (data or {}).items():
            writer.writerow([str(key), json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value)])
        writer.writerow([])

    def write_table_section(title, rows, headers):
        writer.writerow([title])
        writer.writerow(headers)
        for row in rows or []:
            writer.writerow([str(row.get(header, "")) for header in headers])
        writer.writerow([])

    write_key_value_section("Project", snapshot.get("project", {}))
    write_key_value_section("Summary", snapshot.get("summary", {}))

    write_table_section(
        "Hosts",
        snapshot.get("hosts", []),
        ["id", "ip", "hostname", "status", "os", "open_ports", "total_ports"],
    )
    write_table_section(
        "Services",
        snapshot.get("services", []),
        ["service", "host_count", "port_count", "protocols"],
    )
    write_table_section(
        "Tools",
        snapshot.get("tools", []),
        ["label", "tool_id", "run_count", "last_status", "danger_categories"],
    )
    write_table_section(
        "Processes",
        snapshot.get("processes", []),
        ["id", "name", "hostIp", "port", "protocol", "status", "startTime", "elapsed"],
    )
    write_table_section(
        "Scheduler Decisions",
        snapshot.get("scheduler_decisions", []),
        ["id", "timestamp", "host_ip", "port", "protocol", "tool_id", "scheduler_mode", "approved", "executed", "reason"],
    )
    write_table_section(
        "Dangerous Action Approvals",
        snapshot.get("scheduler_approvals", []),
        ["id", "host_ip", "port", "protocol", "tool_id", "danger_categories", "status", "decision_reason"],
    )
    write_table_section(
        "Jobs",
        snapshot.get("jobs", []),
        ["id", "type", "status", "created_at", "started_at", "finished_at", "error"],
    )

    return output.getvalue()


def _safe_filename_token(value: str, fallback: str = "host") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        return str(fallback)
    return token[:96]


def _render_host_ai_report_markdown(report: dict) -> str:
    host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
    ai = report.get("ai_analysis", {}) if isinstance(report.get("ai_analysis", {}), dict) else {}
    host_updates = ai.get("host_updates", {}) if isinstance(ai.get("host_updates", {}), dict) else {}
    technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
    findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
    manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
    ports = report.get("ports", []) if isinstance(report.get("ports", []), list) else []
    cves = report.get("cves", []) if isinstance(report.get("cves", []), list) else []

    lines = [
        "# Legion Host AI Report",
        "",
        f"- Generated: {report.get('generated_at', '')}",
        f"- Host ID: {host.get('id', '')}",
        f"- Host IP: {host.get('ip', '')}",
        f"- Hostname: {host.get('hostname', '')}",
        f"- Status: {host.get('status', '')}",
        f"- OS: {host.get('os', '')}",
        "",
        "## AI Analysis",
        "",
        f"- Provider: {ai.get('provider', '')}",
        f"- Goal Profile: {ai.get('goal_profile', '')}",
        f"- Updated: {ai.get('updated_at', '')}",
        f"- Next Phase: {ai.get('next_phase', '')}",
        f"- Hostname Suggestion: {host_updates.get('hostname', '')} ({host_updates.get('hostname_confidence', 0)}%)",
        f"- OS Suggestion: {host_updates.get('os', '')} ({host_updates.get('os_confidence', 0)}%)",
        "",
        "## Technologies",
        "",
    ]

    if technologies:
        for item in technologies:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('name', '')} {item.get('version', '')} | CPE: {item.get('cpe', '')} | Evidence: {item.get('evidence', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Findings", ""])
    if findings:
        for item in findings:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{item.get('severity', 'info')}] {item.get('title', '')} | CVE: {item.get('cve', '')} | CVSS: {item.get('cvss', '')} | Evidence: {item.get('evidence', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Manual Tests", ""])
    if manual_tests:
        for item in manual_tests:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- Why: {item.get('why', '')} | Command: `{item.get('command', '')}` | Scope: {item.get('scope_note', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Open Services", ""])
    if ports:
        for item in ports:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('port', '')}/{item.get('protocol', '')} {item.get('service', '')} {item.get('service_product', '')} {item.get('service_version', '')}".strip()
            )
    else:
        lines.append("- none")

    lines.extend(["", "## CVEs", ""])
    if cves:
        for item in cves:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('name', '')} | Severity: {item.get('severity', '')} | Product: {item.get('product', '')}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines).strip() + "\n"


@web_bp.get("/")
def index():
    runtime = current_app.extensions["legion_runtime"]
    snapshot = runtime.get_snapshot()
    return render_template(
        "index.html",
        snapshot=snapshot,
        ws_enabled=current_app.config.get("LEGION_WEBSOCKETS_ENABLED", False),
        console_logo_art=_get_sanitized_console_logo(),
    )


@web_bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@web_bp.get("/api/export/json")
def export_json():
    runtime = current_app.extensions["legion_runtime"]
    snapshot = runtime.get_snapshot()
    payload = json.dumps(snapshot, indent=2, default=str)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="legion-export-{timestamp}.json"'
    return response


@web_bp.get("/api/export/csv")
def export_csv():
    runtime = current_app.extensions["legion_runtime"]
    snapshot = runtime.get_snapshot()
    csv_text = _build_csv_export(snapshot)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(csv_text, mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="legion-export-{timestamp}.csv"'
    return response


@web_bp.get("/api/settings/legion-conf")
def settings_legion_conf_get():
    settings = AppSettings()
    conf_path = str(settings.actions.fileName() or "")
    if not conf_path:
        return _json_error("Unable to resolve legion.conf path.", 500)
    if not os.path.isfile(conf_path):
        return _json_error(f"Config file not found: {conf_path}", 404)
    try:
        with open(conf_path, "r", encoding="utf-8") as handle:
            text = handle.read()
        return jsonify({"path": conf_path, "text": text})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/settings/legion-conf")
def settings_legion_conf_save():
    payload = request.get_json(silent=True) or {}
    text_value = payload.get("text", None)
    if not isinstance(text_value, str):
        return _json_error("Field 'text' is required and must be a string.", 400)

    settings = AppSettings()
    conf_path = str(settings.actions.fileName() or "")
    if not conf_path:
        return _json_error("Unable to resolve legion.conf path.", 500)
    try:
        with open(conf_path, "w", encoding="utf-8") as handle:
            handle.write(text_value)
    except Exception as exc:
        return _json_error(str(exc), 500)

    runtime = current_app.extensions.get("legion_runtime")
    if runtime is not None:
        try:
            runtime.settings_file = AppSettings()
            runtime.settings = Settings(runtime.settings_file)
        except Exception:
            pass

    return jsonify({"status": "ok", "path": conf_path})


@web_bp.get("/api/snapshot")
def snapshot():
    runtime = current_app.extensions["legion_runtime"]
    return jsonify(runtime.get_snapshot())


@web_bp.get("/api/project")
def project_details():
    runtime = current_app.extensions["legion_runtime"]
    return jsonify(runtime.get_project_details())


@web_bp.post("/api/project/new-temp")
def project_new_temp():
    runtime = current_app.extensions["legion_runtime"]
    project = runtime.create_new_temporary_project()
    return jsonify({"status": "ok", "project": project})


@web_bp.post("/api/project/open")
def project_open():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    path = str(payload.get("path", "")).strip()
    if not path:
        return _json_error("Project path is required.", 400)
    try:
        project = runtime.open_project(path)
        return jsonify({"status": "ok", "project": project})
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/project/save-as")
def project_save_as():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    path = str(payload.get("path", "")).strip()
    replace = _as_bool(payload.get("replace", True), default=True)
    if not path:
        return _json_error("Project path is required.", 400)
    try:
        if hasattr(runtime, "start_save_project_as_job"):
            job = runtime.start_save_project_as_job(path, replace=replace)
            return jsonify({"status": "accepted", "job": job}), 202
        project = runtime.save_project_as(path, replace=replace)
        return jsonify({"status": "ok", "project": project}), 200
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except RuntimeError as exc:
        return _json_error(str(exc), 409)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/project/download-zip")
def project_download_zip():
    runtime = current_app.extensions["legion_runtime"]
    try:
        bundle_path, bundle_name = runtime.build_project_bundle_zip()
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)

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


@web_bp.post("/api/project/restore-zip")
def project_restore_zip():
    runtime = current_app.extensions["legion_runtime"]
    uploaded = request.files.get("bundle")
    if uploaded is None:
        return _json_error("Field 'bundle' is required.", 400)

    filename = str(getattr(uploaded, "filename", "") or "").strip()
    if not filename:
        return _json_error("Uploaded bundle filename is required.", 400)

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
        return _json_error(f"Failed to save uploaded ZIP: {exc}", 400)

    try:
        if hasattr(runtime, "start_restore_project_zip_job"):
            job = runtime.start_restore_project_zip_job(temp_path)
            return jsonify({"status": "accepted", "job": job}), 202

        if hasattr(runtime, "restore_project_bundle_zip"):
            result = runtime.restore_project_bundle_zip(temp_path)
            _remove_temp_upload()
            return jsonify({"status": "ok", "project": result.get("project", {}), "result": result}), 200

        _remove_temp_upload()
        return _json_error("Runtime does not support ZIP restore.", 501)
    except FileNotFoundError as exc:
        _remove_temp_upload()
        return _json_error(str(exc), 404)
    except ValueError as exc:
        _remove_temp_upload()
        return _json_error(str(exc), 400)
    except RuntimeError as exc:
        _remove_temp_upload()
        return _json_error(str(exc), 409)
    except Exception as exc:
        _remove_temp_upload()
        return _json_error(str(exc), 500)


@web_bp.post("/api/targets/import-file")
def import_targets():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    path = str(payload.get("path", "")).strip()
    if not path:
        return _json_error("Targets file path is required.", 400)
    try:
        job = runtime.start_targets_import_job(path)
        return jsonify({"status": "accepted", "job": job}), 202
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/nmap/import-xml")
def import_nmap_xml():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    path = str(payload.get("path", "")).strip()
    run_actions = _as_bool(payload.get("run_actions", False), default=False)
    if not path:
        return _json_error("Nmap XML path is required.", 400)
    try:
        job = runtime.start_nmap_xml_import_job(path, run_actions=run_actions)
        return jsonify({"status": "accepted", "job": job}), 202
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/nmap/scan")
def nmap_scan():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    targets = payload.get("targets", [])
    discovery = _as_bool(payload.get("discovery", True), default=True)
    staged = _as_bool(payload.get("staged", False), default=False)
    run_actions = _as_bool(payload.get("run_actions", False), default=False)
    nmap_path = str(payload.get("nmap_path", "nmap"))
    nmap_args = str(payload.get("nmap_args", ""))
    scan_mode = str(payload.get("scan_mode", "legacy"))
    scan_options = payload.get("scan_options", {})
    if not isinstance(scan_options, dict):
        scan_options = {}
    try:
        job = runtime.start_nmap_scan_job(
            targets=targets,
            discovery=discovery,
            staged=staged,
            run_actions=run_actions,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            scan_mode=scan_mode,
            scan_options=scan_options,
        )
        return jsonify({"status": "accepted", "job": job}), 202
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/scheduler/run")
def scheduler_run():
    runtime = current_app.extensions["legion_runtime"]
    try:
        job = runtime.start_scheduler_run_job()
        return jsonify({"status": "accepted", "job": job}), 202
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/jobs")
def jobs():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))
    return jsonify({"jobs": runtime.list_jobs(limit=limit)})


@web_bp.get("/api/jobs/<int:job_id>")
def job_details(job_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        return jsonify(runtime.get_job(job_id))
    except KeyError:
        return _json_error(f"Unknown job id: {job_id}", 404)


@web_bp.post("/api/jobs/<int:job_id>/stop")
def job_stop(job_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        result = runtime.stop_job(job_id)
        return jsonify({"status": "ok", **result})
    except KeyError:
        return _json_error(f"Unknown job id: {job_id}", 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/hosts")
def workspace_hosts():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 400))
    except (TypeError, ValueError):
        limit = 400
    limit = max(1, min(limit, 2000))
    try:
        return jsonify({"hosts": runtime.get_workspace_hosts(limit=limit)})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/services")
def workspace_services():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 300))
    except (TypeError, ValueError):
        limit = 300
    limit = max(1, min(limit, 2000))
    try:
        return jsonify({"services": runtime.get_workspace_services(limit=limit)})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/tools")
def workspace_tools():
    runtime = current_app.extensions["legion_runtime"]
    service = str(request.args.get("service", "")).strip()
    try:
        limit = int(request.args.get("limit", 300))
    except (TypeError, ValueError):
        limit = 300
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    try:
        page = runtime.get_workspace_tools_page(service=service, limit=limit, offset=offset)
        return jsonify(page)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/hosts/<int:host_id>")
def workspace_host_detail(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        return jsonify(runtime.get_host_workspace(host_id))
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/hosts/<int:host_id>/ai-report")
def workspace_host_ai_report(host_id):
    runtime = current_app.extensions["legion_runtime"]
    report_format = str(request.args.get("format", "json") or "json").strip().lower()
    if report_format in {"markdown"}:
        report_format = "md"

    try:
        report = runtime.get_host_ai_report(host_id)
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)

    host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
    host_token = _safe_filename_token(
        str(host.get("hostname", "")).strip() or str(host.get("ip", "")).strip() or f"host-{host_id}",
        fallback=f"host-{host_id}",
    )
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")

    if report_format == "md":
        body = runtime.render_host_ai_report_markdown(report)
        response = current_app.response_class(body, mimetype="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="legion-host-ai-report-{host_token}-{timestamp}.md"'
        )
        return response

    payload = json.dumps(report, indent=2, default=str)
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="legion-host-ai-report-{host_token}-{timestamp}.json"'
    )
    return response


@web_bp.get("/api/workspace/ai-reports/download-zip")
def workspace_ai_reports_download_zip():
    runtime = current_app.extensions["legion_runtime"]
    try:
        bundle_path, bundle_name = runtime.build_host_ai_reports_zip()
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)

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


@web_bp.get("/api/workspace/project-ai-report")
def workspace_project_ai_report():
    runtime = current_app.extensions["legion_runtime"]
    report_format = str(request.args.get("format", "json") or "json").strip().lower()
    if report_format in {"markdown"}:
        report_format = "md"

    try:
        report = runtime.get_project_ai_report()
    except Exception as exc:
        return _json_error(str(exc), 500)

    project = report.get("project", {}) if isinstance(report.get("project", {}), dict) else {}
    project_token = _safe_filename_token(
        str(project.get("name", "")).strip() or "project",
        fallback="project",
    )
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")

    if report_format == "md":
        body = runtime.render_project_ai_report_markdown(report)
        response = current_app.response_class(body, mimetype="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="legion-project-ai-report-{project_token}-{timestamp}.md"'
        )
        return response

    payload = json.dumps(report, indent=2, default=str)
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="legion-project-ai-report-{project_token}-{timestamp}.json"'
    )
    return response


@web_bp.post("/api/workspace/project-ai-report/push")
def workspace_project_ai_report_push():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    overrides = payload.get("project_report_delivery")
    if overrides is None and isinstance(payload, dict):
        overrides = {
            key: value
            for key, value in payload.items()
            if key in {"provider_name", "endpoint", "method", "format", "headers", "timeout_seconds", "mtls"}
        }
    if not isinstance(overrides, dict):
        overrides = {}

    try:
        result = runtime.push_project_ai_report(overrides=overrides)
        status_code = 200 if bool(result.get("ok", False)) else 400
        status_value = "ok" if bool(result.get("ok", False)) else "error"
        return jsonify({"status": status_value, **result}), status_code
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/hosts/<int:host_id>/rescan")
def workspace_host_rescan(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        job = runtime.start_host_rescan_job(host_id)
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/hosts/<int:host_id>/dig-deeper")
def workspace_host_dig_deeper(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        job = runtime.start_host_dig_deeper_job(host_id)
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.delete("/api/workspace/hosts/<int:host_id>")
def workspace_host_remove(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        result = runtime.delete_host_workspace(host_id)
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/hosts/<int:host_id>/note")
def workspace_host_note(host_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    text_value = str(payload.get("text", ""))
    try:
        result = runtime.update_host_note(host_id, text_value)
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/hosts/<int:host_id>/scripts")
def workspace_host_script_create(host_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    script_id = str(payload.get("script_id", "")).strip()
    port = str(payload.get("port", "")).strip()
    protocol = str(payload.get("protocol", "tcp")).strip().lower() or "tcp"
    output = str(payload.get("output", ""))
    if not script_id or not port:
        return _json_error("script_id and port are required.", 400)
    try:
        row = runtime.create_script_entry(host_id, port, protocol, script_id, output)
        return jsonify({"status": "ok", "script": row})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.delete("/api/workspace/scripts/<int:script_id>")
def workspace_host_script_delete(script_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        row = runtime.delete_script_entry(script_id)
        return jsonify({"status": "ok", **row})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/scripts/<int:script_id>/output")
def workspace_host_script_output(script_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        offset = int(request.args.get("offset", 0) or 0)
    except (TypeError, ValueError):
        offset = 0
    try:
        max_chars = int(request.args.get("max_chars", 12000) or 12000)
    except (TypeError, ValueError):
        max_chars = 12000
    try:
        return jsonify(runtime.get_script_output(script_id, offset=offset, max_chars=max_chars))
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/hosts/<int:host_id>/cves")
def workspace_host_cve_create(host_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    if not name:
        return _json_error("name is required.", 400)
    try:
        row = runtime.create_cve_entry(
            host_id=host_id,
            name=name,
            url=str(payload.get("url", "")),
            severity=str(payload.get("severity", "")),
            source=str(payload.get("source", "")),
            product=str(payload.get("product", "")),
            version=str(payload.get("version", "")),
            exploit_id=int(payload.get("exploit_id", 0) or 0),
            exploit=str(payload.get("exploit", "")),
            exploit_url=str(payload.get("exploit_url", "")),
        )
        return jsonify({"status": "ok", "cve": row})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.delete("/api/workspace/cves/<int:cve_id>")
def workspace_host_cve_delete(cve_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        row = runtime.delete_cve_entry(cve_id)
        return jsonify({"status": "ok", **row})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/tools/run")
def workspace_tool_run():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    host_ip = str(payload.get("host_ip", "")).strip()
    port = str(payload.get("port", "")).strip()
    protocol = str(payload.get("protocol", "tcp")).strip().lower() or "tcp"
    tool_id = str(payload.get("tool_id", "")).strip()
    command_override = str(payload.get("command_override", ""))
    try:
        timeout = int(payload.get("timeout", 300) or 300)
    except (TypeError, ValueError):
        return _json_error("timeout must be an integer.", 400)
    if not host_ip or not port or not tool_id:
        return _json_error("host_ip, port and tool_id are required.", 400)
    try:
        job = runtime.start_tool_run_job(
            host_ip=host_ip,
            port=port,
            protocol=protocol,
            tool_id=tool_id,
            command_override=command_override,
            timeout=timeout,
        )
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/processes/<int:process_id>/kill")
def workspace_process_kill(process_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        result = runtime.kill_process(process_id)
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/processes/<int:process_id>/retry")
def workspace_process_retry(process_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        timeout = int(payload.get("timeout", 300) or 300)
    except (TypeError, ValueError):
        return _json_error("timeout must be an integer.", 400)
    try:
        job = runtime.start_process_retry_job(process_id=process_id, timeout=timeout)
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/processes/<int:process_id>/close")
def workspace_process_close(process_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        result = runtime.close_process(process_id)
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/processes/clear")
def workspace_process_clear():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    reset_all = _as_bool(payload.get("reset_all", False), default=False)
    try:
        result = runtime.clear_processes(reset_all=reset_all)
        return jsonify({"status": "ok", **result})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/processes/<int:process_id>/output")
def workspace_process_output(process_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        offset = int(request.args.get("offset", 0) or 0)
    except (TypeError, ValueError):
        offset = 0
    try:
        max_chars = int(request.args.get("max_chars", 12000) or 12000)
    except (TypeError, ValueError):
        max_chars = 12000
    try:
        return jsonify(runtime.get_process_output(process_id, offset=offset, max_chars=max_chars))
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/screenshots/<path:filename>")
def workspace_screenshot(filename):
    runtime = current_app.extensions["legion_runtime"]
    try:
        file_path = runtime.get_screenshot_file(filename)
    except FileNotFoundError:
        return _json_error("Screenshot not found.", 404)
    except Exception as exc:
        return _json_error(str(exc), 400)
    directory = os.path.dirname(file_path)
    basename = os.path.basename(file_path)
    return send_from_directory(directory, basename, as_attachment=False)


@web_bp.get("/api/scheduler/preferences")
def scheduler_preferences():
    runtime = current_app.extensions["legion_runtime"]
    return jsonify(runtime.get_scheduler_preferences())


@web_bp.post("/api/scheduler/preferences")
def scheduler_preferences_update():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    allowed_fields = {
        "mode",
        "goal_profile",
        "provider",
        "max_concurrency",
        "max_jobs",
        "providers",
        "dangerous_categories",
        "project_report_delivery",
    }
    updates = {key: value for key, value in payload.items() if key in allowed_fields}
    if hasattr(runtime, "apply_scheduler_preferences"):
        return jsonify(runtime.apply_scheduler_preferences(updates))
    runtime.scheduler_config.update_preferences(updates)
    return jsonify(runtime.get_scheduler_preferences())


@web_bp.post("/api/scheduler/provider/test")
def scheduler_provider_test():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    allowed_fields = {
        "mode",
        "goal_profile",
        "provider",
        "max_concurrency",
        "max_jobs",
        "providers",
        "dangerous_categories",
        "project_report_delivery",
    }
    updates = {key: value for key, value in payload.items() if key in allowed_fields}
    try:
        return jsonify(runtime.test_scheduler_provider(updates))
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/scheduler/provider/logs")
def scheduler_provider_logs():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 300))
    except (TypeError, ValueError):
        limit = 300
    limit = max(1, min(limit, 1000))
    try:
        logs = runtime.get_scheduler_provider_logs(limit=limit)
        lines = []
        for row in logs:
            lines.append(
                f"[{row.get('timestamp', '')}] {row.get('provider', '')} "
                f"{row.get('method', '')} {row.get('endpoint', '')}"
            )
            status = row.get("response_status", "")
            if status not in (None, ""):
                lines.append(f"status: {status}")
            if row.get("api_style"):
                lines.append(f"api_style: {row.get('api_style')}")
            lines.append(f"request headers: {json.dumps(row.get('request_headers', {}), ensure_ascii=False)}")
            lines.append(f"request body: {row.get('request_body', '')}")
            lines.append(f"response body: {row.get('response_body', '')}")
            if row.get("error"):
                lines.append(f"error: {row.get('error')}")
            lines.append("")
        return jsonify({
            "logs": logs,
            "text": "\n".join(lines).strip(),
        })
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/scheduler/approve-family")
def scheduler_approve_family():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    family_id = str(payload.get("family_id", "")).strip()
    metadata = {
        "tool_id": str(payload.get("tool_id", "")),
        "label": str(payload.get("label", "")),
        "danger_categories": payload.get("danger_categories", []),
    }
    runtime.scheduler_config.approve_family(family_id, metadata)
    return jsonify({"status": "ok", "family_id": family_id})


@web_bp.get("/api/scheduler/decisions")
def scheduler_decisions():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))
    return jsonify({"decisions": runtime.get_scheduler_decisions(limit=limit)})


@web_bp.get("/api/scheduler/approvals")
def scheduler_approvals():
    runtime = current_app.extensions["legion_runtime"]
    status = str(request.args.get("status", "")).strip().lower() or None
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(limit, 1000))
    try:
        approvals = runtime.get_scheduler_approvals(limit=limit, status=status)
        return jsonify({"approvals": approvals})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/scheduler/approvals/<int:approval_id>/approve")
def scheduler_approval_approve(approval_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    approve_family = _as_bool(payload.get("approve_family", False), default=False)
    run_now = _as_bool(payload.get("run_now", True), default=True)
    try:
        result = runtime.approve_scheduler_approval(
            approval_id=approval_id,
            approve_family=approve_family,
            run_now=run_now,
        )
        status_code = 202 if result.get("job") else 200
        return jsonify({"status": "ok", **result}), status_code
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/scheduler/approvals/<int:approval_id>/reject")
def scheduler_approval_reject(approval_id):
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason", "rejected via web"))
    try:
        result = runtime.reject_scheduler_approval(approval_id=approval_id, reason=reason)
        return jsonify({"status": "ok", "approval": result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)
