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
from app.tooling import audit_legion_tools, build_tool_install_plan, tool_audit_summary

web_bp = Blueprint("web", __name__)
_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


@web_bp.after_request
def disable_cache_for_api_responses(response):
    path = str(getattr(request, "path", "") or "").strip()
    if not path.startswith("/api/"):
        return response
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


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


def _split_query_tokens(value):
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


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
    write_table_section(
        "Submitted Scans",
        snapshot.get("scan_history", []),
        ["id", "submission_kind", "status", "target_summary", "scope_summary", "scan_mode", "created_at", "result_summary"],
    )

    return output.getvalue()


def _build_hosts_csv_export(rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "ip", "hostname", "status", "os", "open_ports", "total_ports", "services"])
    for row in rows or []:
        writer.writerow([
            str(row.get("id", "")),
            str(row.get("ip", "")),
            str(row.get("hostname", "")),
            str(row.get("status", "")),
            str(row.get("os", "")),
            str(row.get("open_ports", "")),
            str(row.get("total_ports", "")),
            "; ".join(str(item) for item in list(row.get("services", []) or []) if str(item).strip()),
        ])
    return output.getvalue()


def _build_hosts_json_export(rows, *, host_filter: str, service_filter: str = ""):
    payload = {
        "filter": str(host_filter or "hide_down"),
        "service": str(service_filter or ""),
        "host_count": len(list(rows or [])),
        "hosts": list(rows or []),
    }
    return json.dumps(payload, indent=2, default=str)


def _normalized_host_filter(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in {"all", "show_all", "show-all"}:
        return "show_all"
    return "hide_down"


def _host_filter_include_down(host_filter: str) -> bool:
    return str(host_filter or "").strip().lower() == "show_all"


def _normalized_service_filter(value: str) -> str:
    return str(value or "").strip()


def _get_filtered_workspace_hosts(runtime):
    host_filter = _normalized_host_filter(request.args.get("filter", "hide_down"))
    service_filter = _normalized_service_filter(request.args.get("service", ""))
    include_down = _host_filter_include_down(host_filter)
    limit_arg = request.args.get("limit")
    if limit_arg in {None, ""}:
        rows = runtime.get_workspace_hosts(include_down=include_down, service=service_filter)
    else:
        try:
            limit = int(limit_arg)
        except (TypeError, ValueError):
            limit = None
        if limit is not None and limit <= 0:
            limit = None
        rows = runtime.get_workspace_hosts(limit=limit, include_down=include_down, service=service_filter)
    return host_filter, service_filter, rows


def _safe_filename_token(value: str, fallback: str = "host") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        return str(fallback)
    return token[:96]


def _render_host_ai_report_markdown(report: dict) -> str:
    host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
    ai = report.get("ai_analysis", {}) if isinstance(report.get("ai_analysis", {}), dict) else {}
    target_state = report.get("target_state", {}) if isinstance(report.get("target_state", {}), dict) else {}
    host_updates = ai.get("host_updates", {}) if isinstance(ai.get("host_updates", {}), dict) else {}
    technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
    findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
    manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
    coverage_gaps = target_state.get("coverage_gaps", []) if isinstance(target_state.get("coverage_gaps", []), list) else []
    attempted_actions = target_state.get("attempted_actions", []) if isinstance(target_state.get("attempted_actions", []), list) else []
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

    lines.extend(["", "## Shared Target State", ""])
    lines.append(f"- Attempted Actions: {len(attempted_actions)}")
    lines.append(f"- Coverage Gaps: {len(coverage_gaps)}")
    lines.append(f"- URLs: {len(target_state.get('urls', []) if isinstance(target_state.get('urls', []), list) else [])}")
    lines.append(f"- Credentials: {len(target_state.get('credentials', []) if isinstance(target_state.get('credentials', []), list) else [])}")
    lines.append(f"- Sessions: {len(target_state.get('sessions', []) if isinstance(target_state.get('sessions', []), list) else [])}")

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
    graph_workspace_enabled = bool(
        ((snapshot.get("scheduler", {}) or {}).get("feature_flags", {}) or {}).get("graph_workspace", True)
    )
    return render_template(
        "index.html",
        snapshot=snapshot,
        graph_workspace_enabled=graph_workspace_enabled,
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


@web_bp.get("/api/export/hosts-csv")
def export_hosts_csv():
    runtime = current_app.extensions["legion_runtime"]
    host_filter, service_filter, rows = _get_filtered_workspace_hosts(runtime)
    csv_text = _build_hosts_csv_export(rows)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(csv_text, mimetype="text/csv")
    suffix = "all" if _host_filter_include_down(host_filter) else "up-only"
    if service_filter:
        suffix = f"{suffix}-{_safe_filename_token(service_filter, fallback='service')}"
    response.headers["Content-Disposition"] = f'attachment; filename="legion-hosts-{suffix}-{timestamp}.csv"'
    return response


@web_bp.get("/api/export/hosts-json")
def export_hosts_json():
    runtime = current_app.extensions["legion_runtime"]
    host_filter, service_filter, rows = _get_filtered_workspace_hosts(runtime)
    payload = _build_hosts_json_export(rows, host_filter=host_filter, service_filter=service_filter)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(payload, mimetype="application/json")
    suffix = "all" if _host_filter_include_down(host_filter) else "up-only"
    if service_filter:
        suffix = f"{suffix}-{_safe_filename_token(service_filter, fallback='service')}"
    response.headers["Content-Disposition"] = f'attachment; filename="legion-hosts-{suffix}-{timestamp}.json"'
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


@web_bp.get("/api/settings/tool-audit")
def settings_tool_audit():
    runtime = current_app.extensions.get("legion_runtime")
    runtime_getter = getattr(runtime, "get_tool_audit", None) if runtime is not None else None
    if callable(runtime_getter):
        try:
            return jsonify(runtime_getter())
        except Exception as exc:
            return _json_error(str(exc), 500)
    settings = getattr(runtime, "settings", None) if runtime is not None else None
    if settings is None:
        settings = Settings(AppSettings())
    entries = audit_legion_tools(settings)
    return jsonify({
        "summary": tool_audit_summary(entries),
        "tools": [entry.to_dict() for entry in entries],
        "supported_platforms": ["kali", "ubuntu"],
        "recommended_platform": "kali",
    })


@web_bp.get("/api/settings/tool-audit/install-plan")
def settings_tool_audit_install_plan():
    runtime = current_app.extensions.get("legion_runtime")
    platform = str(request.args.get("platform", "kali"))
    scope = str(request.args.get("scope", "missing"))
    tool_keys = _split_query_tokens(request.args.get("tool_keys", ""))
    runtime_getter = getattr(runtime, "get_tool_install_plan", None) if runtime is not None else None
    if callable(runtime_getter):
        try:
            return jsonify(runtime_getter(platform=platform, scope=scope, tool_keys=tool_keys))
        except Exception as exc:
            return _json_error(str(exc), 500)
    settings = getattr(runtime, "settings", None) if runtime is not None else None
    if settings is None:
        settings = Settings(AppSettings())
    entries = audit_legion_tools(settings)
    return jsonify(build_tool_install_plan(entries, platform=platform, scope=scope, tool_keys=tool_keys))


@web_bp.post("/api/settings/tool-audit/install")
def settings_tool_audit_install():
    runtime = current_app.extensions.get("legion_runtime")
    if runtime is None or not callable(getattr(runtime, "start_tool_install_job", None)):
        return _json_error("Tool installation is unavailable in this runtime.", 501)

    payload = request.get_json(silent=True) or {}
    platform = str(payload.get("platform", "kali"))
    scope = str(payload.get("scope", "missing"))
    tool_keys = payload.get("tool_keys", [])
    if tool_keys is None:
        tool_keys = []
    if not isinstance(tool_keys, list):
        return _json_error("Field 'tool_keys' must be an array when provided.", 400)
    normalized_tool_keys = [str(item or "").strip() for item in tool_keys if str(item or "").strip()]
    try:
        job = runtime.start_tool_install_job(
            platform=platform,
            scope=scope,
            tool_keys=normalized_tool_keys,
        )
        return jsonify({"status": "accepted", "job": job}), 202
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/snapshot")
def snapshot():
    runtime = current_app.extensions["legion_runtime"]
    return jsonify(runtime.get_snapshot())


@web_bp.get("/api/project")
def project_details():
    runtime = current_app.extensions["legion_runtime"]
    return jsonify(runtime.get_project_details())


@web_bp.get("/api/projects")
def project_list():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 500) or 500)
    except (TypeError, ValueError):
        limit = 500
    limit = max(1, min(limit, 5000))
    try:
        return jsonify({"projects": runtime.list_projects(limit=limit)})
    except Exception as exc:
        return _json_error(str(exc), 500)


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


@web_bp.get("/api/processes")
def processes():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))
    return jsonify({"processes": runtime.get_workspace_processes(limit=limit)})


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


@web_bp.get("/api/scans/history")
def scan_history():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 1000))
    return jsonify({"scans": runtime.get_scan_history(limit=limit)})


@web_bp.get("/api/workspace/hosts")
def workspace_hosts():
    runtime = current_app.extensions["legion_runtime"]
    try:
        host_filter, service_filter, rows = _get_filtered_workspace_hosts(runtime)
        return jsonify({"filter": host_filter, "service": service_filter, "hosts": rows})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/overview")
def workspace_overview():
    runtime = current_app.extensions["legion_runtime"]
    try:
        return jsonify(runtime.get_workspace_overview())
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/services")
def workspace_services():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 300))
    except (TypeError, ValueError):
        limit = 300
    try:
        host_id = int(request.args.get("host_id", 0))
    except (TypeError, ValueError):
        host_id = 0
    limit = max(1, min(limit, 2000))
    try:
        return jsonify({"services": runtime.get_workspace_services(limit=limit, host_id=host_id), "host_id": host_id})
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


@web_bp.get("/api/workspace/hosts/<int:host_id>/target-state")
def workspace_host_target_state(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        return jsonify(runtime.get_target_state_view(host_id=host_id))
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/workspace/findings")
def workspace_findings():
    runtime = current_app.extensions["legion_runtime"]
    try:
        host_id = int(request.args.get("host_id", 0) or 0)
    except (TypeError, ValueError):
        host_id = 0
    try:
        limit = int(request.args.get("limit", 1000) or 1000)
    except (TypeError, ValueError):
        limit = 1000
    try:
        return jsonify(runtime.get_findings(host_id=host_id, limit_findings=limit))
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


@web_bp.get("/api/workspace/hosts/<int:host_id>/report")
def workspace_host_report(host_id):
    runtime = current_app.extensions["legion_runtime"]
    report_format = str(request.args.get("format", "json") or "json").strip().lower()
    if report_format in {"markdown"}:
        report_format = "md"

    try:
        report = runtime.get_host_report(host_id)
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
        body = runtime.render_host_report_markdown(report)
        response = current_app.response_class(body, mimetype="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="legion-host-report-{host_token}-{timestamp}.md"'
        )
        return response

    payload = json.dumps(report, indent=2, default=str)
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="legion-host-report-{host_token}-{timestamp}.json"'
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


@web_bp.get("/api/workspace/project-report")
def workspace_project_report():
    runtime = current_app.extensions["legion_runtime"]
    report_format = str(request.args.get("format", "json") or "json").strip().lower()
    if report_format in {"markdown"}:
        report_format = "md"

    try:
        report = runtime.get_project_report()
    except Exception as exc:
        return _json_error(str(exc), 500)

    project = report.get("project", {}) if isinstance(report.get("project", {}), dict) else {}
    project_token = _safe_filename_token(
        str(project.get("name", "")).strip() or "project",
        fallback="project",
    )
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")

    if report_format == "md":
        body = runtime.render_project_report_markdown(report)
        response = current_app.response_class(body, mimetype="text/markdown; charset=utf-8")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="legion-project-report-{project_token}-{timestamp}.md"'
        )
        return response

    payload = json.dumps(report, indent=2, default=str)
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="legion-project-report-{project_token}-{timestamp}.json"'
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


@web_bp.post("/api/workspace/project-report/push")
def workspace_project_report_push():
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
        result = runtime.push_project_report(overrides=overrides)
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


@web_bp.post("/api/workspace/subnets/rescan")
def workspace_subnet_rescan():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    subnet = str(payload.get("subnet", "") or "").strip()
    try:
        job = runtime.start_subnet_rescan_job(subnet)
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


@web_bp.post("/api/workspace/hosts/<int:host_id>/refresh-screenshots")
def workspace_host_refresh_screenshots(host_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        job = runtime.start_host_screenshot_refresh_job(host_id)
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/screenshots/refresh")
def workspace_graph_screenshot_refresh():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        job = runtime.start_graph_screenshot_refresh_job(
            int(payload.get("host_id", 0) or 0),
            str(payload.get("port", "") or ""),
            str(payload.get("protocol", "tcp") or "tcp"),
        )
        return jsonify({"status": "accepted", "job": job}), 202
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/screenshots/delete")
def workspace_graph_screenshot_delete():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        result = runtime.delete_graph_screenshot(
            host_id=int(payload.get("host_id", 0) or 0),
            artifact_ref=str(payload.get("artifact_ref", "") or ""),
            filename=str(payload.get("filename", "") or ""),
            port=str(payload.get("port", "") or ""),
            protocol=str(payload.get("protocol", "tcp") or "tcp"),
        )
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/ports/delete")
def workspace_port_delete():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        result = runtime.delete_workspace_port(
            host_id=int(payload.get("host_id", 0) or 0),
            port=str(payload.get("port", "") or ""),
            protocol=str(payload.get("protocol", "tcp") or "tcp"),
        )
        return jsonify({"status": "ok", **result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/workspace/services/delete")
def workspace_service_delete():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        result = runtime.delete_workspace_service(
            host_id=int(payload.get("host_id", 0) or 0),
            port=str(payload.get("port", "") or ""),
            protocol=str(payload.get("protocol", "tcp") or "tcp"),
            service=str(payload.get("service", "") or ""),
        )
        return jsonify({"status": "ok", **result})
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
        "engagement_policy",
        "ai_feedback",
        "feature_flags",
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
        "engagement_policy",
        "feature_flags",
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


@web_bp.get("/api/engagement-policy")
def engagement_policy_get():
    runtime = current_app.extensions["legion_runtime"]
    if hasattr(runtime, "get_engagement_policy"):
        return jsonify(runtime.get_engagement_policy())
    return jsonify(runtime.get_scheduler_preferences().get("engagement_policy", {}))


@web_bp.post("/api/engagement-policy")
def engagement_policy_update():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    if hasattr(runtime, "set_engagement_policy"):
        return jsonify(runtime.set_engagement_policy(payload))
    updates = {"engagement_policy": payload}
    if hasattr(runtime, "apply_scheduler_preferences"):
        return jsonify(runtime.apply_scheduler_preferences(updates))
    runtime.scheduler_config.update_preferences(updates)
    return jsonify(runtime.get_scheduler_preferences().get("engagement_policy", {}))


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
            prompt_metadata = row.get("prompt_metadata", {})
            if isinstance(prompt_metadata, dict) and prompt_metadata:
                lines.append(f"prompt metadata: {json.dumps(prompt_metadata, ensure_ascii=False)}")
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


@web_bp.get("/api/scheduler/plan-preview")
def scheduler_plan_preview():
    runtime = current_app.extensions["legion_runtime"]
    try:
        host_id = int(request.args.get("host_id", 0) or 0)
    except (TypeError, ValueError):
        host_id = 0
    try:
        limit_targets = int(request.args.get("limit_targets", 20) or 20)
    except (TypeError, ValueError):
        limit_targets = 20
    try:
        limit_actions = int(request.args.get("limit_actions", 6) or 6)
    except (TypeError, ValueError):
        limit_actions = 6
    try:
        payload = runtime.get_scheduler_plan_preview(
            host_id=host_id,
            host_ip=str(request.args.get("host_ip", "") or ""),
            service=str(request.args.get("service", "") or ""),
            port=str(request.args.get("port", "") or ""),
            protocol=str(request.args.get("protocol", "tcp") or "tcp"),
            mode=str(request.args.get("mode", "compare") or "compare"),
            limit_targets=limit_targets,
            limit_actions=limit_actions,
        )
        return jsonify(payload)
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


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
    family_action = str(payload.get("family_action", "") or "").strip().lower()
    try:
        result = runtime.approve_scheduler_approval(
            approval_id=approval_id,
            approve_family=approve_family,
            run_now=run_now,
            family_action=family_action,
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
    family_action = str(payload.get("family_action", "") or "").strip().lower()
    try:
        result = runtime.reject_scheduler_approval(
            approval_id=approval_id,
            reason=reason,
            family_action=family_action,
        )
        return jsonify({"status": "ok", "approval": result})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/scheduler/executions")
def scheduler_execution_traces():
    runtime = current_app.extensions["legion_runtime"]
    try:
        limit = int(request.args.get("limit", 200) or 200)
    except (TypeError, ValueError):
        limit = 200
    try:
        host_id = int(request.args.get("host_id", 0) or 0)
    except (TypeError, ValueError):
        host_id = 0
    include_output = _as_bool(request.args.get("include_output", False), default=False)
    try:
        traces = runtime.get_scheduler_execution_traces(
            limit=limit,
            host_id=host_id,
            host_ip=str(request.args.get("host_ip", "") or ""),
            tool_id=str(request.args.get("tool_id", "") or ""),
            include_output=include_output,
        )
        return jsonify({"executions": traces})
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/scheduler/executions/<string:execution_id>")
def scheduler_execution_trace(execution_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        max_chars = int(request.args.get("max_chars", 4000) or 4000)
    except (TypeError, ValueError):
        max_chars = 4000
    try:
        trace = runtime.get_scheduler_execution_trace(execution_id, output_max_chars=max_chars)
        return jsonify(trace)
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph")
def evidence_graph():
    runtime = current_app.extensions["legion_runtime"]
    host_filter = _normalized_host_filter(request.args.get("host_filter", request.args.get("filter", "hide_down")))
    try:
        min_confidence = float(request.args.get("min_confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        min_confidence = 0.0
    try:
        host_id = int(request.args.get("host_id", 0) or 0)
    except (TypeError, ValueError):
        host_id = 0
    try:
        limit_nodes = int(request.args.get("limit_nodes", 600) or 600)
    except (TypeError, ValueError):
        limit_nodes = 600
    try:
        limit_edges = int(request.args.get("limit_edges", 1200) or 1200)
    except (TypeError, ValueError):
        limit_edges = 1200
    include_ai_suggested = not _as_bool(request.args.get("hide_ai_suggested", False), default=False)
    if request.args.get("include_ai_suggested") is not None:
        include_ai_suggested = _as_bool(request.args.get("include_ai_suggested"), default=True)
    hide_nmap_xml_artifacts = _as_bool(request.args.get("hide_nmap_xml_artifacts", False), default=False)
    try:
        payload = runtime.get_evidence_graph(filters={
            "node_types": _split_query_tokens(request.args.get("node_types", request.args.get("node_type", ""))),
            "edge_types": _split_query_tokens(request.args.get("edge_types", request.args.get("edge_type", ""))),
            "source_kinds": _split_query_tokens(request.args.get("source_kinds", request.args.get("source_kind", ""))),
            "min_confidence": min_confidence,
            "search": str(request.args.get("q", "") or ""),
            "include_ai_suggested": include_ai_suggested,
            "hide_nmap_xml_artifacts": hide_nmap_xml_artifacts,
            "host_filter": host_filter,
            "host_id": host_id or None,
            "limit_nodes": max(1, min(limit_nodes, 10000)),
            "limit_edges": max(1, min(limit_edges, 30000)),
        })
        return jsonify(payload)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/graph/rebuild")
def evidence_graph_rebuild():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    try:
        host_id = int(payload.get("host_id", 0) or 0)
    except (TypeError, ValueError):
        host_id = 0
    try:
        result = runtime.rebuild_evidence_graph(host_id=host_id or None)
        return jsonify({"status": "ok", **result})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/export/json")
def evidence_graph_export_json():
    runtime = current_app.extensions["legion_runtime"]
    rebuild = _as_bool(request.args.get("rebuild", False), default=False)
    try:
        payload = json.dumps(runtime.export_evidence_graph_json(rebuild=rebuild), indent=2, default=str)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        response = current_app.response_class(payload, mimetype="application/json")
        response.headers["Content-Disposition"] = f'attachment; filename="legion-evidence-graph-{timestamp}.json"'
        return response
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/export/graphml")
def evidence_graph_export_graphml():
    runtime = current_app.extensions["legion_runtime"]
    rebuild = _as_bool(request.args.get("rebuild", False), default=False)
    try:
        payload = runtime.export_evidence_graph_graphml(rebuild=rebuild)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        response = current_app.response_class(payload, mimetype="application/graphml+xml")
        response.headers["Content-Disposition"] = f'attachment; filename="legion-evidence-graph-{timestamp}.graphml"'
        return response
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/nodes/<path:node_id>/content")
def evidence_graph_node_content(node_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        max_chars = int(request.args.get("max_chars", 12000) or 12000)
    except (TypeError, ValueError):
        max_chars = 12000
    try:
        return jsonify(runtime.get_graph_related_content(node_id, max_chars=max_chars))
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/content/<path:node_id>")
def evidence_graph_content(node_id):
    runtime = current_app.extensions["legion_runtime"]
    try:
        max_chars = int(request.args.get("max_chars", 12000) or 12000)
    except (TypeError, ValueError):
        max_chars = 12000
    download = _as_bool(request.args.get("download", False), default=False)
    try:
        payload = runtime.get_graph_content(node_id, download=download, max_chars=max_chars)
        if payload.get("path"):
            return send_file(
                str(payload.get("path", "")),
                mimetype=str(payload.get("mimetype", "application/octet-stream") or "application/octet-stream"),
                as_attachment=bool(payload.get("download", False)),
                download_name=str(payload.get("filename", "") or None),
                max_age=0,
            )
        response = current_app.response_class(
            str(payload.get("text", "") or ""),
            mimetype=str(payload.get("mimetype", "text/plain; charset=utf-8") or "text/plain; charset=utf-8"),
        )
        if bool(payload.get("download", False)):
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{str(payload.get("filename", "") or "graph-content.txt")}"'
            )
        return response
    except KeyError as exc:
        return _json_error(str(exc), 404)
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/layouts")
def evidence_graph_layouts():
    runtime = current_app.extensions["legion_runtime"]
    try:
        return jsonify({"layouts": runtime.get_evidence_graph_layouts()})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/graph/layouts")
def evidence_graph_save_layout():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    view_id = str(payload.get("view_id", "") or "").strip()
    name = str(payload.get("name", "") or "").strip()
    layout_state = payload.get("layout", {})
    if not view_id:
        return _json_error("view_id is required", 400)
    if not isinstance(layout_state, dict):
        return _json_error("layout must be an object", 400)
    try:
        layout = runtime.save_evidence_graph_layout(
            view_id=view_id,
            name=name or "default",
            layout_state=layout_state,
            layout_id=str(payload.get("layout_id", "") or ""),
        )
        return jsonify({"status": "ok", "layout": layout})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.get("/api/graph/annotations")
def evidence_graph_annotations():
    runtime = current_app.extensions["legion_runtime"]
    try:
        annotations = runtime.get_evidence_graph_annotations(
            target_ref=str(request.args.get("target_ref", "") or ""),
            target_kind=str(request.args.get("target_kind", "") or ""),
        )
        return jsonify({"annotations": annotations})
    except Exception as exc:
        return _json_error(str(exc), 500)


@web_bp.post("/api/graph/annotations")
def evidence_graph_save_annotation():
    runtime = current_app.extensions["legion_runtime"]
    payload = request.get_json(silent=True) or {}
    target_kind = str(payload.get("target_kind", "") or "").strip()
    target_ref = str(payload.get("target_ref", "") or "").strip()
    body = str(payload.get("body", "") or "").strip()
    if not target_kind:
        return _json_error("target_kind is required", 400)
    if not target_ref:
        return _json_error("target_ref is required", 400)
    if not body:
        return _json_error("body is required", 400)
    try:
        annotation = runtime.save_evidence_graph_annotation(
            target_kind=target_kind,
            target_ref=target_ref,
            body=body,
            created_by=str(payload.get("created_by", "") or "operator"),
            source_ref=str(payload.get("source_ref", "") or ""),
            annotation_id=str(payload.get("annotation_id", "") or ""),
        )
        return jsonify({"status": "ok", "annotation": annotation})
    except Exception as exc:
        return _json_error(str(exc), 500)
