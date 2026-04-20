import csv
import datetime
import io
import json
import os
import re

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
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


def _load_display_settings(runtime=None):
    settings = getattr(runtime, "settings", None)
    if settings is None:
        try:
            settings = Settings(AppSettings())
        except Exception:
            settings = None
    colorful_ascii_background = _as_bool(
        getattr(settings, "general_colorful_ascii_background", False) if settings is not None else False,
        False,
    )
    return {
        "colorful_ascii_background": bool(colorful_ascii_background),
    }


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


@web_bp.get("/")
def index():
    runtime = current_app.extensions["legion_runtime"]
    snapshot = runtime.get_snapshot()
    display_settings = _load_display_settings(runtime)
    current_app.config["LEGION_COLORFUL_ASCII_BACKGROUND"] = bool(display_settings.get("colorful_ascii_background", False))
    graph_workspace_enabled = bool(
        ((snapshot.get("scheduler", {}) or {}).get("feature_flags", {}) or {}).get("graph_workspace", False)
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


@web_bp.get("/api/settings/display")
def settings_display_get():
    runtime = current_app.extensions.get("legion_runtime")
    return jsonify(_load_display_settings(runtime))


@web_bp.post("/api/settings/display")
def settings_display_save():
    payload = request.get_json(silent=True) or {}
    colorful_ascii_background = _as_bool(payload.get("colorful_ascii_background"), False)

    settings_file = AppSettings()
    try:
        settings_file.actions.beginGroup("GeneralSettings")
        settings_file.actions.setValue(
            "colorful-ascii-background",
            "True" if colorful_ascii_background else "False",
        )
        settings_file.actions.endGroup()
        settings_file.actions.sync()
    except Exception as exc:
        return _json_error(str(exc), 500)

    runtime = current_app.extensions.get("legion_runtime")
    if runtime is not None:
        try:
            runtime.settings_file = AppSettings()
            runtime.settings = Settings(runtime.settings_file)
        except Exception:
            pass
    current_app.config["LEGION_COLORFUL_ASCII_BACKGROUND"] = bool(colorful_ascii_background)
    return jsonify({
        "status": "ok",
        "colorful_ascii_background": bool(colorful_ascii_background),
    })


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

