import csv
import datetime
import io
import json
import re

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
)

from app.ApplicationInfo import getConsoleLogo
from app.web.services.settings_service import load_display_settings

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


@web_bp.get("/")
def index():
    runtime = current_app.extensions["legion_runtime"]
    snapshot = runtime.get_snapshot()
    display_settings = load_display_settings(runtime)
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
