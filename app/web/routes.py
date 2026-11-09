import datetime
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
from app.web.runtime_exports import (
    EXPORT_TABLES,
    ExportInterrupted,
    build_full_csv_export,
    build_full_export,
    export_table_rows,
    rows_to_csv,
)
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
    # The whole project, not the capped UI snapshot (which drops down hosts and truncates every list).
    runtime = current_app.extensions["legion_runtime"]
    payload = json.dumps(build_full_export(runtime), indent=2, default=str)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(payload, mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="legion-export-{timestamp}.json"'
    return response


@web_bp.get("/api/export/csv")
def export_csv():
    runtime = current_app.extensions["legion_runtime"]
    csv_text = build_full_csv_export(build_full_export(runtime))
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    response = current_app.response_class(csv_text, mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="legion-export-{timestamp}.csv"'
    return response


@web_bp.get("/api/export/tables")
def export_tables():
    return jsonify({"tables": list(EXPORT_TABLES)})


@web_bp.get("/api/export/table/<table>.<fmt>")
def export_table(table, fmt):
    runtime = current_app.extensions["legion_runtime"]
    table_name = str(table or "").strip().lower()
    if table_name not in EXPORT_TABLES:
        return jsonify({"status": "error", "error": f"Unknown export table: {table}"}), 404
    if fmt not in {"csv", "json"}:
        return jsonify({"status": "error", "error": "Format must be csv or json."}), 400
    try:
        rows = export_table_rows(runtime, table_name)
    except ExportInterrupted as exc:
        return jsonify({"status": "error", "error": str(exc)}), 409
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    if fmt == "json":
        body = json.dumps({"table": table_name, "count": len(rows), "rows": rows}, indent=2, default=str)
        response = current_app.response_class(body, mimetype="application/json")
    else:
        response = current_app.response_class(rows_to_csv(rows), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="legion-{table_name}-{timestamp}.{fmt}"'
    return response
