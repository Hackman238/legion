"""Full-workspace exports (JSON and CSV) built from the complete loaders, not the capped UI snapshot."""
from __future__ import annotations

import csv
import datetime
import io
import json
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import text

# Table name -> loader(runtime) returning a list of row dicts. Every table the UI shows (and a few it only
# summarises) can be exported on its own through /api/export/table/<name>.<csv|json>.
EXPORT_TABLES = (
    "hosts",
    "services",
    "ports",
    "cves",
    "findings",
    "scripts",
    "notes",
    "processes",
    "jobs",
    "scan_history",
    "scheduler_decisions",
    "scheduler_approvals",
    "scheduler_executions",
    "credentials",
    "tools",
)

_UNBOUNDED = 1_000_000


def _rows(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        for key in ("rows", "items", "hosts", "services", "findings", "captures", "tools", "processes", "jobs"):
            if isinstance(value.get(key), list):
                return [dict(item) for item in value[key] if isinstance(item, dict)]
        return []
    return [dict(item) for item in list(value or []) if isinstance(item, dict)]


def _sql_rows(runtime, sql: str) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if project is None:
            return []
        session = project.database.session()
        try:
            result = session.execute(text(sql))
            keys = list(result.keys())
            return [dict(zip(keys, row)) for row in result.fetchall()]
        finally:
            session.close()


def export_table_rows(runtime, table: str) -> List[Dict[str, Any]]:
    name = str(table or "").strip().lower()
    if name == "hosts":
        return _rows(runtime.get_workspace_hosts(include_down=True))
    if name == "services":
        return _rows(runtime.get_workspace_services(limit=_UNBOUNDED))
    if name == "ports":
        return _sql_rows(runtime, (
            "SELECT h.ip AS host_ip, h.hostname AS hostname, p.portId AS port, p.protocol AS protocol, "
            "p.state AS state, s.name AS service, s.product AS product, s.version AS version, s.extrainfo AS extrainfo "
            "FROM portObj p JOIN hostObj h ON h.id = p.hostId LEFT JOIN serviceObj s ON s.id = p.serviceId "
            "ORDER BY h.ip, p.protocol, CAST(p.portId AS INTEGER)"
        ))
    if name == "cves":
        return _sql_rows(runtime, (
            "SELECT h.ip AS host_ip, h.hostname AS hostname, c.name AS cve, c.severity AS severity, c.product AS product, "
            "c.version AS version, c.source AS source, c.url AS url, c.exploitId AS exploit_id, c.exploit AS exploit, "
            "c.exploitUrl AS exploit_url "
            "FROM cve c JOIN hostObj h ON h.id = c.hostId ORDER BY h.ip, c.severity DESC, c.name"
        ))
    if name == "findings":
        payload = runtime.get_findings(limit_hosts=_UNBOUNDED, limit_findings=_UNBOUNDED)
        return _rows(payload)
    if name == "scripts":
        return _sql_rows(runtime, (
            "SELECT h.ip AS host_ip, h.hostname AS hostname, p.portId AS port, p.protocol AS protocol, "
            "s.scriptId AS script, s.output AS output "
            "FROM l1ScriptObj s JOIN hostObj h ON h.id = s.hostId LEFT JOIN portObj p ON p.id = s.portId "
            "ORDER BY h.ip, s.scriptId"
        ))
    if name == "notes":
        return _sql_rows(runtime, (
            "SELECT h.ip AS host_ip, h.hostname AS hostname, n.text AS note "
            "FROM note n JOIN hostObj h ON h.id = n.hostId ORDER BY h.ip"
        ))
    if name == "processes":
        return _rows(runtime.get_workspace_processes(limit=_UNBOUNDED))
    if name == "jobs":
        return _rows(runtime.jobs.list_jobs(limit=_UNBOUNDED))
    if name == "scan_history":
        return _rows(runtime.get_scan_history(limit=_UNBOUNDED))
    if name == "scheduler_decisions":
        return _rows(runtime.get_scheduler_decisions(limit=_UNBOUNDED))
    if name == "scheduler_approvals":
        return _rows(runtime.get_scheduler_approvals(limit=_UNBOUNDED, status=None))
    if name == "scheduler_executions":
        return _rows(runtime.get_scheduler_execution_records(limit=_UNBOUNDED))
    if name == "credentials":
        return _rows(runtime.get_workspace_credential_captures(limit=None))
    if name == "tools":
        return _rows(runtime.get_workspace_tools_page(limit=_UNBOUNDED, offset=0))
    raise KeyError(f"Unknown export table: {table}")


def build_full_export(runtime) -> Dict[str, Any]:
    """Everything in the open project, uncapped (down hosts, every service, every process and decision)."""
    with runtime._lock:
        project = runtime._project_metadata()
        summary = runtime._summary()
    payload: Dict[str, Any] = {
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "project": project,
        "summary": summary,
    }
    for table in EXPORT_TABLES:
        try:
            payload[table] = export_table_rows(runtime, table)
        except Exception as exc:  # one broken table must not lose the rest of the export
            payload[table] = []
            payload.setdefault("errors", []).append({"table": table, "error": str(exc)})
    return payload


def _cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    if value is None:
        return ""
    return str(value)


def _headers_for(rows: Iterable[Dict[str, Any]], preferred: Optional[List[str]] = None) -> List[str]:
    headers: List[str] = list(preferred or [])
    seen = set(headers)
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                headers.append(str(key))
    return headers


def rows_to_csv(rows: List[Dict[str, Any]], preferred_headers: Optional[List[str]] = None) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    headers = _headers_for(rows, preferred_headers)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([_cell(row.get(header, "")) for header in headers])
    return output.getvalue()


def build_full_csv_export(payload: Dict[str, Any]) -> str:
    """One CSV with a titled section per table (the historic multi-section layout, now uncapped)."""
    output = io.StringIO()
    writer = csv.writer(output)
    for title in ("project", "summary"):
        writer.writerow([title])
        writer.writerow(["key", "value"])
        for key, value in dict(payload.get(title, {}) or {}).items():
            writer.writerow([str(key), _cell(value)])
        writer.writerow([])
    for table in EXPORT_TABLES:
        rows = list(payload.get(table, []) or [])
        writer.writerow([table])
        headers = _headers_for(rows)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([_cell(row.get(header, "")) for header in headers])
        writer.writerow([])
    return output.getvalue()
