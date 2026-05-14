from __future__ import annotations

import csv
import datetime
import io
import json
import re
from typing import Dict

from app.web.workspace_schema import (
    WorkspaceFindingsQuery,
    WorkspaceHostsQuery,
    WorkspaceServicesQuery,
)


def _safe_filename_token(value: str, fallback: str = "workspace") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        return str(fallback)
    return token[:96]


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


def _build_hosts_json_export(rows, *, host_filter: str, service_filter: str = "", service_filters=None):
    return json.dumps(
        {
            "filter": str(host_filter or "hide_down"),
            "service": str(service_filter or ""),
            "services": list(service_filters or []),
            "host_count": len(list(rows or [])),
            "hosts": list(rows or []),
        },
        indent=2,
        default=str,
    )


class WorkspaceService:
    def __init__(self, runtime):
        self.runtime = runtime

    def _get_workspace_hosts_rows(self, query: WorkspaceHostsQuery):
        if query.limit is None:
            return self.runtime.get_workspace_hosts(
                include_down=query.include_down,
                service=query.service_filter,
                category=query.category_filter,
            )
        return self.runtime.get_workspace_hosts(
            limit=query.limit,
            include_down=query.include_down,
            service=query.service_filter,
            category=query.category_filter,
        )

    def list_workspace_hosts(self, args) -> Dict[str, Any]:
        query = WorkspaceHostsQuery.from_args(args)
        rows = self._get_workspace_hosts_rows(query)
        return {
            "filter": query.host_filter,
            "service": query.service_filter,
            "services": list(query.service_filters),
            "category": query.category_filter,
            "hosts": rows,
        }

    def export_workspace_hosts_csv(self, args) -> Dict[str, Any]:
        query = WorkspaceHostsQuery.from_args(args)
        rows = self._get_workspace_hosts_rows(query)
        csv_text = _build_hosts_csv_export(rows)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        suffix = "all" if query.include_down else "up-only"
        if query.service_filter:
            suffix = f"{suffix}-{_safe_filename_token(query.service_filter, fallback='service')}"
        return {
            "body": csv_text.encode("utf-8"),
            "mimetype": "text/csv",
            "filename": f"legion-hosts-{suffix}-{timestamp}.csv",
        }

    def export_workspace_hosts_json(self, args) -> Dict[str, Any]:
        query = WorkspaceHostsQuery.from_args(args)
        rows = self._get_workspace_hosts_rows(query)
        payload = _build_hosts_json_export(
            rows,
            host_filter=query.host_filter,
            service_filter=query.service_filter,
            service_filters=query.service_filters,
        )
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        suffix = "all" if query.include_down else "up-only"
        if query.service_filter:
            suffix = f"{suffix}-{_safe_filename_token(query.service_filter, fallback='service')}"
        return {
            "body": payload.encode("utf-8"),
            "mimetype": "application/json",
            "filename": f"legion-hosts-{suffix}-{timestamp}.json",
        }

    def get_workspace_overview(self) -> Dict[str, Any]:
        return self.runtime.get_workspace_overview()

    def list_workspace_services(self, args) -> Dict[str, Any]:
        query = WorkspaceServicesQuery.from_args(args)
        return {
            "services": self.runtime.get_workspace_services(
                limit=query.limit,
                host_id=query.host_id,
                category=query.category,
            ),
            "host_id": query.host_id,
            "category": query.category,
        }

    def get_host_workspace(self, host_id: int) -> Dict[str, Any]:
        return self.runtime.get_host_workspace(int(host_id))

    def get_host_target_state(self, host_id: int, limit: int = 500) -> Dict[str, Any]:
        return self.runtime.get_target_state_view(host_id=int(host_id), limit=int(limit or 500))

    def list_findings(self, args) -> Dict[str, Any]:
        query = WorkspaceFindingsQuery.from_args(args)
        return self.runtime.get_findings(host_id=query.host_id, limit_findings=query.limit)
