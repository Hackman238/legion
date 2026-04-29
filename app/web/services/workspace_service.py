from __future__ import annotations

import csv
import datetime
import io
import json
import re
from typing import Any, Dict

from app.web.workspace_schema import (
    CredentialCaptureConfigRequest,
    CredentialCaptureLogQuery,
    CredentialCaptureToolRequest,
    CredentialsDownloadQuery,
    CredentialsQuery,
    CveCreateRequest,
    HostCategoriesRequest,
    HostNoteRequest,
    WorkspaceFindingsQuery,
    WorkspaceHostsQuery,
    WorkspaceServicesQuery,
    ProcessClearRequest,
    ProcessOutputQuery,
    ProcessRetryRequest,
    ScriptCreateRequest,
    ScriptOutputQuery,
    ScreenshotDeleteRequest,
    ScreenshotRefreshRequest,
    ToolRunRequest,
    WorkspaceToolsPageQuery,
    WorkspaceToolTargetsQuery,
    WorkspacePortMutationRequest,
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


def _build_hosts_json_export(rows, *, host_filter: str, service_filter: str = ""):
    return json.dumps(
        {
            "filter": str(host_filter or "hide_down"),
            "service": str(service_filter or ""),
            "host_count": len(list(rows or [])),
            "hosts": list(rows or []),
        },
        indent=2,
        default=str,
    )


class WorkspaceService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_credential_capture_state(self) -> Dict[str, Any]:
        return self.runtime.get_credential_capture_state(include_captures=False)

    def save_credential_capture_config(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureConfigRequest.from_payload(payload)
        return self.runtime.save_credential_capture_config(request.updates)

    def start_credential_capture(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureToolRequest.from_payload(payload)
        job = self.runtime.start_credential_capture_session_job(request.tool_id)
        return {"status": "accepted", "job": job}

    def stop_credential_capture(self, payload: Any) -> Dict[str, Any]:
        request = CredentialCaptureToolRequest.from_payload(payload)
        return self.runtime.stop_credential_capture_session(request.tool_id)

    def download_credential_capture_log(self, args) -> Dict[str, Any]:
        query = CredentialCaptureLogQuery.from_args(args)
        payload = self.runtime.get_credential_capture_log_payload(query.tool_id)
        content = str(payload.get("text", "") or "")
        if not content:
            raise FileNotFoundError("No credential capture log output available.")
        return {
            "body": content.encode("utf-8"),
            "mimetype": "text/plain",
            "filename": f"{_safe_filename_token(query.tool_id or 'credential-capture')}-log.txt",
        }

    def list_credentials(self, args) -> Dict[str, Any]:
        query = CredentialsQuery.from_args(args)
        return self.runtime.get_workspace_credential_captures(limit=query.limit)

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
        payload = _build_hosts_json_export(rows, host_filter=query.host_filter, service_filter=query.service_filter)
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

    def list_workspace_tools(self, args) -> Dict[str, Any]:
        query = WorkspaceToolsPageQuery.from_args(args)
        return self.runtime.get_workspace_tools_page(
            service=query.service,
            limit=query.limit,
            offset=query.offset,
        )

    def list_workspace_tool_targets(self, args) -> Dict[str, Any]:
        query = WorkspaceToolTargetsQuery.from_args(args)
        return {
            "targets": self.runtime.get_workspace_tool_targets(
                host_id=query.host_id,
                service=query.service,
                limit=query.limit,
            ),
            "host_id": query.host_id,
            "service": query.service,
        }

    def get_host_workspace(self, host_id: int) -> Dict[str, Any]:
        return self.runtime.get_host_workspace(int(host_id))

    def get_host_target_state(self, host_id: int, limit: int = 500) -> Dict[str, Any]:
        return self.runtime.get_target_state_view(host_id=int(host_id), limit=int(limit or 500))

    def list_findings(self, args) -> Dict[str, Any]:
        query = WorkspaceFindingsQuery.from_args(args)
        return self.runtime.get_findings(host_id=query.host_id, limit_findings=query.limit)

    def get_screenshot_file(self, filename: str) -> str:
        return self.runtime.get_screenshot_file(filename)

    def download_credentials(self, args) -> Dict[str, Any]:
        query = CredentialsDownloadQuery.from_args(args)
        if query.output_format not in {"txt", "json"}:
            raise ValueError("format must be txt or json")
        payload = self.runtime.get_workspace_credential_captures(limit=5000)
        if query.output_format == "json":
            return {
                "body": json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
                "mimetype": "application/json",
                "filename": "credentials.json",
            }
        deduped_hashes = list(payload.get("deduped_hashes", []) or [])
        content = "\n".join(str(item or "") for item in deduped_hashes if str(item or "").strip())
        return {
            "body": content.encode("utf-8"),
            "mimetype": "text/plain",
            "filename": "credential-hashes.txt",
        }

    def refresh_host_screenshots(self, host_id: int) -> Dict[str, Any]:
        job = self.runtime.start_host_screenshot_refresh_job(int(host_id))
        return {"status": "accepted", "job": job}

    def refresh_graph_screenshot(self, payload: Any) -> Dict[str, Any]:
        request = ScreenshotRefreshRequest.from_payload(payload)
        job = self.runtime.start_graph_screenshot_refresh_job(
            request.host_id,
            request.port,
            request.protocol,
        )
        return {"status": "accepted", "job": job}

    def delete_graph_screenshot(self, payload: Any) -> Dict[str, Any]:
        request = ScreenshotDeleteRequest.from_payload(payload)
        return self.runtime.delete_graph_screenshot(
            host_id=request.host_id,
            artifact_ref=request.artifact_ref,
            filename=request.filename,
            port=request.port,
            protocol=request.protocol,
        )

    def delete_workspace_port(self, payload: Any) -> Dict[str, Any]:
        request = WorkspacePortMutationRequest.from_payload(payload)
        return self.runtime.delete_workspace_port(
            host_id=request.host_id,
            port=request.port,
            protocol=request.protocol,
        )

    def delete_workspace_service(self, payload: Any) -> Dict[str, Any]:
        request = WorkspacePortMutationRequest.from_payload(payload)
        return self.runtime.delete_workspace_service(
            host_id=request.host_id,
            port=request.port,
            protocol=request.protocol,
            service=request.service,
        )

    def update_host_note(self, host_id: int, payload: Any) -> Dict[str, Any]:
        request = HostNoteRequest.from_payload(payload)
        return self.runtime.update_host_note(host_id, request.text_value)

    def update_host_categories(self, host_id: int, payload: Any) -> Dict[str, Any]:
        request = HostCategoriesRequest.from_payload(payload)
        return self.runtime.update_host_categories(
            host_id,
            manual_categories=request.manual_categories,
            override_auto=request.override_auto,
        )

    def create_script_entry(self, host_id: int, payload: Any) -> Dict[str, Any]:
        request = ScriptCreateRequest.from_payload(payload)
        if not request.script_id or not request.port:
            raise ValueError("script_id and port are required.")
        row = self.runtime.create_script_entry(
            host_id,
            request.port,
            request.protocol,
            request.script_id,
            request.output,
        )
        return {"status": "ok", "script": row}

    def delete_script_entry(self, script_id: int) -> Dict[str, Any]:
        return self.runtime.delete_script_entry(script_id)

    def get_script_output(self, script_id: int, args) -> Dict[str, Any]:
        query = ScriptOutputQuery.from_args(args)
        return self.runtime.get_script_output(script_id, offset=query.offset, max_chars=query.max_chars)

    def create_cve_entry(self, host_id: int, payload: Any) -> Dict[str, Any]:
        request = CveCreateRequest.from_payload(payload)
        if not request.name:
            raise ValueError("name is required.")
        row = self.runtime.create_cve_entry(
            host_id=host_id,
            name=request.name,
            url=request.url,
            severity=request.severity,
            source=request.source,
            product=request.product,
            version=request.version,
            exploit_id=request.exploit_id,
            exploit=request.exploit,
            exploit_url=request.exploit_url,
        )
        return {"status": "ok", "cve": row}

    def delete_cve_entry(self, cve_id: int) -> Dict[str, Any]:
        return self.runtime.delete_cve_entry(cve_id)

    def start_host_dig_deeper(self, host_id: int) -> Dict[str, Any]:
        job = self.runtime.start_host_dig_deeper_job(int(host_id))
        return {"status": "accepted", "job": job}

    def delete_host_workspace(self, host_id: int) -> Dict[str, Any]:
        return self.runtime.delete_host_workspace(int(host_id))

    def start_tool_run(self, payload: Any) -> Dict[str, Any]:
        request = ToolRunRequest.from_payload(payload)
        if not request.host_ip or not request.port or not request.tool_id:
            raise ValueError("host_ip, port and tool_id are required.")
        job = self.runtime.start_tool_run_job(
            host_ip=request.host_ip,
            port=request.port,
            protocol=request.protocol,
            tool_id=request.tool_id,
            command_override=request.command_override,
            timeout=request.timeout,
        )
        return {"status": "accepted", "job": job}

    def kill_process(self, process_id: int) -> Dict[str, Any]:
        return self.runtime.kill_process(int(process_id))

    def retry_process(self, process_id: int, payload: Any) -> Dict[str, Any]:
        request = ProcessRetryRequest.from_payload(payload)
        job = self.runtime.start_process_retry_job(process_id=int(process_id), timeout=request.timeout)
        return {"status": "accepted", "job": job}

    def close_process(self, process_id: int) -> Dict[str, Any]:
        return self.runtime.close_process(int(process_id))

    def clear_processes(self, payload: Any) -> Dict[str, Any]:
        request = ProcessClearRequest.from_payload(payload)
        return self.runtime.clear_processes(reset_all=request.reset_all)

    def get_process_output(self, process_id: int, args) -> Dict[str, Any]:
        query = ProcessOutputQuery.from_args(args)
        return self.runtime.get_process_output(int(process_id), offset=query.offset, max_chars=query.max_chars)
