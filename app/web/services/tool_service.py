from __future__ import annotations

from typing import Any, Dict

from app.web.tool_schema import ToolRunRequest, WorkspaceToolTargetsQuery, WorkspaceToolsPageQuery


class ToolService:
    def __init__(self, runtime):
        self.runtime = runtime

    def list_workspace_tools(self, args) -> Dict[str, Any]:
        query = WorkspaceToolsPageQuery.from_args(args)
        return self.runtime.get_workspace_tools_page(
            service=query.service,
            port=query.port,
            protocol=query.protocol,
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

    def start_tool_run(self, payload: Any) -> Dict[str, Any]:
        request = ToolRunRequest.from_payload(payload)
        if not request.host_ip or not request.port or not request.tool_id:
            raise ValueError("host_ip, port and tool_id are required.")
        job = self.runtime.start_tool_run_job(
            host_ip=request.host_ip,
            port=request.port,
            protocol=request.protocol,
            tool_id=request.tool_id,
            timeout=request.timeout,
            parameters=request.parameters,
        )
        return {"status": "accepted", "job": job}
