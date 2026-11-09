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
        kwargs = {"host_id": query.host_id, "service": query.service, "limit": query.limit}
        if query.host_ids:
            kwargs["host_ids"] = list(query.host_ids)
        targets = self.runtime.get_workspace_tool_targets(**kwargs)
        return {
            "targets": targets,
            "host_id": query.host_id,
            "host_ids": list(query.host_ids),
            "service": query.service,
            "limit": query.limit,
            "truncated": len(targets) >= query.limit,  # the caller asked for more than one page can hold
        }

    def start_tool_run(self, payload: Any) -> Dict[str, Any]:
        """Queue one tool run, or one per entry in `targets` (a batch run shares tool, options and timeout)."""
        request = ToolRunRequest.from_payload(payload)
        if not request.tool_id:
            raise ValueError("host_ip, port and tool_id are required.")
        if request.targets:
            seen = set()
            jobs = []
            errors = []
            for target in request.targets:
                if not target.host_ip or not target.port:
                    errors.append({"host_ip": target.host_ip, "port": target.port, "error": "host_ip and port are required."})
                    continue
                key = (target.host_ip, target.port, target.protocol)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    jobs.append(self.runtime.start_tool_run_job(
                        host_ip=target.host_ip,
                        port=target.port,
                        protocol=target.protocol,
                        tool_id=request.tool_id,
                        timeout=request.timeout,
                        parameters=request.parameters,
                    ))
                except Exception as exc:
                    errors.append({"host_ip": target.host_ip, "port": target.port, "protocol": target.protocol, "error": str(exc)})
            if not jobs and errors:
                raise ValueError(errors[0]["error"])
            return {"status": "accepted", "job": jobs[0] if jobs else None, "jobs": jobs, "errors": errors, "queued": len(jobs)}
        if not request.host_ip or not request.port:
            raise ValueError("host_ip, port and tool_id are required.")
        job = self.runtime.start_tool_run_job(
            host_ip=request.host_ip,
            port=request.port,
            protocol=request.protocol,
            tool_id=request.tool_id,
            timeout=request.timeout,
            parameters=request.parameters,
        )
        return {"status": "accepted", "job": job, "jobs": [job], "queued": 1}
