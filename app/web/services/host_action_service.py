from __future__ import annotations

from typing import Any, Dict

from app.web.host_action_schema import (
    CveCreateRequest,
    HostCategoriesRequest,
    HostNoteRequest,
    ScriptCreateRequest,
    ScriptOutputQuery,
    WorkspacePortMutationRequest,
)


class HostActionService:
    def __init__(self, runtime):
        self.runtime = runtime

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
