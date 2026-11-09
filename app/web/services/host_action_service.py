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

    BULK_ACTIONS = ("rescan", "dig-deeper", "refresh-screenshots", "remove")

    def bulk_host_action(self, payload: Any) -> Dict[str, Any]:
        """Apply one host action to many hosts; every host is attempted and failures are reported per host."""
        source = payload if isinstance(payload, dict) else {}
        action = str(source.get("action", "") or "").strip().lower()
        if action not in self.BULK_ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(self.BULK_ACTIONS)}.")
        raw_ids = source.get("host_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            raise ValueError("host_ids must be a non-empty list.")
        host_ids = []
        for raw in raw_ids:
            try:
                value = int(raw)
            except (TypeError, ValueError):
                continue
            if value > 0 and value not in host_ids:
                host_ids.append(value)
        if not host_ids:
            raise ValueError("host_ids must contain at least one host id.")
        if action == "remove":
            # Deleting hosts cascades through ports, scripts, CVEs, notes and the evidence graph; a large
            # selection would hold the request for minutes, so it runs as a cancellable job instead.
            job = self.runtime.start_bulk_host_remove_job(host_ids)
            return {"status": "accepted", "action": action, "requested": len(host_ids), "job": job}
        results = []
        for host_id in host_ids:
            try:
                if action == "rescan":
                    outcome = {"job": self.runtime.start_host_rescan_job(host_id)}
                elif action == "dig-deeper":
                    outcome = {"job": self.runtime.start_host_dig_deeper_job(host_id)}
                elif action == "refresh-screenshots":
                    outcome = {"job": self.runtime.start_host_screenshot_refresh_job(host_id)}
                else:
                    outcome = dict(self.runtime.delete_host_workspace(host_id) or {})
                results.append({"host_id": host_id, "status": "ok", **outcome})
            except Exception as exc:
                results.append({"host_id": host_id, "status": "error", "error": str(exc)})
        succeeded = sum(1 for item in results if item["status"] == "ok")
        return {
            "status": "ok" if succeeded == len(results) else ("partial" if succeeded else "error"),
            "action": action,
            "requested": len(results),
            "succeeded": succeeded,
            "failed": len(results) - succeeded,
            "results": results,
        }
