from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from app.web.scheduler_schema import (
    SchedulerApprovalListQuery,
    SchedulerApprovalRequest,
    SchedulerDecisionQuery,
    SchedulerExecutionQuery,
    SchedulerExecutionTraceQuery,
    SchedulerFamilyApprovalRequest,
    SchedulerLogQuery,
    SchedulerPlanPreviewQuery,
    SchedulerPreferencesPatch,
    SchedulerRejectionRequest,
)


class SchedulerService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_preferences(self) -> Dict[str, Any]:
        return self.runtime.get_scheduler_preferences()

    def update_preferences(self, payload: Any) -> Dict[str, Any]:
        updates = SchedulerPreferencesPatch.from_payload(payload).updates
        if hasattr(self.runtime, "apply_scheduler_preferences"):
            return self.runtime.apply_scheduler_preferences(updates)
        self.runtime.scheduler_config.update_preferences(updates)
        return self.runtime.get_scheduler_preferences()

    def test_provider(self, payload: Any) -> Dict[str, Any]:
        updates = SchedulerPreferencesPatch.from_payload(payload).updates
        return self.runtime.test_scheduler_provider(updates)

    def get_engagement_policy(self) -> Dict[str, Any]:
        if hasattr(self.runtime, "get_engagement_policy"):
            return self.runtime.get_engagement_policy()
        return self.runtime.get_scheduler_preferences().get("engagement_policy", {})

    def update_engagement_policy(self, payload: Any) -> Dict[str, Any]:
        updates = payload if isinstance(payload, dict) else {}
        if hasattr(self.runtime, "set_engagement_policy"):
            return self.runtime.set_engagement_policy(updates)
        return self.update_preferences({"engagement_policy": updates}).get("engagement_policy", {})

    def get_provider_logs(self, args) -> Dict[str, Any]:
        query = SchedulerLogQuery.from_args(args)
        logs = self.runtime.get_scheduler_provider_logs(limit=query.limit)
        lines = []
        for row in logs:
            lines.append(
                f"[{row.get('timestamp', '')}] {row.get('provider', '')} "
                f"{row.get('method', '')} {row.get('endpoint', '')}"
            )
            status = row.get("response_status", "")
            if status not in (None, ""):
                lines.append(f"status: {status}")
            if row.get("api_style"):
                lines.append(f"api_style: {row.get('api_style')}")
            prompt_metadata = row.get("prompt_metadata", {})
            if isinstance(prompt_metadata, dict) and prompt_metadata:
                lines.append(f"prompt metadata: {json.dumps(prompt_metadata, ensure_ascii=False)}")
            lines.append(f"request headers: {json.dumps(row.get('request_headers', {}), ensure_ascii=False)}")
            lines.append(f"request body: {row.get('request_body', '')}")
            lines.append(f"response body: {row.get('response_body', '')}")
            if row.get("error"):
                lines.append(f"error: {row.get('error')}")
            lines.append("")
        return {
            "logs": logs,
            "text": "\n".join(lines).strip(),
        }

    def approve_family(self, payload: Any) -> Dict[str, Any]:
        request = SchedulerFamilyApprovalRequest.from_payload(payload)
        self.runtime.scheduler_config.approve_family(request.family_id, request.metadata)
        return {"status": "ok", "family_id": request.family_id}

    def get_decisions(self, args) -> Dict[str, Any]:
        query = SchedulerDecisionQuery.from_args(args)
        return {"decisions": self.runtime.get_scheduler_decisions(limit=query.limit)}

    def get_plan_preview(self, args) -> Dict[str, Any]:
        query = SchedulerPlanPreviewQuery.from_args(args)
        return self.runtime.get_scheduler_plan_preview(
            host_id=query.host_id,
            host_ip=query.host_ip,
            service=query.service,
            port=query.port,
            protocol=query.protocol,
            mode=query.mode,
            limit_targets=query.limit_targets,
            limit_actions=query.limit_actions,
        )

    def list_approvals(self, args) -> Dict[str, Any]:
        query = SchedulerApprovalListQuery.from_args(args)
        return {"approvals": self.runtime.get_scheduler_approvals(limit=query.limit, status=query.status)}

    def approve_approval(self, approval_id: int, payload: Any) -> Tuple[Dict[str, Any], int]:
        request = SchedulerApprovalRequest.from_payload(payload)
        result = self.runtime.approve_scheduler_approval(
            approval_id=approval_id,
            approve_family=request.approve_family,
            run_now=request.run_now,
            family_action=request.family_action,
        )
        status_code = 202 if result.get("job") else 200
        return {"status": "ok", **result}, status_code

    def reject_approval(self, approval_id: int, payload: Any) -> Dict[str, Any]:
        request = SchedulerRejectionRequest.from_payload(payload)
        result = self.runtime.reject_scheduler_approval(
            approval_id=approval_id,
            reason=request.reason,
            family_action=request.family_action,
        )
        return {"status": "ok", "approval": result}

    def list_executions(self, args) -> Dict[str, Any]:
        query = SchedulerExecutionQuery.from_args(args)
        return {
            "executions": self.runtime.get_scheduler_execution_traces(
                limit=query.limit,
                host_id=query.host_id,
                host_ip=query.host_ip,
                tool_id=query.tool_id,
                include_output=query.include_output,
            )
        }

    def get_execution_trace(self, execution_id: str, args) -> Dict[str, Any]:
        query = SchedulerExecutionTraceQuery.from_args(args)
        return self.runtime.get_scheduler_execution_trace(execution_id, output_max_chars=query.max_chars)

    def start_run(self) -> Tuple[Dict[str, Any], int]:
        job = self.runtime.start_scheduler_run_job()
        return {"status": "accepted", "job": job}, 202
