from __future__ import annotations

from typing import Any, Dict, Optional

from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    update_pending_approval,
)
from app.scheduler.audit import update_scheduler_decision_for_approval
from app.scheduler.planner import ScheduledAction
from app.web import runtime_scheduler_decision_execution as web_runtime_scheduler_decision_execution


execute_scheduler_decision = web_runtime_scheduler_decision_execution.execute_scheduler_decision


def active_execution_job_for_approval(runtime, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        job_id = int(str((item or {}).get("execution_job_id", "") or "0").strip() or 0)
    except (TypeError, ValueError):
        job_id = 0
    if job_id <= 0:
        return None

    job = None
    jobs = getattr(runtime, "jobs", None)
    if jobs is not None and hasattr(jobs, "get_job"):
        try:
            job = jobs.get_job(job_id)
        except Exception:
            job = None
    elif hasattr(runtime, "get_job"):
        try:
            job = runtime.get_job(job_id)
        except Exception:
            job = None
    if not isinstance(job, dict):
        return None

    status = str(job.get("status", "") or "").strip().lower()
    if status not in {"queued", "running"}:
        return None
    return job


def approve_scheduler_approval(
        runtime,
        approval_id: int,
        approve_family: bool = False,
        run_now: bool = True,
        family_action: str = "",
        *,
        ensure_scheduler_approval_table_fn=ensure_scheduler_approval_table,
        get_pending_approval_fn=get_pending_approval,
        update_pending_approval_fn=update_pending_approval,
        update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
):
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_approval_table_fn(project.database)
        item = get_pending_approval_fn(project.database, int(approval_id))
        if item is None:
            raise KeyError(f"Unknown approval id: {approval_id}")
        if str(item.get("status", "")).strip().lower() not in {"pending", "approved"}:
            return {"approval": item, "job": None}
        if run_now:
            existing_job = active_execution_job_for_approval(runtime, item)
            if existing_job is not None:
                return {"approval": item, "job": existing_job}

        resolved_family_action = "allowed" if approve_family and not family_action else str(family_action or "")
        if resolved_family_action not in {"", "allowed", "approval_required"}:
            resolved_family_action = ""
        applied_family_state = runtime._apply_family_policy_action(
            item,
            resolved_family_action,
            reason="approved via web",
        )
        runner_type = runtime._runner_type_for_approval_item(item)
        approved_reason = "approved for operator execution" if runner_type == "manual" else "approved via web"

        updated = update_pending_approval_fn(
            project.database,
            int(approval_id),
            status="approved",
            decision_reason=approved_reason,
            family_policy_state=applied_family_state or item.get("family_policy_state", ""),
        )
        update_scheduler_decision_for_approval_fn(
            project.database,
            int(approval_id),
            approved=True,
            executed=False,
            reason=approved_reason,
        )

        if runner_type == "manual" or not run_now:
            runtime._emit_ui_invalidation("approvals", "decisions", "overview")
            return {"approval": updated, "job": None}

        job = runtime._start_job(
            "scheduler-approval-execute",
            lambda job_id: runtime._execute_approved_scheduler_item(int(approval_id), job_id=job_id),
            payload={
                "approval_id": int(approval_id),
                "approve_family": bool(approve_family),
                "family_action": str(resolved_family_action or ""),
            },
        )
        final_state = update_pending_approval_fn(
            project.database,
            int(approval_id),
            status="approved",
            decision_reason="approved & queued",
            execution_job_id=str(job.get("id", "")),
            family_policy_state=applied_family_state or item.get("family_policy_state", ""),
        )
        update_scheduler_decision_for_approval_fn(
            project.database,
            int(approval_id),
            approved=True,
            executed=False,
            reason="approved & queued",
        )
    runtime._emit_ui_invalidation("approvals", "decisions", "overview")
    return {"approval": final_state, "job": job}


def reject_scheduler_approval(
        runtime,
        approval_id: int,
        reason: str = "rejected via web",
        family_action: str = "",
        *,
        ensure_scheduler_approval_table_fn=ensure_scheduler_approval_table,
        get_pending_approval_fn=get_pending_approval,
        update_pending_approval_fn=update_pending_approval,
        update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
):
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_approval_table_fn(project.database)
        item = get_pending_approval_fn(project.database, int(approval_id))
        if item is None:
            raise KeyError(f"Unknown approval id: {approval_id}")
        resolved_family_action = str(family_action or "").strip().lower()
        if resolved_family_action not in {"", "approval_required", "suppressed", "blocked"}:
            resolved_family_action = ""
        applied_family_state = runtime._apply_family_policy_action(item, resolved_family_action, reason=reason)
        updated = update_pending_approval_fn(
            project.database,
            int(approval_id),
            status="rejected",
            decision_reason=str(reason or "rejected via web"),
            family_policy_state=applied_family_state or item.get("family_policy_state", ""),
        )
        update_scheduler_decision_for_approval_fn(
            project.database,
            int(approval_id),
            approved=False,
            executed=False,
            reason=str(reason or "rejected via web"),
        )
        result = updated
    runtime._emit_ui_invalidation("approvals", "decisions", "overview")
    return result


def execute_approved_scheduler_item(
        runtime,
        approval_id: int,
        job_id: int = 0,
        *,
        get_pending_approval_fn=get_pending_approval,
        update_pending_approval_fn=update_pending_approval,
        update_scheduler_decision_for_approval_fn=update_scheduler_decision_for_approval,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        item = get_pending_approval_fn(project.database, int(approval_id))
        if item is None:
            raise KeyError(f"Unknown approval id: {approval_id}")
        if str(item.get("status", "")).strip().lower() not in {"approved", "pending"}:
            return {"approval_id": int(approval_id), "status": item.get("status", "")}
        if runtime._runner_type_for_approval_item(item) == "manual":
            manual_reason = "approved for operator execution"
            update_pending_approval_fn(
                project.database,
                int(approval_id),
                status="approved",
                decision_reason=manual_reason,
            )
            update_scheduler_decision_for_approval_fn(
                project.database,
                int(approval_id),
                approved=True,
                executed=False,
                reason=manual_reason,
            )
            return {
                "approval_id": int(approval_id),
                "executed": False,
                "reason": "manual runner requires operator execution",
                "process_id": 0,
            }
        update_pending_approval_fn(
            project.database,
            int(approval_id),
            status="running",
            decision_reason="approved & running",
        )
        update_scheduler_decision_for_approval_fn(
            project.database,
            int(approval_id),
            approved=True,
            executed=False,
            reason="approved & running",
        )

    decision = ScheduledAction.from_legacy_fields(
        tool_id=str(item.get("tool_id", "")),
        label=str(item.get("label", "")),
        command_template=str(item.get("command_template", "")),
        protocol=str(item.get("protocol", "tcp") or "tcp"),
        score=100.0,
        rationale=str(item.get("rationale", "")),
        mode=str(item.get("scheduler_mode", "ai") or "ai"),
        goal_profile=str(item.get("goal_profile", "") or ""),
        family_id=str(item.get("command_family_id", "")),
        danger_categories=runtime._split_csv(
            str(item.get("risk_tags", "") or item.get("danger_categories", ""))
        ),
        requires_approval=False,
        target_ref={
            "host_ip": str(item.get("host_ip", "")),
            "port": str(item.get("port", "")),
            "service": str(item.get("service", "")),
            "protocol": str(item.get("protocol", "tcp") or "tcp"),
        },
        approval_state="not_required",
        policy_reason=str(item.get("policy_reason", "")),
        risk_summary=str(item.get("risk_summary", "")),
        safer_alternative=str(item.get("safer_alternative", "")),
        family_policy_state=str(item.get("family_policy_state", "")),
    )
    decision.linked_evidence_refs = runtime._split_csv(str(item.get("evidence_refs", "")))

    execution_result = runtime._execute_scheduler_decision(
        decision,
        host_ip=str(item.get("host_ip", "")),
        port=str(item.get("port", "")),
        protocol=str(item.get("protocol", "tcp") or "tcp"),
        service_name=str(item.get("service", "")),
        command_template=str(item.get("command_template", "")),
        timeout=300,
        job_id=int(job_id or 0),
        capture_metadata=True,
        approval_id=int(approval_id),
    )
    executed = bool(execution_result.get("executed", False))
    reason = str(execution_result.get("reason", "") or "")
    process_id = int(execution_result.get("process_id", 0) or 0)
    execution_record = execution_result.get("execution_record")

    with runtime._lock:
        project = runtime._require_active_project()
        final_reason = "approved & completed" if executed else f"approved & failed ({reason})"
        update_pending_approval_fn(
            project.database,
            int(approval_id),
            status="executed" if executed else "failed",
            decision_reason=final_reason,
        )
        updated_decision = update_scheduler_decision_for_approval_fn(
            project.database,
            int(approval_id),
            approved=True,
            executed=executed,
            reason=final_reason,
        )

    if updated_decision is None:
        runtime._record_scheduler_decision(
            decision,
            str(item.get("host_ip", "")),
            str(item.get("port", "")),
            str(item.get("protocol", "")),
            str(item.get("service", "")),
            approved=True,
            executed=executed,
            reason="approved & completed" if executed else f"approved & failed ({reason})",
            approval_id=int(approval_id),
        )

    runtime._persist_scheduler_execution_record(
        decision,
        execution_record,
        host_ip=str(item.get("host_ip", "")),
        port=str(item.get("port", "")),
        protocol=str(item.get("protocol", "")),
        service_name=str(item.get("service", "")),
    )

    if process_id and executed:
        runtime._save_script_result_if_missing(
            host_ip=str(item.get("host_ip", "")),
            port=str(item.get("port", "")),
            protocol=str(item.get("protocol", "")),
            tool_id=str(item.get("tool_id", "")),
            process_id=process_id,
        )

    return {
        "approval_id": int(approval_id),
        "executed": bool(executed),
        "reason": reason,
        "process_id": process_id,
    }

