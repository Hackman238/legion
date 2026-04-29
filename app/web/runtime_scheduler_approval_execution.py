from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    update_pending_approval,
)
from app.scheduler.audit import update_scheduler_decision_for_approval
from app.scheduler.models import ExecutionRecord
from app.scheduler.planner import ScheduledAction
from app.scheduler.runners import (
    RunnerExecutionRequest,
    RunnerExecutionResult,
    execute_runner_request,
    normalize_runner_settings,
)
from app.settings import AppSettings
from app.timing import getTimestamp


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


def execute_scheduler_decision(
        runtime,
        decision: ScheduledAction,
        *,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        command_template: str,
        timeout: int,
        job_id: int = 0,
        capture_metadata: bool = False,
        approval_id: int = 0,
        runner_preference: str = "",
        runner_settings: Optional[Dict[str, Any]] = None,
) -> Any:
    normalized_runner_settings = normalize_runner_settings(runner_settings or {})
    project = runtime._require_active_project()
    input_error = AppSettings._scheduler_target_input_error(
        str(decision.tool_id or ""),
        str(command_template or ""),
        port=str(port or ""),
    )
    if not isinstance(input_error, str):
        input_error = ""
    if input_error:
        if not capture_metadata:
            return False, input_error, 0
        fallback_timestamp = getTimestamp(True)
        execution_record = ExecutionRecord.from_plan_step(
            decision,
            started_at=fallback_timestamp,
            finished_at=fallback_timestamp,
            exit_status=input_error,
            runner_type="local",
            approval_id=str(approval_id or ""),
        )
        return {
            "executed": False,
            "reason": input_error,
            "process_id": 0,
            "execution_record": execution_record,
        }
    request = RunnerExecutionRequest(
        decision=decision,
        tool_id=str(decision.tool_id or ""),
        command_template=str(command_template or ""),
        host_ip=str(host_ip or ""),
        hostname=str(runtime._hostname_for_ip(host_ip) or ""),
        port=str(port or ""),
        protocol=str(protocol or "tcp"),
        service_name=str(service_name or ""),
        timeout=int(timeout or 300),
        job_id=int(job_id or 0),
        approval_id=int(approval_id or 0),
        declared_runner_type=str(getattr(getattr(decision, "action", None), "runner_type", "local") or "local"),
    )

    def _build_command(request_payload):
        return runtime._build_command(
            str(request_payload.command_template or ""),
            str(request_payload.host_ip or ""),
            str(request_payload.port or ""),
            str(request_payload.protocol or "tcp"),
            str(request_payload.tool_id or ""),
            str(getattr(request_payload, "service_name", "") or ""),
        )

    def _execute_local_command(*, request, rendered_command, outputfile, runner_type):
        tab_title = f"{request.tool_id} ({request.port}/{request.protocol})"
        command_result = runtime._run_command_with_tracking(
            tool_name=request.tool_id,
            tab_title=tab_title,
            host_ip=request.host_ip,
            port=request.port,
            protocol=request.protocol,
            command=rendered_command,
            outputfile=outputfile,
            timeout=int(request.timeout or 300),
            job_id=int(request.job_id or 0),
            return_metadata=True,
        )
        executed, reason, process_id, metadata = command_result
        return RunnerExecutionResult(
            executed=bool(executed),
            reason=str(reason or ""),
            runner_type=str(runner_type or "local"),
            process_id=int(process_id or 0),
            started_at=str(metadata.get("started_at", "") or ""),
            finished_at=str(metadata.get("finished_at", "") or ""),
            stdout_ref=str(metadata.get("stdout_ref", "") or ""),
            stderr_ref=str(metadata.get("stderr_ref", "") or ""),
            artifact_refs=list(metadata.get("artifact_refs", []) or []),
        )

    def _execute_browser_action(*, request, browser_settings, runner_type):
        started_at = getTimestamp(True)
        executed, reason, artifact_refs = runtime._take_screenshot(
            str(request.host_ip or ""),
            str(request.port or ""),
            service_name=str(request.service_name or ""),
            return_artifacts=True,
            browser_settings=browser_settings,
        )
        return RunnerExecutionResult(
            executed=bool(executed),
            reason=str(reason or ""),
            runner_type=str(runner_type or "browser"),
            started_at=started_at,
            finished_at=getTimestamp(True),
            artifact_refs=list(artifact_refs or []),
        )

    allow_optional_runners = True
    scheduler_config = getattr(runtime, "scheduler_config", None)
    if scheduler_config is not None and hasattr(scheduler_config, "is_feature_enabled"):
        allow_optional_runners = bool(scheduler_config.is_feature_enabled("optional_runners"))

    runner_result = execute_runner_request(
        request,
        runner_preference=str(runner_preference or ""),
        runner_settings=normalized_runner_settings,
        allow_optional_runners=allow_optional_runners,
        build_command=_build_command,
        execute_local_command=_execute_local_command,
        execute_browser_action=_execute_browser_action,
        mount_paths=[
            getattr(project.properties, "runningFolder", ""),
            getattr(project.properties, "outputFolder", ""),
            os.getcwd(),
        ],
        workdir=os.getcwd(),
    )
    if not capture_metadata:
        return bool(runner_result.executed), str(runner_result.reason or ""), int(runner_result.process_id or 0)

    fallback_timestamp = getTimestamp(True)
    execution_record = ExecutionRecord.from_plan_step(
        decision,
        started_at=str(runner_result.started_at or fallback_timestamp),
        finished_at=str(runner_result.finished_at or fallback_timestamp),
        exit_status=str(runner_result.reason or ""),
        runner_type=str(runner_result.runner_type or "local"),
        stdout_ref=str(runner_result.stdout_ref or ""),
        stderr_ref=str(runner_result.stderr_ref or ""),
        artifact_refs=list(runner_result.artifact_refs or []),
        approval_id=str(approval_id or ""),
    )
    return {
        "executed": bool(runner_result.executed),
        "reason": str(runner_result.reason or ""),
        "process_id": int(runner_result.process_id or 0),
        "execution_record": execution_record,
    }
