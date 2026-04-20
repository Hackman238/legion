from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from app.scheduler.approvals import (
    ensure_scheduler_approval_table,
    get_pending_approval,
    update_pending_approval,
)
from app.scheduler.audit import update_scheduler_decision_for_approval
from app.scheduler.execution import (
    ensure_scheduler_execution_table,
    get_execution_record,
    list_execution_records,
    store_execution_record,
)
from app.scheduler.models import ExecutionRecord
from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.orchestrator import SchedulerDecisionDisposition
from app.scheduler.planner import ScheduledAction
from app.scheduler.providers import reflect_on_scheduler_progress
from app.scheduler.state import build_attempted_action_entry
from app.scheduler.runners import (
    RunnerExecutionRequest,
    RunnerExecutionResult,
    execute_runner_request,
    normalize_runner_settings,
)
from app.settings import AppSettings
from app.timing import getTimestamp


def get_scheduler_execution_records(runtime, limit: int = 200) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_execution_table(project.database)
        return list_execution_records(project.database, limit=limit)


def start_scheduler_run_job(runtime) -> Dict[str, Any]:
    return runtime._start_job(
        "scheduler-run",
        lambda job_id: runtime._run_scheduler_actions_web(job_id=int(job_id or 0)),
        payload={},
    )


def start_host_dig_deeper_job(runtime, host_id: int) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    with runtime._lock:
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")

        prefs = runtime.scheduler_config.load()
        scheduler_mode = str(prefs.get("mode", "deterministic") or "deterministic").strip().lower()
        if scheduler_mode != "ai":
            raise ValueError("Dig Deeper requires scheduler mode 'ai'.")

        provider_name = str(prefs.get("provider", "none") or "none").strip().lower()
        providers = prefs.get("providers", {}) if isinstance(prefs.get("providers", {}), dict) else {}
        provider_cfg = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
        provider_enabled = bool(provider_cfg.get("enabled", False)) if isinstance(provider_cfg, dict) else False
        if provider_name == "none" or not provider_enabled:
            raise ValueError("Dig Deeper requires an enabled AI provider.")

        existing = runtime._find_active_job(job_type="scheduler-dig-deeper", host_id=resolved_host_id)
        if existing is not None:
            existing_copy = dict(existing)
            existing_copy["existing"] = True
            return existing_copy

    return runtime._start_job(
        "scheduler-dig-deeper",
        lambda job_id: runtime._run_scheduler_actions_web(
            host_ids={resolved_host_id},
            dig_deeper=True,
            job_id=int(job_id or 0),
        ),
        payload={"host_id": resolved_host_id, "host_ip": host_ip, "dig_deeper": True},
    )


def read_text_excerpt(path: str, max_chars: int = 4000) -> str:
    normalized_path = str(path or "").strip()
    if not normalized_path or not os.path.isfile(normalized_path):
        return ""
    safe_max_chars = max(0, min(int(max_chars or 4000), 200000))
    if safe_max_chars <= 0:
        return ""
    try:
        size = os.path.getsize(normalized_path)
        read_bytes = max(4096, min(safe_max_chars * 4, 2_000_000))
        with open(normalized_path, "rb") as handle:
            if size > read_bytes:
                handle.seek(size - read_bytes)
            data = handle.read(read_bytes)
        return data.decode("utf-8", errors="replace")[-safe_max_chars:]
    except Exception:
        return ""


def get_scheduler_execution_traces(
        runtime,
        *,
        limit: int = 200,
        host_id: int = 0,
        host_ip: str = "",
        tool_id: str = "",
        include_output: bool = False,
        output_max_chars: int = 4000,
) -> List[Dict[str, Any]]:
    resolved_host_ip = str(host_ip or "").strip()
    if int(host_id or 0) > 0 and not resolved_host_ip:
        with runtime._lock:
            host = runtime._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            resolved_host_ip = str(getattr(host, "ip", "") or "")
    rows = runtime.get_scheduler_execution_records(limit=max(1, min(max(int(limit or 200), 50), 1000)))
    filtered = []
    normalized_tool_id = str(tool_id or "").strip().lower()
    for item in list(rows or []):
        if resolved_host_ip and str(item.get("host_ip", "") or "").strip() != resolved_host_ip:
            continue
        if normalized_tool_id and str(item.get("tool_id", "") or "").strip().lower() != normalized_tool_id:
            continue
        record = dict(item)
        if include_output:
            record["stdout_excerpt"] = runtime._read_text_excerpt(
                str(record.get("stdout_ref", "") or ""),
                max_chars=output_max_chars,
            )
            record["stderr_excerpt"] = runtime._read_text_excerpt(
                str(record.get("stderr_ref", "") or ""),
                max_chars=output_max_chars,
            )
        filtered.append(record)
        if len(filtered) >= max(1, min(int(limit or 200), 1000)):
            break
    return filtered


def get_scheduler_execution_trace(
        runtime,
        execution_id: str,
        output_max_chars: int = 4000,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_execution_table(project.database)
        trace = get_execution_record(project.database, str(execution_id or ""))
    if trace is None:
        raise KeyError(f"Unknown execution id: {execution_id}")
    payload = dict(trace)
    payload["stdout_excerpt"] = runtime._read_text_excerpt(
        str(payload.get("stdout_ref", "") or ""),
        max_chars=output_max_chars,
    )
    payload["stderr_excerpt"] = runtime._read_text_excerpt(
        str(payload.get("stderr_ref", "") or ""),
        max_chars=output_max_chars,
    )
    return payload


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
    with runtime._lock:
        project = runtime._require_active_project()
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


def persist_scheduler_execution_record(
        runtime,
        decision: ScheduledAction,
        execution_record: Optional[ExecutionRecord],
        *,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
) -> Optional[Dict[str, Any]]:
    if not isinstance(execution_record, ExecutionRecord):
        return None
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        database = getattr(project, "database", None) if project else None
        if database is None:
            return None
        try:
            ensure_scheduler_execution_table(database)
            return store_execution_record(
                database,
                execution_record,
                step=decision,
                host_ip=host_ip,
                port=port,
                protocol=protocol,
                service=service_name,
            )
        except Exception:
            return None


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


def run_scheduler_actions_web(
        runtime,
        *,
        host_ids: Optional[set] = None,
        dig_deeper: bool = False,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    normalized_host_ids = {
        int(item) for item in list(host_ids or set())
        if str(item).strip()
    }

    with runtime._lock:
        project = runtime._require_active_project()
        settings = runtime._get_settings()
        scheduler_prefs = runtime.scheduler_config.load()
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
        options = runtime.scheduler_orchestrator.build_run_options(
            scheduler_prefs,
            dig_deeper=bool(dig_deeper),
            job_id=resolved_job_id,
        )
        targets = runtime.scheduler_orchestrator.collect_project_targets(
            project,
            host_ids=normalized_host_ids,
            allowed_states={"open", "open|filtered"},
        )
        goal_profile = str(
            engagement_policy.get("legacy_goal_profile", scheduler_prefs.get("goal_profile", "internal_asset_discovery"))
            or "internal_asset_discovery"
        )
        engagement_preset = str(
            engagement_policy.get("preset", scheduler_prefs.get("engagement_preset", "internal_recon"))
            or "internal_recon"
        )

    def _should_cancel(job_identifier: int) -> bool:
        return int(job_identifier or 0) > 0 and runtime.jobs.is_cancel_requested(int(job_identifier or 0))

    def _existing_attempts(*, target, **_kwargs):
        return runtime._existing_attempt_summary_for_target(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
        )

    def _build_context(
            *,
            target,
            attempted_tool_ids,
            attempted_family_ids=None,
            attempted_command_signatures=None,
            recent_output_chars,
            analysis_mode,
    ):
        return runtime._build_scheduler_target_context(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            goal_profile=goal_profile,
            engagement_preset=engagement_preset,
            attempted_tool_ids=set(attempted_tool_ids or set()),
            attempted_family_ids=set(attempted_family_ids or set()),
            attempted_command_signatures=set(attempted_command_signatures or set()),
            recent_output_chars=int(recent_output_chars or 900),
            analysis_mode=str(analysis_mode or "standard"),
        )

    def _on_ai_analysis(*, target, provider_payload):
        runtime._persist_scheduler_ai_analysis(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            goal_profile=goal_profile,
            provider_payload=provider_payload,
        )

    def _reflect_progress(*, target, context, recent_rounds, trigger=None):
        return reflect_on_scheduler_progress(
            scheduler_prefs,
            goal_profile,
            str(target.service_name or ""),
            str(target.protocol or "tcp"),
            engagement_preset=engagement_preset,
            context=context,
            recent_rounds=recent_rounds,
            trigger_reason=str((trigger or {}).get("reason", "") or ""),
            trigger_context=trigger if isinstance(trigger, dict) else {},
        )

    def _on_reflection_analysis(*, target, reflection_payload, recent_rounds):
        _ = recent_rounds
        runtime._persist_scheduler_reflection_analysis(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            goal_profile=goal_profile,
            reflection_payload=reflection_payload,
        )

    def _handle_blocked(*, target, decision, command_template):
        _ = command_template
        runtime._persist_shared_target_state(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            scheduler_mode=str(decision.mode),
            goal_profile=str(decision.goal_profile),
            engagement_preset=str(decision.engagement_preset),
            attempted_action=build_attempted_action_entry(
                decision=decision,
                status="blocked",
                reason=str(decision.policy_reason or "blocked by policy"),
                attempted_at=getTimestamp(True),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service=str(target.service_name or ""),
                family_id=str(decision.family_id or ""),
                command_signature=runtime._command_signature_for_target(
                    str(command_template or decision.command_template or ""),
                    str(target.protocol or "tcp"),
                ),
            ),
        )
        runtime._record_scheduler_decision(
            decision,
            str(target.host_ip or ""),
            str(target.port or ""),
            str(target.protocol or "tcp"),
            str(target.service_name or ""),
            approved=False,
            executed=False,
            reason=decision.policy_reason or "blocked by policy",
        )
        return SchedulerDecisionDisposition(
            action="skipped",
            reason=decision.policy_reason or "blocked by policy",
        )

    def _handle_approval(*, target, decision, command_template):
        approval_id = runtime._queue_scheduler_approval(
            decision,
            str(target.host_ip or ""),
            str(target.port or ""),
            str(target.protocol or "tcp"),
            str(target.service_name or ""),
            str(command_template or ""),
        )
        runtime._persist_shared_target_state(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            scheduler_mode=str(decision.mode),
            goal_profile=str(decision.goal_profile),
            engagement_preset=str(decision.engagement_preset),
            attempted_action=build_attempted_action_entry(
                decision=decision,
                status="approval_queued",
                reason=f"pending approval #{approval_id}",
                attempted_at=getTimestamp(True),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service=str(target.service_name or ""),
                family_id=str(decision.family_id or ""),
                command_signature=runtime._command_signature_for_target(
                    str(command_template or decision.command_template or ""),
                    str(target.protocol or "tcp"),
                ),
            ),
        )
        runtime._record_scheduler_decision(
            decision,
            str(target.host_ip or ""),
            str(target.port or ""),
            str(target.protocol or "tcp"),
            str(target.service_name or ""),
            approved=False,
            executed=False,
            reason=f"pending approval #{approval_id}",
            approval_id=int(approval_id),
        )
        return SchedulerDecisionDisposition(
            action="queued",
            reason=f"pending approval #{approval_id}",
            approval_id=int(approval_id),
        )

    def _execute_batch(tasks, max_concurrency):
        runner_settings = normalize_runner_settings(scheduler_prefs.get("runners", {}))
        payload = []
        for task in list(tasks or []):
            payload.append({
                "decision": task.decision,
                "tool_id": str(task.tool_id or ""),
                "host_ip": str(task.host_ip or ""),
                "port": str(task.port or ""),
                "protocol": str(task.protocol or "tcp"),
                "service_name": str(task.service_name or ""),
                "command_template": str(task.command_template or ""),
                "timeout": int(task.timeout or 300),
                "job_id": int(task.job_id or 0),
                "approval_id": int(task.approval_id or 0),
                "runner_preference": str(task.runner_preference or ""),
                "runner_settings": runner_settings,
            })
        return runtime._execute_scheduler_task_batch(payload, max_concurrency=max_concurrency)

    def _on_execution_result(*, target, decision, result):
        executed = bool(result.get("executed", False))
        reason = str(result.get("reason", "") or "")
        process_id = int(result.get("process_id", 0) or 0)
        execution_record = result.get("execution_record")
        artifact_refs = list(getattr(execution_record, "artifact_refs", []) or [])
        observed_payload = {}
        observed_raw = {}
        output_text = ""
        if process_id > 0:
            try:
                process_output = runtime.get_process_output(int(process_id), offset=0, max_chars=200000)
                output_text = str(process_output.get("output", "") or "")
            except Exception:
                output_text = ""
        if output_text or artifact_refs:
            observed_payload = extract_tool_observations(
                str(decision.tool_id or ""),
                output_text,
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service=str(target.service_name or ""),
                artifact_refs=artifact_refs,
                host_ip=str(target.host_ip or ""),
                hostname=str(getattr(target, "hostname", "") or ""),
            )
            quality_events = list(observed_payload.get("finding_quality_events", []) or [])
            if quality_events:
                observed_raw["finding_quality_events"] = quality_events
            discovered_hosts = list(observed_payload.get("discovered_hosts", []) or [])
            if discovered_hosts:
                observed_raw["discovered_hosts"] = discovered_hosts
                discovered_summary = runtime._ingest_discovered_hosts(
                    discovered_hosts,
                    source_tool_id=str(decision.tool_id or ""),
                )
                added_hosts = list(discovered_summary.get("added_hosts", []) or [])
                if added_hosts:
                    observed_raw["discovered_hosts_added"] = added_hosts
                followup_job = discovered_summary.get("followup_job", {})
                if isinstance(followup_job, dict) and int(followup_job.get("id", 0) or 0) > 0:
                    observed_raw["discovered_hosts_followup_job"] = {
                        "id": int(followup_job.get("id", 0) or 0),
                        "type": str(followup_job.get("type", "") or ""),
                        "target_count": len(added_hosts),
                    }
                followup_error = str(discovered_summary.get("followup_error", "") or "").strip()
                if followup_error:
                    observed_raw["discovered_hosts_followup_error"] = followup_error
                bootstrap_job = discovered_summary.get("bootstrap_job", {})
                if isinstance(bootstrap_job, dict) and int(bootstrap_job.get("id", 0) or 0) > 0:
                    observed_raw["discovered_hosts_bootstrap_job"] = {
                        "id": int(bootstrap_job.get("id", 0) or 0),
                        "type": str(bootstrap_job.get("type", "") or ""),
                        "target_count": len(added_hosts),
                    }
                bootstrap_error = str(discovered_summary.get("bootstrap_error", "") or "").strip()
                if bootstrap_error:
                    observed_raw["discovered_hosts_bootstrap_error"] = bootstrap_error
        runtime._persist_shared_target_state(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            scheduler_mode=str(decision.mode),
            goal_profile=str(decision.goal_profile),
            engagement_preset=str(decision.engagement_preset),
            attempted_action=build_attempted_action_entry(
                decision=decision,
                status="executed" if executed else "failed",
                reason=reason,
                attempted_at=getTimestamp(True),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                service=str(target.service_name or ""),
                family_id=str(decision.family_id or ""),
                command_signature=runtime._command_signature_for_target(
                    str(getattr(decision, "command_template", "") or ""),
                    str(target.protocol or "tcp"),
                ),
                artifact_refs=artifact_refs,
            ),
            artifact_refs=artifact_refs,
            screenshots=list(result.get("screenshots", [])) if isinstance(result.get("screenshots", []), list) else None,
            technologies=list(observed_payload.get("technologies", []) or []) or None,
            findings=list(observed_payload.get("findings", []) or []) or None,
            urls=list(observed_payload.get("urls", []) or []) or None,
            raw=observed_raw or None,
        )
        runtime._record_scheduler_decision(
            decision,
            str(target.host_ip or ""),
            str(target.port or ""),
            str(target.protocol or "tcp"),
            str(target.service_name or ""),
            approved=True,
            executed=executed,
            reason=reason,
            approval_id=int(result.get("approval_id", 0) or 0),
        )
        runtime._persist_scheduler_execution_record(
            decision,
            execution_record,
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
        )
        if process_id and executed:
            runtime._save_script_result_if_missing(
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
                tool_id=decision.tool_id,
                process_id=process_id,
            )
        if executed:
            runtime._enrich_host_from_observed_results(
                host_ip=str(target.host_ip or ""),
                port=str(target.port or ""),
                protocol=str(target.protocol or "tcp"),
            )

    return runtime._run_scheduler_targets(
        settings=settings,
        targets=targets,
        engagement_policy=engagement_policy,
        options=options,
        should_cancel=_should_cancel,
        existing_attempts=_existing_attempts,
        build_context=_build_context,
        on_ai_analysis=_on_ai_analysis,
        reflect_progress=_reflect_progress,
        on_reflection_analysis=_on_reflection_analysis,
        handle_blocked=_handle_blocked,
        handle_approval=_handle_approval,
        execute_batch=_execute_batch,
        on_execution_result=_on_execution_result,
    )


def run_scheduler_targets(
        runtime,
        *,
        settings,
        targets,
        engagement_policy,
        options,
        should_cancel,
        existing_attempts,
        build_context,
        on_ai_analysis,
        reflect_progress,
        on_reflection_analysis,
        handle_blocked,
        handle_approval,
        execute_batch,
        on_execution_result,
) -> Dict[str, Any]:
    target_list = list(targets or [])
    host_concurrency = max(1, min(int(getattr(options, "host_concurrency", 1) or 1), 8))
    if bool(getattr(options, "dig_deeper", False)) or host_concurrency <= 1 or len(target_list) <= 1:
        return runtime.scheduler_orchestrator.run_targets(
            settings=settings,
            targets=target_list,
            engagement_policy=engagement_policy,
            options=options,
            should_cancel=should_cancel,
            existing_attempts=existing_attempts,
            build_context=build_context,
            on_ai_analysis=on_ai_analysis,
            reflect_progress=reflect_progress,
            on_reflection_analysis=on_reflection_analysis,
            handle_blocked=handle_blocked,
            handle_approval=handle_approval,
            execute_batch=execute_batch,
            on_execution_result=on_execution_result,
        )

    target_groups = group_scheduler_targets_by_host(target_list)
    if len(target_groups) <= 1:
        return runtime.scheduler_orchestrator.run_targets(
            settings=settings,
            targets=target_list,
            engagement_policy=engagement_policy,
            options=options,
            should_cancel=should_cancel,
            existing_attempts=existing_attempts,
            build_context=build_context,
            on_ai_analysis=on_ai_analysis,
            reflect_progress=reflect_progress,
            on_reflection_analysis=on_reflection_analysis,
            handle_blocked=handle_blocked,
            handle_approval=handle_approval,
            execute_batch=execute_batch,
            on_execution_result=on_execution_result,
        )

    summaries: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(
            max_workers=min(host_concurrency, len(target_groups)),
            thread_name_prefix="legion-scheduler-hosts",
    ) as pool:
        future_map = {
            pool.submit(
                runtime.scheduler_orchestrator.run_targets,
                settings=settings,
                targets=group,
                engagement_policy=engagement_policy,
                options=options,
                should_cancel=should_cancel,
                existing_attempts=existing_attempts,
                build_context=build_context,
                on_ai_analysis=on_ai_analysis,
                reflect_progress=reflect_progress,
                on_reflection_analysis=on_reflection_analysis,
                handle_blocked=handle_blocked,
                handle_approval=handle_approval,
                execute_batch=execute_batch,
                on_execution_result=on_execution_result,
            ): group
            for group in target_groups
        }
        for future in as_completed(future_map):
            summaries.append(future.result())

    return merge_scheduler_run_summaries(
        summaries,
        target_count=len(target_list),
        dig_deeper=bool(getattr(options, "dig_deeper", False)),
    )


def group_scheduler_targets_by_host(targets) -> List[List[Any]]:
    grouped: List[List[Any]] = []
    index: Dict[Tuple[str, Any], int] = {}
    for target in list(targets or []):
        host_id = int(getattr(target, "host_id", 0) or 0)
        host_ip = str(getattr(target, "host_ip", "") or "").strip()
        hostname = str(getattr(target, "hostname", "") or "").strip()
        if host_id > 0:
            key: Tuple[str, Any] = ("host_id", host_id)
        elif host_ip:
            key = ("host_ip", host_ip)
        elif hostname:
            key = ("hostname", hostname)
        else:
            key = ("target", len(grouped))
        position = index.get(key)
        if position is None:
            position = len(grouped)
            index[key] = position
            grouped.append([])
        grouped[position].append(target)
    return grouped


def merge_scheduler_run_summaries(
        summaries: Optional[List[Dict[str, Any]]] = None,
        *,
        target_count: int = 0,
        dig_deeper: bool = False,
) -> Dict[str, Any]:
    merged = {
        "considered": 0,
        "approval_queued": 0,
        "executed": 0,
        "skipped": 0,
        "host_scope_count": int(target_count or 0),
        "dig_deeper": bool(dig_deeper),
        "reflections": 0,
        "reflection_stops": 0,
    }
    for item in list(summaries or []):
        if not isinstance(item, dict):
            continue
        for key in ("considered", "approval_queued", "executed", "skipped", "reflections", "reflection_stops"):
            try:
                merged[key] += int(item.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        if bool(item.get("cancelled", False)):
            merged["cancelled"] = True
            if not str(merged.get("cancel_reason", "") or "").strip():
                merged["cancel_reason"] = str(item.get("cancel_reason", "") or "cancelled by user")
        if not str(merged.get("stopped_early", "") or "").strip():
            stopped_early = str(item.get("stopped_early", "") or "").strip()
            if stopped_early:
                merged["stopped_early"] = stopped_early
    return merged
