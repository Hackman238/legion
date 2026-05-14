from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.scheduler.providers import reflect_on_scheduler_progress
from app.scheduler.runners import normalize_runner_settings
from app.web import runtime_scheduler_approval_execution as web_runtime_scheduler_approval_execution
from app.web import runtime_scheduler_execution_handlers as web_runtime_scheduler_execution_handlers
from app.web import runtime_scheduler_target_runner as web_runtime_scheduler_target_runner
from app.web import runtime_scheduler_trace as web_runtime_scheduler_trace


get_scheduler_execution_records = web_runtime_scheduler_trace.get_scheduler_execution_records
read_text_excerpt = web_runtime_scheduler_trace.read_text_excerpt
get_scheduler_execution_traces = web_runtime_scheduler_trace.get_scheduler_execution_traces
get_scheduler_execution_trace = web_runtime_scheduler_trace.get_scheduler_execution_trace
persist_scheduler_execution_record = web_runtime_scheduler_trace.persist_scheduler_execution_record

approve_scheduler_approval = web_runtime_scheduler_approval_execution.approve_scheduler_approval
reject_scheduler_approval = web_runtime_scheduler_approval_execution.reject_scheduler_approval
execute_approved_scheduler_item = web_runtime_scheduler_approval_execution.execute_approved_scheduler_item
execute_scheduler_decision = web_runtime_scheduler_approval_execution.execute_scheduler_decision
run_scheduler_targets = web_runtime_scheduler_target_runner.run_scheduler_targets
group_scheduler_targets_by_host = web_runtime_scheduler_target_runner.group_scheduler_targets_by_host
merge_scheduler_run_summaries = web_runtime_scheduler_target_runner.merge_scheduler_run_summaries


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
            protocol=str(target.protocol or ""),
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
            protocol=str(target.protocol or ""),
            service_name=str(target.service_name or ""),
            goal_profile=goal_profile,
            reflection_payload=reflection_payload,
        )

    def _handle_blocked(*, target, decision, command_template):
        return web_runtime_scheduler_execution_handlers.handle_scheduler_blocked_decision(
            runtime,
            target=target,
            decision=decision,
            command_template=command_template,
        )

    def _handle_approval(*, target, decision, command_template):
        return web_runtime_scheduler_execution_handlers.handle_scheduler_approval_decision(
            runtime,
            target=target,
            decision=decision,
            command_template=command_template,
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
        web_runtime_scheduler_execution_handlers.handle_scheduler_execution_result(
            runtime,
            target=target,
            decision=decision,
            result=result,
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

