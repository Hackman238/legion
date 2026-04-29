from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.orchestrator import SchedulerDecisionDisposition
from app.scheduler.providers import reflect_on_scheduler_progress
from app.scheduler.runners import normalize_runner_settings
from app.scheduler.state import build_attempted_action_entry
from app.timing import getTimestamp
from app.web import runtime_scheduler_approval_execution as web_runtime_scheduler_approval_execution
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
