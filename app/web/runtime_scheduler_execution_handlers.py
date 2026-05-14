from __future__ import annotations

from typing import Any, Dict

from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.orchestrator import SchedulerDecisionDisposition
from app.scheduler.state import build_attempted_action_entry
from app.timing import getTimestamp


def handle_scheduler_blocked_decision(runtime, *, target, decision, command_template):
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


def handle_scheduler_approval_decision(runtime, *, target, decision, command_template):
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


def handle_scheduler_execution_result(runtime, *, target, decision, result: Dict[str, Any]):
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
        _merge_observed_discovery_results(runtime, decision, observed_payload, observed_raw)

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


def _merge_observed_discovery_results(
        runtime,
        decision,
        observed_payload: Dict[str, Any],
        observed_raw: Dict[str, Any],
) -> None:
    quality_events = list(observed_payload.get("finding_quality_events", []) or [])
    if quality_events:
        observed_raw["finding_quality_events"] = quality_events
    discovered_hosts = list(observed_payload.get("discovered_hosts", []) or [])
    if not discovered_hosts:
        return

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
