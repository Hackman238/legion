from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from app.web import runtime_scheduler_ai_state as web_runtime_scheduler_ai_state
from app.web import runtime_scheduler_capture as web_runtime_scheduler_capture
from app.web import runtime_scheduler_approval_execution as web_runtime_scheduler_approval_execution
from app.web import runtime_scheduler_config as web_runtime_scheduler_config
from app.web import runtime_scheduler_context as web_runtime_scheduler_context
from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt
from app.web import runtime_scheduler_execution as web_runtime_scheduler_execution
from app.web import runtime_scheduler_inference as web_runtime_scheduler_inference
from app.web import runtime_scheduler_preview as web_runtime_scheduler_preview
from app.web import runtime_scheduler_rationale as web_runtime_scheduler_rationale
from app.web import runtime_scheduler_target_state as web_runtime_scheduler_target_state
from app.web import runtime_scheduler_trace as web_runtime_scheduler_trace


get_scheduler_preferences = web_runtime_scheduler_config.get_scheduler_preferences
merge_engagement_policy_payload = web_runtime_scheduler_config.merge_engagement_policy_payload
load_engagement_policy_locked = web_runtime_scheduler_config.load_engagement_policy_locked
get_engagement_policy = web_runtime_scheduler_config.get_engagement_policy
set_engagement_policy = web_runtime_scheduler_config.set_engagement_policy
apply_scheduler_preferences = web_runtime_scheduler_config.apply_scheduler_preferences
test_scheduler_provider = web_runtime_scheduler_config.test_scheduler_provider
get_scheduler_provider_logs = web_runtime_scheduler_config.get_scheduler_provider_logs
get_scheduler_decisions = web_runtime_scheduler_config.get_scheduler_decisions
get_scheduler_approvals = web_runtime_scheduler_config.get_scheduler_approvals
scheduler_family_policy_metadata = web_runtime_scheduler_config.scheduler_family_policy_metadata
apply_family_policy_action = web_runtime_scheduler_config.apply_family_policy_action
get_scan_history = web_runtime_scheduler_config.get_scan_history
job_worker_count = web_runtime_scheduler_config.job_worker_count
scheduler_max_concurrency = web_runtime_scheduler_config.scheduler_max_concurrency
scheduler_max_host_concurrency = web_runtime_scheduler_config.scheduler_max_host_concurrency
scheduler_max_jobs = web_runtime_scheduler_config.scheduler_max_jobs
scheduler_feedback_config = web_runtime_scheduler_config.scheduler_feedback_config
is_host_scoped_scheduler_tool = web_runtime_scheduler_config.is_host_scoped_scheduler_tool
normalize_project_report_headers = web_runtime_scheduler_config.normalize_project_report_headers
project_report_delivery_config = web_runtime_scheduler_config.project_report_delivery_config
sanitize_provider_config = web_runtime_scheduler_config.sanitize_provider_config
sanitize_integration_config = web_runtime_scheduler_config.sanitize_integration_config
scheduler_integration_api_key = web_runtime_scheduler_config.scheduler_integration_api_key
scheduler_command_placeholders = web_runtime_scheduler_config.scheduler_command_placeholders
scheduler_preferences = web_runtime_scheduler_config.scheduler_preferences
ensure_scheduler_table = web_runtime_scheduler_config.ensure_scheduler_table
ensure_scheduler_approval_store = web_runtime_scheduler_config.ensure_scheduler_approval_store
scheduler_tool_audit_snapshot = web_runtime_scheduler_config.scheduler_tool_audit_snapshot
shodan_integration_enabled = web_runtime_scheduler_config.shodan_integration_enabled
grayhatwarfare_integration_enabled = web_runtime_scheduler_config.grayhatwarfare_integration_enabled
device_category_options_for_runtime = web_runtime_scheduler_config.device_category_options_for_runtime
built_in_device_category_options = web_runtime_scheduler_config.built_in_device_category_options

build_scheduler_context_summary = web_runtime_scheduler_context.build_scheduler_context_summary
build_scheduler_coverage_summary = web_runtime_scheduler_context.build_scheduler_coverage_summary
extract_scheduler_signals = web_runtime_scheduler_context.extract_scheduler_signals
build_scheduler_target_context = web_runtime_scheduler_context.build_scheduler_target_context
truncate_scheduler_text = web_runtime_scheduler_excerpt.truncate_scheduler_text
scheduler_output_lines = web_runtime_scheduler_excerpt.scheduler_output_lines
scheduler_line_signal_score = web_runtime_scheduler_excerpt.scheduler_line_signal_score
build_scheduler_excerpt = web_runtime_scheduler_excerpt.build_scheduler_excerpt
build_scheduler_prompt_excerpt = web_runtime_scheduler_excerpt.build_scheduler_prompt_excerpt
build_scheduler_analysis_excerpt = web_runtime_scheduler_excerpt.build_scheduler_analysis_excerpt
scheduler_tool_alias_tokens = web_runtime_scheduler_excerpt.scheduler_tool_alias_tokens
extract_unavailable_tool_tokens = web_runtime_scheduler_excerpt.extract_unavailable_tool_tokens
extract_missing_nse_script_tokens = web_runtime_scheduler_excerpt.extract_missing_nse_script_tokens
looks_like_local_tool_dependency_failure = web_runtime_scheduler_excerpt.looks_like_local_tool_dependency_failure
scheduler_banner_from_evidence = web_runtime_scheduler_excerpt.scheduler_banner_from_evidence
scheduler_service_banner_fallback = web_runtime_scheduler_excerpt.scheduler_service_banner_fallback

get_scheduler_execution_records = web_runtime_scheduler_execution.get_scheduler_execution_records
start_scheduler_run_job = web_runtime_scheduler_execution.start_scheduler_run_job
start_host_dig_deeper_job = web_runtime_scheduler_execution.start_host_dig_deeper_job
read_text_excerpt = web_runtime_scheduler_trace.read_text_excerpt
get_scheduler_execution_traces = web_runtime_scheduler_trace.get_scheduler_execution_traces
get_scheduler_execution_trace = web_runtime_scheduler_trace.get_scheduler_execution_trace
approve_scheduler_approval = web_runtime_scheduler_approval_execution.approve_scheduler_approval
reject_scheduler_approval = web_runtime_scheduler_approval_execution.reject_scheduler_approval
persist_scheduler_execution_record = web_runtime_scheduler_trace.persist_scheduler_execution_record
execute_approved_scheduler_item = web_runtime_scheduler_approval_execution.execute_approved_scheduler_item
execute_scheduler_decision = web_runtime_scheduler_approval_execution.execute_scheduler_decision
run_scheduler_actions_web = web_runtime_scheduler_execution.run_scheduler_actions_web
run_scheduler_targets = web_runtime_scheduler_execution.run_scheduler_targets
group_scheduler_targets_by_host = web_runtime_scheduler_execution.group_scheduler_targets_by_host
merge_scheduler_run_summaries = web_runtime_scheduler_execution.merge_scheduler_run_summaries

serialize_plan_step_preview = web_runtime_scheduler_preview.serialize_plan_step_preview
get_scheduler_plan_preview = web_runtime_scheduler_preview.get_scheduler_plan_preview

persist_scheduler_ai_analysis = web_runtime_scheduler_ai_state.persist_scheduler_ai_analysis
persist_scheduler_reflection_analysis = web_runtime_scheduler_ai_state.persist_scheduler_reflection_analysis
apply_ai_host_updates = web_runtime_scheduler_ai_state.apply_ai_host_updates
enrich_host_from_observed_results = web_runtime_scheduler_ai_state.enrich_host_from_observed_results
queue_scheduler_approval = web_runtime_scheduler_capture.queue_scheduler_approval
record_scheduler_decision = web_runtime_scheduler_capture.record_scheduler_decision
build_scheduler_credential_row = web_runtime_scheduler_capture.build_scheduler_credential_row
build_scheduler_session_row = web_runtime_scheduler_capture.build_scheduler_session_row
extract_credential_capture_entries = web_runtime_scheduler_capture.extract_credential_capture_entries
persist_credential_captures_to_scheduler = web_runtime_scheduler_capture.persist_credential_captures_to_scheduler
persist_credential_capture_output = web_runtime_scheduler_capture.persist_credential_capture_output
is_placeholder_scheduler_text = web_runtime_scheduler_inference.is_placeholder_scheduler_text
infer_technologies_from_observations = web_runtime_scheduler_inference.infer_technologies_from_observations
infer_host_technologies = web_runtime_scheduler_inference.infer_host_technologies
normalize_ai_technologies = web_runtime_scheduler_inference.normalize_ai_technologies
merge_technologies = web_runtime_scheduler_inference.merge_technologies
infer_findings_from_observations = web_runtime_scheduler_inference.infer_findings_from_observations
infer_host_findings = web_runtime_scheduler_inference.infer_host_findings
infer_urls_from_observations = web_runtime_scheduler_inference.infer_urls_from_observations
infer_host_urls = web_runtime_scheduler_inference.infer_host_urls
normalize_ai_findings = web_runtime_scheduler_inference.normalize_ai_findings
normalize_ai_manual_tests = web_runtime_scheduler_inference.normalize_ai_manual_tests
merge_ai_items = web_runtime_scheduler_inference.merge_ai_items
coverage_gaps_from_summary = web_runtime_scheduler_target_state.coverage_gaps_from_summary
persist_shared_target_state = web_runtime_scheduler_target_state.persist_shared_target_state
load_host_ai_analysis = web_runtime_scheduler_target_state.load_host_ai_analysis
scan_history_targets = web_runtime_scheduler_target_state.scan_history_targets

get_scheduler_rationale_feed = web_runtime_scheduler_rationale.get_scheduler_rationale_feed
scheduler_rationale_feed_locked = web_runtime_scheduler_rationale.scheduler_rationale_feed_locked
safe_json_loads = web_runtime_scheduler_rationale.safe_json_loads
dedupe_text_tokens = web_runtime_scheduler_rationale.dedupe_text_tokens
truncate_rationale_text = web_runtime_scheduler_rationale.truncate_rationale_text
scheduler_event_timestamp_epoch = web_runtime_scheduler_rationale.scheduler_event_timestamp_epoch
strip_json_fences = web_runtime_scheduler_rationale.strip_json_fences
extract_prompt_text_from_provider_request = web_runtime_scheduler_rationale.extract_prompt_text_from_provider_request
extract_scheduler_target_fields_from_prompt = web_runtime_scheduler_rationale.extract_scheduler_target_fields_from_prompt
extract_provider_response_payload = web_runtime_scheduler_rationale.extract_provider_response_payload
rationale_list_text = web_runtime_scheduler_rationale.rationale_list_text
rationale_tag_label = web_runtime_scheduler_rationale.rationale_tag_label
index_scheduler_rows_by_target_tool = web_runtime_scheduler_rationale.index_scheduler_rows_by_target_tool
nearest_scheduler_row = web_runtime_scheduler_rationale.nearest_scheduler_row
manual_test_lines = web_runtime_scheduler_rationale.manual_test_lines
findings_line = web_runtime_scheduler_rationale.findings_line
match_rationale_outcomes = web_runtime_scheduler_rationale.match_rationale_outcomes
build_provider_rationale_entry = web_runtime_scheduler_rationale.build_provider_rationale_entry
build_audit_rationale_entry = web_runtime_scheduler_rationale.build_audit_rationale_entry
build_scheduler_rationale_feed_items = web_runtime_scheduler_rationale.build_scheduler_rationale_feed_items


def execute_scheduler_task_batch(runtime, tasks: List[Dict[str, Any]], max_concurrency: int) -> List[Dict[str, Any]]:
    if not tasks:
        return []

    concurrency = max(1, min(int(max_concurrency or 1), 16))
    if concurrency <= 1 or len(tasks) <= 1:
        return [execute_scheduler_task(runtime, task) for task in tasks]

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="legion-scheduler") as pool:
        future_map = {pool.submit(execute_scheduler_task, runtime, task): task for task in tasks}
        for future in as_completed(future_map):
            task = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({
                    "decision": task["decision"],
                    "tool_id": str(task.get("tool_id", "") or ""),
                    "executed": False,
                    "reason": f"error: {exc}",
                    "process_id": 0,
                    "execution_record": None,
                })
    return results


def execute_scheduler_task(runtime, task: Dict[str, Any]) -> Dict[str, Any]:
    decision = task["decision"]
    approval_id = int(task.get("approval_id", 0) or 0)
    execution_result = runtime._execute_scheduler_decision(
        decision,
        host_ip=str(task.get("host_ip", "") or ""),
        port=str(task.get("port", "") or ""),
        protocol=str(task.get("protocol", "tcp") or "tcp"),
        service_name=str(task.get("service_name", "") or ""),
        command_template=str(task.get("command_template", "") or ""),
        timeout=int(task.get("timeout", 300) or 300),
        job_id=int(task.get("job_id", 0) or 0),
        capture_metadata=True,
        approval_id=approval_id,
        runner_preference=str(task.get("runner_preference", "") or ""),
        runner_settings=task.get("runner_settings", {}),
    )
    return {
        "decision": decision,
        "tool_id": str(task.get("tool_id", "") or ""),
        "executed": bool(execution_result.get("executed", False)),
        "reason": str(execution_result.get("reason", "") or ""),
        "process_id": int(execution_result.get("process_id", 0) or 0),
        "execution_record": execution_result.get("execution_record"),
        "approval_id": approval_id,
    }
