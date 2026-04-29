from __future__ import annotations

from typing import Any, Dict, List

from app.scheduler.execution import list_execution_records
from app.scheduler.providers import get_provider_logs
from app.web import runtime_scheduler_rationale_build as web_runtime_scheduler_rationale_build


def get_scheduler_rationale_feed(runtime, limit: int = 18) -> List[Dict[str, Any]]:
    with runtime._lock:
        return scheduler_rationale_feed_locked(runtime, limit=limit)


def scheduler_rationale_feed_locked(runtime, limit: int = 18) -> List[Dict[str, Any]]:
    project = getattr(runtime.logic, "activeProject", None)
    database = getattr(project, "database", None) if project else None
    if database is None:
        return []
    resolved_limit = max(1, min(int(limit or 18), 48))
    provider_logs = list(get_provider_logs(limit=max(resolved_limit * 4, 40)) or [])
    decisions = runtime.get_scheduler_decisions(limit=max(resolved_limit * 8, 200))
    executions = list_execution_records(database, limit=max(resolved_limit * 10, 240))
    return runtime._build_scheduler_rationale_feed_items(
        provider_logs,
        decisions,
        executions,
        limit=resolved_limit,
    )


safe_json_loads = web_runtime_scheduler_rationale_build.safe_json_loads
dedupe_text_tokens = web_runtime_scheduler_rationale_build.dedupe_text_tokens
truncate_rationale_text = web_runtime_scheduler_rationale_build.truncate_rationale_text
scheduler_event_timestamp_epoch = web_runtime_scheduler_rationale_build.scheduler_event_timestamp_epoch
strip_json_fences = web_runtime_scheduler_rationale_build.strip_json_fences
extract_prompt_text_from_provider_request = web_runtime_scheduler_rationale_build.extract_prompt_text_from_provider_request
extract_scheduler_target_fields_from_prompt = web_runtime_scheduler_rationale_build.extract_scheduler_target_fields_from_prompt
extract_provider_response_payload = web_runtime_scheduler_rationale_build.extract_provider_response_payload
rationale_list_text = web_runtime_scheduler_rationale_build.rationale_list_text
rationale_tag_label = web_runtime_scheduler_rationale_build.rationale_tag_label
index_scheduler_rows_by_target_tool = web_runtime_scheduler_rationale_build.index_scheduler_rows_by_target_tool
nearest_scheduler_row = web_runtime_scheduler_rationale_build.nearest_scheduler_row
manual_test_lines = web_runtime_scheduler_rationale_build.manual_test_lines
findings_line = web_runtime_scheduler_rationale_build.findings_line
match_rationale_outcomes = web_runtime_scheduler_rationale_build.match_rationale_outcomes
build_provider_rationale_entry = web_runtime_scheduler_rationale_build.build_provider_rationale_entry
build_audit_rationale_entry = web_runtime_scheduler_rationale_build.build_audit_rationale_entry
build_scheduler_rationale_feed_items = web_runtime_scheduler_rationale_build.build_scheduler_rationale_feed_items
