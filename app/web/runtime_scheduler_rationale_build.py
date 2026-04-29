from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.web.runtime_scheduler_rationale_outcomes import (
    index_scheduler_rows_by_target_tool,
    match_rationale_outcomes,
    nearest_scheduler_row,
    scheduler_event_timestamp_epoch,
)
from app.web.runtime_scheduler_rationale_parse import (
    extract_prompt_text_from_provider_request,
    extract_provider_response_payload,
    extract_scheduler_target_fields_from_prompt,
    strip_json_fences,
)
from app.web.runtime_scheduler_rationale_text import (
    dedupe_text_tokens,
    findings_line,
    manual_test_lines,
    rationale_list_text,
    rationale_tag_label,
    safe_json_loads,
    truncate_rationale_text,
)


def build_provider_rationale_entry(
        runtime_or_cls,
        log_row: Dict[str, Any],
        *,
        decision_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
        execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    prompt_metadata = log_row.get("prompt_metadata", {}) if isinstance(log_row.get("prompt_metadata", {}), dict) else {}
    prompt_type = str(prompt_metadata.get("prompt_type", "") or "").strip().lower()
    if prompt_type not in {"ranking", "reflection", "web_followup"}:
        return None

    response_payload = extract_provider_response_payload(runtime_or_cls, log_row.get("response_body", ""))
    if not response_payload:
        return None

    prompt_text = extract_prompt_text_from_provider_request(runtime_or_cls, log_row.get("request_body", ""))
    target = extract_scheduler_target_fields_from_prompt(prompt_text or log_row.get("request_body", ""))
    host_ip = str(target.get("host_ip", "") or "").strip()
    port = str(target.get("port", "") or "").strip()
    protocol = str(target.get("protocol", "") or "").strip()
    service = str(target.get("service", "") or "").strip()
    visible_tool_ids = dedupe_text_tokens(prompt_metadata.get("visible_candidate_tool_ids", []), limit=64)
    selected_tool_ids: List[str] = []
    dropped_tool_ids: List[str] = []
    details: List[str] = []
    headline = ""
    summary = ""

    if prompt_type == "ranking":
        actions_all = []
        for item in list(response_payload.get("actions", []) or []):
            if not isinstance(item, dict):
                continue
            tool_id = str(item.get("tool_id", "") or "").strip()
            if not tool_id:
                continue
            actions_all.append({
                "tool_id": tool_id,
                "score": int(item.get("score", 0) or 0),
                "rationale": truncate_rationale_text(item.get("rationale", ""), 180),
            })
        filtered_actions = []
        for item in actions_all:
            if visible_tool_ids and item["tool_id"] not in visible_tool_ids:
                dropped_tool_ids.append(item["tool_id"])
                continue
            filtered_actions.append(item)
        selected_tool_ids = [item["tool_id"] for item in filtered_actions]
        headline = rationale_list_text(selected_tool_ids, limit=3) or "No action selected"
        summary = (
            filtered_actions[0].get("rationale", "")
            if filtered_actions else
            truncate_rationale_text("Provider recommended manual review instead of a safe automated action.", 180)
        )
        if selected_tool_ids:
            details.append(f"Selected: {rationale_list_text(selected_tool_ids, limit=4)}")
        else:
            details.append("Selected: none")
        if filtered_actions:
            scores_text = ", ".join(f"{item['tool_id']} {item['score']}" for item in filtered_actions[:4])
            details.append(f"Scores: {scores_text}")
        skipped_tool_ids = [item for item in visible_tool_ids if item not in selected_tool_ids]
        if skipped_tool_ids:
            details.append(f"Not selected: {rationale_list_text(skipped_tool_ids, limit=5)}")
        if dropped_tool_ids:
            details.append(f"Ignored out-of-scope suggestions: {rationale_list_text(dropped_tool_ids, limit=4)}")
        findings = findings_line(runtime_or_cls, response_payload.get("findings", []))
        if findings:
            details.append(findings)
        next_phase = str(response_payload.get("next_phase", "") or "").strip()
        if next_phase:
            details.append(f"Next phase: {next_phase}")
        details.extend(manual_test_lines(runtime_or_cls, response_payload.get("manual_tests", [])))
    elif prompt_type == "web_followup":
        selected_all = dedupe_text_tokens(response_payload.get("selected_tool_ids", []), limit=16)
        selected_tool_ids = [item for item in selected_all if not visible_tool_ids or item in visible_tool_ids]
        dropped_tool_ids = [item for item in selected_all if visible_tool_ids and item not in visible_tool_ids]
        headline = rationale_list_text(selected_tool_ids, limit=3) or "Manual review only"
        summary = truncate_rationale_text(
            response_payload.get("reason", "") or "Provider recommended a bounded follow-up review.",
            200,
        )
        focus = str(response_payload.get("focus", "") or "").strip()
        if selected_tool_ids:
            details.append(f"Selected: {rationale_list_text(selected_tool_ids, limit=4)}")
        else:
            details.append("Selected: none")
        if visible_tool_ids:
            skipped_tool_ids = [item for item in visible_tool_ids if item not in selected_tool_ids]
            if skipped_tool_ids:
                details.append(f"Not selected: {rationale_list_text(skipped_tool_ids, limit=5)}")
        if dropped_tool_ids:
            details.append(f"Ignored out-of-scope suggestions: {rationale_list_text(dropped_tool_ids, limit=4)}")
        if focus:
            details.append(f"Focus: {focus}")
        details.extend(manual_test_lines(runtime_or_cls, response_payload.get("manual_tests", [])))
    else:
        state = str(response_payload.get("state", "") or "").strip()
        priority_shift = str(response_payload.get("priority_shift", "") or "").strip()
        promote_tool_ids = dedupe_text_tokens(response_payload.get("promote_tool_ids", []), limit=16)
        suppress_tool_ids = dedupe_text_tokens(response_payload.get("suppress_tool_ids", []), limit=24)
        headline = " -> ".join([item for item in [state or "Reflection", priority_shift] if item]) or "Reflection"
        summary = truncate_rationale_text(response_payload.get("reason", "") or "Scheduler reflection recorded.", 220)
        if promote_tool_ids:
            details.append(f"Promote: {rationale_list_text(promote_tool_ids, limit=5)}")
        if suppress_tool_ids:
            details.append(f"Suppress: {rationale_list_text(suppress_tool_ids, limit=5)}")
        details.extend(manual_test_lines(runtime_or_cls, response_payload.get("manual_tests", [])))

    event_ts = scheduler_event_timestamp_epoch(runtime_or_cls, log_row.get("timestamp", ""))
    outcome_line, matched_decision_ids = match_rationale_outcomes(
        runtime_or_cls,
        decision_index,
        execution_index,
        host_ip=host_ip,
        port=port,
        protocol=protocol,
        tool_ids=selected_tool_ids,
        event_ts=event_ts,
    )
    if outcome_line:
        details.insert(0, outcome_line)

    tags = dedupe_text_tokens([
        rationale_tag_label(prompt_type),
        rationale_tag_label(prompt_metadata.get("current_phase", "")),
        rationale_tag_label(prompt_metadata.get("prompt_profile", "")),
        rationale_tag_label(response_payload.get("focus", "") if prompt_type == "web_followup" else response_payload.get("priority_shift", "")),
    ], limit=5)

    normalized_timestamp = runtime_or_cls._normalize_process_timestamp_to_utc(log_row.get("timestamp", "")) or str(log_row.get("timestamp", "") or "")
    return {
        "id": f"provider:{prompt_type}:{normalized_timestamp}:{host_ip}:{port}:{headline}",
        "timestamp": normalized_timestamp,
        "host_ip": host_ip,
        "port": port,
        "protocol": protocol,
        "service": service,
        "kind": prompt_type,
        "headline": headline or rationale_tag_label(prompt_type) or "Decision",
        "summary": summary or "Scheduler decision recorded.",
        "details": [line for line in details if str(line or "").strip()],
        "tags": tags,
        "_matched_decision_ids": matched_decision_ids,
        "_sort_ts": event_ts,
    }


def build_audit_rationale_entry(
        runtime_or_cls,
        decision_row: Dict[str, Any],
        *,
        execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    tool_id = str(decision_row.get("tool_id", "") or decision_row.get("label", "") or "").strip()
    if not tool_id:
        return None
    event_ts = float(decision_row.get("_sort_ts", 0.0) or 0.0)
    execution = nearest_scheduler_row(execution_index.get((
        str(decision_row.get("host_ip", "") or "").strip(),
        str(decision_row.get("port", "") or "").strip(),
        str(decision_row.get("protocol", "") or "").strip(),
        tool_id,
    ), []), event_ts)

    details: List[str] = []
    approval_state = str(decision_row.get("requires_approval", "") or "").strip().lower()
    approved = str(decision_row.get("approved", "") or "").strip().lower()
    executed = str(decision_row.get("executed", "") or "").strip().lower()
    if approved == "true" and executed == "true":
        details.append("Outcome: executed")
    elif approved == "true":
        details.append("Outcome: approved")
    elif approval_state == "true":
        details.append("Outcome: awaiting approval")
    policy_decision = str(decision_row.get("policy_decision", "") or "").strip()
    if policy_decision:
        details.append(f"Policy: {policy_decision}")
    policy_reason = truncate_rationale_text(decision_row.get("policy_reason", ""), 120)
    if policy_reason:
        details.append(f"Policy reason: {policy_reason}")
    safer_alternative = truncate_rationale_text(decision_row.get("safer_alternative", ""), 120)
    if safer_alternative:
        details.append(f"Safer alternative: {safer_alternative}")
    risk_summary = truncate_rationale_text(decision_row.get("risk_summary", ""), 120)
    if risk_summary:
        details.append(f"Risk: {risk_summary}")
    if isinstance(execution, dict):
        execution_id = str(execution.get("execution_id", "") or "").strip()
        exit_status = str(execution.get("exit_status", "") or "").strip()
        if execution_id and exit_status:
            details.append(f"Execution: {execution_id} [exit {exit_status}]")
        elif execution_id:
            details.append(f"Execution: {execution_id}")

    normalized_timestamp = runtime_or_cls._normalize_process_timestamp_to_utc(decision_row.get("timestamp", "")) or str(decision_row.get("timestamp", "") or "")
    return {
        "id": f"audit:{decision_row.get('id', '')}:{tool_id}",
        "timestamp": normalized_timestamp,
        "host_ip": str(decision_row.get("host_ip", "") or "").strip(),
        "port": str(decision_row.get("port", "") or "").strip(),
        "protocol": str(decision_row.get("protocol", "") or "").strip(),
        "service": str(decision_row.get("service", "") or "").strip(),
        "kind": "decision",
        "headline": tool_id,
        "summary": truncate_rationale_text(
            decision_row.get("rationale", "") or decision_row.get("reason", "") or "Scheduler decision recorded.",
            200,
        ),
        "details": [line for line in details if str(line or "").strip()],
        "tags": dedupe_text_tokens([
            "Decision",
            rationale_tag_label(decision_row.get("scheduler_mode", "")),
            rationale_tag_label(decision_row.get("service", "")),
        ], limit=4),
        "_sort_ts": event_ts,
    }


def build_scheduler_rationale_feed_items(
        runtime_or_cls,
        provider_logs: List[Dict[str, Any]],
        decisions: List[Dict[str, Any]],
        executions: List[Dict[str, Any]],
        *,
        limit: int = 18,
) -> List[Dict[str, Any]]:
    resolved_limit = max(1, min(int(limit or 18), 48))
    normalized_decisions = [dict(item) for item in list(decisions or []) if isinstance(item, dict)]
    normalized_executions = [dict(item) for item in list(executions or []) if isinstance(item, dict)]
    for item in normalized_decisions:
        item["_sort_ts"] = scheduler_event_timestamp_epoch(runtime_or_cls, item.get("timestamp", ""))
    for item in normalized_executions:
        item["_sort_ts"] = scheduler_event_timestamp_epoch(runtime_or_cls, item.get("started_at", "") or item.get("finished_at", ""))

    decision_index = index_scheduler_rows_by_target_tool(runtime_or_cls, normalized_decisions, timestamp_field="timestamp")
    execution_index = index_scheduler_rows_by_target_tool(runtime_or_cls, normalized_executions, timestamp_field="started_at")

    entries: List[Dict[str, Any]] = []
    matched_decision_ids = set()

    for log_row in reversed(list(provider_logs or [])):
        if not isinstance(log_row, dict):
            continue
        entry = build_provider_rationale_entry(
            runtime_or_cls,
            log_row,
            decision_index=decision_index,
            execution_index=execution_index,
        )
        if not isinstance(entry, dict):
            continue
        matched_decision_ids.update(int(item) for item in list(entry.pop("_matched_decision_ids", []) or []) if int(item or 0) > 0)
        entries.append(entry)

    for decision_row in normalized_decisions:
        try:
            decision_id = int(decision_row.get("id", 0) or 0)
        except (TypeError, ValueError):
            decision_id = 0
        if decision_id > 0 and decision_id in matched_decision_ids:
            continue
        entry = build_audit_rationale_entry(
            runtime_or_cls,
            decision_row,
            execution_index=execution_index,
        )
        if isinstance(entry, dict):
            entries.append(entry)

    entries.sort(key=lambda item: float(item.get("_sort_ts", 0.0) or 0.0), reverse=True)
    trimmed = entries[:resolved_limit]
    for item in trimmed:
        item.pop("_sort_ts", None)
    return trimmed
