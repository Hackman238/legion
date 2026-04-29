from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from app.web.runtime_scheduler_rationale_text import (
    dedupe_text_tokens,
    rationale_list_text,
    truncate_rationale_text,
)


def scheduler_event_timestamp_epoch(runtime_or_cls, value: Any) -> float:
    normalized = runtime_or_cls._normalize_process_timestamp_to_utc(value)
    if not normalized:
        return 0.0
    try:
        return datetime.datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return 0.0


def index_scheduler_rows_by_target_tool(
        runtime_or_cls,
        rows: List[Dict[str, Any]],
        *,
        timestamp_field: str,
) -> Dict[Tuple[str, str, str, str], List[Dict[str, Any]]]:
    index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for raw_row in list(rows or []):
        if not isinstance(raw_row, dict):
            continue
        item = dict(raw_row)
        item["_sort_ts"] = scheduler_event_timestamp_epoch(runtime_or_cls, item.get(timestamp_field, ""))
        key = (
            str(item.get("host_ip", "") or "").strip(),
            str(item.get("port", "") or "").strip(),
            str(item.get("protocol", "") or "").strip(),
            str(item.get("tool_id", "") or item.get("label", "") or "").strip(),
        )
        if not key[3]:
            continue
        index[key].append(item)
    for entries in index.values():
        entries.sort(key=lambda entry: float(entry.get("_sort_ts", 0.0) or 0.0), reverse=True)
    return index


def nearest_scheduler_row(rows: List[Dict[str, Any]], event_ts: float) -> Optional[Dict[str, Any]]:
    if not rows:
        return None
    if float(event_ts or 0.0) <= 0.0:
        return rows[0]
    best: Optional[Dict[str, Any]] = None
    best_delta: Optional[float] = None
    for item in list(rows or [])[:10]:
        delta = abs(float(item.get("_sort_ts", 0.0) or 0.0) - float(event_ts or 0.0))
        if best is None or best_delta is None or delta < best_delta:
            best = item
            best_delta = delta
    if best is None:
        return None
    if best_delta is not None and best_delta > 7200:
        return None
    return best


def match_rationale_outcomes(
        runtime_or_cls,
        decision_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
        execution_index: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]],
        *,
        host_ip: str,
        port: str,
        protocol: str,
        tool_ids: List[str],
        event_ts: float,
) -> Tuple[str, List[int]]:
    _ = runtime_or_cls
    outcome_tokens: List[str] = []
    matched_decision_ids: List[int] = []
    for tool_id in dedupe_text_tokens(tool_ids, limit=16):
        key = (str(host_ip or "").strip(), str(port or "").strip(), str(protocol or "").strip(), tool_id)
        decision = nearest_scheduler_row(decision_index.get(key, []), event_ts)
        execution = nearest_scheduler_row(execution_index.get(key, []), event_ts)
        if isinstance(decision, dict):
            try:
                decision_id = int(decision.get("id", 0) or 0)
            except (TypeError, ValueError):
                decision_id = 0
            if decision_id > 0:
                matched_decision_ids.append(decision_id)
        if isinstance(execution, dict):
            execution_id = str(execution.get("execution_id", "") or "").strip()
            exit_status = str(execution.get("exit_status", "") or "").strip()
            token = f"{tool_id} executed"
            if execution_id:
                token += f" [{execution_id}"
                if exit_status:
                    token += f", exit {exit_status}"
                token += "]"
            elif exit_status:
                token += f" [exit {exit_status}]"
            outcome_tokens.append(token)
            continue

        if not isinstance(decision, dict):
            continue
        if str(decision.get("executed", "") or "").strip().lower() == "true":
            outcome_tokens.append(f"{tool_id} executed")
        elif str(decision.get("approved", "") or "").strip().lower() == "true":
            outcome_tokens.append(f"{tool_id} approved")
        elif str(decision.get("requires_approval", "") or "").strip().lower() == "true":
            outcome_tokens.append(f"{tool_id} awaiting approval")
        else:
            decision_reason = truncate_rationale_text(
                decision.get("reason", "") or decision.get("policy_decision", "") or "recorded",
                72,
            )
            outcome_tokens.append(f"{tool_id} {decision_reason}".strip())

    if not outcome_tokens:
        return "", matched_decision_ids
    return f"Outcome: {rationale_list_text(outcome_tokens, limit=4)}", matched_decision_ids
