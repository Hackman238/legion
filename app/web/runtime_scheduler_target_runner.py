from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple


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
