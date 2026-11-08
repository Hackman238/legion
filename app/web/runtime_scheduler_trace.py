from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from app.scheduler.execution import (
    ensure_scheduler_execution_table,
    get_execution_record,
    list_execution_records,
    store_execution_record,
)
from app.scheduler.models import ExecutionRecord
from app.scheduler.planner import ScheduledAction

logger = logging.getLogger(__name__)


def get_scheduler_execution_records(
        runtime,
        limit: int = 200,
        *,
        host_ip: Optional[str] = None,
        tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_execution_table(project.database)
        return list_execution_records(project.database, limit=limit, host_ip=host_ip, tool_id=tool_id)


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


def read_ref_excerpt(runtime, ref: str, max_chars: int = 4000) -> str:
    normalized_ref = str(ref or "").strip()
    if normalized_ref.startswith("process_output:"):
        try:
            process_id = int(normalized_ref.split(":", 1)[1])
        except (TypeError, ValueError):
            return ""
        safe_max_chars = max(0, min(int(max_chars or 4000), 200000))
        if safe_max_chars <= 0:
            return ""
        try:
            tail_reader = getattr(runtime, "get_process_output_tail", None)
            if callable(tail_reader):
                # Slices the tail in SQL so large outputs are not loaded just to keep the end.
                return str(tail_reader(process_id, max_chars=safe_max_chars) or "")[-safe_max_chars:]
            payload = runtime.get_process_output(process_id, offset=0, max_chars=safe_max_chars)
        except Exception:
            return ""
        output_text = str(payload.get("output", "") or payload.get("output_chunk", "") or "")
        return output_text[-safe_max_chars:]
    return runtime._read_text_excerpt(normalized_ref, max_chars=max_chars)


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
            resolved_host_ip = str(getattr(host, "ip", "") or "").strip()
    normalized_tool_id = str(tool_id or "").strip().lower()
    max_items = max(1, min(int(limit or 200), 1000))
    rows = get_scheduler_execution_records(
        runtime,
        limit=max_items,
        host_ip=resolved_host_ip or None,
        tool_id=normalized_tool_id or None,
    )
    filtered = []
    for item in list(rows or []):
        record = dict(item)
        if include_output:
            record["stdout_excerpt"] = read_ref_excerpt(
                runtime,
                str(record.get("stdout_ref", "") or ""),
                max_chars=output_max_chars,
            )
            record["stderr_excerpt"] = read_ref_excerpt(
                runtime,
                str(record.get("stderr_ref", "") or ""),
                max_chars=output_max_chars,
            )
        filtered.append(record)
        if len(filtered) >= max_items:
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
    payload["stdout_excerpt"] = read_ref_excerpt(
        runtime,
        str(payload.get("stdout_ref", "") or ""),
        max_chars=output_max_chars,
    )
    payload["stderr_excerpt"] = read_ref_excerpt(
        runtime,
        str(payload.get("stderr_ref", "") or ""),
        max_chars=output_max_chars,
    )
    return payload


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
            logger.warning("Execution record for %s on %s was not stored.", getattr(decision, "tool_id", ""), host_ip, exc_info=True)
            return None
