from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.settings import AppSettings, Settings
from app.tooling import (
    audit_legion_tools,
    build_tool_install_plan,
    detect_supported_tool_install_platform,
    execute_tool_install_plan,
    normalize_tool_install_platform,
    tool_audit_summary,
)


def get_tool_audit(runtime) -> Dict[str, Any]:
    settings = getattr(runtime, "settings", None)
    if settings is None:
        settings = Settings(AppSettings())
    entries = audit_legion_tools(settings)
    return {
        "summary": tool_audit_summary(entries),
        "tools": [entry.to_dict() for entry in entries],
        "supported_platforms": ["kali", "ubuntu"],
        "recommended_platform": detect_supported_tool_install_platform(),
    }


def tool_audit_availability(entries: Any) -> Dict[str, List[str]]:
    available = set()
    unavailable = set()
    for item in list(entries or []):
        status = ""
        key = ""
        if isinstance(item, dict):
            key = str(item.get("key", "") or "").strip().lower()
            status = str(item.get("status", "") or "").strip().lower()
        else:
            key = str(getattr(item, "key", "") or "").strip().lower()
            status = str(getattr(item, "status", "") or "").strip().lower()
        if not key:
            continue
        if status == "installed":
            available.add(key)
        elif status in {"missing", "configured-missing"}:
            unavailable.add(key)
    unavailable.difference_update(available)
    return {
        "available_tool_ids": sorted(available),
        "unavailable_tool_ids": sorted(unavailable),
    }


def get_tool_install_plan(
        runtime,
        *,
        platform: str = "kali",
        scope: str = "missing",
        tool_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    settings = getattr(runtime, "settings", None)
    if settings is None:
        settings = Settings(AppSettings())
    entries = audit_legion_tools(settings)
    return build_tool_install_plan(
        entries,
        platform=platform,
        scope=scope,
        tool_keys=tool_keys,
    )


def start_tool_install_job(
        runtime,
        *,
        platform: str = "kali",
        scope: str = "missing",
        tool_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    normalized_platform = normalize_tool_install_platform(platform)
    normalized_scope = str(scope or "missing").strip().lower() or "missing"
    normalized_keys = [str(item or "").strip() for item in list(tool_keys or []) if str(item or "").strip()]
    payload = {
        "platform": normalized_platform,
        "scope": normalized_scope,
        "tool_keys": normalized_keys,
    }
    return runtime._start_job(
        "tool-install",
        lambda job_id: run_tool_install_job(
            runtime,
            platform=normalized_platform,
            scope=normalized_scope,
            tool_keys=normalized_keys,
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )


def run_tool_install_job(
        runtime,
        *,
        platform: str = "kali",
        scope: str = "missing",
        tool_keys: Optional[List[str]] = None,
        job_id: int = 0,
) -> Dict[str, Any]:
    plan = get_tool_install_plan(runtime, platform=platform, scope=scope, tool_keys=tool_keys)
    resolved_job_id = int(job_id or 0)
    return execute_tool_install_plan(
        plan,
        is_cancel_requested=(lambda: runtime.jobs.is_cancel_requested(resolved_job_id)) if resolved_job_id > 0 else None,
    )
