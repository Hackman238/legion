from __future__ import annotations

import datetime
from typing import Any, Dict, List


def get_workspace_processes(runtime, limit: int = 75) -> List[Dict[str, Any]]:
    with runtime._lock:
        return runtime._processes(limit=max(1, min(int(limit or 75), 500)))


def get_snapshot(runtime) -> Dict[str, Any]:
    with runtime._lock:
        runtime._maybe_schedule_autosave_locked()
        tools_page = runtime.get_workspace_tools_page(limit=300, offset=0)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "project": runtime._project_metadata(),
            "summary": runtime._summary(),
            "host_filter": "hide_down",
            "hosts": runtime._hosts(include_down=False),
            "processes": runtime._processes(limit=75),
            "services": runtime.get_workspace_services(limit=40),
            "tools": tools_page.get("tools", []),
            "tools_meta": {
                "offset": int(tools_page.get("offset", 0) or 0),
                "limit": int(tools_page.get("limit", 0) or 0),
                "total": int(tools_page.get("total", 0) or 0),
                "has_more": bool(tools_page.get("has_more", False)),
                "next_offset": tools_page.get("next_offset"),
            },
            "credential_capture": runtime._credential_capture_state_locked(include_captures=False),
            "scheduler": runtime._scheduler_preferences(),
            "scheduler_decisions": runtime.get_scheduler_decisions(limit=80),
            "scheduler_rationale_feed": runtime._scheduler_rationale_feed_locked(limit=12),
            "scheduler_approvals": runtime.get_scheduler_approvals(limit=40, status="pending"),
            "scheduler_executions": runtime.get_scheduler_execution_records(limit=40),
            "scan_history": runtime.get_scan_history(limit=40),
            "jobs": runtime.jobs.list_jobs(limit=20),
        }
