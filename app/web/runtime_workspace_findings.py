from __future__ import annotations

from typing import Any, Dict, List

from app.scheduler.state import get_target_state as load_target_state
from app.web.runtime_workspace_identity import resolve_host_os
from app.web.runtime_workspace_target_state import load_target_state_cache


def _host_state_row(host: Any, target_state: Dict[str, Any] | None = None) -> Dict[str, Any]:
    os_state = resolve_host_os(host, target_state=target_state or {})
    return {
        "id": int(getattr(host, "id", 0) or 0),
        "ip": str(getattr(host, "ip", "") or ""),
        "hostname": str(getattr(host, "hostname", "") or ""),
        "status": str(getattr(host, "status", "") or ""),
        "os": str(os_state.get("os", "") or ""),
        "raw_os": str(os_state.get("raw_os", "") or ""),
        "os_source": str(os_state.get("os_source", "") or ""),
        "os_confidence": float(os_state.get("os_confidence", 0.0) or 0.0),
    }


def get_target_state_view(
        runtime,
        host_id: int = 0,
        limit: int = 500,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
    with runtime._lock:
        project = runtime._require_active_project()
        max_hosts = max(1, min(int(limit or 500), 5000))
        if int(host_id or 0) > 0:
            host = runtime._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            target_state = target_state_getter(project.database, int(host_id)) or {}
            return {
                "host": _host_state_row(host, target_state),
                "target_state": target_state,
            }

        states = []
        for row in list(runtime._hosts(limit=max_hosts) or []):
            states.append({
                "host": dict(row),
                "target_state": target_state_getter(project.database, int(row.get("id", 0) or 0)) or {},
            })
        return {
            "count": len(states),
            "states": states,
        }


def get_findings(
        runtime,
        host_id: int = 0,
        limit_hosts: int = 500,
        limit_findings: int = 1000,
        *,
        get_target_state_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
    with runtime._lock:
        project = runtime._require_active_project()
        if int(host_id or 0) > 0:
            host = runtime._resolve_host(int(host_id))
            if host is None:
                raise KeyError(f"Unknown host id: {host_id}")
            target_state = target_state_getter(project.database, int(host_id)) or {}
            host_rows = [_host_state_row(host, target_state)]
            preloaded_states = {int(host_id): target_state}
        else:
            host_rows = list(runtime._hosts(limit=max(1, min(int(limit_hosts or 500), 5000))) or [])
            preloaded_states = None
            if target_state_getter is load_target_state:
                # Default getter (also what WebRuntime passes): one bulk query instead of a lookup per host.
                # A custom getter (e.g. in tests) is still called per host.
                preloaded_states = load_target_state_cache(
                    project,
                    [int(row.get("id", 0) or 0) for row in host_rows],
                )

        findings = []
        max_items = max(1, min(int(limit_findings or 1000), 5000))
        for row in host_rows:
            row_host_id = int(row.get("id", 0) or 0)
            if preloaded_states is not None:
                state = preloaded_states.get(row_host_id) or {}
            else:
                state = target_state_getter(project.database, row_host_id) or {}
            for item in list(state.get("findings", []) or []):
                if not isinstance(item, dict):
                    continue
                findings.append({
                    "host": dict(row),
                    "title": str(item.get("title", "") or ""),
                    "severity": str(item.get("severity", "") or ""),
                    "confidence": item.get("confidence", 0.0),
                    "source_kind": str(item.get("source_kind", "") or "observed"),
                    "finding": dict(item),
                })
                if len(findings) >= max_items:
                    break
            if len(findings) >= max_items:
                break
        return {
            "count": len(findings),
            "host_scope_count": len(host_rows),
            "findings": findings,
        }
