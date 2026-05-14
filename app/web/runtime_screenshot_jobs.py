from __future__ import annotations

from typing import Any, Dict

from app.web.runtime_screenshot_targets import (
    collect_host_screenshot_targets,
    is_rdp_service,
    is_vnc_service,
    is_web_screenshot_target,
    list_screenshots_for_host,
)


def start_host_screenshot_refresh_job(runtime, host_id: int) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    with runtime._lock:
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")
        existing = runtime._find_active_job(job_type="host-screenshot-refresh", host_id=resolved_host_id)
        if existing is not None:
            existing_copy = dict(existing)
            existing_copy["existing"] = True
            return existing_copy

    targets = collect_host_screenshot_targets(runtime, resolved_host_id)
    if not targets:
        raise ValueError("Host does not have any open HTTP/HTTPS services to screenshot.")

    return runtime._start_job(
        "host-screenshot-refresh",
        lambda job_id: run_host_screenshot_refresh(
            runtime,
            host_id=resolved_host_id,
            job_id=int(job_id or 0),
        ),
        payload={
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "target_count": len(targets),
        },
    )


def start_graph_screenshot_refresh_job(runtime, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    if resolved_host_id <= 0 or not resolved_port:
        raise ValueError("host_id and port are required.")
    with runtime._lock:
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")
        for job in runtime.jobs.list_jobs(limit=200):
            if str(job.get("type", "")).strip() != "graph-screenshot-refresh":
                continue
            status = str(job.get("status", "") or "").strip().lower()
            if status not in {"queued", "running"}:
                continue
            payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
            if int(payload.get("host_id", 0) or 0) != resolved_host_id:
                continue
            if str(payload.get("port", "") or "").strip() != resolved_port:
                continue
            if str(payload.get("protocol", "tcp") or "tcp").strip().lower() != resolved_protocol:
                continue
            existing_copy = dict(job)
            existing_copy["existing"] = True
            return existing_copy
        service_name = runtime._service_name_for_target(host_ip, resolved_port, resolved_protocol)
        normalized_service = str(service_name or "").strip().rstrip("?").lower()
        if not (
                is_web_screenshot_target(resolved_port, resolved_protocol, normalized_service)
                or is_rdp_service(normalized_service)
                or is_vnc_service(normalized_service)
        ):
            raise ValueError("Target does not support screenshot refresh.")

    return runtime._start_job(
        "graph-screenshot-refresh",
        lambda job_id: run_graph_screenshot_refresh(
            runtime,
            host_id=resolved_host_id,
            port=resolved_port,
            protocol=resolved_protocol,
            job_id=int(job_id or 0),
        ),
        payload={
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "port": resolved_port,
            "protocol": resolved_protocol,
        },
    )


def run_host_screenshot_refresh(runtime, *, host_id: int, job_id: int = 0) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    with runtime._lock:
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")

    targets = collect_host_screenshot_targets(runtime, resolved_host_id)
    if not targets:
        return {
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "target_count": 0,
            "completed": 0,
            "results": [],
            "screenshots": [],
        }

    results = []
    completed = 0
    for target in targets:
        if int(job_id or 0) > 0 and runtime.jobs.is_cancel_requested(int(job_id)):
            break
        executed, reason, artifact_refs = runtime._take_screenshot(
            host_ip,
            str(target.get("port", "") or ""),
            service_name=str(target.get("service_name", "") or ""),
            return_artifacts=True,
        )
        if executed:
            completed += 1
        results.append({
            "port": str(target.get("port", "") or ""),
            "protocol": str(target.get("protocol", "tcp") or "tcp"),
            "service_name": str(target.get("service_name", "") or ""),
            "executed": bool(executed),
            "reason": str(reason or ""),
            "artifact_refs": list(artifact_refs or []),
        })

    with runtime._lock:
        project = runtime._require_active_project()
        screenshots = list_screenshots_for_host(runtime, project, host_ip)

    try:
        runtime.get_host_workspace(resolved_host_id)
    except Exception:
        pass

    runtime._emit_ui_invalidation("graph", "hosts", "services")

    return {
        "host_id": resolved_host_id,
        "host_ip": host_ip,
        "hostname": hostname,
        "target_count": len(targets),
        "completed": int(completed),
        "results": results,
        "screenshots": screenshots,
    }


def run_graph_screenshot_refresh(
        runtime,
        *,
        host_id: int,
        port: str,
        protocol: str = "tcp",
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    with runtime._lock:
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")
        service_name = runtime._service_name_for_target(host_ip, resolved_port, resolved_protocol)

    if int(job_id or 0) > 0 and runtime.jobs.is_cancel_requested(int(job_id)):
        return {
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "port": resolved_port,
            "protocol": resolved_protocol,
            "executed": False,
            "reason": "cancelled",
            "artifact_refs": [],
            "screenshots": [],
        }

    executed, reason, artifact_refs = runtime._take_screenshot(
        host_ip,
        resolved_port,
        service_name=str(service_name or ""),
        return_artifacts=True,
    )
    with runtime._lock:
        project = runtime._require_active_project()
        screenshots = list_screenshots_for_host(runtime, project, host_ip)

    try:
        runtime.get_host_workspace(resolved_host_id)
    except Exception:
        pass

    runtime._emit_ui_invalidation("graph", "hosts", "services")

    return {
        "host_id": resolved_host_id,
        "host_ip": host_ip,
        "hostname": hostname,
        "port": resolved_port,
        "protocol": resolved_protocol,
        "service_name": str(service_name or ""),
        "executed": bool(executed),
        "reason": str(reason or ""),
        "artifact_refs": list(artifact_refs or []),
        "screenshots": screenshots,
    }
