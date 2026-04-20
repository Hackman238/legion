from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.httputil.isHttps import isHttps
from app.scheduler.planner import SchedulerPlanner
from app.scheduler.runners import normalize_runner_settings
from app.screenshot_metadata import (
    build_screenshot_metadata,
    load_screenshot_metadata,
    screenshot_metadata_path,
    write_screenshot_metadata,
)
from app.screenshot_targets import choose_preferred_screenshot_host
from app.tooling import build_tool_execution_env


def is_rdp_service(service_name: str) -> bool:
    value = str(service_name or "").strip().rstrip("?").lower()
    return value in {"rdp", "ms-wbt-server", "vmrdp", "ms-term-serv"}


def is_vnc_service(service_name: str) -> bool:
    value = str(service_name or "").strip().rstrip("?").lower()
    return value in {"vnc", "vnc-http", "rfb"}


def port_sort_key(port_value: str) -> Tuple[int, str]:
    token = str(port_value or "").strip()
    try:
        return 0, f"{int(token):08d}"
    except (TypeError, ValueError):
        return 1, token


def is_web_screenshot_target(port: str, protocol: str, service_name: str) -> bool:
    if str(protocol or "").strip().lower() != "tcp":
        return False
    service_lower = str(service_name or "").strip().rstrip("?").lower()
    if (
            service_lower in SchedulerPlanner.WEB_SERVICE_IDS
            or service_lower.startswith("http")
            or "https" in service_lower
            or service_lower.endswith("http")
            or service_lower.endswith("https")
            or service_lower in {"soap", "ssl/http", "ssl|http", "webcache", "www"}
    ):
        return True
    return str(port or "").strip() in {
        "80",
        "81",
        "82",
        "88",
        "443",
        "591",
        "593",
        "8000",
        "8008",
        "8080",
        "8081",
        "8088",
        "8443",
        "8888",
        "9000",
        "9090",
        "9443",
    }


def list_screenshots_for_host(runtime, project, host_ip: str) -> List[Dict[str, Any]]:
    screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
    if not os.path.isdir(screenshot_dir):
        return []

    prefix = f"{host_ip}-"
    rows = []
    for filename in sorted(os.listdir(screenshot_dir)):
        if not filename.lower().endswith(".png"):
            continue
        if not filename.startswith(prefix):
            continue
        port = ""
        stripped = filename[len(prefix):]
        if stripped.endswith("-screenshot.png"):
            port = stripped[:-len("-screenshot.png")]
        screenshot_path = os.path.join(screenshot_dir, filename)
        metadata = load_screenshot_metadata(screenshot_path)
        row = {
            "filename": filename,
            "artifact_ref": f"/api/screenshots/{filename}",
            "port": str(metadata.get("port", "") or port or ""),
            "url": f"/api/screenshots/{filename}",
        }
        for field in ("target_url", "capture_engine", "capture_reason", "captured_at", "service_name", "hostname"):
            value = str(metadata.get(field, "") or "").strip()
            if value:
                row[field] = value
        rows.append(row)
    return rows


def collect_host_screenshot_targets(runtime, host_id: int) -> List[Dict[str, str]]:
    resolved_host_id = int(host_id or 0)
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        repo_container = getattr(project, "repositoryContainer", None)
        port_repo = getattr(repo_container, "portRepository", None)
        service_repo = getattr(repo_container, "serviceRepository", None)
        port_rows = list(port_repo.getPortsByHostId(host.id)) if port_repo else []

    targets: List[Dict[str, str]] = []
    seen = set()
    for port_row in port_rows:
        port_value = str(getattr(port_row, "portId", "") or "").strip()
        protocol = str(getattr(port_row, "protocol", "tcp") or "tcp").strip().lower() or "tcp"
        state = str(getattr(port_row, "state", "") or "").strip().lower()
        if not port_value or protocol != "tcp":
            continue
        if state and "open" not in state:
            continue
        service_name = ""
        service_id = getattr(port_row, "serviceId", None)
        if service_id and service_repo:
            try:
                service_obj = service_repo.getServiceById(service_id)
            except Exception:
                service_obj = None
            service_name = str(getattr(service_obj, "name", "") or "") if service_obj else ""
        if not is_web_screenshot_target(port_value, protocol, service_name):
            continue
        dedupe_key = (port_value, protocol)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        targets.append({
            "port": port_value,
            "protocol": protocol,
            "service_name": service_name,
        })
    targets.sort(key=lambda item: (port_sort_key(item.get("port", "")), item.get("protocol", "")))
    return targets


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
        executed, reason, artifact_refs = take_screenshot(
            runtime,
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

    executed, reason, artifact_refs = take_screenshot(
        runtime,
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


def take_screenshot(
        runtime,
        host_ip: str,
        port: str,
        service_name: str = "",
        return_artifacts: bool = False,
        browser_settings: Optional[Dict[str, Any]] = None,
) -> Any:
    normalized_service = str(service_name or "").strip().rstrip("?").lower()
    if is_rdp_service(normalized_service) or is_vnc_service(normalized_service):
        return take_remote_service_screenshot(
            runtime,
            host_ip=host_ip,
            port=port,
            service_name=normalized_service,
            return_artifacts=return_artifacts,
            browser_settings=browser_settings,
        )

    with runtime._lock:
        project = runtime._require_active_project()
        screenshots_dir = os.path.join(project.properties.outputFolder, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

    normalized_browser = normalize_runner_settings({"browser": browser_settings or {}}).get("browser", {})

    target_host = choose_preferred_screenshot_host(runtime._hostname_for_ip(host_ip), host_ip)
    host_port = f"{target_host}:{port}"
    prefer_https = bool(isHttps(target_host, port))
    url_candidates = [
        f"https://{host_port}",
        f"http://{host_port}",
    ] if prefer_https else [
        f"http://{host_port}",
        f"https://{host_port}",
    ]

    capture = None
    failure_capture = None
    captured_url = ""
    for url in url_candidates:
        current_capture = run_eyewitness_capture(
            url=url,
            output_parent_dir=screenshots_dir,
            delay=int(normalized_browser.get("delay", 5) or 5),
            use_xvfb=bool(normalized_browser.get("use_xvfb", True)),
            timeout=int(normalized_browser.get("timeout", 180) or 180),
        )
        if current_capture.get("ok"):
            capture = current_capture
            captured_url = url
            break
        failure_capture = current_capture
        if str(current_capture.get("reason", "") or "") == "eyewitness missing":
            break

    if not capture:
        failed = failure_capture or {}
        reason = str(failed.get("reason", "") or "")
        if reason == "eyewitness missing":
            if return_artifacts:
                return False, "skipped: eyewitness missing", []
            return False, "skipped: eyewitness missing"
        detail = summarize_eyewitness_failure(failed.get("attempts", []))
        if detail:
            if return_artifacts:
                return False, f"skipped: screenshot png missing ({detail})", []
            return False, f"skipped: screenshot png missing ({detail})"
        if return_artifacts:
            return False, "skipped: screenshot png missing", []
        return False, "skipped: screenshot png missing"

    src_path = str(capture.get("screenshot_path", "") or "")
    if not src_path or not os.path.isfile(src_path):
        if return_artifacts:
            return False, "skipped: screenshot output missing", []
        return False, "skipped: screenshot output missing"

    deterministic_name = f"{host_ip}-{port}-screenshot.png"
    dst_path = os.path.join(screenshots_dir, deterministic_name)
    shutil.copy2(src_path, dst_path)
    capture_reason = "completed"
    returncode = int(capture.get("returncode", 0) or 0)
    if returncode != 0:
        capture_reason = f"completed (eyewitness exited {returncode})"
    metadata_path = write_screenshot_metadata(
        dst_path,
        build_screenshot_metadata(
            screenshot_path=dst_path,
            host_ip=host_ip,
            hostname=runtime._hostname_for_ip(host_ip) if hasattr(runtime, "_hostname_for_ip") else "",
            port=port,
            protocol="tcp",
            service_name=normalized_service or str(service_name or ""),
            target_url=captured_url,
            capture_engine=str(capture.get("executable", "") or "eyewitness"),
            capture_reason=capture_reason,
            captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            capture_returncode=returncode,
        ),
    )
    artifact_refs = [dst_path]
    if metadata_path:
        artifact_refs.append(metadata_path)
    if returncode != 0:
        if return_artifacts:
            return True, capture_reason, artifact_refs
        return True, capture_reason
    if return_artifacts:
        return True, "completed", artifact_refs
    return True, "completed"


def take_remote_service_screenshot(
        runtime,
        *,
        host_ip: str,
        port: str,
        service_name: str,
        return_artifacts: bool = False,
        browser_settings: Optional[Dict[str, Any]] = None,
) -> Any:
    with runtime._lock:
        project = runtime._require_active_project()
        screenshots_dir = os.path.join(project.properties.outputFolder, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

    deterministic_name = f"{host_ip}-{port}-screenshot.png"
    dst_path = os.path.join(screenshots_dir, deterministic_name)
    probe_host_port = f"{host_ip}:{port}"
    if os.path.isfile(dst_path):
        try:
            os.remove(dst_path)
        except Exception:
            pass
    metadata_path = screenshot_metadata_path(dst_path)
    if metadata_path and os.path.isfile(metadata_path):
        try:
            os.remove(metadata_path)
        except Exception:
            pass

    commands = []
    if is_vnc_service(service_name):
        commands = [
            ["vncsnapshot", "-allowblank", "-quality", "85", f"{host_ip}::{port}", dst_path],
            ["vncsnapshot", "-allowblank", "-quality", "85", probe_host_port, dst_path],
            ["python3", "-m", "vncdotool", "-s", f"{host_ip}::{port}", "capture", dst_path],
        ]
    elif is_rdp_service(service_name):
        commands = [
            ["rdpy-rdpscreenshot", "-o", dst_path, probe_host_port],
            ["rdpy-rdpscreenshot", probe_host_port, dst_path],
        ]

    attempts = []
    normalized_browser = normalize_runner_settings({"browser": browser_settings or {}}).get("browser", {})
    timeout = max(30, min(int(normalized_browser.get("timeout", 180) or 180), 300))
    for command in commands:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env=build_tool_execution_env(),
            )
            output = runtime._truncate_scheduler_text(result.stdout or "", 260)
            attempts.append({
                "command": " ".join(command),
                "returncode": int(result.returncode),
                "output": output,
            })
            if result.returncode == 0 and os.path.isfile(dst_path) and os.path.getsize(dst_path) > 0:
                metadata_path = write_screenshot_metadata(
                    dst_path,
                    build_screenshot_metadata(
                        screenshot_path=dst_path,
                        host_ip=host_ip,
                        hostname=runtime._hostname_for_ip(host_ip) if hasattr(runtime, "_hostname_for_ip") else "",
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        capture_engine=str(command[0] if command else ""),
                        capture_reason="completed",
                        captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        capture_returncode=int(result.returncode),
                    ),
                )
                artifact_refs = [dst_path]
                if metadata_path:
                    artifact_refs.append(metadata_path)
                if return_artifacts:
                    return True, "completed", artifact_refs
                return True, "completed"
        except FileNotFoundError:
            attempts.append({
                "command": " ".join(command),
                "returncode": 127,
                "output": "command not found",
            })
        except Exception as exc:
            attempts.append({
                "command": " ".join(command),
                "returncode": 1,
                "output": runtime._truncate_scheduler_text(str(exc), 260),
            })

    detail_parts = []
    for item in attempts[:3]:
        detail_parts.append(
            f"{item.get('command', '')} rc={item.get('returncode', '')} {item.get('output', '')}".strip()
        )
    if detail_parts:
        reason = "skipped: remote screenshot missing (" + " | ".join(detail_parts) + ")"
        if return_artifacts:
            return False, reason, []
        return False, reason
    if return_artifacts:
        return False, "skipped: remote screenshot missing", []
    return False, "skipped: remote screenshot missing"
