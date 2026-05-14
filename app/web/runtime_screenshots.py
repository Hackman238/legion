from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from typing import Any, Dict, Optional

from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.httputil.isHttps import isHttps
from app.scheduler.runners import normalize_runner_settings
from app.screenshot_metadata import (
    build_screenshot_metadata,
    screenshot_metadata_path,
    write_screenshot_metadata,
)
from app.screenshot_targets import choose_preferred_screenshot_host
from app.tooling import build_tool_execution_env
from app.web import runtime_screenshot_jobs as web_runtime_screenshot_jobs
from app.web.runtime_screenshot_targets import (
    collect_host_screenshot_targets,
    is_rdp_service,
    is_vnc_service,
    is_web_screenshot_target,
    list_screenshots_for_host,
    port_sort_key,
)


start_host_screenshot_refresh_job = web_runtime_screenshot_jobs.start_host_screenshot_refresh_job
start_graph_screenshot_refresh_job = web_runtime_screenshot_jobs.start_graph_screenshot_refresh_job
run_host_screenshot_refresh = web_runtime_screenshot_jobs.run_host_screenshot_refresh
run_graph_screenshot_refresh = web_runtime_screenshot_jobs.run_graph_screenshot_refresh


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
