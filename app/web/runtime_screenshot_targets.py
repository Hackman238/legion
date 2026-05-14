from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from app.scheduler.planner import SchedulerPlanner
from app.screenshot_metadata import load_screenshot_metadata


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
