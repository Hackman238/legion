import json
import os
from typing import Any, Dict


def screenshot_metadata_path(screenshot_path: Any) -> str:
    token = str(screenshot_path or "").strip()
    if not token:
        return ""
    if token.lower().endswith(".json"):
        return token
    return f"{token}.json"


def build_screenshot_metadata(
        *,
        screenshot_path: Any,
        host_ip: Any,
        hostname: Any = "",
        port: Any = "",
        protocol: Any = "tcp",
        service_name: Any = "",
        target_url: Any = "",
        capture_engine: Any = "",
        capture_reason: Any = "",
        captured_at: Any = "",
        capture_returncode: Any = None,
) -> Dict[str, Any]:
    filename = os.path.basename(str(screenshot_path or "").strip())
    row: Dict[str, Any] = {
        "tool_id": "screenshooter",
        "artifact_type": "screenshot_metadata",
        "filename": filename[:200],
        "host_ip": str(host_ip or "").strip()[:80],
        "hostname": str(hostname or "").strip()[:160],
        "port": str(port or "").strip()[:20],
        "protocol": str(protocol or "tcp").strip().lower()[:12] or "tcp",
        "service_name": str(service_name or "").strip()[:64],
        "capture_engine": os.path.basename(str(capture_engine or "").strip())[:80],
        "capture_reason": str(capture_reason or "").strip()[:160],
        "captured_at": str(captured_at or "").strip()[:64],
    }
    normalized_target = str(target_url or "").strip()
    if normalized_target:
        row["target_url"] = normalized_target[:320]
    if capture_returncode not in (None, ""):
        try:
            row["capture_returncode"] = int(capture_returncode)
        except Exception:
            pass
    return row


def write_screenshot_metadata(screenshot_path: Any, metadata: Dict[str, Any]) -> str:
    path = screenshot_metadata_path(screenshot_path)
    if not path or not isinstance(metadata, dict) or not metadata:
        return ""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return path
    except Exception:
        return ""


def load_screenshot_metadata(path_or_screenshot: Any) -> Dict[str, Any]:
    path = screenshot_metadata_path(path_or_screenshot)
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def build_screenshot_state_row(
        *,
        screenshot_path: Any = "",
        artifact_ref: Any = "",
        metadata: Any = None,
        port: Any = "",
        protocol: Any = "tcp",
) -> Dict[str, Any]:
    details = metadata if isinstance(metadata, dict) else {}
    resolved_artifact_ref = str(artifact_ref or screenshot_path or "").strip()
    filename = str(details.get("filename", "") or os.path.basename(str(screenshot_path or artifact_ref or "").strip())).strip()
    if not resolved_artifact_ref and not filename:
        return {}

    row: Dict[str, Any] = {
        "artifact_ref": resolved_artifact_ref[:320],
        "filename": filename[:200],
        "port": str(details.get("port", "") or port or "").strip()[:20],
        "protocol": str(details.get("protocol", "") or protocol or "tcp").strip().lower()[:12] or "tcp",
        "source_kind": "observed",
        "observed": True,
    }
    optional_fields = {
        "target_url": 320,
        "capture_engine": 80,
        "capture_reason": 160,
        "captured_at": 64,
        "service_name": 64,
        "hostname": 160,
    }
    for field, limit in optional_fields.items():
        value = str(details.get(field, "") or "").strip()
        if value:
            row[field] = value[:limit]
    return row
