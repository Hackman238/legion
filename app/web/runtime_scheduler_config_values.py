from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional

from app.device_categories import built_in_device_category_rules, device_category_options
from app.hostsfile import registrable_root_domain
from app.scheduler.orchestrator import DEFAULT_AI_FEEDBACK_CONFIG


def job_worker_count(preferences: Optional[Dict[str, Any]] = None) -> int:
    source = preferences if isinstance(preferences, dict) else {}
    try:
        value = int(source.get("max_concurrency", 1))
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, 8))


def normalize_project_report_headers(headers: Any) -> Dict[str, str]:
    source = headers
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except Exception:
            source = {}
    if not isinstance(source, dict):
        return {}
    normalized = {}
    for name, value in source.items():
        key = str(name or "").strip()
        if not key:
            continue
        normalized[key] = str(value or "")
    return normalized


def project_report_delivery_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    source = preferences if isinstance(preferences, dict) else {}
    raw = source.get("project_report_delivery", {})
    defaults = {
        "provider_name": "",
        "endpoint": "",
        "method": "POST",
        "format": "json",
        "headers": {},
        "timeout_seconds": 30,
        "mtls": {
            "enabled": False,
            "client_cert_path": "",
            "client_key_path": "",
            "ca_cert_path": "",
        },
    }
    if isinstance(raw, dict):
        defaults.update(raw)

    headers = normalize_project_report_headers(defaults.get("headers", {}))

    method = str(defaults.get("method", "POST") or "POST").strip().upper()
    if method not in {"POST", "PUT", "PATCH"}:
        method = "POST"

    report_format = str(defaults.get("format", "json") or "json").strip().lower()
    if report_format in {"markdown"}:
        report_format = "md"
    if report_format not in {"json", "md"}:
        report_format = "json"

    try:
        timeout_seconds = int(defaults.get("timeout_seconds", 30))
    except (TypeError, ValueError):
        timeout_seconds = 30
    timeout_seconds = max(5, min(timeout_seconds, 300))

    mtls_raw = defaults.get("mtls", {})
    if not isinstance(mtls_raw, dict):
        mtls_raw = {}

    return {
        "provider_name": str(defaults.get("provider_name", "") or ""),
        "endpoint": str(defaults.get("endpoint", "") or ""),
        "method": method,
        "format": report_format,
        "headers": headers,
        "timeout_seconds": int(timeout_seconds),
        "mtls": {
            "enabled": bool(mtls_raw.get("enabled", False)),
            "client_cert_path": str(mtls_raw.get("client_cert_path", "") or ""),
            "client_key_path": str(mtls_raw.get("client_key_path", "") or ""),
            "ca_cert_path": str(mtls_raw.get("ca_cert_path", "") or ""),
        },
    }


def scheduler_max_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
    source = preferences if isinstance(preferences, dict) else {}
    try:
        value = int(source.get("max_concurrency", 1))
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, 16))


def scheduler_max_host_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
    source = preferences if isinstance(preferences, dict) else {}
    try:
        value = int(source.get("max_host_concurrency", 1))
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, 8))


def scheduler_max_jobs(preferences: Optional[Dict[str, Any]] = None) -> int:
    source = preferences if isinstance(preferences, dict) else {}
    try:
        value = int(source.get("max_jobs", 200))
    except (TypeError, ValueError):
        value = 200
    return max(20, min(value, 2000))


def scheduler_feedback_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    merged = dict(DEFAULT_AI_FEEDBACK_CONFIG)
    source = preferences.get("ai_feedback", {}) if isinstance(preferences, dict) else {}
    if not isinstance(source, dict):
        source = {}

    if "enabled" in source:
        merged["enabled"] = bool(source.get("enabled"))

    for key in (
            "max_rounds_per_target",
            "max_actions_per_round",
            "recent_output_chars",
            "stall_rounds_without_progress",
            "stall_repeat_selection_threshold",
            "max_reflections_per_target",
    ):
        try:
            merged[key] = int(source.get(key, merged[key]))
        except (TypeError, ValueError):
            continue

    merged["reflection_enabled"] = bool(source.get("reflection_enabled", merged.get("reflection_enabled", True)))
    merged["max_rounds_per_target"] = max(1, min(int(merged["max_rounds_per_target"]), 12))
    merged["max_actions_per_round"] = max(1, min(int(merged["max_actions_per_round"]), 8))
    merged["recent_output_chars"] = max(320, min(int(merged["recent_output_chars"]), 4000))
    merged["stall_rounds_without_progress"] = max(1, min(int(merged["stall_rounds_without_progress"]), 6))
    merged["stall_repeat_selection_threshold"] = max(1, min(int(merged["stall_repeat_selection_threshold"]), 8))
    merged["max_reflections_per_target"] = max(0, min(int(merged["max_reflections_per_target"]), 4))
    return merged


def is_host_scoped_scheduler_tool(tool_id: str) -> bool:
    return str(tool_id or "").strip().lower() in {
        "subfinder",
        "grayhatwarfare",
        "shodan-enrichment",
        "responder",
        "ntlmrelayx",
    }


def sanitize_provider_config(provider_cfg: Dict[str, Any]) -> Dict[str, Any]:
    value = dict(provider_cfg)
    api_key = str(value.get("api_key", "") or "")
    value["api_key"] = ""
    value["api_key_configured"] = bool(api_key)
    return value


def sanitize_integration_config(integration_cfg: Dict[str, Any]) -> Dict[str, Any]:
    value = dict(integration_cfg)
    api_key = str(value.get("api_key", "") or "")
    value["api_key"] = ""
    value["api_key_configured"] = bool(api_key)
    return value


def scheduler_integration_api_key(
        integration_name: str,
        preferences: Optional[Dict[str, Any]] = None,
) -> str:
    config = preferences if isinstance(preferences, dict) else {}
    integrations = config.get("integrations", {}) if isinstance(config.get("integrations", {}), dict) else {}
    integration_cfg = integrations.get(str(integration_name or "").strip().lower(), {})
    if not isinstance(integration_cfg, dict):
        return ""
    return str(integration_cfg.get("api_key", "") or "").strip()


def shodan_integration_enabled(runtime, preferences: Optional[Dict[str, Any]] = None) -> bool:
    config = preferences if isinstance(preferences, dict) else runtime.scheduler_config.load()
    api_key = scheduler_integration_api_key("shodan", config)
    return bool(api_key and api_key.lower() not in {"yourkeygoeshere", "changeme"})


def grayhatwarfare_integration_enabled(runtime, preferences: Optional[Dict[str, Any]] = None) -> bool:
    config = preferences if isinstance(preferences, dict) else runtime.scheduler_config.load()
    api_key = scheduler_integration_api_key("grayhatwarfare", config)
    return bool(api_key and api_key.lower() not in {"yourkeygoeshere", "changeme"})


def device_category_options_for_runtime(runtime) -> List[Dict[str, Any]]:
    return device_category_options(runtime.scheduler_config.get_device_categories())


def built_in_device_category_options() -> List[Dict[str, Any]]:
    return [
        {"id": str(item.get("id", "") or ""), "name": str(item.get("name", "") or ""), "built_in": True}
        for item in built_in_device_category_rules()
    ]


def scheduler_command_placeholders(
        runtime,
        *,
        host_ip: str,
        hostname: str,
        preferences: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    config = preferences if isinstance(preferences, dict) else runtime.scheduler_config.load()
    root_domain = registrable_root_domain(str(hostname or "").strip()) or registrable_root_domain(str(host_ip or "").strip())
    return {
        "ROOT_DOMAIN": shlex.quote(root_domain) if root_domain else "",
        "GRAYHAT_API_KEY": shlex.quote(scheduler_integration_api_key("grayhatwarfare", config)),
        "SHODAN_API_KEY": shlex.quote(scheduler_integration_api_key("shodan", config)),
    }
