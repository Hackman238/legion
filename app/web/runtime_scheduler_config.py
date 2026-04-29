from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.device_categories import built_in_device_category_rules, device_category_options
from app.hostsfile import registrable_root_domain
from app.scheduler.approvals import ensure_scheduler_approval_table, list_pending_approvals
from app.scheduler.audit import ensure_scheduler_audit_table
from app.scheduler.config import normalize_device_categories
from app.scheduler.insights import ensure_scheduler_ai_state_table
from app.scheduler.orchestrator import DEFAULT_AI_FEEDBACK_CONFIG
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    list_engagement_presets,
    normalize_engagement_policy,
    preset_from_legacy_goal_profile,
    upsert_project_engagement_policy,
)
from app.scheduler.providers import get_provider_logs, test_provider_connection
from app.scheduler.scan_history import ensure_scan_submission_table, list_scan_submissions
from app.settings import AppSettings, Settings
from app.timing import getTimestamp
from app.tooling import audit_legion_tools


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


def get_scheduler_preferences(runtime) -> Dict[str, Any]:
    with runtime._lock:
        return scheduler_preferences(runtime)


def merge_engagement_policy_payload(
        current_policy: Optional[Dict[str, Any]],
        updates: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    merged = dict(current_policy or {})
    incoming = dict(updates or {}) if isinstance(updates, dict) else {}
    if isinstance(merged.get("custom_overrides"), dict) and isinstance(incoming.get("custom_overrides"), dict):
        custom_overrides = dict(merged.get("custom_overrides", {}))
        custom_overrides.update(incoming.get("custom_overrides", {}))
        incoming["custom_overrides"] = custom_overrides
    merged.update(incoming)
    return merged


def load_engagement_policy_locked(runtime, *, persist_if_missing: bool = True) -> Dict[str, Any]:
    config = runtime.scheduler_config.load()
    fallback_policy = normalize_engagement_policy(
        config.get("engagement_policy", {}),
        fallback_goal_profile=str(config.get("goal_profile", "internal_asset_discovery") or "internal_asset_discovery"),
    )
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return fallback_policy.to_dict()

    ensure_scheduler_engagement_policy_table(project.database)
    stored = get_project_engagement_policy(project.database)
    if stored is None:
        payload = fallback_policy.to_dict()
        if persist_if_missing:
            upsert_project_engagement_policy(
                project.database,
                payload,
                updated_at=getTimestamp(True),
            )
        return payload

    normalized = normalize_engagement_policy(
        stored,
        fallback_goal_profile=fallback_policy.legacy_goal_profile,
    )
    return normalized.to_dict()


def get_engagement_policy(runtime) -> Dict[str, Any]:
    with runtime._lock:
        return load_engagement_policy_locked(runtime, persist_if_missing=True)


def set_engagement_policy(runtime, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with runtime._lock:
        current = load_engagement_policy_locked(runtime, persist_if_missing=True)
        merged = merge_engagement_policy_payload(current, updates)
        normalized_policy = normalize_engagement_policy(
            merged,
            fallback_goal_profile=str(current.get("legacy_goal_profile", current.get("goal_profile", "internal_asset_discovery")) or "internal_asset_discovery"),
        )
        runtime.scheduler_config.update_preferences({
            "engagement_policy": normalized_policy.to_dict(),
            "goal_profile": normalized_policy.legacy_goal_profile,
        })
        project = getattr(runtime.logic, "activeProject", None)
        if project:
            ensure_scheduler_engagement_policy_table(project.database)
            upsert_project_engagement_policy(
                project.database,
                normalized_policy.to_dict(),
                updated_at=getTimestamp(True),
            )
        return normalized_policy.to_dict()


def apply_scheduler_preferences(runtime, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with runtime._lock:
        normalized = dict(updates or {})
        policy_updates = normalized.get("engagement_policy") if isinstance(normalized.get("engagement_policy"), dict) else None
        if policy_updates is not None or "goal_profile" in normalized:
            current_policy = load_engagement_policy_locked(runtime, persist_if_missing=True)
            if policy_updates is not None:
                merged_policy = merge_engagement_policy_payload(current_policy, policy_updates)
            else:
                merged_policy = merge_engagement_policy_payload(
                    current_policy,
                    {"preset": preset_from_legacy_goal_profile(str(normalized.get("goal_profile", "") or ""))},
                )
            resolved_policy = normalize_engagement_policy(
                merged_policy,
                fallback_goal_profile=str(current_policy.get("legacy_goal_profile", current_policy.get("goal_profile", "internal_asset_discovery")) or "internal_asset_discovery"),
            )
            normalized["engagement_policy"] = resolved_policy.to_dict()
            normalized["goal_profile"] = resolved_policy.legacy_goal_profile
        saved = runtime.scheduler_config.update_preferences(normalized)
        if isinstance(saved.get("engagement_policy"), dict):
            project = getattr(runtime.logic, "activeProject", None)
            if project:
                ensure_scheduler_engagement_policy_table(project.database)
                upsert_project_engagement_policy(
                    project.database,
                    saved.get("engagement_policy", {}),
                    updated_at=getTimestamp(True),
                )

    requested_workers = job_worker_count(saved)
    requested_max_jobs = runtime._scheduler_max_jobs(saved)
    try:
        runtime.jobs.ensure_worker_count(requested_workers)
    except Exception:
        pass
    try:
        runtime.jobs.ensure_max_jobs(requested_max_jobs)
    except Exception:
        pass
    prefs = runtime.get_scheduler_preferences()
    runtime._emit_ui_invalidation("overview")
    return prefs


def test_scheduler_provider(runtime, updates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with runtime._lock:
        merged = runtime.scheduler_config.merge_preferences(updates or {})
    return test_provider_connection(merged)


def get_scheduler_provider_logs(runtime, limit: int = 200) -> List[Dict[str, Any]]:
    with runtime._lock:
        runtime._require_active_project()
    return get_provider_logs(limit=limit)


def get_scheduler_decisions(runtime, limit: int = 80) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return []

        ensure_scheduler_audit_table(project.database)
        session = project.database.session()
        try:
            result = session.execute(text(
                "SELECT id, timestamp, host_ip, port, protocol, service, scheduler_mode, goal_profile, "
                "engagement_preset, tool_id, label, command_family_id, danger_categories, risk_tags, "
                "requires_approval, policy_decision, policy_reason, risk_summary, safer_alternative, "
                "family_policy_state, approved, executed, reason, rationale, approval_id "
                "FROM scheduler_decision_log ORDER BY id DESC LIMIT :limit"
            ), {"limit": int(limit)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except Exception:
            return []
        finally:
            session.close()


def get_scheduler_approvals(
        runtime,
        limit: int = 200,
        status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_approval_table(project.database)
        return list_pending_approvals(project.database, limit=limit, status=status)


def scheduler_family_policy_metadata(runtime, item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tool_id": str(item.get("tool_id", "")),
        "label": str(item.get("label", "")),
        "danger_categories": runtime._split_csv(str(item.get("danger_categories", ""))),
        "risk_tags": runtime._split_csv(str(item.get("risk_tags", ""))),
        "approval_scope": "family",
    }


def apply_family_policy_action(
        runtime,
        item: Dict[str, Any],
        family_action: str,
        *,
        reason: str = "",
) -> str:
    action = str(family_action or "").strip().lower()
    if action == "allowed":
        runtime.scheduler_config.approve_family(
            str(item.get("command_family_id", "")),
            scheduler_family_policy_metadata(runtime, item),
        )
        return "allowed"
    if action == "approval_required":
        runtime.scheduler_config.require_family_approval(
            str(item.get("command_family_id", "")),
            scheduler_family_policy_metadata(runtime, item),
            reason=reason,
        )
        return "approval_required"
    if action == "suppressed":
        runtime.scheduler_config.suppress_family(
            str(item.get("command_family_id", "")),
            scheduler_family_policy_metadata(runtime, item),
            reason=reason,
        )
        return "suppressed"
    if action == "blocked":
        runtime.scheduler_config.block_family(
            str(item.get("command_family_id", "")),
            scheduler_family_policy_metadata(runtime, item),
            reason=reason,
        )
        return "blocked"
    return ""


def get_scan_history(runtime, limit: int = 200) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scan_submission_table(project.database)
        return list_scan_submissions(project.database, limit=limit)


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


def scheduler_preferences(runtime) -> Dict[str, Any]:
    config = runtime.scheduler_config.load()
    engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
    providers = config.get("providers", {})
    sanitized_providers = {}
    for name, provider_cfg in providers.items():
        sanitized_providers[name] = sanitize_provider_config(provider_cfg)
    integrations = config.get("integrations", {})
    sanitized_integrations = {}
    for name, integration_cfg in integrations.items():
        sanitized_integrations[name] = sanitize_integration_config(integration_cfg)
    return {
        "mode": config.get("mode", "deterministic"),
        "available_modes": ["deterministic", "ai"],
        "goal_profile": str(engagement_policy.get("legacy_goal_profile", config.get("goal_profile", "internal_asset_discovery"))),
        "goal_profiles": [
            {"id": "internal_asset_discovery", "name": "Internal Asset Discovery"},
            {"id": "external_pentest", "name": "External Pentest"},
        ],
        "engagement_policy": engagement_policy,
        "engagement_presets": list_engagement_presets(),
        "provider": config.get("provider", "none"),
        "max_concurrency": scheduler_max_concurrency(config),
        "max_host_concurrency": scheduler_max_host_concurrency(config),
        "max_jobs": scheduler_max_jobs(config),
        "job_workers": int(getattr(runtime.jobs, "worker_count", 1) or 1),
        "job_max": int(getattr(runtime.jobs, "max_jobs", 200) or 200),
        "providers": sanitized_providers,
        "integrations": sanitized_integrations,
        "device_categories": normalize_device_categories(config.get("device_categories", [])),
        "built_in_device_categories": list(runtime._built_in_device_category_options()),
        "feature_flags": runtime.scheduler_config.get_feature_flags(),
        "dangerous_categories": config.get("dangerous_categories", []),
        "preapproved_families_count": len(config.get("preapproved_command_families", [])),
        "ai_feedback": scheduler_feedback_config(config),
        "project_report_delivery": project_report_delivery_config(config),
        "secret_storage": runtime.scheduler_config.secret_storage_status(),
        "cloud_notice": config.get(
            "cloud_notice",
            "Cloud AI mode may send host/service metadata to third-party providers.",
        ),
    }


def ensure_scheduler_table(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    ensure_scheduler_audit_table(project.database)
    ensure_scheduler_ai_state_table(project.database)
    ensure_scheduler_engagement_policy_table(project.database)
    ensure_scan_submission_table(project.database)


def ensure_scheduler_approval_store(runtime):
    project = getattr(runtime.logic, "activeProject", None)
    if not project:
        return
    ensure_scheduler_approval_table(project.database)


def scheduler_tool_audit_snapshot(runtime) -> Dict[str, List[str]]:
    settings = getattr(runtime, "settings", None)
    if settings is None:
        settings = Settings(AppSettings())
    return runtime._tool_audit_availability(audit_legion_tools(settings))
