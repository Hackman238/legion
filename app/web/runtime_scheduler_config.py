from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import text

from app.scheduler.approvals import ensure_scheduler_approval_table, list_pending_approvals
from app.scheduler.audit import ensure_scheduler_audit_table
from app.scheduler.config import normalize_device_categories
from app.scheduler.insights import ensure_scheduler_ai_state_table
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
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
from app.web import runtime_scheduler_config_values as web_runtime_scheduler_config_values
from app.web import runtime_scheduler_policy_config as web_runtime_scheduler_policy_config


job_worker_count = web_runtime_scheduler_config_values.job_worker_count
normalize_project_report_headers = web_runtime_scheduler_config_values.normalize_project_report_headers
project_report_delivery_config = web_runtime_scheduler_config_values.project_report_delivery_config
scheduler_max_concurrency = web_runtime_scheduler_config_values.scheduler_max_concurrency
scheduler_max_host_concurrency = web_runtime_scheduler_config_values.scheduler_max_host_concurrency
scheduler_max_jobs = web_runtime_scheduler_config_values.scheduler_max_jobs
scheduler_feedback_config = web_runtime_scheduler_config_values.scheduler_feedback_config
is_host_scoped_scheduler_tool = web_runtime_scheduler_config_values.is_host_scoped_scheduler_tool
sanitize_provider_config = web_runtime_scheduler_config_values.sanitize_provider_config
sanitize_integration_config = web_runtime_scheduler_config_values.sanitize_integration_config
scheduler_integration_api_key = web_runtime_scheduler_config_values.scheduler_integration_api_key
shodan_integration_enabled = web_runtime_scheduler_config_values.shodan_integration_enabled
grayhatwarfare_integration_enabled = web_runtime_scheduler_config_values.grayhatwarfare_integration_enabled
device_category_options_for_runtime = web_runtime_scheduler_config_values.device_category_options_for_runtime
built_in_device_category_options = web_runtime_scheduler_config_values.built_in_device_category_options
scheduler_command_placeholders = web_runtime_scheduler_config_values.scheduler_command_placeholders
merge_engagement_policy_payload = web_runtime_scheduler_policy_config.merge_engagement_policy_payload
load_engagement_policy_locked = web_runtime_scheduler_policy_config.load_engagement_policy_locked
get_engagement_policy = web_runtime_scheduler_policy_config.get_engagement_policy
set_engagement_policy = web_runtime_scheduler_policy_config.set_engagement_policy


def get_scheduler_preferences(runtime) -> Dict[str, Any]:
    with runtime._lock:
        return scheduler_preferences(runtime)


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
