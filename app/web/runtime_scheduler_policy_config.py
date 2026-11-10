from __future__ import annotations

from typing import Any, Dict, Optional

from app.scheduler.policy import (
    VALID_ENGAGEMENT_PRESETS,
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    normalize_engagement_policy,
    upsert_project_engagement_policy,
)
from app.timing import getTimestamp


def merge_engagement_policy_payload(
        current_policy: Optional[Dict[str, Any]],
        updates: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    merged = dict(current_policy or {})
    incoming = dict(updates or {}) if isinstance(updates, dict) else {}
    named_preset = str(incoming.get("preset", "") or "").strip().lower()
    if named_preset in VALID_ENGAGEMENT_PRESETS and named_preset != "custom":
        # Choosing a standard preset means that preset: start from its defaults and apply only what came with
        # this update. Merging over the current policy kept earlier overrides (credential attacks allowed,
        # approvals off) under the name of a preset that does not allow them.
        return incoming
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
