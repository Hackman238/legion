import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.paths import ensure_legion_home, get_scheduler_config_path
from app.scheduler.policy_engine import VALID_FAMILY_POLICY_STATES
from app.scheduler.policy import (
    legacy_goal_profile_from_policy,
    normalize_engagement_policy,
    preset_from_legacy_goal_profile,
)
from app.scheduler.runners import normalize_runner_settings

DEFAULT_FEATURE_FLAGS = {
    "graph_workspace": True,
    "optional_runners": True,
    "scheduler_prompt_profiles": True,
    "scheduler_web_followup_sidecar": False,
}
DEFAULT_DISABLED_TOOL_IDS = [
    "http-drupal-modules.nse",
    "http-vuln-zimbra-lfi.nse",
]
DEFAULT_TOOL_EXECUTION_PROFILES = {
    "nikto": {
        "quiet_long_running": True,
        "activity_timeout_seconds": 1800,
        "hard_timeout_seconds": 0,
    }
}


def normalize_feature_flags(raw: Any) -> Dict[str, bool]:
    source = raw if isinstance(raw, dict) else {}
    flags = dict(DEFAULT_FEATURE_FLAGS)
    for key in tuple(flags.keys()):
        if key in source:
            flags[key] = bool(source.get(key))
    return flags


def normalize_disabled_tool_ids(raw: Any) -> List[str]:
    values = raw if isinstance(raw, list) else DEFAULT_DISABLED_TOOL_IDS
    normalized = []
    seen = set()
    for item in list(values or []):
        token = str(item or "").strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        normalized.append(token)
    return normalized


def normalize_tool_execution_profiles(raw: Any) -> Dict[str, Dict[str, Any]]:
    source = raw if isinstance(raw, dict) else {}
    merged: Dict[str, Dict[str, Any]] = {
        str(tool_id): dict(profile)
        for tool_id, profile in DEFAULT_TOOL_EXECUTION_PROFILES.items()
        if isinstance(profile, dict)
    }
    for tool_id, profile in source.items():
        if not isinstance(profile, dict):
            continue
        token = str(tool_id or "").strip().lower()
        if not token:
            continue
        current = dict(merged.get(token, {}))
        current.update(profile)
        merged[token] = current

    normalized: Dict[str, Dict[str, Any]] = {}
    for tool_id, profile in merged.items():
        token = str(tool_id or "").strip().lower()
        if not token:
            continue
        quiet_long_running = bool(profile.get("quiet_long_running", False))
        try:
            activity_timeout = int(profile.get("activity_timeout_seconds", 0) or 0)
        except (TypeError, ValueError):
            activity_timeout = 0
        try:
            hard_timeout = int(profile.get("hard_timeout_seconds", 0) or 0)
        except (TypeError, ValueError):
            hard_timeout = 0

        if quiet_long_running:
            activity_timeout = max(30, min(activity_timeout or 1800, 86400))
        else:
            activity_timeout = 0
        hard_timeout = max(0, min(hard_timeout, 172800))

        normalized[token] = {
            "quiet_long_running": quiet_long_running,
            "activity_timeout_seconds": int(activity_timeout),
            "hard_timeout_seconds": int(hard_timeout),
        }
    return normalized


DEFAULT_SCHEDULER_CONFIG = {
    "mode": "deterministic",
    "goal_profile": "internal_asset_discovery",
    "engagement_policy": normalize_engagement_policy(
        {"preset": "internal_recon"},
        fallback_goal_profile="internal_asset_discovery",
    ).to_dict(),
    "provider": "none",
    "max_concurrency": 1,
    "max_jobs": 200,
    "providers": {
        "lm_studio": {
            "enabled": False,
            "base_url": "http://127.0.0.1:1234/v1",
            "model": "",
            "api_key": "",
        },
        "openai": {
            "enabled": False,
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4.1-mini",
            "api_key": "",
            "structured_outputs": False,
        },
        "claude": {
            "enabled": False,
            "base_url": "https://api.anthropic.com",
            "model": "",
            "api_key": "",
        },
    },
    "cloud_notice": (
        "Cloud AI mode may send host/service metadata to third-party providers."
    ),
    "feature_flags": normalize_feature_flags({}),
    "disabled_tool_ids": normalize_disabled_tool_ids(DEFAULT_DISABLED_TOOL_IDS),
    "tool_execution_profiles": normalize_tool_execution_profiles(DEFAULT_TOOL_EXECUTION_PROFILES),
    "dangerous_categories": [
        "exploit_execution",
        "credential_bruteforce",
        "network_flooding",
        "destructive_write_actions",
    ],
    "preapproved_command_families": [],
    "ai_feedback": {
        "enabled": True,
        "max_rounds_per_target": 5,
        "max_actions_per_round": 6,
        "recent_output_chars": 900,
        "reflection_enabled": True,
        "stall_rounds_without_progress": 2,
        "stall_repeat_selection_threshold": 2,
        "max_reflections_per_target": 1,
    },
    "runners": normalize_runner_settings({}),
    "project_report_delivery": {
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
    },
}

VALID_MODES = {"deterministic", "ai"}
VALID_GOAL_PROFILES = {"internal_asset_discovery", "external_pentest"}


def get_default_scheduler_config_path() -> str:
    ensure_legion_home()
    return get_scheduler_config_path("scheduler-ai.json")


class SchedulerConfigManager:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or get_default_scheduler_config_path()
        self._cache = None

    def load(self) -> Dict[str, Any]:
        if self._cache is not None:
            return self._cache

        if not os.path.exists(self.config_path):
            self._cache = self._normalize_config(dict(DEFAULT_SCHEDULER_CONFIG))
            self.save(self._cache)
            return self._cache

        try:
            with open(self.config_path, "r", encoding="utf-8") as handle:
                parsed = json.load(handle)
        except Exception:
            parsed = dict(DEFAULT_SCHEDULER_CONFIG)

        self._cache = self._normalize_config(parsed)
        self.save(self._cache)
        return self._cache

    def save(self, config: Dict[str, Any]):
        normalized = self._normalize_config(config)
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(normalized, handle, indent=2, sort_keys=True)
        self._cache = normalized

    def merge_preferences(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        current = self.load()
        merged = dict(current)
        for key, value in updates.items():
            if key == "providers" and isinstance(value, dict):
                providers = dict(merged.get("providers", {}))
                for provider_name, provider_config in value.items():
                    existing_provider = dict(providers.get(provider_name, {}))
                    if isinstance(provider_config, dict):
                        existing_provider.update(provider_config)
                    providers[provider_name] = existing_provider
                merged["providers"] = providers
            elif key == "project_report_delivery" and isinstance(value, dict):
                delivery = dict(merged.get("project_report_delivery", {}))
                for delivery_key, delivery_value in value.items():
                    if delivery_key == "headers" and isinstance(delivery_value, dict):
                        headers = dict(delivery.get("headers", {}))
                        headers.update(delivery_value)
                        delivery["headers"] = headers
                    elif delivery_key == "mtls" and isinstance(delivery_value, dict):
                        mtls = dict(delivery.get("mtls", {}))
                        mtls.update(delivery_value)
                        delivery["mtls"] = mtls
                    else:
                        delivery[delivery_key] = delivery_value
                merged["project_report_delivery"] = delivery
            elif key == "feature_flags" and isinstance(value, dict):
                feature_flags = normalize_feature_flags(merged.get("feature_flags", {}))
                for flag_name, flag_value in value.items():
                    if flag_name not in DEFAULT_FEATURE_FLAGS:
                        continue
                    feature_flags[flag_name] = bool(flag_value)
                merged["feature_flags"] = feature_flags
            elif key == "tool_execution_profiles" and isinstance(value, dict):
                profiles = normalize_tool_execution_profiles(merged.get("tool_execution_profiles", {}))
                for tool_id, profile in value.items():
                    token = str(tool_id or "").strip().lower()
                    if not token or not isinstance(profile, dict):
                        continue
                    merged_profile = dict(profiles.get(token, {}))
                    merged_profile.update(profile)
                    profiles[token] = merged_profile
                merged["tool_execution_profiles"] = normalize_tool_execution_profiles(profiles)
            elif key == "engagement_policy" and isinstance(value, dict):
                policy = dict(merged.get("engagement_policy", {}))
                for policy_key, policy_value in value.items():
                    if policy_key == "custom_overrides" and isinstance(policy_value, dict):
                        overrides = dict(policy.get("custom_overrides", {}))
                        overrides.update(policy_value)
                        policy["custom_overrides"] = overrides
                    else:
                        policy[policy_key] = policy_value
                merged["engagement_policy"] = policy
            elif key == "runners" and isinstance(value, dict):
                runners = normalize_runner_settings(merged.get("runners", {}))
                for runner_name, runner_config in value.items():
                    if not isinstance(runner_config, dict):
                        continue
                    merged_runner = dict(runners.get(runner_name, {}))
                    merged_runner.update(runner_config)
                    runners[runner_name] = merged_runner
                merged["runners"] = runners
            elif key == "goal_profile":
                merged["goal_profile"] = value
                policy = dict(merged.get("engagement_policy", {}))
                policy["preset"] = preset_from_legacy_goal_profile(str(value or ""))
                merged["engagement_policy"] = policy
            else:
                merged[key] = value
        return self._normalize_config(merged)

    def update_preferences(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self.merge_preferences(updates)
        self.save(normalized)
        return self.load()

    def get_mode(self) -> str:
        return self.load().get("mode", "deterministic")

    def get_goal_profile(self) -> str:
        return self.load().get("goal_profile", "internal_asset_discovery")

    def get_engagement_policy(self) -> Dict[str, Any]:
        return dict(self.load().get("engagement_policy", {}))

    def get_feature_flags(self) -> Dict[str, bool]:
        return dict(self.load().get("feature_flags", {}))

    def is_feature_enabled(self, feature_name: str, default: bool = True) -> bool:
        feature_key = str(feature_name or "").strip()
        if not feature_key:
            return bool(default)
        flags = self.get_feature_flags()
        if feature_key not in DEFAULT_FEATURE_FLAGS:
            return bool(default)
        return bool(flags.get(feature_key, DEFAULT_FEATURE_FLAGS[feature_key]))

    def get_dangerous_categories(self) -> List[str]:
        values = self.load().get("dangerous_categories", [])
        return [str(item) for item in values if item]

    def get_disabled_tool_ids(self) -> List[str]:
        return normalize_disabled_tool_ids(self.load().get("disabled_tool_ids", []))

    def list_preapproved_families(self) -> List[Dict[str, Any]]:
        return [
            dict(item)
            for item in self.list_family_policies()
            if str(item.get("policy_state", "allowed")).strip().lower() == "allowed"
        ]

    def list_family_policies(self) -> List[Dict[str, Any]]:
        families = self.load().get("preapproved_command_families", [])
        return [dict(item) for item in families if isinstance(item, dict)]

    def is_family_preapproved(self, family_id: str) -> bool:
        return self.get_family_policy_state(family_id) == "allowed"

    def get_family_policy(self, family_id: str) -> Dict[str, Any]:
        family_key = str(family_id or "").strip()
        if not family_key:
            return {}
        for item in self.list_family_policies():
            if item.get("family_id") == family_key:
                return dict(item)
        return {}

    def get_family_policy_state(self, family_id: str) -> str:
        policy = self.get_family_policy(family_id)
        state = str(policy.get("policy_state", "") or "").strip().lower()
        if state not in VALID_FAMILY_POLICY_STATES:
            return ""
        return state

    def set_family_policy(
            self,
            family_id: str,
            metadata: Dict[str, Any],
            policy_state: str,
            *,
            reason: str = "",
    ) -> Dict[str, Any]:
        family_key = str(family_id or "").strip()
        normalized_state = str(policy_state or "").strip().lower()
        if not family_key or normalized_state not in VALID_FAMILY_POLICY_STATES:
            return self.load()

        config = self.load()
        families = self.list_family_policies()
        entry = {
            "family_id": family_key,
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "tool_id": str(metadata.get("tool_id", "")),
            "label": str(metadata.get("label", "")),
            "danger_categories": metadata.get("danger_categories", []),
            "approval_scope": str(metadata.get("approval_scope", "family")),
            "policy_state": normalized_state,
            "risk_tags": metadata.get("risk_tags", []),
            "reason": str(reason or metadata.get("reason", "")),
        }

        replaced = False
        for index, item in enumerate(families):
            if item.get("family_id") != family_key:
                continue
            merged = dict(item)
            merged.update(entry)
            families[index] = merged
            replaced = True
            break
        if not replaced:
            families.append(entry)

        config["preapproved_command_families"] = families
        self.save(config)
        return self.load()

    def approve_family(self, family_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return self.set_family_policy(family_id, metadata, "allowed")

    def require_family_approval(self, family_id: str, metadata: Dict[str, Any], *, reason: str = "") -> Dict[str, Any]:
        return self.set_family_policy(family_id, metadata, "approval_required", reason=reason)

    def suppress_family(self, family_id: str, metadata: Dict[str, Any], *, reason: str = "") -> Dict[str, Any]:
        return self.set_family_policy(family_id, metadata, "suppressed", reason=reason)

    def block_family(self, family_id: str, metadata: Dict[str, Any], *, reason: str = "") -> Dict[str, Any]:
        return self.set_family_policy(family_id, metadata, "blocked", reason=reason)

    @staticmethod
    def _normalize_config(raw: Dict[str, Any]) -> Dict[str, Any]:
        config = dict(DEFAULT_SCHEDULER_CONFIG)
        config.update({k: v for k, v in raw.items() if k in config})

        mode = str(config.get("mode", "deterministic")).strip().lower()
        if mode not in VALID_MODES:
            mode = "deterministic"
        config["mode"] = mode

        goal_profile = str(raw.get("goal_profile", config.get("goal_profile", "internal_asset_discovery"))).strip().lower()
        if goal_profile not in VALID_GOAL_PROFILES:
            goal_profile = "internal_asset_discovery"

        policy_input = raw.get("engagement_policy", config.get("engagement_policy", {}))
        normalized_policy = normalize_engagement_policy(
            policy_input,
            fallback_goal_profile=goal_profile,
        )
        config["engagement_policy"] = normalized_policy.to_dict()
        config["goal_profile"] = legacy_goal_profile_from_policy(
            normalized_policy.preset,
            scope=normalized_policy.scope,
            intent=normalized_policy.intent,
        )

        provider = str(config.get("provider", "none")).strip().lower()
        config["provider"] = provider

        try:
            max_concurrency = int(raw.get("max_concurrency", config.get("max_concurrency", 1)))
        except (TypeError, ValueError):
            max_concurrency = 1
        config["max_concurrency"] = max(1, min(max_concurrency, 16))

        try:
            max_jobs = int(raw.get("max_jobs", config.get("max_jobs", 200)))
        except (TypeError, ValueError):
            max_jobs = 200
        config["max_jobs"] = max(20, min(max_jobs, 2000))

        providers = dict(DEFAULT_SCHEDULER_CONFIG["providers"])
        user_providers = raw.get("providers", {}) if isinstance(raw, dict) else {}
        if isinstance(user_providers, dict):
            for provider_name, provider_cfg in user_providers.items():
                existing = dict(providers.get(provider_name, {}))
                if isinstance(provider_cfg, dict):
                    existing.update(provider_cfg)
                providers[provider_name] = existing

        openai_provider = providers.get("openai", {})
        if isinstance(openai_provider, dict):
            model_value = str(openai_provider.get("model", "")).strip()
            if not model_value:
                openai_provider["model"] = str(DEFAULT_SCHEDULER_CONFIG["providers"]["openai"]["model"])
            openai_provider["structured_outputs"] = bool(openai_provider.get("structured_outputs", False))
            providers["openai"] = openai_provider
        config["providers"] = providers
        config["feature_flags"] = normalize_feature_flags(raw.get("feature_flags", config.get("feature_flags", {})))
        config["runners"] = normalize_runner_settings(raw.get("runners", config.get("runners", {})))
        config["disabled_tool_ids"] = normalize_disabled_tool_ids(
            raw.get("disabled_tool_ids", config.get("disabled_tool_ids", DEFAULT_DISABLED_TOOL_IDS))
        )
        config["tool_execution_profiles"] = normalize_tool_execution_profiles(
            raw.get("tool_execution_profiles", config.get("tool_execution_profiles", DEFAULT_TOOL_EXECUTION_PROFILES))
        )

        dangerous_categories = raw.get("dangerous_categories", config["dangerous_categories"])
        if not isinstance(dangerous_categories, list):
            dangerous_categories = list(DEFAULT_SCHEDULER_CONFIG["dangerous_categories"])
        config["dangerous_categories"] = [str(item) for item in dangerous_categories if item]

        families = raw.get("preapproved_command_families", [])
        if not isinstance(families, list):
            families = []
        normalized_families = []
        for item in families:
            if not isinstance(item, dict):
                continue
            family_id = str(item.get("family_id", "")).strip()
            if not family_id:
                continue
            normalized_families.append({
                "family_id": family_id,
                "approved_at": str(item.get("approved_at", "")),
                "tool_id": str(item.get("tool_id", "")),
                "label": str(item.get("label", "")),
                "danger_categories": item.get("danger_categories", []),
                "approval_scope": str(item.get("approval_scope", "family")),
                "policy_state": (
                    str(item.get("policy_state", "allowed")).strip().lower()
                    if str(item.get("policy_state", "allowed")).strip().lower() in VALID_FAMILY_POLICY_STATES
                    else "allowed"
                ),
                "risk_tags": item.get("risk_tags", []),
                "reason": str(item.get("reason", "")),
            })
        config["preapproved_command_families"] = normalized_families

        feedback_defaults = dict(DEFAULT_SCHEDULER_CONFIG["ai_feedback"])
        feedback_raw = raw.get("ai_feedback", {})
        if isinstance(feedback_raw, dict):
            feedback_defaults.update(feedback_raw)

        feedback = {
            "enabled": bool(feedback_defaults.get("enabled", True)),
            "max_rounds_per_target": 4,
            "max_actions_per_round": 2,
            "recent_output_chars": 900,
            "reflection_enabled": bool(feedback_defaults.get("reflection_enabled", True)),
            "stall_rounds_without_progress": 2,
            "stall_repeat_selection_threshold": 2,
            "max_reflections_per_target": 1,
        }
        for key in (
                "max_rounds_per_target",
                "max_actions_per_round",
                "recent_output_chars",
                "stall_rounds_without_progress",
                "stall_repeat_selection_threshold",
                "max_reflections_per_target",
        ):
            try:
                feedback[key] = int(feedback_defaults.get(key, feedback[key]))
            except (TypeError, ValueError):
                continue
        feedback["max_rounds_per_target"] = max(1, min(int(feedback["max_rounds_per_target"]), 12))
        feedback["max_actions_per_round"] = max(1, min(int(feedback["max_actions_per_round"]), 8))
        feedback["recent_output_chars"] = max(320, min(int(feedback["recent_output_chars"]), 4000))
        feedback["stall_rounds_without_progress"] = max(1, min(int(feedback["stall_rounds_without_progress"]), 6))
        feedback["stall_repeat_selection_threshold"] = max(1, min(int(feedback["stall_repeat_selection_threshold"]), 8))
        feedback["max_reflections_per_target"] = max(0, min(int(feedback["max_reflections_per_target"]), 4))
        config["ai_feedback"] = feedback

        delivery_defaults = dict(DEFAULT_SCHEDULER_CONFIG["project_report_delivery"])
        delivery_raw = raw.get("project_report_delivery", {})
        if isinstance(delivery_raw, dict):
            delivery_defaults.update(delivery_raw)

        delivery_method = str(delivery_defaults.get("method", "POST")).strip().upper()
        if delivery_method not in {"POST", "PUT", "PATCH"}:
            delivery_method = "POST"

        delivery_format = str(delivery_defaults.get("format", "json")).strip().lower()
        if delivery_format in {"markdown"}:
            delivery_format = "md"
        if delivery_format not in {"json", "md"}:
            delivery_format = "json"

        headers_raw = delivery_defaults.get("headers", {})
        if isinstance(headers_raw, str):
            try:
                parsed_headers = json.loads(headers_raw)
            except Exception:
                parsed_headers = {}
            headers_raw = parsed_headers
        if not isinstance(headers_raw, dict):
            headers_raw = {}
        delivery_headers = {}
        for header_name, header_value in headers_raw.items():
            label = str(header_name or "").strip()
            if not label:
                continue
            delivery_headers[label] = str(header_value or "")

        try:
            timeout_seconds = int(delivery_defaults.get("timeout_seconds", 30))
        except (TypeError, ValueError):
            timeout_seconds = 30
        timeout_seconds = max(5, min(timeout_seconds, 300))

        mtls_defaults = dict(DEFAULT_SCHEDULER_CONFIG["project_report_delivery"]["mtls"])
        mtls_raw = delivery_defaults.get("mtls", {})
        if isinstance(mtls_raw, dict):
            mtls_defaults.update(mtls_raw)
        delivery_mtls = {
            "enabled": bool(mtls_defaults.get("enabled", False)),
            "client_cert_path": str(mtls_defaults.get("client_cert_path", "") or ""),
            "client_key_path": str(mtls_defaults.get("client_key_path", "") or ""),
            "ca_cert_path": str(mtls_defaults.get("ca_cert_path", "") or ""),
        }

        config["project_report_delivery"] = {
            "provider_name": str(delivery_defaults.get("provider_name", "") or ""),
            "endpoint": str(delivery_defaults.get("endpoint", "") or ""),
            "method": delivery_method,
            "format": delivery_format,
            "headers": delivery_headers,
            "timeout_seconds": int(timeout_seconds),
            "mtls": delivery_mtls,
        }
        return config
