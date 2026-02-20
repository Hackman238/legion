import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.paths import ensure_legion_home, get_scheduler_config_path

DEFAULT_SCHEDULER_CONFIG = {
    "mode": "deterministic",
    "goal_profile": "internal_asset_discovery",
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
    "dangerous_categories": [
        "exploit_execution",
        "credential_bruteforce",
        "network_flooding",
        "destructive_write_actions",
    ],
    "preapproved_command_families": [],
    "ai_feedback": {
        "enabled": True,
        "max_rounds_per_target": 4,
        "max_actions_per_round": 4,
        "recent_output_chars": 900,
    },
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

    def get_dangerous_categories(self) -> List[str]:
        values = self.load().get("dangerous_categories", [])
        return [str(item) for item in values if item]

    def list_preapproved_families(self) -> List[Dict[str, Any]]:
        families = self.load().get("preapproved_command_families", [])
        return [dict(item) for item in families if isinstance(item, dict)]

    def is_family_preapproved(self, family_id: str) -> bool:
        if not family_id:
            return False
        for item in self.list_preapproved_families():
            if item.get("family_id") == family_id:
                return True
        return False

    def approve_family(self, family_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        if not family_id:
            return self.load()

        config = self.load()
        families = self.list_preapproved_families()
        for item in families:
            if item.get("family_id") == family_id:
                return config

        entry = {
            "family_id": family_id,
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "tool_id": metadata.get("tool_id", ""),
            "label": metadata.get("label", ""),
            "danger_categories": metadata.get("danger_categories", []),
            "approval_scope": "family",
        }
        families.append(entry)
        config["preapproved_command_families"] = families
        self.save(config)
        return self.load()

    @staticmethod
    def _normalize_config(raw: Dict[str, Any]) -> Dict[str, Any]:
        config = dict(DEFAULT_SCHEDULER_CONFIG)
        config.update({k: v for k, v in raw.items() if k in config})

        mode = str(config.get("mode", "deterministic")).strip().lower()
        if mode not in VALID_MODES:
            mode = "deterministic"
        config["mode"] = mode

        goal_profile = str(config.get("goal_profile", "internal_asset_discovery")).strip().lower()
        if goal_profile not in VALID_GOAL_PROFILES:
            goal_profile = "internal_asset_discovery"
        config["goal_profile"] = goal_profile

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
            providers["openai"] = openai_provider
        config["providers"] = providers

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
        }
        for key in ("max_rounds_per_target", "max_actions_per_round", "recent_output_chars"):
            try:
                feedback[key] = int(feedback_defaults.get(key, feedback[key]))
            except (TypeError, ValueError):
                continue
        feedback["max_rounds_per_target"] = max(1, min(int(feedback["max_rounds_per_target"]), 12))
        feedback["max_actions_per_round"] = max(1, min(int(feedback["max_actions_per_round"]), 8))
        feedback["recent_output_chars"] = max(320, min(int(feedback["recent_output_chars"]), 4000))
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
