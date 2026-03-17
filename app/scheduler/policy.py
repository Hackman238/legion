import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from sqlalchemy import text


VALID_ENGAGEMENT_PRESETS = {
    "external_recon",
    "external_pentest",
    "internal_recon",
    "internal_pentest",
    "custom",
}
VALID_SCOPE = {"internal", "external", "mixed"}
VALID_INTENT = {"recon", "pentest"}
VALID_RISK_MODE = {"blocked", "approval", "allowed"}
VALID_DETECTION_RISK_MODE = {"low", "medium", "high"}
VALID_APPROVAL_MODE = {"never", "risky", "always"}
VALID_RUNNER_PREFERENCE = {"local", "container", "browser", "manual", "auto"}
VALID_NOISE_BUDGET = {"low", "medium", "high"}

ENGAGEMENT_PRESET_LABELS = {
    "external_recon": "External Recon",
    "external_pentest": "External Pentest",
    "internal_recon": "Internal Recon",
    "internal_pentest": "Internal Pentest",
    "custom": "Custom",
}

LEGACY_GOAL_TO_PRESET = {
    "internal_asset_discovery": "internal_recon",
    "external_pentest": "external_pentest",
    "internal_recon": "internal_recon",
    "external_recon": "external_recon",
    "internal_pentest": "internal_pentest",
    "custom": "custom",
}

PRESET_DEFAULTS = {
    "external_recon": {
        "scope": "external",
        "intent": "recon",
        "allow_exploitation": False,
        "allow_lateral_movement": False,
        "credential_attack_mode": "blocked",
        "lockout_risk_mode": "blocked",
        "stability_risk_mode": "approval",
        "detection_risk_mode": "low",
        "approval_mode": "risky",
        "runner_preference": "local",
        "noise_budget": "low",
    },
    "external_pentest": {
        "scope": "external",
        "intent": "pentest",
        "allow_exploitation": True,
        "allow_lateral_movement": False,
        "credential_attack_mode": "approval",
        "lockout_risk_mode": "approval",
        "stability_risk_mode": "approval",
        "detection_risk_mode": "medium",
        "approval_mode": "risky",
        "runner_preference": "local",
        "noise_budget": "medium",
    },
    "internal_recon": {
        "scope": "internal",
        "intent": "recon",
        "allow_exploitation": False,
        "allow_lateral_movement": False,
        "credential_attack_mode": "blocked",
        "lockout_risk_mode": "blocked",
        "stability_risk_mode": "approval",
        "detection_risk_mode": "low",
        "approval_mode": "risky",
        "runner_preference": "local",
        "noise_budget": "low",
    },
    "internal_pentest": {
        "scope": "internal",
        "intent": "pentest",
        "allow_exploitation": True,
        "allow_lateral_movement": True,
        "credential_attack_mode": "approval",
        "lockout_risk_mode": "approval",
        "stability_risk_mode": "approval",
        "detection_risk_mode": "medium",
        "approval_mode": "risky",
        "runner_preference": "local",
        "noise_budget": "medium",
    },
}


def _normalize_text(value: Any, *, default: str = "") -> str:
    text_value = str(value or "").strip().lower()
    return text_value or str(default or "").strip().lower()


def _normalize_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    text_value = str(value).strip().lower()
    if text_value in {"1", "true", "yes", "on"}:
        return True
    if text_value in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _normalize_choice(value: Any, valid_values: set, *, default: str) -> str:
    normalized = _normalize_text(value, default=default)
    if normalized not in valid_values:
        return str(default)
    return normalized


def _normalize_custom_overrides(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items() if str(key).strip()}


def preset_from_legacy_goal_profile(goal_profile: str) -> str:
    normalized = _normalize_text(goal_profile, default="internal_asset_discovery")
    return LEGACY_GOAL_TO_PRESET.get(normalized, "internal_recon")


def legacy_goal_profile_from_policy(
        preset: str,
        *,
        scope: str = "internal",
        intent: str = "recon",
) -> str:
    normalized_preset = _normalize_choice(preset, VALID_ENGAGEMENT_PRESETS, default="internal_recon")
    if normalized_preset in {"external_recon", "external_pentest"}:
        return "external_pentest"
    if normalized_preset in {"internal_recon", "internal_pentest"}:
        return "internal_asset_discovery"
    if _normalize_text(scope, default="internal") == "external":
        return "external_pentest"
    if _normalize_text(intent, default="recon") == "pentest" and _normalize_text(scope, default="internal") == "external":
        return "external_pentest"
    return "internal_asset_discovery"


def list_engagement_presets() -> list:
    return [
        {"id": preset_id, "name": ENGAGEMENT_PRESET_LABELS.get(preset_id, preset_id.replace("_", " ").title())}
        for preset_id in ("external_recon", "external_pentest", "internal_recon", "internal_pentest", "custom")
    ]


@dataclass(frozen=True)
class EngagementPolicy:
    preset: str
    scope: str
    intent: str
    allow_exploitation: bool
    allow_lateral_movement: bool
    credential_attack_mode: str
    lockout_risk_mode: str
    stability_risk_mode: str
    detection_risk_mode: str
    approval_mode: str
    runner_preference: str
    noise_budget: str
    custom_overrides: Dict[str, Any] = field(default_factory=dict)

    @property
    def preset_label(self) -> str:
        return ENGAGEMENT_PRESET_LABELS.get(self.preset, self.preset.replace("_", " ").title())

    @property
    def legacy_goal_profile(self) -> str:
        return legacy_goal_profile_from_policy(
            self.preset,
            scope=self.scope,
            intent=self.intent,
        )

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["preset_label"] = self.preset_label
        payload["legacy_goal_profile"] = self.legacy_goal_profile
        return payload


def normalize_engagement_policy(
        raw: Optional[Dict[str, Any]] = None,
        *,
        fallback_goal_profile: str = "internal_asset_discovery",
) -> EngagementPolicy:
    source = dict(raw or {}) if isinstance(raw, dict) else {}
    fallback_preset = preset_from_legacy_goal_profile(fallback_goal_profile)
    requested_preset = _normalize_text(source.get("preset"), default="")
    if requested_preset not in VALID_ENGAGEMENT_PRESETS:
        requested_preset = preset_from_legacy_goal_profile(
            str(source.get("goal_profile", "") or fallback_goal_profile)
        )
    base_preset = fallback_preset if requested_preset == "custom" else requested_preset
    base = dict(PRESET_DEFAULTS.get(base_preset, PRESET_DEFAULTS["internal_recon"]))

    scope = _normalize_choice(source.get("scope", base.get("scope")), VALID_SCOPE, default=base["scope"])
    intent = _normalize_choice(source.get("intent", base.get("intent")), VALID_INTENT, default=base["intent"])

    return EngagementPolicy(
        preset=_normalize_choice(requested_preset, VALID_ENGAGEMENT_PRESETS, default=fallback_preset),
        scope=scope,
        intent=intent,
        allow_exploitation=_normalize_bool(
            source.get("allow_exploitation", base.get("allow_exploitation")),
            default=bool(base.get("allow_exploitation", False)),
        ),
        allow_lateral_movement=_normalize_bool(
            source.get("allow_lateral_movement", base.get("allow_lateral_movement")),
            default=bool(base.get("allow_lateral_movement", False)),
        ),
        credential_attack_mode=_normalize_choice(
            source.get("credential_attack_mode", base.get("credential_attack_mode")),
            VALID_RISK_MODE,
            default=base["credential_attack_mode"],
        ),
        lockout_risk_mode=_normalize_choice(
            source.get("lockout_risk_mode", base.get("lockout_risk_mode")),
            VALID_RISK_MODE,
            default=base["lockout_risk_mode"],
        ),
        stability_risk_mode=_normalize_choice(
            source.get("stability_risk_mode", base.get("stability_risk_mode")),
            VALID_RISK_MODE,
            default=base["stability_risk_mode"],
        ),
        detection_risk_mode=_normalize_choice(
            source.get("detection_risk_mode", base.get("detection_risk_mode")),
            VALID_DETECTION_RISK_MODE,
            default=base["detection_risk_mode"],
        ),
        approval_mode=_normalize_choice(
            source.get("approval_mode", base.get("approval_mode")),
            VALID_APPROVAL_MODE,
            default=base["approval_mode"],
        ),
        runner_preference=_normalize_choice(
            source.get("runner_preference", base.get("runner_preference")),
            VALID_RUNNER_PREFERENCE,
            default=base["runner_preference"],
        ),
        noise_budget=_normalize_choice(
            source.get("noise_budget", base.get("noise_budget")),
            VALID_NOISE_BUDGET,
            default=base["noise_budget"],
        ),
        custom_overrides=_normalize_custom_overrides(source.get("custom_overrides")),
    )


def _ensure_column(session, table_name: str, column_name: str, column_type: str):
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if column_name in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _ensure_table(session):
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS scheduler_engagement_policy ("
        "policy_id INTEGER PRIMARY KEY,"
        "preset TEXT,"
        "scope TEXT,"
        "intent TEXT,"
        "allow_exploitation TEXT,"
        "allow_lateral_movement TEXT,"
        "credential_attack_mode TEXT,"
        "lockout_risk_mode TEXT,"
        "stability_risk_mode TEXT,"
        "detection_risk_mode TEXT,"
        "approval_mode TEXT,"
        "runner_preference TEXT,"
        "noise_budget TEXT,"
        "custom_overrides_json TEXT,"
        "updated_at TEXT,"
        "derived_from_goal_profile TEXT"
        ")"
    ))
    for column_name, column_type in (
            ("preset", "TEXT"),
            ("scope", "TEXT"),
            ("intent", "TEXT"),
            ("allow_exploitation", "TEXT"),
            ("allow_lateral_movement", "TEXT"),
            ("credential_attack_mode", "TEXT"),
            ("lockout_risk_mode", "TEXT"),
            ("stability_risk_mode", "TEXT"),
            ("detection_risk_mode", "TEXT"),
            ("approval_mode", "TEXT"),
            ("runner_preference", "TEXT"),
            ("noise_budget", "TEXT"),
            ("custom_overrides_json", "TEXT"),
            ("updated_at", "TEXT"),
            ("derived_from_goal_profile", "TEXT"),
    ):
        _ensure_column(session, "scheduler_engagement_policy", column_name, column_type)


def ensure_scheduler_engagement_policy_table(database):
    session = database.session()
    try:
        _ensure_table(session)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def get_project_engagement_policy(database) -> Optional[Dict[str, Any]]:
    session = database.session()
    try:
        _ensure_table(session)
        result = session.execute(text(
            "SELECT preset, scope, intent, allow_exploitation, allow_lateral_movement, "
            "credential_attack_mode, lockout_risk_mode, stability_risk_mode, detection_risk_mode, "
            "approval_mode, runner_preference, noise_budget, custom_overrides_json, updated_at, "
            "derived_from_goal_profile "
            "FROM scheduler_engagement_policy WHERE policy_id = 1 LIMIT 1"
        ))
        row = result.fetchone()
        if row is None:
            return None
        keys = list(result.keys())
        payload = dict(zip(keys, row))
        try:
            payload["custom_overrides"] = json.loads(str(payload.get("custom_overrides_json", "") or "{}"))
        except Exception:
            payload["custom_overrides"] = {}
        return payload
    finally:
        session.close()


def upsert_project_engagement_policy(
        database,
        policy: Any,
        *,
        updated_at: str = "",
) -> Dict[str, Any]:
    normalized = policy if isinstance(policy, EngagementPolicy) else normalize_engagement_policy(policy or {})
    payload = normalized.to_dict()
    row = {
        "policy_id": 1,
        "preset": payload["preset"],
        "scope": payload["scope"],
        "intent": payload["intent"],
        "allow_exploitation": "True" if payload["allow_exploitation"] else "False",
        "allow_lateral_movement": "True" if payload["allow_lateral_movement"] else "False",
        "credential_attack_mode": payload["credential_attack_mode"],
        "lockout_risk_mode": payload["lockout_risk_mode"],
        "stability_risk_mode": payload["stability_risk_mode"],
        "detection_risk_mode": payload["detection_risk_mode"],
        "approval_mode": payload["approval_mode"],
        "runner_preference": payload["runner_preference"],
        "noise_budget": payload["noise_budget"],
        "custom_overrides_json": json.dumps(payload.get("custom_overrides", {}), sort_keys=True),
        "updated_at": str(updated_at or ""),
        "derived_from_goal_profile": payload["legacy_goal_profile"],
    }
    session = database.session()
    try:
        _ensure_table(session)
        existing = session.execute(text(
            "SELECT policy_id FROM scheduler_engagement_policy WHERE policy_id = 1 LIMIT 1"
        )).fetchone()
        if existing is None:
            session.execute(text(
                "INSERT INTO scheduler_engagement_policy ("
                "policy_id, preset, scope, intent, allow_exploitation, allow_lateral_movement, "
                "credential_attack_mode, lockout_risk_mode, stability_risk_mode, detection_risk_mode, "
                "approval_mode, runner_preference, noise_budget, custom_overrides_json, updated_at, "
                "derived_from_goal_profile"
                ") VALUES ("
                ":policy_id, :preset, :scope, :intent, :allow_exploitation, :allow_lateral_movement, "
                ":credential_attack_mode, :lockout_risk_mode, :stability_risk_mode, :detection_risk_mode, "
                ":approval_mode, :runner_preference, :noise_budget, :custom_overrides_json, :updated_at, "
                ":derived_from_goal_profile"
                ")"
            ), row)
        else:
            session.execute(text(
                "UPDATE scheduler_engagement_policy SET "
                "preset = :preset, "
                "scope = :scope, "
                "intent = :intent, "
                "allow_exploitation = :allow_exploitation, "
                "allow_lateral_movement = :allow_lateral_movement, "
                "credential_attack_mode = :credential_attack_mode, "
                "lockout_risk_mode = :lockout_risk_mode, "
                "stability_risk_mode = :stability_risk_mode, "
                "detection_risk_mode = :detection_risk_mode, "
                "approval_mode = :approval_mode, "
                "runner_preference = :runner_preference, "
                "noise_budget = :noise_budget, "
                "custom_overrides_json = :custom_overrides_json, "
                "updated_at = :updated_at, "
                "derived_from_goal_profile = :derived_from_goal_profile "
                "WHERE policy_id = :policy_id"
            ), row)
        session.commit()
        return payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
