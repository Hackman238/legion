from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from app.scheduler.policy import EngagementPolicy, normalize_engagement_policy
from app.scheduler.risk import (
    normalize_risk_tags,
    risk_tags_to_legacy_categories,
    safer_alternative_for_risk_tags,
    summarize_risk_tags,
)


VALID_POLICY_DECISIONS = {"allowed", "approval_required", "blocked"}
VALID_FAMILY_POLICY_STATES = {"allowed", "approval_required", "suppressed", "blocked"}


def _normalize_text(value) -> str:
    return str(value or "").strip().lower()


def _normalize_family_policy_state(value: str) -> str:
    normalized = _normalize_text(value)
    if normalized in VALID_FAMILY_POLICY_STATES:
        return normalized
    return ""


def _risk_mode_to_decision(value: str) -> str:
    normalized = _normalize_text(value)
    if normalized == "approval":
        return "approval_required"
    if normalized in {"allowed", "blocked"}:
        return normalized
    return "allowed"


@dataclass(frozen=True)
class PolicyDecision:
    state: str
    risk_tags: List[str] = field(default_factory=list)
    legacy_danger_categories: List[str] = field(default_factory=list)
    reason: str = ""
    risk_summary: str = ""
    safer_alternative: str = ""
    family_policy_state: str = ""

    @property
    def requires_approval(self) -> bool:
        return self.state == "approval_required"

    @property
    def is_blocked(self) -> bool:
        return self.state == "blocked"

    def to_dict(self):
        return {
            "state": self.state,
            "risk_tags": list(self.risk_tags),
            "legacy_danger_categories": list(self.legacy_danger_categories),
            "reason": self.reason,
            "risk_summary": self.risk_summary,
            "safer_alternative": self.safer_alternative,
            "family_policy_state": self.family_policy_state,
        }


def _decision_rank(state: str) -> int:
    normalized = _normalize_text(state)
    if normalized == "blocked":
        return 3
    if normalized == "approval_required":
        return 2
    return 1


def _combine_decisions(left: str, right: str) -> str:
    return left if _decision_rank(left) >= _decision_rank(right) else right


def _decision_for_tag(tag: str, policy: EngagementPolicy) -> str:
    normalized = _normalize_text(tag)
    if normalized == "exploit_execution":
        return "approval_required" if policy.allow_exploitation else "blocked"
    if normalized in {"credential_bruteforce", "password_spray"}:
        return _risk_mode_to_decision(policy.credential_attack_mode)
    if normalized == "account_lockout_risk":
        return _risk_mode_to_decision(policy.lockout_risk_mode)
    if normalized == "service_instability":
        return _risk_mode_to_decision(policy.stability_risk_mode)
    if normalized == "lateral_movement":
        return "approval_required" if policy.allow_lateral_movement else "blocked"
    if normalized == "credential_capture_side_effect":
        return "approval_required" if policy.intent == "pentest" else "blocked"
    if normalized == "browser_state_change":
        return "approval_required"
    if normalized == "network_flooding":
        return "blocked" if policy.intent == "recon" else "approval_required"
    if normalized == "high_detection_likelihood":
        return "approval_required" if policy.detection_risk_mode in {"low", "medium", "high"} else "allowed"
    if normalized == "destructive_write":
        if bool(policy.custom_overrides.get("allow_destructive_write", False)):
            return "approval_required"
        return "blocked"
    if normalized == "persistence_action":
        if bool(policy.custom_overrides.get("allow_persistence", False)):
            return "approval_required"
        return "blocked"
    if normalized == "data_exfiltration_risk":
        if bool(policy.custom_overrides.get("allow_data_exfiltration", False)):
            return "approval_required"
        return "blocked" if policy.intent == "recon" else "approval_required"
    return "allowed"


def _policy_reason(
        state: str,
        risk_tags: List[str],
        policy: EngagementPolicy,
        family_policy_state: str,
) -> str:
    if family_policy_state == "blocked":
        return "Blocked by a project family policy override."
    if family_policy_state == "suppressed":
        return "Suppressed for this project by a family policy override."
    if family_policy_state == "approval_required":
        return "Project family policy keeps this action behind approval."

    if state == "blocked":
        if not risk_tags:
            return f"Blocked by engagement preset {policy.preset}."
        return (
            f"Engagement preset {policy.preset} blocks this action because of risk tags: "
            + ", ".join(risk_tags)
            + "."
        )
    if state == "approval_required":
        if policy.approval_mode == "always":
            return f"Engagement preset {policy.preset} requires approval for every step."
        if risk_tags:
            return (
                f"Engagement preset {policy.preset} requires approval because of risk tags: "
                + ", ".join(risk_tags)
                + "."
            )
        return f"Engagement preset {policy.preset} requires approval for this action."
    if family_policy_state == "allowed":
        return "Allowed by a project family approval override."
    return f"Allowed under engagement preset {policy.preset}."


def evaluate_policy_for_risk_tags(
        risk_tags: Optional[Iterable[str]],
        policy,
        *,
        family_policy_state: str = "",
) -> PolicyDecision:
    resolved_policy = normalize_engagement_policy(
        policy if isinstance(policy, dict) else getattr(policy, "to_dict", lambda: {})(),
        fallback_goal_profile=getattr(policy, "legacy_goal_profile", "internal_asset_discovery"),
    ) if not isinstance(policy, EngagementPolicy) else policy
    resolved_tags = normalize_risk_tags(risk_tags)
    state = "allowed"
    for tag in resolved_tags:
        state = _combine_decisions(state, _decision_for_tag(tag, resolved_policy))

    if resolved_policy.approval_mode == "always" and state != "blocked":
        state = "approval_required"
    elif resolved_policy.approval_mode == "never" and state == "approval_required":
        state = "allowed"

    normalized_family_policy = _normalize_family_policy_state(family_policy_state)
    if normalized_family_policy in {"blocked", "suppressed"}:
        state = "blocked"
    elif normalized_family_policy == "approval_required" and state != "blocked":
        state = "approval_required"
    elif (
            normalized_family_policy == "allowed"
            and state == "approval_required"
            and resolved_policy.approval_mode != "always"
    ):
        state = "allowed"

    return PolicyDecision(
        state=state if state in VALID_POLICY_DECISIONS else "allowed",
        risk_tags=resolved_tags,
        legacy_danger_categories=risk_tags_to_legacy_categories(resolved_tags),
        reason=_policy_reason(state, resolved_tags, resolved_policy, normalized_family_policy),
        risk_summary=summarize_risk_tags(resolved_tags),
        safer_alternative=safer_alternative_for_risk_tags(resolved_tags),
        family_policy_state=normalized_family_policy,
    )
