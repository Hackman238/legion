from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.web.http_utils import as_bool, clamp_int

SCHEDULER_PREFERENCE_ALLOWED_FIELDS = {
    "mode",
    "goal_profile",
    "engagement_policy",
    "ai_feedback",
    "feature_flags",
    "provider",
    "max_concurrency",
    "max_host_concurrency",
    "max_jobs",
    "providers",
    "integrations",
    "device_categories",
    "dangerous_categories",
    "project_report_delivery",
}


@dataclass(frozen=True)
class SchedulerPreferencesPatch:
    updates: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Any) -> "SchedulerPreferencesPatch":
        source = payload if isinstance(payload, dict) else {}
        return cls({key: value for key, value in source.items() if key in SCHEDULER_PREFERENCE_ALLOWED_FIELDS})


@dataclass(frozen=True)
class SchedulerLogQuery:
    limit: int

    @classmethod
    def from_args(cls, args) -> "SchedulerLogQuery":
        return cls(limit=clamp_int(args.get("limit"), 300, 1, 1000))


@dataclass(frozen=True)
class SchedulerDecisionQuery:
    limit: int

    @classmethod
    def from_args(cls, args) -> "SchedulerDecisionQuery":
        return cls(limit=clamp_int(args.get("limit"), 100, 1, 500))


@dataclass(frozen=True)
class SchedulerPlanPreviewQuery:
    host_id: int
    host_ip: str
    service: str
    port: str
    protocol: str
    mode: str
    limit_targets: int
    limit_actions: int

    @classmethod
    def from_args(cls, args) -> "SchedulerPlanPreviewQuery":
        return cls(
            host_id=clamp_int(args.get("host_id"), 0, 0, 2**31 - 1),
            host_ip=str(args.get("host_ip", "") or ""),
            service=str(args.get("service", "") or ""),
            port=str(args.get("port", "") or ""),
            protocol=str(args.get("protocol", "tcp") or "tcp"),
            mode=str(args.get("mode", "compare") or "compare"),
            limit_targets=clamp_int(args.get("limit_targets"), 20, 1, 200),
            limit_actions=clamp_int(args.get("limit_actions"), 6, 1, 50),
        )


@dataclass(frozen=True)
class SchedulerApprovalListQuery:
    status: Optional[str]
    limit: int

    @classmethod
    def from_args(cls, args) -> "SchedulerApprovalListQuery":
        status = str(args.get("status", "") or "").strip().lower() or None
        return cls(status=status, limit=clamp_int(args.get("limit"), 200, 1, 1000))


@dataclass(frozen=True)
class SchedulerApprovalRequest:
    approve_family: bool
    run_now: bool
    family_action: str

    @classmethod
    def from_payload(cls, payload: Any) -> "SchedulerApprovalRequest":
        source = payload if isinstance(payload, dict) else {}
        family_action = str(source.get("family_action", "") or "").strip().lower()
        return cls(
            approve_family=as_bool(source.get("approve_family", False), default=False),
            run_now=as_bool(source.get("run_now", True), default=True),
            family_action=family_action,
        )


@dataclass(frozen=True)
class SchedulerRejectionRequest:
    reason: str
    family_action: str

    @classmethod
    def from_payload(cls, payload: Any) -> "SchedulerRejectionRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            reason=str(source.get("reason", "rejected via web") or "rejected via web"),
            family_action=str(source.get("family_action", "") or "").strip().lower(),
        )


@dataclass(frozen=True)
class SchedulerFamilyApprovalRequest:
    family_id: str
    metadata: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Any) -> "SchedulerFamilyApprovalRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            family_id=str(source.get("family_id", "") or "").strip(),
            metadata={
                "tool_id": str(source.get("tool_id", "") or ""),
                "label": str(source.get("label", "") or ""),
                "danger_categories": source.get("danger_categories", []),
            },
        )


@dataclass(frozen=True)
class SchedulerExecutionQuery:
    limit: int
    host_id: int
    host_ip: str
    tool_id: str
    include_output: bool

    @classmethod
    def from_args(cls, args) -> "SchedulerExecutionQuery":
        return cls(
            limit=clamp_int(args.get("limit"), 200, 1, 1000),
            host_id=clamp_int(args.get("host_id"), 0, 0, 2**31 - 1),
            host_ip=str(args.get("host_ip", "") or ""),
            tool_id=str(args.get("tool_id", "") or ""),
            include_output=as_bool(args.get("include_output", False), default=False),
        )


@dataclass(frozen=True)
class SchedulerExecutionTraceQuery:
    max_chars: int

    @classmethod
    def from_args(cls, args) -> "SchedulerExecutionTraceQuery":
        return cls(max_chars=clamp_int(args.get("max_chars"), 4000, 200, 50000))
