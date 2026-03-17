import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.scheduler.policy import legacy_goal_profile_from_policy


WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}


def _stable_id(prefix: str, payload: Dict[str, Any]) -> str:
    rendered = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return f"{str(prefix or '').strip().lower()}-{digest[:16]}"


def _normalize_protocol(value: Any) -> str:
    return str(value or "tcp").strip().lower() or "tcp"


def _normalize_text_list(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    cleaned = []
    for item in list(values or []):
        text = str(item or "").strip()
        if text:
            cleaned.append(text)
    return cleaned


def _extract_parameter_schema(command_template: str) -> Dict[str, Any]:
    placeholders = sorted(set(re.findall(r"\[([A-Z0-9_]+)\]", str(command_template or ""))))
    properties = {}
    required = []
    for placeholder in placeholders:
        field_name = str(placeholder).strip().lower()
        properties[field_name] = {
            "type": "string",
            "source_placeholder": str(placeholder),
        }
        required.append(field_name)
    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    tool_id: str
    label: str
    description: str
    command_template: str
    parameter_schema: Dict[str, Any] = field(default_factory=dict)
    service_scope: List[str] = field(default_factory=list)
    protocol_scope: List[str] = field(default_factory=list)
    runner_type: str = "local"
    artifact_types: List[str] = field(default_factory=list)
    risk_tags: List[str] = field(default_factory=list)
    impact_level: str = "low"
    noise_level: str = "low"
    default_timeout: int = 300
    family_id: str = ""
    requires_credentials: bool = False
    requires_web_context: bool = False
    supports_deterministic: bool = False
    supports_ai_selection: bool = False
    methodology_tags: List[str] = field(default_factory=list)
    pack_tags: List[str] = field(default_factory=list)

    @property
    def primary_protocol(self) -> str:
        protocols = _normalize_text_list(self.protocol_scope)
        return _normalize_protocol(protocols[0] if protocols else "tcp")


@dataclass
class PlanStep:
    step_id: str
    action: ActionSpec
    origin_mode: str
    origin_planner: str
    engagement_preset: str
    policy_snapshot_hash: str
    target_ref: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    preconditions: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    approval_state: str = "not_required"
    status: str = "planned"
    linked_evidence_refs: List[str] = field(default_factory=list)
    linked_graph_nodes: List[str] = field(default_factory=list)
    linked_graph_edges: List[str] = field(default_factory=list)
    selection_score: float = 0.0
    family_id: str = ""
    risk_tags: List[str] = field(default_factory=list)

    @classmethod
    def from_action_spec(
            cls,
            action: ActionSpec,
            *,
            origin_mode: str,
            origin_planner: str,
            engagement_preset: str,
            policy_snapshot_hash: str,
            target_ref: Optional[Dict[str, Any]] = None,
            parameters: Optional[Dict[str, Any]] = None,
            rationale: str = "",
            preconditions: Optional[List[str]] = None,
            success_criteria: Optional[List[str]] = None,
            approval_required: bool = False,
            status: str = "planned",
            selection_score: float = 0.0,
            family_id: str = "",
            risk_tags: Optional[List[str]] = None,
            linked_evidence_refs: Optional[List[str]] = None,
            linked_graph_nodes: Optional[List[str]] = None,
            linked_graph_edges: Optional[List[str]] = None,
    ) -> "PlanStep":
        resolved_target = dict(target_ref or {})
        resolved_parameters = dict(parameters or {})
        resolved_risk_tags = list(risk_tags if risk_tags is not None else action.risk_tags)
        resolved_family_id = str(family_id or action.family_id or "")
        resolved_step_id = _stable_id("step", {
            "action_id": action.action_id,
            "origin_mode": str(origin_mode or ""),
            "origin_planner": str(origin_planner or ""),
            "engagement_preset": str(engagement_preset or ""),
            "target_ref": resolved_target,
            "parameters": resolved_parameters,
            "family_id": resolved_family_id,
        })
        return cls(
            step_id=resolved_step_id,
            action=action,
            origin_mode=str(origin_mode or ""),
            origin_planner=str(origin_planner or ""),
            engagement_preset=str(engagement_preset or ""),
            policy_snapshot_hash=str(policy_snapshot_hash or ""),
            target_ref=resolved_target,
            parameters=resolved_parameters,
            rationale=str(rationale or ""),
            preconditions=list(preconditions or []),
            success_criteria=list(success_criteria or []),
            approval_state="approval_required" if bool(approval_required) else "not_required",
            status=str(status or "planned"),
            linked_evidence_refs=list(linked_evidence_refs or []),
            linked_graph_nodes=list(linked_graph_nodes or []),
            linked_graph_edges=list(linked_graph_edges or []),
            selection_score=float(selection_score or 0.0),
            family_id=resolved_family_id,
            risk_tags=resolved_risk_tags,
        )

    @classmethod
    def from_legacy_fields(
            cls,
            *,
            tool_id: str,
            label: str,
            command_template: str,
            protocol: str,
            score: float,
            rationale: str,
            mode: str,
            goal_profile: str,
            family_id: str,
            danger_categories: Optional[List[str]] = None,
            requires_approval: bool = False,
            target_ref: Optional[Dict[str, Any]] = None,
            parameters: Optional[Dict[str, Any]] = None,
    ) -> "PlanStep":
        protocol_name = _normalize_protocol(protocol)
        service_scope = _normalize_text_list((target_ref or {}).get("service"))
        action = ActionSpec(
            action_id=str(tool_id or "").strip() or "unknown-action",
            tool_id=str(tool_id or "").strip(),
            label=str(label or "").strip() or str(tool_id or "").strip(),
            description=str(label or "").strip() or str(tool_id or "").strip(),
            command_template=str(command_template or ""),
            parameter_schema=_extract_parameter_schema(command_template),
            service_scope=service_scope,
            protocol_scope=[protocol_name],
            runner_type="browser" if str(tool_id or "").strip().lower() in {"screenshooter", "x11screen"} else "local",
            artifact_types=["screenshot"] if str(tool_id or "").strip().lower() in {"screenshooter", "x11screen"} else [],
            risk_tags=list(danger_categories or []),
            family_id=str(family_id or ""),
            requires_web_context=bool(service_scope and any(item in WEB_SERVICE_IDS for item in service_scope)),
            supports_deterministic=True,
            supports_ai_selection=True,
        )
        merged_parameters = dict(parameters or {})
        merged_parameters.setdefault("protocol", protocol_name)
        return cls.from_action_spec(
            action,
            origin_mode=str(mode or ""),
            origin_planner="legacy_scheduler_adapter",
            engagement_preset=str(goal_profile or ""),
            policy_snapshot_hash="",
            target_ref=target_ref or {"protocol": protocol_name},
            parameters=merged_parameters,
            rationale=str(rationale or ""),
            approval_required=bool(requires_approval),
            selection_score=float(score or 0.0),
            family_id=str(family_id or ""),
            risk_tags=list(danger_categories or []),
        )

    @property
    def action_id(self) -> str:
        return str(self.action.action_id)

    @property
    def tool_id(self) -> str:
        return str(self.action.tool_id)

    @property
    def label(self) -> str:
        return str(self.action.label)

    @property
    def description(self) -> str:
        return str(self.action.description)

    @property
    def command_template(self) -> str:
        return str(self.action.command_template)

    @property
    def protocol(self) -> str:
        return _normalize_protocol(
            self.parameters.get("protocol")
            or self.target_ref.get("protocol")
            or self.action.primary_protocol
        )

    @property
    def score(self) -> float:
        return float(self.selection_score)

    @property
    def mode(self) -> str:
        return str(self.origin_mode)

    @property
    def goal_profile(self) -> str:
        return legacy_goal_profile_from_policy(str(self.engagement_preset or ""))

    @property
    def danger_categories(self) -> List[str]:
        return list(self.risk_tags or [])

    @property
    def requires_approval(self) -> bool:
        return str(self.approval_state or "").strip().lower() in {"approval_required", "required", "pending"}


@dataclass
class ExecutionRecord:
    execution_id: str
    step_id: str
    started_at: str
    finished_at: str
    runner_type: str
    exit_status: str
    stdout_ref: str = ""
    stderr_ref: str = ""
    artifact_refs: List[str] = field(default_factory=list)
    approval_id: str = ""
    observations_created: List[str] = field(default_factory=list)
    graph_mutations: List[str] = field(default_factory=list)
    operator_notes: str = ""

    @classmethod
    def from_plan_step(
            cls,
            step: PlanStep,
            *,
            started_at: str,
            finished_at: str,
            exit_status: str,
            stdout_ref: str = "",
            stderr_ref: str = "",
            artifact_refs: Optional[List[str]] = None,
            approval_id: str = "",
            observations_created: Optional[List[str]] = None,
            graph_mutations: Optional[List[str]] = None,
            operator_notes: str = "",
    ) -> "ExecutionRecord":
        payload = {
            "step_id": str(step.step_id),
            "started_at": str(started_at or ""),
            "finished_at": str(finished_at or ""),
            "runner_type": str(step.action.runner_type or "local"),
            "exit_status": str(exit_status or ""),
            "approval_id": str(approval_id or ""),
            "stdout_ref": str(stdout_ref or ""),
            "stderr_ref": str(stderr_ref or ""),
        }
        return cls(
            execution_id=_stable_id("exec", payload),
            step_id=str(step.step_id),
            started_at=str(started_at or ""),
            finished_at=str(finished_at or ""),
            runner_type=str(step.action.runner_type or "local"),
            exit_status=str(exit_status or ""),
            stdout_ref=str(stdout_ref or ""),
            stderr_ref=str(stderr_ref or ""),
            artifact_refs=list(artifact_refs or []),
            approval_id=str(approval_id or ""),
            observations_created=list(observations_created or []),
            graph_mutations=list(graph_mutations or []),
            operator_notes=str(operator_notes or ""),
        )
