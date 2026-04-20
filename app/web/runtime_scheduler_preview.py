from __future__ import annotations

from typing import Any, Dict, List


def serialize_plan_step_preview(step: Any) -> Dict[str, Any]:
    return {
        "step_id": str(step.step_id or ""),
        "action_id": str(step.action_id or ""),
        "tool_id": str(step.tool_id or ""),
        "label": str(step.label or ""),
        "description": str(step.description or ""),
        "command_template": str(step.command_template or ""),
        "origin_mode": str(step.origin_mode or ""),
        "origin_planner": str(step.origin_planner or ""),
        "engagement_preset": str(step.engagement_preset or ""),
        "target_ref": dict(step.target_ref or {}),
        "parameters": dict(step.parameters or {}),
        "rationale": str(step.rationale or ""),
        "preconditions": list(step.preconditions or []),
        "success_criteria": list(step.success_criteria or []),
        "approval_state": str(step.approval_state or ""),
        "policy_decision": str(step.policy_decision or ""),
        "policy_reason": str(step.policy_reason or ""),
        "risk_tags": list(step.risk_tags or []),
        "risk_summary": str(step.risk_summary or ""),
        "safer_alternative": str(step.safer_alternative or ""),
        "family_id": str(step.family_id or ""),
        "family_policy_state": str(step.family_policy_state or ""),
        "score": float(step.score or 0.0),
        "pack_ids": list(step.pack_ids or []),
        "methodology_tags": list(step.methodology_tags or []),
        "pack_tags": list(step.pack_tags or []),
        "coverage_gap": str(step.coverage_gap or ""),
        "coverage_notes": str(step.coverage_notes or ""),
        "evidence_expectations": list(step.evidence_expectations or []),
        "runner_type": str(getattr(step.action, "runner_type", "") or ""),
        "service_scope": list(getattr(step.action, "service_scope", []) or []),
        "protocol_scope": list(getattr(step.action, "protocol_scope", []) or []),
    }


def get_scheduler_plan_preview(
        runtime,
        *,
        host_id: int = 0,
        host_ip: str = "",
        service: str = "",
        port: str = "",
        protocol: str = "tcp",
        mode: str = "compare",
        limit_targets: int = 20,
        limit_actions: int = 6,
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        scheduler_prefs = runtime.scheduler_config.load()
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
        settings = runtime._get_settings()
        goal_profile = str(
            engagement_policy.get("legacy_goal_profile", scheduler_prefs.get("goal_profile", "internal_asset_discovery"))
            or "internal_asset_discovery"
        )
        targets = runtime.scheduler_orchestrator.collect_project_targets(
            project,
            host_ids={int(host_id)} if int(host_id or 0) > 0 else None,
            allowed_states={"open", "open|filtered"},
        )

    requested_mode = str(mode or "compare").strip().lower() or "compare"
    if requested_mode not in {"current", "deterministic", "ai", "compare"}:
        requested_mode = "compare"
    resolved_host_ip = str(host_ip or "").strip()
    resolved_service = str(service or "").strip().lower()
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    max_targets = max(1, min(int(limit_targets or 20), 200))
    max_actions = max(1, min(int(limit_actions or 6), 32))
    current_mode = str(scheduler_prefs.get("mode", "deterministic") or "deterministic").strip().lower()
    recent_output_chars = int(
        runtime.scheduler_orchestrator._scheduler_feedback_config(scheduler_prefs).get("recent_output_chars", 900) or 900
    )

    filtered_targets: List[Any] = []
    for target in list(targets or []):
        if resolved_host_ip and str(target.host_ip or "").strip() != resolved_host_ip:
            continue
        if resolved_service and str(target.service_name or "").strip().lower() != resolved_service:
            continue
        if resolved_port and str(target.port or "").strip() != resolved_port:
            continue
        if resolved_protocol and str(target.protocol or "tcp").strip().lower() != resolved_protocol:
            continue
        filtered_targets.append(target)
        if len(filtered_targets) >= max_targets:
            break

    previews = []
    for target in filtered_targets:
        attempted_summary = runtime._existing_attempt_summary_for_target(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
        )
        attempted_tool_ids = sorted(attempted_summary["tool_ids"])
        context = runtime._build_scheduler_target_context(
            host_id=int(target.host_id or 0),
            host_ip=str(target.host_ip or ""),
            port=str(target.port or ""),
            protocol=str(target.protocol or "tcp"),
            service_name=str(target.service_name or ""),
            goal_profile=goal_profile,
            attempted_tool_ids=set(attempted_tool_ids),
            attempted_family_ids=set(attempted_summary["family_ids"]),
            attempted_command_signatures=set(attempted_summary["command_signatures"]),
            recent_output_chars=recent_output_chars,
            analysis_mode="standard",
        )

        def _preview_for_mode(selected_mode: str) -> Dict[str, Any]:
            steps = runtime.scheduler_planner.plan_steps(
                str(target.service_name or ""),
                str(target.protocol or "tcp"),
                settings,
                context=context,
                excluded_tool_ids=list(attempted_tool_ids),
                excluded_family_ids=sorted(attempted_summary["family_ids"]),
                excluded_command_signatures=sorted(attempted_summary["command_signatures"]),
                limit=max_actions,
                engagement_policy=engagement_policy,
                mode_override=selected_mode,
            )
            serialized = [runtime._serialize_plan_step_preview(step) for step in list(steps or [])]
            fallback_used = bool(
                selected_mode == "ai"
                and serialized
                and not any(str(item.get("origin_mode", "") or "").strip().lower() == "ai" for item in serialized)
            )
            return {
                "requested_mode": str(selected_mode or ""),
                "fallback_used": fallback_used,
                "steps": serialized,
            }

        preview = {
            "target": {
                "host_id": int(target.host_id or 0),
                "host_ip": str(target.host_ip or ""),
                "hostname": str(target.hostname or ""),
                "port": str(target.port or ""),
                "protocol": str(target.protocol or "tcp"),
                "service_name": str(target.service_name or ""),
            },
            "attempted_tool_ids": list(attempted_tool_ids),
            "attempted_family_ids": sorted(attempted_summary["family_ids"]),
        }
        if requested_mode == "compare":
            deterministic_preview = _preview_for_mode("deterministic")
            ai_preview = _preview_for_mode("ai")
            deterministic_tool_ids = {
                str(item.get("tool_id", "") or "").strip().lower()
                for item in list(deterministic_preview.get("steps", []) or [])
                if str(item.get("tool_id", "") or "").strip()
            }
            ai_tool_ids = {
                str(item.get("tool_id", "") or "").strip().lower()
                for item in list(ai_preview.get("steps", []) or [])
                if str(item.get("tool_id", "") or "").strip()
            }
            preview.update({
                "mode": "compare",
                "deterministic": deterministic_preview,
                "ai": ai_preview,
                "agreement": sorted(deterministic_tool_ids & ai_tool_ids),
                "deterministic_only": sorted(deterministic_tool_ids - ai_tool_ids),
                "ai_only": sorted(ai_tool_ids - deterministic_tool_ids),
            })
        else:
            selected_mode = current_mode if requested_mode == "current" else requested_mode
            preview.update({
                "mode": requested_mode,
                "selected_mode": selected_mode,
                "plan": _preview_for_mode(selected_mode),
            })
        previews.append(preview)

    return {
        "requested_mode": requested_mode,
        "current_mode": current_mode,
        "engagement_policy": dict(engagement_policy or {}),
        "target_count": len(previews),
        "targets": previews,
    }
