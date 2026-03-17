import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from app.scheduler.planner import SchedulerPlanner
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    normalize_engagement_policy,
    upsert_project_engagement_policy,
)


DEFAULT_AI_FEEDBACK_CONFIG = {
    "enabled": True,
    "max_rounds_per_target": 4,
    "max_actions_per_round": 4,
    "recent_output_chars": 900,
}
DIG_DEEPER_MAX_RUNTIME_SECONDS = 900
DIG_DEEPER_MAX_TOTAL_ACTIONS = 24
DIG_DEEPER_TASK_TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class SchedulerTarget:
    host_id: int = 0
    host_ip: str = ""
    hostname: str = ""
    port: str = ""
    protocol: str = "tcp"
    service_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SchedulerExecutionTask:
    decision: Any
    tool_id: str
    host_ip: str
    port: str
    protocol: str
    service_name: str
    command_template: str
    timeout: int
    job_id: int = 0
    host_id: int = 0
    hostname: str = ""
    approval_id: int = 0


@dataclass(frozen=True)
class SchedulerDecisionDisposition:
    action: str
    reason: str = ""
    approval_id: int = 0


@dataclass(frozen=True)
class SchedulerRunOptions:
    scheduler_mode: str = "deterministic"
    scheduler_concurrency: int = 1
    ai_feedback_enabled: bool = False
    max_rounds: int = 1
    max_actions_per_round: int = 0
    recent_output_chars: int = 900
    dig_deeper: bool = False
    max_runtime_seconds: int = 0
    max_total_actions: int = 0
    task_timeout_seconds: int = 300
    job_id: int = 0

    @property
    def analysis_mode(self) -> str:
        return "dig_deeper" if bool(self.dig_deeper) else "standard"


class SchedulerOrchestrator:
    def __init__(self, config_manager, planner: Optional[SchedulerPlanner] = None):
        self.config_manager = config_manager
        self.planner = planner or SchedulerPlanner(config_manager)

    @staticmethod
    def _normalize_host_id_set(host_ids: Optional[Iterable[Any]]) -> Set[int]:
        normalized = set()
        for item in list(host_ids or set()):
            try:
                normalized.add(int(item))
            except (TypeError, ValueError):
                continue
        return normalized

    @staticmethod
    def _scheduler_max_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_concurrency", 1))
        except (TypeError, ValueError):
            value = 1
        return max(1, min(value, 16))

    @staticmethod
    def _scheduler_feedback_config(preferences: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = dict(DEFAULT_AI_FEEDBACK_CONFIG)
        source = preferences.get("ai_feedback", {}) if isinstance(preferences, dict) else {}
        if isinstance(source, dict):
            merged.update(source)

        try:
            merged["max_rounds_per_target"] = int(merged.get("max_rounds_per_target", 4))
        except (TypeError, ValueError):
            merged["max_rounds_per_target"] = 4
        try:
            merged["max_actions_per_round"] = int(merged.get("max_actions_per_round", 4))
        except (TypeError, ValueError):
            merged["max_actions_per_round"] = 4
        try:
            merged["recent_output_chars"] = int(merged.get("recent_output_chars", 900))
        except (TypeError, ValueError):
            merged["recent_output_chars"] = 900

        merged["enabled"] = bool(merged.get("enabled", True))
        merged["max_rounds_per_target"] = max(1, min(int(merged["max_rounds_per_target"]), 12))
        merged["max_actions_per_round"] = max(1, min(int(merged["max_actions_per_round"]), 8))
        merged["recent_output_chars"] = max(320, min(int(merged["recent_output_chars"]), 4000))
        return merged

    def build_run_options(
            self,
            preferences: Optional[Dict[str, Any]] = None,
            *,
            dig_deeper: bool = False,
            job_id: int = 0,
            enable_feedback: Optional[bool] = None,
            max_actions_per_round: Optional[int] = None,
            max_rounds: Optional[int] = None,
    ) -> SchedulerRunOptions:
        prefs = preferences if isinstance(preferences, dict) else self.config_manager.load()
        scheduler_mode = str(prefs.get("mode", "deterministic") or "deterministic").strip().lower()
        scheduler_concurrency = self._scheduler_max_concurrency(prefs)
        ai_feedback_cfg = self._scheduler_feedback_config(prefs)
        ai_feedback_enabled = bool(ai_feedback_cfg.get("enabled", True))
        if enable_feedback is not None:
            ai_feedback_enabled = bool(enable_feedback)

        resolved_max_rounds = int(ai_feedback_cfg.get("max_rounds_per_target", 4)) if ai_feedback_enabled else 1
        resolved_max_actions = int(ai_feedback_cfg.get("max_actions_per_round", 4)) if ai_feedback_enabled else 0
        recent_output_chars = int(ai_feedback_cfg.get("recent_output_chars", 900))
        task_timeout_seconds = DIG_DEEPER_TASK_TIMEOUT_SECONDS if bool(dig_deeper) else 300

        if max_rounds is not None:
            resolved_max_rounds = max(1, int(max_rounds))
        if max_actions_per_round is not None:
            resolved_max_actions = max(0, int(max_actions_per_round))

        if ai_feedback_enabled:
            resolved_max_actions = max(
                resolved_max_actions,
                max(1, min(int(scheduler_concurrency), 8)),
            )

        if ai_feedback_enabled and bool(dig_deeper):
            resolved_max_rounds = max(resolved_max_rounds, 4)
            resolved_max_actions = max(resolved_max_actions, 3)
            recent_output_chars = max(recent_output_chars, 1600)

        return SchedulerRunOptions(
            scheduler_mode=scheduler_mode,
            scheduler_concurrency=scheduler_concurrency,
            ai_feedback_enabled=ai_feedback_enabled,
            max_rounds=max(1, min(int(resolved_max_rounds), 12)),
            max_actions_per_round=max(0, min(int(resolved_max_actions), 8)),
            recent_output_chars=max(320, min(int(recent_output_chars), 4000)),
            dig_deeper=bool(dig_deeper),
            max_runtime_seconds=DIG_DEEPER_MAX_RUNTIME_SECONDS if bool(dig_deeper) else 0,
            max_total_actions=DIG_DEEPER_MAX_TOTAL_ACTIONS if bool(dig_deeper) else 0,
            task_timeout_seconds=task_timeout_seconds,
            job_id=int(job_id or 0),
        )

    def load_project_engagement_policy(
            self,
            database,
            *,
            persist_if_missing: bool = True,
            updated_at: str = "",
    ) -> Dict[str, Any]:
        config = self.config_manager.load()
        fallback_policy = normalize_engagement_policy(
            config.get("engagement_policy", {}),
            fallback_goal_profile=str(config.get("goal_profile", "internal_asset_discovery") or "internal_asset_discovery"),
        )
        if database is None:
            return fallback_policy.to_dict()

        ensure_scheduler_engagement_policy_table(database)
        stored = get_project_engagement_policy(database)
        if stored is None:
            payload = fallback_policy.to_dict()
            if persist_if_missing:
                upsert_project_engagement_policy(
                    database,
                    payload,
                    updated_at=str(updated_at or ""),
                )
            return payload

        normalized = normalize_engagement_policy(
            stored,
            fallback_goal_profile=fallback_policy.legacy_goal_profile,
        )
        return normalized.to_dict()

    @staticmethod
    def collect_project_targets(
            project,
            *,
            host_ids: Optional[Iterable[Any]] = None,
            allowed_states: Optional[Iterable[str]] = None,
    ) -> List[SchedulerTarget]:
        if not project:
            return []

        normalized_host_ids = SchedulerOrchestrator._normalize_host_id_set(host_ids)
        allowed_state_set = {
            str(item or "").strip().lower()
            for item in list(allowed_states or {"open", "open|filtered"})
            if str(item or "").strip()
        }
        repo_container = getattr(project, "repositoryContainer", None)
        host_repo = getattr(repo_container, "hostRepository", None)
        port_repo = getattr(repo_container, "portRepository", None)
        service_repo = getattr(repo_container, "serviceRepository", None)
        if not host_repo or not port_repo:
            return []

        targets: List[SchedulerTarget] = []
        for host in list(host_repo.getAllHostObjs() or []):
            host_id = int(getattr(host, "id", 0) or 0)
            if normalized_host_ids and host_id not in normalized_host_ids:
                continue
            host_ip = str(getattr(host, "ip", "") or "")
            hostname = str(getattr(host, "hostname", "") or "")
            for port_obj in list(port_repo.getPortsByHostId(host_id) or []):
                state = str(getattr(port_obj, "state", "") or "").strip().lower()
                if allowed_state_set and state not in allowed_state_set:
                    continue
                service_name = ""
                service_id = getattr(port_obj, "serviceId", None)
                if service_id and service_repo:
                    try:
                        service_obj = service_repo.getServiceById(service_id)
                        if service_obj:
                            service_name = str(getattr(service_obj, "name", "") or "")
                    except Exception:
                        service_name = ""
                targets.append(SchedulerTarget(
                    host_id=host_id,
                    host_ip=host_ip,
                    hostname=hostname,
                    port=str(getattr(port_obj, "portId", "") or ""),
                    protocol=str(getattr(port_obj, "protocol", "tcp") or "tcp").lower(),
                    service_name=str(service_name or "").rstrip("?"),
                    metadata={
                        "state": state,
                        "service_id": int(service_id or 0) if str(service_id or "").strip() else 0,
                    },
                ))
        return targets

    @staticmethod
    def collect_parser_targets(parser) -> List[SchedulerTarget]:
        targets: List[SchedulerTarget] = []
        if parser is None or not hasattr(parser, "getAllHosts"):
            return targets
        for host in list(parser.getAllHosts() or []):
            hostname = str(getattr(host, "hostname", "") or "")
            host_ip = str(getattr(host, "ip", "") or "")
            for port in list(host.all_ports() or []):
                state = str(getattr(port, "state", "") or "").strip().lower()
                if state != "open":
                    continue
                service = port.getService() if hasattr(port, "getService") else None
                service_name = str(getattr(service, "name", "") or "").rstrip("?") if service else ""
                targets.append(SchedulerTarget(
                    host_id=0,
                    host_ip=host_ip,
                    hostname=hostname,
                    port=str(getattr(port, "portId", "") or ""),
                    protocol=str(getattr(port, "protocol", "tcp") or "tcp").lower(),
                    service_name=service_name,
                    metadata={"state": state, "parser_host": host},
                ))
        return targets

    @staticmethod
    def _find_command_template_for_tool(settings, tool_id: str) -> str:
        for action in list(getattr(settings, "portActions", []) or []):
            if str(action[1]) == str(tool_id):
                return str(action[2])
        return ""

    def run_targets(
            self,
            *,
            settings,
            targets: Sequence[SchedulerTarget],
            engagement_policy: Optional[Dict[str, Any]] = None,
            options: Optional[SchedulerRunOptions] = None,
            should_cancel: Optional[Callable[[int], bool]] = None,
            existing_attempts: Optional[Callable[[SchedulerTarget], Set[str]]] = None,
            build_context: Optional[Callable[..., Dict[str, Any]]] = None,
            on_ai_analysis: Optional[Callable[..., None]] = None,
            handle_blocked: Optional[Callable[..., SchedulerDecisionDisposition]] = None,
            handle_approval: Optional[Callable[..., SchedulerDecisionDisposition]] = None,
            execute_batch: Optional[Callable[[List[SchedulerExecutionTask], int], List[Dict[str, Any]]]] = None,
            on_execution_result: Optional[Callable[..., None]] = None,
    ) -> Dict[str, Any]:
        resolved_options = options or SchedulerRunOptions()
        summary = {
            "considered": 0,
            "approval_queued": 0,
            "executed": 0,
            "skipped": 0,
            "host_scope_count": len(list(targets or [])),
            "dig_deeper": bool(resolved_options.dig_deeper),
        }
        started_at = time.monotonic()

        for target in list(targets or []):
            if should_cancel and should_cancel(int(resolved_options.job_id or 0)):
                summary["cancelled"] = True
                summary["cancel_reason"] = "cancelled by user"
                return summary

            use_feedback_loop = (
                str(resolved_options.scheduler_mode or "").strip().lower() == "ai"
                and bool(resolved_options.ai_feedback_enabled)
            )
            attempted_tool_ids = set(
                existing_attempts(target=target)
                if use_feedback_loop and existing_attempts else set()
            )

            for _round in range(int(resolved_options.max_rounds or 1) if use_feedback_loop else 1):
                if should_cancel and should_cancel(int(resolved_options.job_id or 0)):
                    summary["cancelled"] = True
                    summary["cancel_reason"] = "cancelled by user"
                    return summary
                if (
                        int(resolved_options.max_runtime_seconds or 0) > 0
                        and (time.monotonic() - started_at) >= int(resolved_options.max_runtime_seconds or 0)
                ):
                    summary["stopped_early"] = "dig_deeper_runtime_cap"
                    return summary
                if (
                        int(resolved_options.max_total_actions or 0) > 0
                        and (summary["executed"] + summary["skipped"] + summary["approval_queued"]) >= int(resolved_options.max_total_actions or 0)
                ):
                    summary["stopped_early"] = "dig_deeper_action_cap"
                    return summary

                context = None
                if use_feedback_loop and build_context:
                    context = build_context(
                        target=target,
                        attempted_tool_ids=set(attempted_tool_ids),
                        recent_output_chars=int(resolved_options.recent_output_chars or 900),
                        analysis_mode=resolved_options.analysis_mode,
                    )

                decisions = self.planner.plan_actions(
                    target.service_name,
                    target.protocol,
                    settings,
                    context=context,
                    excluded_tool_ids=sorted(attempted_tool_ids),
                    limit=int(resolved_options.max_actions_per_round or 0) or None,
                    engagement_policy=engagement_policy,
                )

                if str(resolved_options.scheduler_mode or "").strip().lower() == "ai":
                    provider_payload = self.planner.get_last_provider_payload(clear=True)
                    if on_ai_analysis:
                        on_ai_analysis(target=target, provider_payload=provider_payload)

                if not decisions:
                    break

                round_progress = False
                execution_tasks: List[SchedulerExecutionTask] = []
                round_scheduled_tool_ids: Set[str] = set()

                for decision in decisions:
                    normalized_tool_id = str(decision.tool_id or "").strip().lower()
                    if (
                            not normalized_tool_id
                            or normalized_tool_id in attempted_tool_ids
                            or normalized_tool_id in round_scheduled_tool_ids
                    ):
                        continue

                    summary["considered"] += 1
                    command_template = str(decision.command_template or "") or self._find_command_template_for_tool(
                        settings,
                        decision.tool_id,
                    )

                    if decision.is_blocked:
                        disposition = (
                            handle_blocked(
                                target=target,
                                decision=decision,
                                command_template=command_template,
                            )
                            if handle_blocked else
                            SchedulerDecisionDisposition(
                                action="skipped",
                                reason=decision.policy_reason or "blocked by policy",
                            )
                        )
                        attempted_tool_ids.add(normalized_tool_id)
                        summary["skipped"] += 1
                        round_progress = True
                        _ = disposition
                        continue

                    if decision.requires_approval:
                        disposition = (
                            handle_approval(
                                target=target,
                                decision=decision,
                                command_template=command_template,
                            )
                            if handle_approval else
                            SchedulerDecisionDisposition(
                                action="queued",
                                reason=decision.policy_reason or "approval required",
                            )
                        )
                        action = str(getattr(disposition, "action", "queued") or "queued").strip().lower()
                        if action == "execute":
                            round_scheduled_tool_ids.add(normalized_tool_id)
                            execution_tasks.append(SchedulerExecutionTask(
                                decision=decision,
                                tool_id=normalized_tool_id,
                                host_id=int(target.host_id or 0),
                                host_ip=str(target.host_ip or ""),
                                hostname=str(target.hostname or ""),
                                port=str(target.port or ""),
                                protocol=str(target.protocol or "tcp"),
                                service_name=str(target.service_name or ""),
                                command_template=command_template,
                                timeout=int(resolved_options.task_timeout_seconds or 300),
                                job_id=int(resolved_options.job_id or 0),
                                approval_id=int(getattr(disposition, "approval_id", 0) or 0),
                            ))
                        else:
                            attempted_tool_ids.add(normalized_tool_id)
                            round_progress = True
                            if action == "queued":
                                summary["approval_queued"] += 1
                            else:
                                summary["skipped"] += 1
                        continue

                    round_scheduled_tool_ids.add(normalized_tool_id)
                    execution_tasks.append(SchedulerExecutionTask(
                        decision=decision,
                        tool_id=normalized_tool_id,
                        host_id=int(target.host_id or 0),
                        host_ip=str(target.host_ip or ""),
                        hostname=str(target.hostname or ""),
                        port=str(target.port or ""),
                        protocol=str(target.protocol or "tcp"),
                        service_name=str(target.service_name or ""),
                        command_template=command_template,
                        timeout=int(resolved_options.task_timeout_seconds or 300),
                        job_id=int(resolved_options.job_id or 0),
                    ))

                execution_results = execute_batch(execution_tasks, int(resolved_options.scheduler_concurrency or 1)) if execute_batch else []
                for result in list(execution_results or []):
                    decision = result.get("decision")
                    normalized_tool_id = str(result.get("tool_id", "") or "").strip().lower()
                    executed = bool(result.get("executed", False))

                    if on_execution_result and decision is not None:
                        on_execution_result(
                            target=target,
                            decision=decision,
                            result=result,
                        )

                    if normalized_tool_id:
                        attempted_tool_ids.add(normalized_tool_id)
                    round_progress = True
                    if executed:
                        summary["executed"] += 1
                    else:
                        summary["skipped"] += 1

                if not round_progress:
                    break
                if not use_feedback_loop:
                    break

        return summary
