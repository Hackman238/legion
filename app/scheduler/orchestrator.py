import time
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from app.hostsfile import registrable_root_domain
from app.scheduler.planner import SchedulerPlanner
from app.scheduler.tool_prompt_registry import get_scheduler_tool_prompt_info
from app.scheduler.policy import (
    ensure_scheduler_engagement_policy_table,
    get_project_engagement_policy,
    normalize_engagement_policy,
    upsert_project_engagement_policy,
)


DEFAULT_AI_FEEDBACK_CONFIG = {
    "enabled": True,
    "max_rounds_per_target": 5,
    "max_actions_per_round": 6,
    "recent_output_chars": 900,
    "reflection_enabled": True,
    "stall_rounds_without_progress": 2,
    "stall_repeat_selection_threshold": 2,
    "max_reflections_per_target": 1,
}
DIG_DEEPER_MAX_RUNTIME_SECONDS = 900
DIG_DEEPER_MAX_TOTAL_ACTIONS = 24
DIG_DEEPER_TASK_TIMEOUT_SECONDS = 180
WEB_PARALLEL_FOLLOWUP_MAX_TOOLS = 3


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
    runner_preference: str = ""


@dataclass(frozen=True)
class SchedulerDecisionDisposition:
    action: str
    reason: str = ""
    approval_id: int = 0


@dataclass(frozen=True)
class SchedulerRunOptions:
    scheduler_mode: str = "deterministic"
    scheduler_concurrency: int = 1
    host_concurrency: int = 1
    ai_feedback_enabled: bool = False
    max_rounds: int = 1
    max_actions_per_round: int = 0
    recent_output_chars: int = 900
    reflection_enabled: bool = False
    stall_rounds_without_progress: int = 2
    stall_repeat_selection_threshold: int = 2
    max_reflections_per_target: int = 0
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
    def _candidate_host_root_token(host_ip: Any, hostname: Any) -> str:
        for value in (hostname, host_ip):
            token = str(value or "").strip()
            if not token:
                continue
            lowered = token.lower()
            if lowered in {"unknown", "localhost"}:
                continue
            try:
                ipaddress.ip_address(token)
                continue
            except ValueError:
                pass
            root_domain = registrable_root_domain(token)
            if root_domain:
                return root_domain
        return ""

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
    def _scheduler_max_host_concurrency(preferences: Optional[Dict[str, Any]] = None) -> int:
        source = preferences if isinstance(preferences, dict) else {}
        try:
            value = int(source.get("max_host_concurrency", 1))
        except (TypeError, ValueError):
            value = 1
        return max(1, min(value, 8))

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
        for key, default_value in (
                ("recent_output_chars", 900),
                ("stall_rounds_without_progress", 2),
                ("stall_repeat_selection_threshold", 2),
                ("max_reflections_per_target", 1),
        ):
            try:
                merged[key] = int(merged.get(key, default_value))
            except (TypeError, ValueError):
                merged[key] = default_value

        merged["enabled"] = bool(merged.get("enabled", True))
        merged["reflection_enabled"] = bool(merged.get("reflection_enabled", True))
        merged["max_rounds_per_target"] = max(1, min(int(merged["max_rounds_per_target"]), 12))
        merged["max_actions_per_round"] = max(1, min(int(merged["max_actions_per_round"]), 8))
        merged["recent_output_chars"] = max(320, min(int(merged["recent_output_chars"]), 4000))
        merged["stall_rounds_without_progress"] = max(1, min(int(merged["stall_rounds_without_progress"]), 6))
        merged["stall_repeat_selection_threshold"] = max(1, min(int(merged["stall_repeat_selection_threshold"]), 8))
        merged["max_reflections_per_target"] = max(0, min(int(merged["max_reflections_per_target"]), 4))
        return merged

    @staticmethod
    def _normalize_text_token(value: Any) -> str:
        return str(value or "").strip().lower()

    @classmethod
    def _expand_reflection_suppression_aliases(
            cls,
            values: Iterable[Any],
            *,
            attempted_tool_ids: Optional[Iterable[Any]] = None,
            context: Optional[Dict[str, Any]] = None,
    ) -> Set[str]:
        exact = {
            cls._normalize_text_token(item)
            for item in list(values or [])
            if cls._normalize_text_token(item)
        }
        if not exact:
            return set()

        expanded = set(exact)
        whatweb_family = {"whatweb", "whatweb-http", "whatweb-https"}
        if not (exact & whatweb_family):
            return expanded

        evidence = {
            cls._normalize_text_token(item)
            for item in list(attempted_tool_ids or set())
            if cls._normalize_text_token(item)
        }
        if isinstance(context, dict):
            evidence.update(
                cls._normalize_text_token(item)
                for item in list(context.get("attempted_tool_ids", []) or [])
                if cls._normalize_text_token(item)
            )
            recent_processes = context.get("recent_processes", []) if isinstance(context.get("recent_processes", []), list) else []
            evidence.update(
                cls._normalize_text_token(item.get("tool_id", ""))
                for item in recent_processes
                if isinstance(item, dict) and cls._normalize_text_token(item.get("tool_id", ""))
            )
            host_ports = context.get("host_ports", []) if isinstance(context.get("host_ports", []), list) else []
            for port_row in host_ports:
                if not isinstance(port_row, dict):
                    continue
                evidence.update(
                    cls._normalize_text_token(item)
                    for item in list(port_row.get("scripts", []) or [])
                    if cls._normalize_text_token(item)
                )
            signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
            evidence.update(
                cls._normalize_text_token(item)
                for item in list(signals.get("missing_tools", []) or []) + list(signals.get("audited_missing_tools", []) or [])
                if cls._normalize_text_token(item)
            )
            tool_audit = context.get("tool_audit", {}) if isinstance(context.get("tool_audit", {}), dict) else {}
            evidence.update(
                cls._normalize_text_token(item)
                for item in list(tool_audit.get("unavailable_tool_ids", []) or [])
                if cls._normalize_text_token(item)
            )
            context_summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
            evidence.update(
                cls._normalize_text_token(item)
                for item in list(context_summary.get("recent_attempts", []) or [])
                if cls._normalize_text_token(item)
            )

        if evidence & whatweb_family:
            expanded.update(whatweb_family)
        return expanded

    @classmethod
    def _normalize_attempt_summary(cls, payload: Any) -> Dict[str, Set[str]]:
        if isinstance(payload, dict):
            return {
                "tool_ids": {cls._normalize_text_token(item) for item in list(payload.get("tool_ids", []) or []) if cls._normalize_text_token(item)},
                "family_ids": {cls._normalize_text_token(item) for item in list(payload.get("family_ids", []) or []) if cls._normalize_text_token(item)},
                "command_signatures": {cls._normalize_text_token(item) for item in list(payload.get("command_signatures", []) or []) if cls._normalize_text_token(item)},
            }
        normalized = {cls._normalize_text_token(item) for item in list(payload or set()) if cls._normalize_text_token(item)}
        return {
            "tool_ids": normalized,
            "family_ids": set(),
            "command_signatures": set(),
        }

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
        host_concurrency = self._scheduler_max_host_concurrency(prefs)
        ai_feedback_cfg = self._scheduler_feedback_config(prefs)
        ai_feedback_enabled = bool(ai_feedback_cfg.get("enabled", True))
        if enable_feedback is not None:
            ai_feedback_enabled = bool(enable_feedback)

        resolved_max_rounds = int(ai_feedback_cfg.get("max_rounds_per_target", 4)) if ai_feedback_enabled else 1
        resolved_max_actions = int(ai_feedback_cfg.get("max_actions_per_round", 4)) if ai_feedback_enabled else 0
        recent_output_chars = int(ai_feedback_cfg.get("recent_output_chars", 900))
        reflection_enabled = bool(ai_feedback_cfg.get("reflection_enabled", True)) if ai_feedback_enabled else False
        stall_rounds_without_progress = int(ai_feedback_cfg.get("stall_rounds_without_progress", 2))
        stall_repeat_selection_threshold = int(ai_feedback_cfg.get("stall_repeat_selection_threshold", 2))
        max_reflections_per_target = int(ai_feedback_cfg.get("max_reflections_per_target", 1)) if ai_feedback_enabled else 0
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
            max_reflections_per_target = max(max_reflections_per_target, 1)
            host_concurrency = 1

        return SchedulerRunOptions(
            scheduler_mode=scheduler_mode,
            scheduler_concurrency=scheduler_concurrency,
            host_concurrency=max(1, min(int(host_concurrency or 1), 8)),
            ai_feedback_enabled=ai_feedback_enabled,
            max_rounds=max(1, min(int(resolved_max_rounds), 12)),
            max_actions_per_round=max(0, min(int(resolved_max_actions), 8)),
            recent_output_chars=max(320, min(int(recent_output_chars), 4000)),
            reflection_enabled=bool(reflection_enabled),
            stall_rounds_without_progress=max(1, min(int(stall_rounds_without_progress), 6)),
            stall_repeat_selection_threshold=max(1, min(int(stall_repeat_selection_threshold), 8)),
            max_reflections_per_target=max(0, min(int(max_reflections_per_target), 4)),
            dig_deeper=bool(dig_deeper),
            max_runtime_seconds=DIG_DEEPER_MAX_RUNTIME_SECONDS if bool(dig_deeper) else 0,
            max_total_actions=DIG_DEEPER_MAX_TOTAL_ACTIONS if bool(dig_deeper) else 0,
            task_timeout_seconds=task_timeout_seconds,
            job_id=int(job_id or 0),
        )

    @staticmethod
    def _context_coverage_missing(context: Optional[Dict[str, Any]]) -> List[str]:
        coverage = context.get("coverage", {}) if isinstance(context, dict) else {}
        if not isinstance(coverage, dict):
            return []
        values = []
        for item in list(coverage.get("missing", []) or []):
            token = str(item or "").strip().lower()
            if token and token not in values:
                values.append(token[:64])
        return values[:24]

    @classmethod
    def _context_signal_key(cls, context: Optional[Dict[str, Any]]) -> str:
        if not isinstance(context, dict):
            return ""
        parts: List[str] = []
        coverage = context.get("coverage", {})
        if isinstance(coverage, dict):
            stage = str(coverage.get("stage", "") or "").strip().lower()
            if stage:
                parts.append(f"stage:{stage[:32]}")
        signals = context.get("signals", {})
        if isinstance(signals, dict):
            enabled = sorted([
                str(key or "").strip().lower()
                for key, value in signals.items()
                if isinstance(value, bool) and value
            ])[:12]
            parts.extend(enabled)
            observed = [
                str(item or "").strip().lower()
                for item in list(signals.get("observed_technologies", []) or [])[:6]
                if str(item or "").strip()
            ]
            parts.extend([f"tech:{item[:32]}" for item in observed])
        return "|".join(parts)[:240]

    @classmethod
    def _context_current_phase(cls, context: Optional[Dict[str, Any]]) -> str:
        if not isinstance(context, dict):
            return ""
        context_summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
        focus = context_summary.get("focus", {}) if isinstance(context_summary.get("focus", {}), dict) else {}
        for value in (
                focus.get("current_phase", ""),
                context.get("current_phase", ""),
                context.get("phase", ""),
                context.get("next_phase", ""),
        ):
            token = cls._normalize_text_token(value)
            if token:
                return token[:64]
        host_ai_state = context.get("host_ai_state", {}) if isinstance(context.get("host_ai_state", {}), dict) else {}
        return cls._normalize_text_token(host_ai_state.get("next_phase", ""))[:64]

    @classmethod
    def _context_recent_failures(cls, context: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(context, dict):
            return []
        context_summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
        summary_failures = [
            cls._normalize_text_token(item)
            for item in list(context_summary.get("recent_failures", []) or [])[:8]
            if cls._normalize_text_token(item)
        ]
        if summary_failures:
            return summary_failures[:8]

        rows = context.get("target_recent_processes", []) if isinstance(context.get("target_recent_processes", []), list) else []
        if not rows:
            rows = context.get("recent_processes", []) if isinstance(context.get("recent_processes", []), list) else []
        labels: List[str] = []
        for item in rows[:32]:
            if not isinstance(item, dict):
                continue
            tool_id = cls._normalize_text_token(item.get("tool_id", ""))
            status = cls._normalize_text_token(item.get("status", ""))
            output_excerpt = cls._normalize_text_token(item.get("output_excerpt", ""))
            failure_reason = ""
            if any(token in status for token in ("crash", "fail", "error", "timeout", "cancel", "kill", "missing")):
                failure_reason = status[:80]
            elif "command not found" in output_excerpt:
                failure_reason = "command not found"
            elif "no such file" in output_excerpt or "missing file" in output_excerpt:
                failure_reason = "missing file"
            elif "traceback" in output_excerpt or "exception" in output_excerpt:
                failure_reason = "exception"
            if not failure_reason:
                continue
            label = ": ".join(part for part in (tool_id[:80], failure_reason[:80]) if part)
            if label and label not in labels:
                labels.append(label)
        return labels[:8]

    @classmethod
    def _reflection_trigger(
            cls,
            *,
            recent_rounds: Sequence[Dict[str, Any]],
            options: SchedulerRunOptions,
            reflections_used: int,
            context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not bool(options.reflection_enabled):
            return None
        if int(options.max_reflections_per_target or 0) <= 0:
            return None
        if int(reflections_used or 0) >= int(options.max_reflections_per_target or 0):
            return None

        rounds = [item for item in list(recent_rounds or []) if isinstance(item, dict)]
        current_phase = cls._context_current_phase(context)
        round_number = len(rounds) + 1
        window_size = max(1, int(options.stall_rounds_without_progress or 1))
        analysis_mode = cls._normalize_text_token((context or {}).get("analysis_mode", "")) if isinstance(context, dict) else ""

        if not rounds:
            if bool(options.dig_deeper) or analysis_mode == "dig_deeper":
                return {
                    "reason": "first_round",
                    "round_number": round_number,
                    "current_phase": current_phase,
                }
            return None

        previous_phase = cls._normalize_text_token(rounds[-1].get("observed_phase", "") or rounds[-1].get("next_phase", ""))[:64]
        if current_phase and previous_phase and current_phase != previous_phase:
            return {
                "reason": "phase_transition",
                "round_number": round_number,
                "current_phase": current_phase,
                "previous_phase": previous_phase,
            }

        if len(rounds) < window_size:
            return None

        window = rounds[-window_size:]
        if any(int(item.get("progress_score", 0) or 0) > 0 for item in window):
            return None

        stable_coverage = len({tuple(item.get("coverage_missing", []) or []) for item in window}) == 1
        stable_signal = len({str(item.get("signal_key", "") or "") for item in window}) <= 1
        if not (stable_coverage and stable_signal):
            return None

        failure_sets = []
        for item in window:
            values = {
                cls._normalize_text_token(entry)
                for entry in list(item.get("recent_failures", []) or [])[:8]
                if cls._normalize_text_token(entry)
            }
            if not values:
                failure_sets = []
                break
            failure_sets.append(values)
        if len(failure_sets) >= 2:
            shared_failures = sorted(set.intersection(*failure_sets))
            if shared_failures:
                return {
                    "reason": "repeated_failures",
                    "round_number": round_number,
                    "current_phase": current_phase,
                    "window_size": window_size,
                    "recent_failures": shared_failures[:6],
                }

        repeated_threshold = max(1, int(options.stall_repeat_selection_threshold or 1))
        repeated_selection_count = max(
            int(item.get("repeated_selection_count", 0) or 0)
            for item in window
        )
        if repeated_selection_count >= repeated_threshold:
            return {
                "reason": "repeated_selection_stagnation",
                "round_number": round_number,
                "current_phase": current_phase,
                "window_size": window_size,
                "repeated_selection_count": repeated_selection_count,
            }

        if window_size <= 2:
            return {
                "reason": "stalled_window",
                "round_number": round_number,
                "current_phase": current_phase,
                "window_size": window_size,
            }

        empty_decisions = all(not list(item.get("decision_tool_ids", []) or []) for item in window)
        if empty_decisions:
            return {
                "reason": "stalled_window",
                "round_number": round_number,
                "current_phase": current_phase,
                "window_size": window_size,
            }
        return None

    @classmethod
    def _round_repeated_selection_count(
            cls,
            *,
            recent_rounds: Sequence[Dict[str, Any]],
            tool_ids: Sequence[str],
            family_ids: Sequence[str],
            duplicate_filtered_count: int = 0,
            suppressed_filtered_count: int = 0,
    ) -> int:
        prior_tool_ids: Set[str] = set()
        prior_family_ids: Set[str] = set()
        for item in list(recent_rounds or [])[-4:]:
            if not isinstance(item, dict):
                continue
            prior_tool_ids.update({
                cls._normalize_text_token(entry)
                for entry in list(item.get("decision_tool_ids", []) or [])
                if cls._normalize_text_token(entry)
            })
            prior_family_ids.update({
                cls._normalize_text_token(entry)
                for entry in list(item.get("decision_family_ids", []) or [])
                if cls._normalize_text_token(entry)
            })
        repeated = int(duplicate_filtered_count or 0) + int(suppressed_filtered_count or 0)
        repeated += sum(1 for item in list(tool_ids or []) if cls._normalize_text_token(item) in prior_tool_ids)
        repeated += sum(1 for item in list(family_ids or []) if cls._normalize_text_token(item) in prior_family_ids)
        return max(0, repeated)

    @classmethod
    def _build_round_snapshot(
            cls,
            *,
            round_number: int,
            context: Optional[Dict[str, Any]],
            provider_payload: Optional[Dict[str, Any]],
            decision_tool_ids: Sequence[str],
            decision_family_ids: Sequence[str],
            duplicate_filtered_count: int = 0,
            suppressed_filtered_count: int = 0,
            recent_rounds: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload = provider_payload if isinstance(provider_payload, dict) else {}
        tool_ids = [
            cls._normalize_text_token(item)
            for item in list(decision_tool_ids or [])
            if cls._normalize_text_token(item)
        ]
        family_ids = [
            cls._normalize_text_token(item)
            for item in list(decision_family_ids or [])
            if cls._normalize_text_token(item)
        ]
        snapshot = {
            "round": int(round_number or 0),
            "coverage_missing": cls._context_coverage_missing(context),
            "findings_count": len(list(payload.get("findings", []) or [])),
            "manual_tests_count": len(list(payload.get("manual_tests", []) or [])),
            "technologies_count": len(list(payload.get("technologies", []) or [])),
            "next_phase": str(payload.get("next_phase", "") or "")[:64],
            "observed_phase": cls._context_current_phase(context),
            "recent_failures": cls._context_recent_failures(context),
            "decision_tool_ids": tool_ids[:16],
            "decision_family_ids": family_ids[:16],
            "signal_key": cls._context_signal_key(context),
            "repeated_selection_count": cls._round_repeated_selection_count(
                recent_rounds=recent_rounds or [],
                tool_ids=tool_ids,
                family_ids=family_ids,
                duplicate_filtered_count=duplicate_filtered_count,
                suppressed_filtered_count=suppressed_filtered_count,
            ),
        }
        return snapshot

    @staticmethod
    def _round_progress_score(previous_round: Optional[Dict[str, Any]], current_round: Optional[Dict[str, Any]]) -> int:
        if not isinstance(previous_round, dict) or not isinstance(current_round, dict):
            return 0

        score = 0
        previous_missing = set(previous_round.get("coverage_missing", []) or [])
        current_missing = set(current_round.get("coverage_missing", []) or [])
        if current_missing != previous_missing:
            if len(current_missing) < len(previous_missing):
                score += 2
            else:
                score += 1

        for key, weight in (
                ("findings_count", 2),
                ("manual_tests_count", 1),
                ("technologies_count", 1),
        ):
            try:
                previous_value = int(previous_round.get(key, 0) or 0)
                current_value = int(current_round.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
            if current_value > previous_value:
                score += weight

        previous_phase = str(previous_round.get("next_phase", "") or "").strip().lower()
        current_phase = str(current_round.get("next_phase", "") or "").strip().lower()
        if current_phase and current_phase != previous_phase:
            score += 1
        return score

    @staticmethod
    def _should_trigger_reflection(
            recent_rounds: Sequence[Dict[str, Any]],
            options: SchedulerRunOptions,
            reflections_used: int,
            context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return bool(
            SchedulerOrchestrator._reflection_trigger(
                recent_rounds=recent_rounds,
                options=options,
                reflections_used=reflections_used,
                context=context,
            )
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
            host_root_token = SchedulerOrchestrator._candidate_host_root_token(host_ip, hostname)
            if host_root_token:
                targets.append(SchedulerTarget(
                    host_id=host_id,
                    host_ip=host_ip,
                    hostname=hostname,
                    port="",
                    protocol="tcp",
                    service_name="host",
                    metadata={
                        "state": "up",
                        "service_id": 0,
                        "target_type": "host_root",
                        "host_root_token": host_root_token,
                    },
                ))
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
            host_root_token = SchedulerOrchestrator._candidate_host_root_token(host_ip, hostname)
            if host_root_token:
                targets.append(SchedulerTarget(
                    host_id=0,
                    host_ip=host_ip,
                    hostname=hostname,
                    port="",
                    protocol="tcp",
                    service_name="host",
                    metadata={"state": "up", "parser_host": host, "target_type": "host_root", "host_root_token": host_root_token},
                ))
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

    @classmethod
    def _web_parallel_followup_wave_tool_ids(
            cls,
            *,
            target: SchedulerTarget,
            decisions: Sequence[Any],
            provider_payload: Optional[Dict[str, Any]],
            options: SchedulerRunOptions,
    ) -> List[str]:
        service_name = cls._normalize_text_token(getattr(target, "service_name", ""))
        if service_name not in SchedulerPlanner.WEB_SERVICE_IDS:
            return []

        payload = provider_payload if isinstance(provider_payload, dict) else {}
        specialist_sidecars = payload.get("specialist_sidecars", [])
        if not isinstance(specialist_sidecars, list) or not specialist_sidecars:
            return []

        wave_cap = min(
            int(WEB_PARALLEL_FOLLOWUP_MAX_TOOLS),
            max(1, int(options.scheduler_concurrency or 1)),
            max(1, int(options.max_actions_per_round or 0) or int(WEB_PARALLEL_FOLLOWUP_MAX_TOOLS)),
        )
        if wave_cap < 2:
            return []

        decision_tool_ids = {
            cls._normalize_text_token(getattr(item, "tool_id", ""))
            for item in list(decisions or [])
            if cls._normalize_text_token(getattr(item, "tool_id", ""))
        }
        if not decision_tool_ids:
            return []

        selected_tool_ids: List[str] = []
        seen: Set[str] = set()
        for sidecar in reversed(specialist_sidecars):
            if not isinstance(sidecar, dict):
                continue
            for item in list(sidecar.get("selected_tool_ids", []) or []):
                tool_id = cls._normalize_text_token(item)
                if not tool_id or tool_id in seen:
                    continue
                seen.add(tool_id)
                selected_tool_ids.append(tool_id)

        if not selected_tool_ids:
            return []

        wave_tool_ids: List[str] = []
        for tool_id in selected_tool_ids:
            if tool_id not in decision_tool_ids:
                continue
            if not bool(get_scheduler_tool_prompt_info(tool_id).safe_parallel):
                continue
            wave_tool_ids.append(tool_id)
            if len(wave_tool_ids) >= wave_cap:
                break

        if len(wave_tool_ids) < 2:
            return []
        return wave_tool_ids

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
            reflect_progress: Optional[Callable[..., Dict[str, Any]]] = None,
            on_reflection_analysis: Optional[Callable[..., None]] = None,
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
            "reflections": 0,
            "reflection_stops": 0,
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
            attempted_state = self._normalize_attempt_summary(
                existing_attempts(target=target)
                if use_feedback_loop and existing_attempts else {}
            )
            attempted_tool_ids = set(attempted_state["tool_ids"])
            attempted_family_ids = set(attempted_state["family_ids"])
            attempted_command_signatures = set(attempted_state["command_signatures"])
            suppressed_tool_ids: Set[str] = set()
            promoted_tool_ids: List[str] = []
            recent_rounds: List[Dict[str, Any]] = []
            reflections_used = 0

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
                        attempted_family_ids=set(attempted_family_ids),
                        attempted_command_signatures=set(attempted_command_signatures),
                        recent_output_chars=int(resolved_options.recent_output_chars or 900),
                        analysis_mode=resolved_options.analysis_mode,
                    )

                reflection_trigger = None
                if use_feedback_loop and reflect_progress and context is not None:
                    reflection_trigger = self._reflection_trigger(
                        recent_rounds=recent_rounds,
                        options=resolved_options,
                        reflections_used=reflections_used,
                        context=context,
                    )

                if reflection_trigger:
                    try:
                        reflection_payload = reflect_progress(
                            target=target,
                            context=context,
                            recent_rounds=list(recent_rounds),
                            trigger=reflection_trigger,
                        )
                    except Exception:
                        reflection_payload = {}
                    if isinstance(reflection_payload, dict) and reflection_payload:
                        reflection_payload.setdefault("trigger_reason", str(reflection_trigger.get("reason", "") or "").strip().lower())
                        reflection_payload.setdefault("trigger_context", dict(reflection_trigger))
                        reflections_used += 1
                        summary["reflections"] += 1
                        if on_reflection_analysis:
                            on_reflection_analysis(
                                target=target,
                                reflection_payload=reflection_payload,
                                recent_rounds=list(recent_rounds),
                            )
                        suppressed_tool_ids.update(
                            self._expand_reflection_suppression_aliases(
                                reflection_payload.get("suppress_tool_ids", []),
                                attempted_tool_ids=attempted_tool_ids,
                                context=context,
                            )
                        )
                        promoted_tool_ids = [
                            self._normalize_text_token(item)
                            for item in list(reflection_payload.get("promote_tool_ids", []) or [])
                            if self._normalize_text_token(item)
                        ]
                        reflection_state = str(reflection_payload.get("state", "continue") or "continue").strip().lower()
                        priority_shift = str(reflection_payload.get("priority_shift", "") or "").strip().lower()
                        if reflection_state == "complete" or priority_shift in {"manual_validation", "stop"}:
                            summary["reflection_stops"] += 1
                            break

                decisions = self.planner.plan_actions(
                    target.service_name,
                    target.protocol,
                    settings,
                    context=context,
                    excluded_tool_ids=sorted(set(attempted_tool_ids).union(suppressed_tool_ids)),
                    excluded_family_ids=sorted(attempted_family_ids),
                    excluded_command_signatures=sorted(attempted_command_signatures),
                    limit=int(resolved_options.max_actions_per_round or 0) or None,
                    engagement_policy=engagement_policy,
                )

                if str(resolved_options.scheduler_mode or "").strip().lower() == "ai":
                    provider_payload = self.planner.get_last_provider_payload(clear=True)
                    if on_ai_analysis:
                        on_ai_analysis(target=target, provider_payload=provider_payload)

                if not decisions:
                    break

                if promoted_tool_ids:
                    promoted_set = {self._normalize_text_token(item) for item in promoted_tool_ids if self._normalize_text_token(item)}
                    decisions = sorted(
                        list(decisions),
                        key=lambda item: (
                            0 if self._normalize_text_token(getattr(item, "tool_id", "")) in promoted_set else 1,
                        ),
                    )

                parallel_wave_tool_ids = self._web_parallel_followup_wave_tool_ids(
                    target=target,
                    decisions=decisions,
                    provider_payload=provider_payload if isinstance(locals().get("provider_payload"), dict) else {},
                    options=resolved_options,
                )
                if parallel_wave_tool_ids:
                    wave_order = {
                        tool_id: index
                        for index, tool_id in enumerate(parallel_wave_tool_ids)
                        if tool_id
                    }
                    decisions = sorted(
                        [
                            item for item in list(decisions)
                            if self._normalize_text_token(getattr(item, "tool_id", "")) in wave_order
                        ],
                        key=lambda item: wave_order.get(
                            self._normalize_text_token(getattr(item, "tool_id", "")),
                            len(wave_order),
                        ),
                    )

                round_progress = False
                execution_tasks: List[SchedulerExecutionTask] = []
                round_scheduled_tool_ids: Set[str] = set()
                round_scheduled_family_ids: Set[str] = set()
                round_scheduled_command_signatures: Set[str] = set()
                round_selected_tool_ids: List[str] = []
                round_selected_family_ids: List[str] = []
                duplicate_filtered_count = 0
                suppressed_filtered_count = 0

                for decision in decisions:
                    normalized_tool_id = str(decision.tool_id or "").strip().lower()
                    normalized_family_id = self._normalize_text_token(getattr(decision, "family_id", ""))
                    if normalized_tool_id and normalized_tool_id in suppressed_tool_ids:
                        suppressed_filtered_count += 1
                        continue
                    if (
                            not normalized_tool_id
                            or normalized_tool_id in attempted_tool_ids
                            or normalized_tool_id in round_scheduled_tool_ids
                            or (normalized_family_id and normalized_family_id in attempted_family_ids)
                            or (normalized_family_id and normalized_family_id in round_scheduled_family_ids)
                    ):
                        duplicate_filtered_count += 1
                        continue

                    summary["considered"] += 1
                    command_template = str(decision.command_template or "") or self._find_command_template_for_tool(
                        settings,
                        decision.tool_id,
                    )
                    normalized_command_signature = self._normalize_text_token(
                        SchedulerPlanner._command_signature(str(target.protocol or "tcp"), command_template)
                    )
                    if (
                            normalized_command_signature
                            and (
                                normalized_command_signature in attempted_command_signatures
                                or normalized_command_signature in round_scheduled_command_signatures
                            )
                    ):
                        duplicate_filtered_count += 1
                        continue

                    round_selected_tool_ids.append(normalized_tool_id)
                    if normalized_family_id:
                        round_selected_family_ids.append(normalized_family_id)

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
                        if normalized_family_id:
                            attempted_family_ids.add(normalized_family_id)
                        if normalized_command_signature:
                            attempted_command_signatures.add(normalized_command_signature)
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
                            if normalized_family_id:
                                round_scheduled_family_ids.add(normalized_family_id)
                            if normalized_command_signature:
                                round_scheduled_command_signatures.add(normalized_command_signature)
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
                                runner_preference=str((engagement_policy or {}).get("runner_preference", "") or ""),
                            ))
                        else:
                            attempted_tool_ids.add(normalized_tool_id)
                            if normalized_family_id:
                                attempted_family_ids.add(normalized_family_id)
                            if normalized_command_signature:
                                attempted_command_signatures.add(normalized_command_signature)
                            round_progress = True
                            if action == "queued":
                                summary["approval_queued"] += 1
                            else:
                                summary["skipped"] += 1
                        continue

                    round_scheduled_tool_ids.add(normalized_tool_id)
                    if normalized_family_id:
                        round_scheduled_family_ids.add(normalized_family_id)
                    if normalized_command_signature:
                        round_scheduled_command_signatures.add(normalized_command_signature)
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
                        runner_preference=str((engagement_policy or {}).get("runner_preference", "") or ""),
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
                    normalized_family_id = self._normalize_text_token(getattr(decision, "family_id", ""))
                    if normalized_family_id:
                        attempted_family_ids.add(normalized_family_id)
                    command_template = str(getattr(decision, "command_template", "") or "")
                    if not command_template:
                        command_template = self._find_command_template_for_tool(settings, getattr(decision, "tool_id", ""))
                    normalized_command_signature = self._normalize_text_token(
                        SchedulerPlanner._command_signature(str(target.protocol or "tcp"), command_template)
                    )
                    if normalized_command_signature:
                        attempted_command_signatures.add(normalized_command_signature)
                    round_progress = True
                    if executed:
                        summary["executed"] += 1
                    else:
                        summary["skipped"] += 1

                post_round_context = context
                if use_feedback_loop and build_context:
                    post_round_context = build_context(
                        target=target,
                        attempted_tool_ids=set(attempted_tool_ids),
                        attempted_family_ids=set(attempted_family_ids),
                        attempted_command_signatures=set(attempted_command_signatures),
                        recent_output_chars=int(resolved_options.recent_output_chars or 900),
                        analysis_mode=resolved_options.analysis_mode,
                    )

                round_snapshot = self._build_round_snapshot(
                    round_number=len(recent_rounds) + 1,
                    context=post_round_context,
                    provider_payload=provider_payload if isinstance(locals().get("provider_payload"), dict) else {},
                    decision_tool_ids=round_selected_tool_ids,
                    decision_family_ids=round_selected_family_ids,
                    duplicate_filtered_count=duplicate_filtered_count,
                    suppressed_filtered_count=suppressed_filtered_count,
                    recent_rounds=recent_rounds,
                )
                previous_round = recent_rounds[-1] if recent_rounds else None
                round_snapshot["progress_score"] = self._round_progress_score(previous_round, round_snapshot)
                recent_rounds.append(round_snapshot)
                if len(recent_rounds) > 8:
                    recent_rounds = recent_rounds[-8:]

                if not round_progress:
                    break
                if not use_feedback_loop:
                    break

        return summary
