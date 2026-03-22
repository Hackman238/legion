import logging
import json
import re
import shlex
import threading
from typing import Any, Dict, List, Optional, Set

from app.scheduler.family import build_command_family_id
from app.scheduler.models import PlanStep
from app.scheduler.policy_engine import evaluate_policy_for_risk_tags
from app.scheduler.policy import EngagementPolicy, normalize_engagement_policy
from app.scheduler.providers import (
    ProviderError,
    get_last_provider_payload,
    rank_actions_with_provider,
    select_web_followup_with_provider,
)
from app.scheduler.registry import ActionRegistry
from app.scheduler.strategy_packs import evaluate_action_strategy, select_strategy_packs
from app.scheduler.tool_prompt_registry import tool_ids_for_prompt_group

logger = logging.getLogger(__name__)

ScheduledAction = PlanStep


class SchedulerPlanner:
    WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}
    WEB_AI_BASELINE_TOOL_IDS = tuple(tool_ids_for_prompt_group("web_baseline"))
    WEB_AI_DEEP_WEB_TOOL_IDS = tuple(tool_ids_for_prompt_group("web_deep"))
    WEB_AI_TARGETED_NUCLEI_TOOL_IDS = tuple(tool_ids_for_prompt_group("web_targeted_nuclei"))
    WEB_AI_GENERIC_HTTP_FOLLOWUP_TOOL_IDS = tuple(tool_ids_for_prompt_group("web_http_followup"))
    WEB_AI_SPECIALIST_FOLLOWUP_TOOL_IDS = tuple(tool_ids_for_prompt_group("web_specialist_followup"))
    WEB_AI_SPECIALIST_FOLLOWUP_BONUS = 18.0
    STRICT_COVERAGE_GAP_IDS = {
        "missing_discovery",
        "missing_banner",
        "missing_screenshot",
        "missing_remote_screenshot",
        "missing_nmap_vuln",
        "missing_nuclei_auto",
        "missing_whatweb",
        "missing_nikto",
        "missing_web_content_discovery",
        "missing_http_followup",
        "missing_smb_signing_checks",
        "missing_internal_safe_enum",
    }
    GENERIC_WEB_TOOL_TOKENS = {
        "http", "https", "ssl", "tls", "web", "proxy", "alt",
        "scan", "scanner", "check", "checker", "test", "testing",
        "enum", "enumerate", "discovery", "discover", "fingerprint",
        "banner", "title", "headers", "robots", "favicon", "version",
        "script", "scripts", "vuln", "vulnerability", "cve", "path", "default",
        "nmap", "nse", "nuclei", "nikto", "whatweb", "httpx", "wafw00f", "sslscan", "sslyze",
        "feroxbuster", "gobuster", "dirsearch", "ffuf", "wordlist", "content",
        "port", "ports", "tcp", "udp", "open", "service", "status",
        "run", "quick", "full", "safe", "basic", "manual",
        "usr", "bin", "sbin", "local", "share", "opt", "etc", "tmp", "var", "dev", "home",
        "python", "bash", "shell", "command", "echo", "cat", "grep", "awk", "sed",
        "txt", "json", "xml", "html", "log", "out", "output", "report",
        "silent", "color", "timeout", "threads", "thread", "rate", "verbose",
        "dir", "dirs", "list", "lists", "wordlists", "dirb", "common", "url",
    }
    IGNORED_CONTEXT_TOKENS = {
        "unknown", "localhost", "local", "internal", "external", "customer",
        "host", "target", "network", "service", "device",
        "http", "https", "ssl", "tls", "tcp", "udp",
    }
    SPECIALIZED_WEB_TOOL_RULES = (
        {
            "tokens": ("wpscan", "wordpress", "wp-"),
            "required_signals": ("wordpress_detected",),
        },
        {
            "tokens": ("vmware", "vsphere", "vcenter", "esxi"),
            "required_signals": ("vmware_detected",),
        },
        {
            "tokens": ("coldfusion", "cfusion"),
            "required_signals": ("coldfusion_detected",),
        },
        {
            "tokens": ("webdav",),
            "required_signals": ("webdav_detected", "iis_detected"),
        },
        {
            "tokens": ("http-iis", "microsoft-iis", "iis-"),
            "required_signals": ("iis_detected",),
        },
        {
            "tokens": ("huawei", "hg5x"),
            "required_signals": ("huawei_detected",),
        },
    )

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self._thread_state = threading.local()

    def _set_last_provider_payload(self, payload: Optional[Dict[str, Any]] = None):
        try:
            self._thread_state.last_provider_payload = dict(payload or {})
        except Exception:
            self._thread_state.last_provider_payload = {}

    def get_last_provider_payload(self, clear: bool = False) -> Dict[str, Any]:
        payload = getattr(self._thread_state, "last_provider_payload", {}) or {}
        result = dict(payload) if isinstance(payload, dict) else {}
        if clear:
            self._set_last_provider_payload({})
        return result

    def plan_actions(
            self,
            service: str,
            protocol: str,
            settings,
            *,
            context: Optional[Dict[str, Any]] = None,
            excluded_tool_ids: Optional[List[str]] = None,
            excluded_family_ids: Optional[List[str]] = None,
            excluded_command_signatures: Optional[List[str]] = None,
            limit: Optional[int] = None,
            engagement_policy: Optional[Dict[str, Any]] = None,
            mode_override: Optional[str] = None,
    ) -> List[PlanStep]:
        return self.plan_steps(
            service,
            protocol,
            settings,
            context=context,
            excluded_tool_ids=excluded_tool_ids,
            excluded_family_ids=excluded_family_ids,
            excluded_command_signatures=excluded_command_signatures,
            limit=limit,
            engagement_policy=engagement_policy,
            mode_override=mode_override,
        )

    def plan_steps(
            self,
            service: str,
            protocol: str,
            settings,
            *,
            context: Optional[Dict[str, Any]] = None,
            excluded_tool_ids: Optional[List[str]] = None,
            excluded_family_ids: Optional[List[str]] = None,
            excluded_command_signatures: Optional[List[str]] = None,
            limit: Optional[int] = None,
            engagement_policy: Optional[Dict[str, Any]] = None,
            mode_override: Optional[str] = None,
    ) -> List[PlanStep]:
        self._set_last_provider_payload({})
        prefs = self.config_manager.load()
        mode = str(mode_override or prefs.get("mode", "deterministic") or "deterministic").strip().lower()
        if mode not in {"deterministic", "ai"}:
            mode = "deterministic"
        policy = normalize_engagement_policy(
            engagement_policy or prefs.get("engagement_policy", {}),
            fallback_goal_profile=str(prefs.get("goal_profile", "internal_asset_discovery") or "internal_asset_discovery"),
        )
        dangerous_categories = self.config_manager.get_dangerous_categories()
        excluded = self._normalize_tool_id_set(excluded_tool_ids)
        excluded.update(self._normalize_tool_id_set(prefs.get("disabled_tool_ids", [])))
        excluded_families = self._normalize_text_token_set(excluded_family_ids)
        excluded_signatures = self._normalize_text_token_set(excluded_command_signatures)
        registry = self.build_action_registry(settings, dangerous_categories)

        if mode == "ai":
            actions = self._plan_ai(
                service,
                protocol,
                registry,
                policy,
                dangerous_categories,
                context=context,
                excluded_tool_ids=excluded,
                excluded_family_ids=excluded_families,
                excluded_command_signatures=excluded_signatures,
                limit=limit,
            )
            if actions:
                return actions
            # deterministic fallback when AI path cannot produce candidates.
            mode = "deterministic"

        return self._plan_deterministic(
            service,
            protocol,
            registry,
            policy,
            dangerous_categories,
            mode=mode,
            context=context,
            excluded_tool_ids=excluded,
            excluded_family_ids=excluded_families,
            excluded_command_signatures=excluded_signatures,
            limit=limit,
        )

    @staticmethod
    def build_action_registry(settings, dangerous_categories: Optional[List[str]] = None) -> ActionRegistry:
        return ActionRegistry.from_settings(settings, dangerous_categories=dangerous_categories)

    def _plan_deterministic(self, service: str, protocol: str, registry: ActionRegistry, policy: EngagementPolicy,
                            dangerous_categories: List[str], mode: str = "deterministic",
                            context: Optional[Dict[str, Any]] = None,
                            excluded_tool_ids: Optional[Set[str]] = None,
                            excluded_family_ids: Optional[Set[str]] = None,
                            excluded_command_signatures: Optional[Set[str]] = None,
                            limit: Optional[int] = None) -> List[PlanStep]:
        service_name = str(service or "").strip().rstrip("?")
        protocol_name = str(protocol or "tcp").strip().lower()
        decisions = []
        excluded = set(excluded_tool_ids or set())
        excluded_families = set(excluded_family_ids or set())
        excluded_signatures = set(excluded_command_signatures or set())
        policy_snapshot_hash = self._policy_snapshot_hash(policy, dangerous_categories)
        target_ref = self._build_target_ref(service_name, protocol_name, policy=policy, context=context)
        selected_packs = self._select_strategy_packs(
            service_name,
            protocol_name,
            policy,
            context=context,
        )
        ranked_steps = []

        for index, action in enumerate(registry.for_deterministic(service_name, protocol_name)):
            tool_id = str(action.tool_id)
            family_id = build_command_family_id(tool_id, protocol_name, action.command_template or tool_id)
            command_signature = self._command_signature(protocol_name, action.command_template or tool_id)
            if (
                    self._normalized_tool_id(tool_id) in excluded
                    or self._normalize_text_token(family_id) in excluded_families
                    or self._normalize_text_token(command_signature) in excluded_signatures
            ):
                continue
            if self._candidate_blocked_by_tool_audit(
                    tool_id=tool_id,
                    command_template=str(action.command_template or ""),
                    context=context,
            ):
                continue
            strategy_guidance = evaluate_action_strategy(
                action,
                selected_packs,
                policy,
                context=context,
            )
            step = PlanStep.from_action_spec(
                action,
                origin_mode=mode,
                origin_planner="scheduler_deterministic",
                engagement_preset=policy.preset,
                policy_snapshot_hash=policy_snapshot_hash,
                target_ref=target_ref,
                parameters={"protocol": protocol_name},
                rationale=self._build_deterministic_rationale(
                    action,
                    selected_packs,
                    strategy_guidance,
                ),
                success_criteria=["Action completed without execution errors."],
                selection_score=1.0 + float(strategy_guidance.bonus or 0.0),
                family_id=family_id,
                risk_tags=list(action.risk_tags),
                pack_ids=list(strategy_guidance.pack_ids),
                coverage_gap=str(strategy_guidance.coverage_gap or ""),
                coverage_notes=str(strategy_guidance.coverage_notes or ""),
                evidence_expectations=list(strategy_guidance.evidence_expectations),
            )
            self._apply_policy_decision(step, policy)
            ranked_steps.append((index, step))
        if self._context_has_strategy_signals(context):
            ranked_steps.sort(key=lambda item: (-float(item[1].score), int(item[0])))
        decisions = [item[1] for item in ranked_steps]
        if limit is not None:
            try:
                max_items = int(limit)
            except (TypeError, ValueError):
                max_items = 0
            if max_items > 0:
                return decisions[:max_items]
        return decisions

    def _plan_ai(self, service: str, protocol: str, registry: ActionRegistry, policy: EngagementPolicy,
                 dangerous_categories: List[str],
                 context: Optional[Dict[str, Any]] = None,
                 excluded_tool_ids: Optional[Set[str]] = None,
                 excluded_family_ids: Optional[Set[str]] = None,
                 excluded_command_signatures: Optional[Set[str]] = None,
                 limit: Optional[int] = None) -> List[PlanStep]:
        service_name = str(service or "").strip().rstrip("?")
        protocol_name = str(protocol or "tcp").strip().lower()
        candidates_by_tool = {}
        excluded = set(excluded_tool_ids or set())
        excluded_families = set(excluded_family_ids or set())
        excluded_signatures = set(excluded_command_signatures or set())
        policy_snapshot_hash = self._policy_snapshot_hash(policy, dangerous_categories)
        target_ref = self._build_target_ref(service_name, protocol_name, policy=policy, context=context)
        selected_packs = self._select_strategy_packs(
            service_name,
            protocol_name,
            policy,
            context=context,
        )

        for action in registry.for_ai_selection(service_name, protocol_name):
            label = str(action.label)
            tool_id = str(action.tool_id)
            family_id = build_command_family_id(tool_id, protocol_name, action.command_template or tool_id)
            command_signature = self._command_signature(protocol_name, action.command_template or tool_id)
            if (
                    self._normalized_tool_id(tool_id) in excluded
                    or self._normalize_text_token(family_id) in excluded_families
                    or self._normalize_text_token(command_signature) in excluded_signatures
            ):
                continue

            candidates_by_tool[tool_id] = {
                "action": action,
                "tool_id": tool_id,
                "label": label,
                "command_template": str(action.command_template),
                "service_scope": ",".join(action.service_scope),
                "family_id": family_id,
                "command_signature": command_signature,
            }

        candidates = list(candidates_by_tool.values())
        candidates = self._filter_candidates_with_context(candidates, context)

        if not candidates:
            return []

        config = self.config_manager.load()
        feature_flags = config.get("feature_flags", {}) if isinstance(config, dict) else {}
        provider_name = str(config.get("provider", "none") or "none").strip().lower()
        provider_cfg = config.get("providers", {}).get(provider_name, {}) if isinstance(config.get("providers", {}), dict) else {}
        provider_enabled = bool(provider_cfg.get("enabled", False)) if isinstance(provider_cfg, dict) else False
        if provider_enabled and self._should_abstain_for_unmatched_strict_coverage_gap(candidates, context=context):
            return []

        scores_by_tool = {}
        rationales_by_tool = {}
        web_followup_sidecar_enabled = bool(feature_flags.get("scheduler_web_followup_sidecar", False)) \
            if isinstance(feature_flags, dict) else False
        provider_error = ""
        provider_payload = {}
        specialist_selected_tool_ids = set()
        specialist_reason_by_tool = {}
        try:
            provider_ranked = rank_actions_with_provider(
                config=config,
                goal_profile=policy.legacy_goal_profile,
                service=service_name,
                protocol=protocol_name,
                candidates=candidates,
                context=context or {},
            )
            provider_payload = get_last_provider_payload(clear=True)
            self._set_last_provider_payload(provider_payload)
        except ProviderError as exc:
            provider_error = str(exc)
            logger.warning(
                "AI scheduler provider failed for %s/%s using provider=%s: %s",
                service_name,
                protocol_name,
                provider_name,
                provider_error,
            )
            provider_payload = get_last_provider_payload(clear=True)
            self._set_last_provider_payload(provider_payload)
            provider_ranked = []

        for item in provider_ranked:
            tool_id = str(item.get("tool_id", "")).strip()
            if not tool_id:
                continue
            try:
                score = float(item.get("score", 50))
            except (TypeError, ValueError):
                score = 50.0
            scores_by_tool[tool_id] = score
            rationales_by_tool[tool_id] = str(item.get("rationale", "")).strip()

        if provider_ranked and self._provider_rankings_skip_visible_gap_closers(
                provider_ranked=provider_ranked,
                candidates=candidates,
                context=context,
        ):
            scores_by_tool = {}
            rationales_by_tool = {}

        if (
                provider_enabled
                and not provider_error
                and bool(web_followup_sidecar_enabled)
                and self._should_run_web_followup_sidecar(service_name, context=context)
        ):
            specialist_candidates = self._web_followup_sidecar_candidates(candidates, context=context)
            if specialist_candidates:
                try:
                    sidecar_payload = select_web_followup_with_provider(
                        config=config,
                        goal_profile=policy.legacy_goal_profile,
                        service=service_name,
                        protocol=protocol_name,
                        candidates=specialist_candidates,
                        context=context or {},
                    )
                    allowed_sidecar_tool_ids = {
                        self._normalized_tool_id(item.get("tool_id", ""))
                        for item in specialist_candidates
                        if str(item.get("tool_id", "")).strip()
                    }
                    normalized_sidecar_tool_ids = [
                        tool_id
                        for tool_id in self._normalize_tool_id_set(sidecar_payload.get("selected_tool_ids", []))
                        if tool_id in allowed_sidecar_tool_ids
                    ]
                    sidecar_payload["selected_tool_ids"] = normalized_sidecar_tool_ids
                    specialist_selected_tool_ids = set(normalized_sidecar_tool_ids)
                    sidecar_reason = str(sidecar_payload.get("reason", "") or "").strip()
                    if sidecar_reason:
                        for tool_id in specialist_selected_tool_ids:
                            specialist_reason_by_tool[tool_id] = sidecar_reason
                    provider_payload = self._merge_specialist_sidecar_payload(provider_payload, sidecar_payload)
                    self._set_last_provider_payload(provider_payload)
                except ProviderError as exc:
                    logger.warning(
                        "AI web follow-up sidecar failed for %s/%s using provider=%s: %s",
                        service_name,
                        protocol_name,
                        provider_name,
                        exc,
                    )

        decisions = []
        for candidate in candidates:
            action = candidate["action"]
            tool_id = candidate["tool_id"]
            label = candidate["label"]
            command_template = candidate["command_template"]
            family_id = str(candidate.get("family_id", "") or build_command_family_id(tool_id, protocol_name, command_template))
            command_signature = str(candidate.get("command_signature", "") or self._command_signature(protocol_name, command_template))
            unavailable_tools = self._context_unavailable_tool_ids(context)
            tool_unavailable = (
                self._normalized_tool_id(tool_id) in unavailable_tools
                or bool(self._command_tool_tokens(command_template) & unavailable_tools)
            )

            score = scores_by_tool.get(tool_id)
            provider_supplied_score = score is not None
            if score is None:
                score = self._score_candidate(tool_id, label, command_template, policy)
            score = self._score_with_context(
                score,
                tool_id=tool_id,
                family_id=family_id,
                command_signature=command_signature,
                label=label,
                command_template=command_template,
                context=context,
            )
            strategy_guidance = evaluate_action_strategy(
                action,
                selected_packs,
                policy,
                context=context,
            )
            if not provider_supplied_score:
                score = float(score) + float(strategy_guidance.bonus or 0.0)
            if self._is_web_service(service_name) and not tool_unavailable:
                if tool_id == "nuclei-web":
                    score = max(score, 96.0)
                elif tool_id == "nmap-vuln.nse":
                    score = max(score, 94.0)
                elif tool_id == "screenshooter":
                    score = max(score, 92.0)
                elif tool_id == "nuclei-cves":
                    score = max(score, 90.0)
                elif tool_id == "nuclei-exposures":
                    score = max(score, 88.0)
                elif tool_id in {"whatweb", "whatweb-http", "whatweb-https"}:
                    score = max(score, 84.0)
                elif tool_id == "nikto":
                    score = max(score, 82.0)
            if self._normalized_tool_id(tool_id) in specialist_selected_tool_ids:
                score = min(100.0, max(float(score) + float(self.WEB_AI_SPECIALIST_FOLLOWUP_BONUS), 86.0))
            rationale = rationales_by_tool.get(tool_id) or self._build_rationale(
                tool_id,
                policy,
                list(action.risk_tags),
                provider_name=provider_name if provider_enabled else "",
                provider_error=provider_error,
                provider_returned_rankings=bool(provider_ranked),
                context_signals=self._active_context_signals(context),
            )
            rationale = self._append_strategy_context(rationale, strategy_guidance)
            rationale = self._append_specialist_sidecar_context(
                rationale,
                tool_id=tool_id,
                specialist_reason=specialist_reason_by_tool.get(self._normalized_tool_id(tool_id), ""),
            )

            step = PlanStep.from_action_spec(
                action,
                origin_mode="ai",
                origin_planner="scheduler_ai",
                engagement_preset=policy.preset,
                policy_snapshot_hash=policy_snapshot_hash,
                target_ref=target_ref,
                parameters={"protocol": protocol_name},
                rationale=rationale,
                success_criteria=["Action completed without execution errors."],
                selection_score=score,
                family_id=family_id,
                risk_tags=list(action.risk_tags),
                pack_ids=list(strategy_guidance.pack_ids),
                coverage_gap=str(strategy_guidance.coverage_gap or ""),
                coverage_notes=str(strategy_guidance.coverage_notes or ""),
                evidence_expectations=list(strategy_guidance.evidence_expectations),
            )
            self._apply_policy_decision(step, policy)
            decisions.append(step)

        decisions.sort(key=lambda item: item.score, reverse=True)
        resolved_limit = self._default_ai_limit(service_name, context=context)
        if limit is not None:
            try:
                max_items = int(limit)
            except (TypeError, ValueError):
                max_items = 0
            if max_items > 0:
                resolved_limit = max_items
        return self._apply_web_ai_baseline(service_name, decisions, context=context, limit=resolved_limit)

    @staticmethod
    def _parse_services(raw: str) -> List[str]:
        cleaned = raw.strip().strip('"')
        if not cleaned:
            return []
        return [item.strip().strip('"') for item in cleaned.split(",") if item.strip()]

    @staticmethod
    def _port_actions_by_id(port_actions: List[List[str]]) -> Dict[str, Dict[str, str]]:
        result = {}
        for action in port_actions:
            action_id = str(action[1])
            result[action_id] = {
                "label": str(action[0]),
                "command": str(action[2]),
                "services": str(action[3] if len(action) > 3 else ""),
            }
        return result

    @staticmethod
    def _score_candidate(tool_id: str, label: str, command_template: str, policy: EngagementPolicy) -> float:
        score = 50.0
        text = " ".join([tool_id.lower(), label.lower(), command_template.lower()])
        has_vuln_signal = any(token in text for token in [
            "script=vuln",
            "--script vuln",
            "vuln.nse",
            " nmap-vuln",
        ])
        has_nuclei_signal = "nuclei" in text
        has_web_content_discovery = any(token in text for token in ["feroxbuster", "gobuster"])
        has_legacy_dirbuster = any(token in text for token in ["dirbuster", "java -xmx256m -jar"])

        if policy.intent == "recon":
            if any(token in text for token in ["enum", "discover", "info", "list", "scan", "fingerprint", "title", "headers"]):
                score += 20
            if policy.scope == "internal" and any(token in text for token in ["smb", "ldap", "rpc", "snmp", "kerberos", "rdp", "winrm"]):
                score += 12
            if policy.scope == "external" and any(token in text for token in ["whatweb", "sslscan", "sslyze", "http", "https", "web", "screenshot"]):
                score += 14
            if has_vuln_signal:
                score += 14
            if has_nuclei_signal:
                score += 8 if policy.scope == "internal" else 12
            if has_web_content_discovery:
                score += 6 if policy.noise_budget == "low" else 10
        else:
            if any(token in text for token in ["whatweb", "sslscan", "sslyze", "nikto", "nmap", "validate", "check"]):
                score += 18
            if policy.scope == "external" and any(token in text for token in ["http", "https", "web"]):
                score += 10
            if policy.scope == "internal" and any(token in text for token in ["smb", "ldap", "rpc", "kerberos", "rdp", "winrm"]):
                score += 10
            if has_vuln_signal:
                score += 22
            if has_nuclei_signal:
                score += 18 if policy.scope == "internal" else 28
            if has_web_content_discovery:
                score += 10 if policy.scope == "external" else 6

        if any(token in text for token in ["brute", "spray", "relay", "responder", "persistence", "pivot", "lateral", "exploit"]):
            if not policy.allow_exploitation:
                score -= 30
            if policy.credential_attack_mode == "blocked":
                score -= 18
        if any(token in text for token in ["flood", "dos", "masscan"]):
            score -= 28 if policy.detection_risk_mode == "low" else 16
        if policy.noise_budget == "low" and has_web_content_discovery:
            score -= 6

        if has_legacy_dirbuster:
            score -= 35

        return score

    @classmethod
    def _score_with_context(
            cls,
            score: float,
            *,
            tool_id: str,
            family_id: str = "",
            command_signature: str = "",
            label: str,
            command_template: str,
            context: Optional[Dict[str, Any]],
    ) -> float:
        value = float(score)
        if not isinstance(context, dict):
            return max(0.0, min(value, 100.0))

        tool_norm = cls._normalized_tool_id(tool_id)
        attempted = cls._normalize_tool_id_set(context.get("attempted_tool_ids", []))
        attempted_families = cls._normalize_text_token_set(context.get("attempted_family_ids", []))
        attempted_signatures = cls._normalize_text_token_set(context.get("attempted_command_signatures", []))
        signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
        missing_tools = cls._context_unavailable_tool_ids(context)
        command_tools = cls._command_tool_tokens(command_template)
        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        coverage_recommended = cls._normalize_tool_id_set(
            coverage.get("recommended_tool_ids", []) if isinstance(coverage.get("recommended_tool_ids", []), list) else []
        )
        analysis_mode = str(
            coverage.get("analysis_mode", "")
            or context.get("analysis_mode", "")
            or "standard"
        ).strip().lower()

        text = " ".join([str(tool_id or ""), str(label or ""), str(command_template or "")]).lower()
        if tool_norm in attempted:
            value -= 50.0
        if cls._normalize_text_token(family_id) in attempted_families:
            value -= 42.0
        if cls._normalize_text_token(command_signature) in attempted_signatures:
            value -= 58.0
        if tool_norm in missing_tools or bool(command_tools & missing_tools):
            value -= 90.0
        if tool_norm in coverage_recommended:
            value += 22.0
        if "missing_discovery" in coverage_missing and (tool_norm == "nmap" or tool_norm.startswith("nmap")):
            value += 34.0
        if "missing_banner" in coverage_missing and tool_norm == "banner":
            value += 26.0
        if {"missing_screenshot", "missing_remote_screenshot"} & coverage_missing and tool_norm == "screenshooter":
            value += 34.0
        if "missing_nmap_vuln" in coverage_missing and tool_norm == "nmap-vuln.nse":
            value += 40.0
        if "missing_nuclei_auto" in coverage_missing and tool_norm == "nuclei-web":
            value += 40.0
        if "missing_followup_after_vuln" in coverage_missing and tool_norm in {
            "whatweb",
            "whatweb-http",
            "whatweb-https",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "nuclei-cves",
            "nuclei-exposures",
            "curl-headers",
            "curl-options",
            "curl-robots",
        }:
            value += 24.0
        if "missing_http_followup" in coverage_missing and tool_norm in {
            "curl-headers",
            "curl-options",
            "curl-robots",
        }:
            value += 22.0
        if "missing_cpe_cve_enrichment" in coverage_missing and cls._matches_any_token(
                text,
                ("nmap-vuln", "nuclei", "vuln", "cve"),
        ):
            value += 24.0
        if "missing_whatweb" in coverage_missing and cls._matches_any_token(text, ("whatweb",)):
            value += 24.0
        if "missing_nikto" in coverage_missing and cls._matches_any_token(text, ("nikto",)):
            value += 24.0
        if "missing_web_content_discovery" in coverage_missing and cls._matches_any_token(text, ("feroxbuster", "gobuster", "web-content-discovery", "dirsearch", "ffuf")):
            value += 24.0
        if "missing_smb_signing_checks" in coverage_missing and cls._matches_any_token(text, ("smb-security-mode", "smb2-security-mode")):
            value += 26.0
        if "missing_internal_safe_enum" in coverage_missing and cls._matches_any_token(text, ("enum4linux", "smbmap", "rpcclient", "smb-enum-users")):
            value += 28.0
        if analysis_mode == "dig_deeper" and "missing_followup_after_vuln" in coverage_missing and cls._matches_any_token(
                text,
                ("nikto", "whatweb", "web-content-discovery", "dirsearch", "ffuf", "sslscan", "sslyze", "wafw00f"),
        ):
            value += 18.0
        if analysis_mode == "dig_deeper" and tool_norm in {
            "nuclei-cves",
            "nuclei-exposures",
            "curl-headers",
            "curl-options",
            "curl-robots",
        }:
            value += 16.0

        if bool(signals.get("web_service")) and any(token in text for token in ["http", "https", "web", "nuclei", "waf"]):
            value += 7.0
        if bool(signals.get("rdp_service")) and "screenshooter" in text:
            value += 14.0
        if bool(signals.get("vnc_service")) and "screenshooter" in text:
            value += 14.0
        if (bool(signals.get("rdp_service")) or bool(signals.get("vnc_service"))) and "banner" in text:
            value += 6.0
        if bool(signals.get("tls_detected")) and any(token in text for token in ["https", "ssl", "tls", "sslyze", "sslscan", "nuclei"]):
            value += 8.0
        if bool(signals.get("directory_listing")) and any(token in text for token in ["feroxbuster", "gobuster", "dirsearch", "ffuf", "web-content"]):
            value += 8.0
        if bool(signals.get("smb_signing_disabled")) and any(token in text for token in ["smb", "crackmapexec", "enum", "rpc"]):
            value += 10.0
        if bool(signals.get("waf_detected")) and "waf" in text:
            value += 10.0
        if int(signals.get("vuln_hits", 0) or 0) > 0 and any(token in text for token in ["vuln", "cve", "nuclei", "exploit"]):
            value += 6.0
        if int(signals.get("vuln_hits", 0) or 0) > 0 and tool_norm in {"nmap-vuln.nse", "nuclei-cves", "nuclei-exposures"}:
            value += 18.0
        if cls._matches_any_token(text, ("ubiquiti", "unifi", "ubnt")) and bool(signals.get("ubiquiti_detected")):
            value += 10.0
        if cls._matches_any_token(text, ("nginx", "apache", "http")) and bool(signals.get("web_service")):
            value += 2.0
        if bool(signals.get("wordpress_detected")) and tool_norm in {"wpscan", "nuclei-wordpress"}:
            value += 22.0
        host_cves = context.get("host_cves", []) if isinstance(context.get("host_cves", []), list) else []
        if host_cves and tool_norm in {
            "nmap-vuln.nse",
            "nuclei-cves",
            "nuclei-exposures",
            "whatweb",
            "whatweb-http",
            "whatweb-https",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
        }:
            value += 18.0

        specialization_delta = cls._specialized_tool_signal_delta(text, signals)
        value += specialization_delta
        if bool(signals.get("web_service")):
            value += cls._generic_context_signal_delta(
                tool_id=str(tool_id or ""),
                label=str(label or ""),
                command_template=str(command_template or ""),
                context=context,
            )

        return max(0.0, min(value, 100.0))

    @classmethod
    def _filter_candidates_with_context(
            cls,
            candidates: List[Dict[str, str]],
            context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        if not isinstance(context, dict):
            return candidates

        signals = context.get("signals", {})
        if not isinstance(signals, dict):
            return candidates
        missing_tools = cls._context_unavailable_tool_ids(context)
        suppressed_tools = cls._context_suppressed_tool_ids(context)
        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        baseline_missing = bool(coverage_missing & {
            "missing_discovery",
            "missing_screenshot",
            "missing_remote_screenshot",
            "missing_nmap_vuln",
            "missing_nuclei_auto",
            "missing_cpe_cve_enrichment",
        })
        observed_tokens = cls._observed_context_tokens(context)
        web_service = bool(signals.get("web_service"))

        filtered: List[Dict[str, str]] = []
        for candidate in candidates:
            tool_id = str(candidate.get("tool_id", "") or "")
            label = str(candidate.get("label", "") or "")
            command_template = str(candidate.get("command_template", "") or "")
            tool_text = " ".join([
                tool_id,
                label,
                command_template,
            ]).lower()
            command_tools = cls._command_tool_tokens(command_template)

            blocked = False
            specialized_rule_matched = False
            if cls._candidate_blocked_by_tool_audit(
                    tool_id=tool_id,
                    command_template=command_template,
                    context=context,
            ):
                blocked = True
            if (
                    cls._normalized_tool_id(tool_id) in missing_tools
                    or bool(command_tools & missing_tools)
                    or cls._normalized_tool_id(tool_id) in suppressed_tools
            ):
                blocked = True
            if cls._covered_web_followup_tool_already_satisfied(
                    tool_id=tool_id,
                    context=context,
            ):
                blocked = True
            if baseline_missing:
                if cls._matches_any_token(tool_text, ("coldfusion", "vmware", "webdav", "huawei", "drupal", "wordpress", "qnap", "domino")):
                    if cls._normalized_tool_id(tool_id) not in {
                        "nmap-vuln.nse",
                        "nuclei-web",
                        "screenshooter",
                        "whatweb",
                        "whatweb-http",
                        "whatweb-https",
                        "nikto",
                        "web-content-discovery",
                        "dirsearch",
                        "ffuf",
                        "banner",
                        "nmap",
                    }:
                        blocked = True

            for rule in cls.SPECIALIZED_WEB_TOOL_RULES:
                if not cls._matches_any_token(tool_text, rule.get("tokens", ())):
                    continue
                if not cls._has_any_signal(signals, rule.get("required_signals", ())):
                    blocked = True
                    break
                specialized_rule_matched = True

            if (
                    not blocked
                    and web_service
                    and observed_tokens
                    and not specialized_rule_matched
            ):
                specific_tokens = cls._candidate_specific_tokens(
                    tool_id=tool_id,
                    label=label,
                    command_template=command_template,
                )
                if "missing_web_content_discovery" in coverage_missing and cls._matches_any_token(
                        tool_text,
                        ("feroxbuster", "gobuster", "web-content-discovery", "dirsearch", "ffuf"),
                ):
                    specific_tokens = set()
                if "missing_internal_safe_enum" in coverage_missing and cls._matches_any_token(
                        tool_text,
                        ("enum4linux", "smbmap", "rpcclient", "smb-enum-users"),
                ):
                    specific_tokens = set()
                if specific_tokens and not (specific_tokens & observed_tokens):
                    blocked = True

            if not blocked:
                filtered.append(candidate)

        # Keep original candidates if pruning would remove everything.
        return filtered or candidates

    @classmethod
    def _covered_web_followup_tool_already_satisfied(
            cls,
            *,
            tool_id: str,
            context: Optional[Dict[str, Any]],
    ) -> bool:
        if not isinstance(context, dict):
            return False
        tool_norm = cls._normalized_tool_id(tool_id)
        if not tool_norm:
            return False

        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_has = coverage.get("has", {}) if isinstance(coverage.get("has", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        analysis_mode = str(
            coverage.get("analysis_mode", "")
            or context.get("analysis_mode", "")
            or "standard"
        ).strip().lower()
        if analysis_mode == "dig_deeper":
            return False

        summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
        reflection = summary.get("reflection_posture", {}) if isinstance(summary.get("reflection_posture", {}), dict) else {}
        reflection_promotes = cls._normalize_tool_id_set(reflection.get("promote_tool_ids", []))
        if tool_norm in reflection_promotes:
            return False

        if tool_norm in {"whatweb", "whatweb-http", "whatweb-https"}:
            return bool(coverage_has.get("whatweb")) and not bool(
                coverage_missing & {"missing_whatweb", "missing_technology_fingerprint"}
            )
        if tool_norm == "nikto":
            return bool(coverage_has.get("nikto")) and not bool(
                coverage_missing & {"missing_nikto", "missing_followup_after_vuln"}
            )
        if tool_norm in {"web-content-discovery", "dirsearch", "ffuf", "feroxbuster", "gobuster"}:
            return bool(coverage_has.get("web_content_discovery")) and not bool(
                coverage_missing & {"missing_web_content_discovery", "missing_followup_after_vuln"}
            )
        return False

    @classmethod
    def _tool_matches_coverage_gap(cls, *, tool_id: str, coverage_missing: Set[str]) -> bool:
        tool_norm = cls._normalized_tool_id(tool_id)
        if not tool_norm or not coverage_missing:
            return False
        if "missing_discovery" in coverage_missing and (tool_norm == "nmap" or tool_norm.startswith("nmap")):
            return True
        if "missing_banner" in coverage_missing and tool_norm == "banner":
            return True
        if {"missing_screenshot", "missing_remote_screenshot"} & coverage_missing and tool_norm in {"screenshooter", "x11screen"}:
            return True
        if "missing_nmap_vuln" in coverage_missing and tool_norm == "nmap-vuln.nse":
            return True
        if "missing_nuclei_auto" in coverage_missing and tool_norm == "nuclei-web":
            return True
        if "missing_cpe_cve_enrichment" in coverage_missing and tool_norm in {
            "nmap-vuln.nse",
            "nuclei-web",
            "nuclei-cves",
            "nuclei-exposures",
        }:
            return True
        if "missing_whatweb" in coverage_missing and tool_norm in {"whatweb", "whatweb-http", "whatweb-https"}:
            return True
        if "missing_nikto" in coverage_missing and tool_norm == "nikto":
            return True
        if "missing_web_content_discovery" in coverage_missing and tool_norm in {
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "feroxbuster",
            "gobuster",
        }:
            return True
        if "missing_http_followup" in coverage_missing and tool_norm in {"curl-headers", "curl-options", "curl-robots"}:
            return True
        if "missing_followup_after_vuln" in coverage_missing and tool_norm in {
            "whatweb",
            "whatweb-http",
            "whatweb-https",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "feroxbuster",
            "gobuster",
            "nuclei-cves",
            "nuclei-exposures",
            "curl-headers",
            "curl-options",
            "curl-robots",
        }:
            return True
        if "missing_smb_signing_checks" in coverage_missing and tool_norm in {"smb-security-mode", "smb2-security-mode"}:
            return True
        if "missing_internal_safe_enum" in coverage_missing and tool_norm in {
            "enum4linux-ng",
            "smbmap",
            "rpcclient-enum",
            "smb-enum-users.nse",
        }:
            return True
        return False

    @classmethod
    def _strict_coverage_gaps_without_visible_closer(
            cls,
            candidates: List[Dict[str, Any]],
            *,
            context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not isinstance(context, dict):
            return False
        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        strict_missing = coverage_missing & cls.STRICT_COVERAGE_GAP_IDS
        if not strict_missing or (coverage_missing - strict_missing):
            return False
        for candidate in list(candidates or []):
            if not isinstance(candidate, dict):
                continue
            if cls._tool_matches_coverage_gap(
                    tool_id=str(candidate.get("tool_id", "") or ""),
                    coverage_missing=strict_missing,
            ):
                return False
        return True

    @classmethod
    def _should_abstain_for_unmatched_strict_coverage_gap(
            cls,
            candidates: List[Dict[str, Any]],
            *,
            context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return cls._strict_coverage_gaps_without_visible_closer(candidates, context=context)

    @classmethod
    def _provider_rankings_skip_visible_gap_closers(
            cls,
            *,
            provider_ranked: List[Dict[str, Any]],
            candidates: List[Dict[str, Any]],
            context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not isinstance(context, dict):
            return False
        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        if not coverage_missing:
            return False
        has_visible_gap_closer = False
        for candidate in list(candidates or []):
            if not isinstance(candidate, dict):
                continue
            if cls._tool_matches_coverage_gap(
                    tool_id=str(candidate.get("tool_id", "") or ""),
                    coverage_missing=coverage_missing,
            ):
                has_visible_gap_closer = True
                break
        if not has_visible_gap_closer:
            return False

        for item in list(provider_ranked or []):
            if not isinstance(item, dict):
                continue
            if cls._tool_matches_coverage_gap(
                    tool_id=str(item.get("tool_id", "") or ""),
                    coverage_missing=coverage_missing,
            ):
                return False
        return True

    @staticmethod
    def _matches_any_token(text: str, tokens) -> bool:
        lowered = str(text or "").lower()
        return any(str(token or "").strip().lower() in lowered for token in list(tokens or []))

    @classmethod
    def _expand_tool_id_aliases(cls, values: Set[str]) -> Set[str]:
        expanded = set()
        for item in set(values or set()):
            token = cls._normalized_tool_id(item)
            if not token:
                continue
            expanded.add(token)
            if token in {"whatweb", "whatweb-http", "whatweb-https"}:
                expanded.update({"whatweb", "whatweb-http", "whatweb-https"})
            if token.endswith(".nse"):
                expanded.add("nmap")
        return expanded

    @classmethod
    def _context_audited_tool_availability(cls, context: Optional[Dict[str, Any]]) -> Dict[str, Set[str]]:
        if not isinstance(context, dict):
            return {
                "known": set(),
                "available": set(),
                "unavailable": set(),
            }

        tool_audit = context.get("tool_audit", {}) if isinstance(context.get("tool_audit", {}), dict) else {}
        available = cls._expand_tool_id_aliases(cls._normalize_tool_id_set(tool_audit.get("available_tool_ids", [])))
        unavailable = cls._expand_tool_id_aliases(cls._normalize_tool_id_set(tool_audit.get("unavailable_tool_ids", [])))
        unavailable.difference_update(available)
        return {
            "known": set(available) | set(unavailable),
            "available": set(available),
            "unavailable": set(unavailable),
        }

    @classmethod
    def _candidate_blocked_by_tool_audit(
            cls,
            *,
            tool_id: str,
            command_template: str,
            context: Optional[Dict[str, Any]],
    ) -> bool:
        availability = cls._context_audited_tool_availability(context)
        known = availability.get("known", set())
        if not known:
            return False

        matched = set()
        tool_norm = cls._normalized_tool_id(tool_id)
        if tool_norm in known:
            matched.add(tool_norm)
        matched.update(cls._command_tool_tokens(command_template) & known)
        if not matched:
            return False

        available = availability.get("available", set())
        return not bool(matched & available)

    @classmethod
    def _context_unavailable_tool_ids(cls, context: Optional[Dict[str, Any]]) -> Set[str]:
        if not isinstance(context, dict):
            return set()
        signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
        raw_missing = cls._normalize_tool_id_set(signals.get("missing_tools", []))
        raw_missing.update(cls._normalize_tool_id_set(signals.get("audited_missing_tools", [])))
        tool_audit = context.get("tool_audit", {}) if isinstance(context.get("tool_audit", {}), dict) else {}
        raw_missing.update(cls._normalize_tool_id_set(tool_audit.get("unavailable_tool_ids", [])))
        return cls._expand_tool_id_aliases(raw_missing)

    @classmethod
    def _context_suppressed_tool_ids(cls, context: Optional[Dict[str, Any]]) -> Set[str]:
        if not isinstance(context, dict):
            return set()
        summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
        reflection = summary.get("reflection_posture", {}) if isinstance(summary.get("reflection_posture", {}), dict) else {}
        raw_suppressed = cls._normalize_tool_id_set(reflection.get("suppress_tool_ids", []))
        host_ai_state = context.get("host_ai_state", {}) if isinstance(context.get("host_ai_state", {}), dict) else {}
        host_reflection = host_ai_state.get("reflection", {}) if isinstance(host_ai_state.get("reflection", {}), dict) else {}
        raw_suppressed.update(cls._normalize_tool_id_set(host_reflection.get("suppress_tool_ids", [])))
        return cls._expand_tool_id_aliases(raw_suppressed)

    @staticmethod
    def _command_tool_tokens(command: str) -> Set[str]:
        text = str(command or "").strip()
        if not text:
            return set()
        try:
            tokens = shlex.split(text, posix=True)
        except ValueError:
            tokens = re.findall(r"[A-Za-z0-9_./+-]+", text)

        wrappers = {"sudo", "env", "timeout", "nohup", "stdbuf", "nice"}
        shell_tokens = {"bash", "sh", "zsh", "fish"}
        control_tokens = {"&&", "||", ";", "|", "(", ")", "{", "}"}
        results: Set[str] = set()
        for token in tokens:
            current = str(token or "").strip()
            if not current or current in control_tokens:
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", current):
                continue
            base = current.rsplit("/", 1)[-1].strip().lower()
            if not base or base in wrappers or base in shell_tokens:
                continue
            if re.fullmatch(r"[a-z0-9][a-z0-9._+-]*", base):
                results.add(base)
        return results

    @staticmethod
    def _has_any_signal(signals: Dict[str, Any], names) -> bool:
        if not isinstance(signals, dict):
            return False
        return any(bool(signals.get(str(name))) for name in list(names or []))

    @classmethod
    def _specialized_tool_signal_delta(cls, tool_text: str, signals: Dict[str, Any]) -> float:
        if not isinstance(signals, dict):
            return 0.0

        delta = 0.0
        for rule in cls.SPECIALIZED_WEB_TOOL_RULES:
            if not cls._matches_any_token(tool_text, rule.get("tokens", ())):
                continue
            if cls._has_any_signal(signals, rule.get("required_signals", ())):
                delta += 12.0
            else:
                delta -= 40.0
        return delta

    @classmethod
    def _generic_context_signal_delta(
            cls,
            *,
            tool_id: str,
            label: str,
            command_template: str,
            context: Optional[Dict[str, Any]],
    ) -> float:
        if not isinstance(context, dict):
            return 0.0
        observed_tokens = cls._observed_context_tokens(context)
        if not observed_tokens:
            return 0.0
        specific_tokens = cls._candidate_specific_tokens(
            tool_id=tool_id,
            label=label,
            command_template=command_template,
        )
        if not specific_tokens:
            return 0.0
        if specific_tokens & observed_tokens:
            return 12.0
        return -28.0

    @classmethod
    def _candidate_specific_tokens(
            cls,
            *,
            tool_id: str,
            label: str,
            command_template: str,
    ) -> Set[str]:
        if cls._normalized_tool_id(tool_id) in {
            "nuclei-cves",
            "nuclei-exposures",
            "curl-headers",
            "curl-options",
            "curl-robots",
        }:
            return set()
        # Include command template to catch specialized scripts referenced in command text.
        source = " ".join([
            str(tool_id or ""),
            str(label or ""),
            str(command_template or ""),
        ]).lower()
        tokens = cls._tokenize(source)
        specific = set()
        for token in tokens:
            if token in cls.GENERIC_WEB_TOOL_TOKENS:
                continue
            if token in cls.IGNORED_CONTEXT_TOKENS:
                continue
            if token.isdigit():
                continue
            if len(token) < 3:
                continue
            specific.add(token)
        return specific

    @classmethod
    def _observed_context_tokens(cls, context: Optional[Dict[str, Any]]) -> Set[str]:
        if not isinstance(context, dict):
            return set()

        observed: Set[str] = set()
        target = context.get("target", {})
        if isinstance(target, dict):
            target_text = " ".join([
                str(target.get("hostname", "") or ""),
                str(target.get("os", "") or ""),
                str(target.get("service", "") or ""),
                str(target.get("service_product", "") or ""),
                str(target.get("service_version", "") or ""),
                str(target.get("service_extrainfo", "") or ""),
                " ".join(str(item or "") for item in target.get("host_open_services", []) if str(item or "").strip()),
                " ".join(str(item or "") for item in target.get("host_open_ports", []) if str(item or "").strip()),
                " ".join(str(item or "") for item in target.get("host_banners", []) if str(item or "").strip()),
            ]).lower()
            observed.update(cls._tokenize(target_text))

        host_ports = context.get("host_ports", [])
        if isinstance(host_ports, list):
            for item in host_ports[:72]:
                if not isinstance(item, dict):
                    continue
                port_text = " ".join([
                    str(item.get("service", "") or ""),
                    str(item.get("service_product", "") or ""),
                    str(item.get("service_version", "") or ""),
                    str(item.get("service_extrainfo", "") or ""),
                    str(item.get("banner", "") or ""),
                ]).lower()
                observed.update(cls._tokenize(port_text))

        inferred_technologies = context.get("inferred_technologies", [])
        if isinstance(inferred_technologies, list):
            for item in inferred_technologies[:64]:
                if not isinstance(item, dict):
                    continue
                observed.update(cls._tokenize(" ".join([
                    str(item.get("name", "") or ""),
                    str(item.get("version", "") or ""),
                    str(item.get("cpe", "") or ""),
                    str(item.get("evidence", "") or ""),
                ])))

        signals = context.get("signals", {})
        if isinstance(signals, dict):
            observed_tech = signals.get("observed_technologies", [])
            if isinstance(observed_tech, list):
                observed.update(cls._tokenize(" ".join(str(item or "") for item in observed_tech)))

            for key, value in signals.items():
                if isinstance(value, bool) and value and str(key).endswith("_detected"):
                    observed.update(cls._tokenize(str(key)[:-len("_detected")]))
                elif isinstance(value, str) and value.strip() and key in {"server", "vendor", "product"}:
                    observed.update(cls._tokenize(value))

        scripts = context.get("scripts", [])
        if isinstance(scripts, list):
            for item in scripts[:48]:
                if isinstance(item, dict):
                    observed.update(cls._tokenize(str(item.get("excerpt", "") or "")))

        processes = context.get("recent_processes", [])
        if isinstance(processes, list):
            for item in processes[:48]:
                if isinstance(item, dict):
                    observed.update(cls._tokenize(str(item.get("output_excerpt", "") or "")))

        host_ai_state = context.get("host_ai_state", {})
        if isinstance(host_ai_state, dict):
            ai_text_parts = []
            for item in list(host_ai_state.get("technologies", []) or [])[:32]:
                if not isinstance(item, dict):
                    continue
                ai_text_parts.append(" ".join([
                    str(item.get("name", "") or ""),
                    str(item.get("version", "") or ""),
                    str(item.get("cpe", "") or ""),
                    str(item.get("evidence", "") or ""),
                ]))
            for item in list(host_ai_state.get("findings", []) or [])[:32]:
                if not isinstance(item, dict):
                    continue
                ai_text_parts.append(" ".join([
                    str(item.get("title", "") or ""),
                    str(item.get("cve", "") or ""),
                    str(item.get("evidence", "") or ""),
                ]))
            observed.update(cls._tokenize(" ".join(ai_text_parts)))

            host_updates = host_ai_state.get("host_updates", {})
            if isinstance(host_updates, dict):
                observed.update(cls._tokenize(" ".join([
                    str(host_updates.get("hostname", "") or ""),
                    str(host_updates.get("os", "") or ""),
                ])))

            technologies = host_ai_state.get("technologies", [])
            if isinstance(technologies, list):
                for item in technologies[:48]:
                    if not isinstance(item, dict):
                        continue
                    observed.update(cls._tokenize(" ".join([
                        str(item.get("name", "") or ""),
                        str(item.get("version", "") or ""),
                        str(item.get("cpe", "") or ""),
                        str(item.get("evidence", "") or ""),
                    ])))

            findings = host_ai_state.get("findings", [])
            if isinstance(findings, list):
                for item in findings[:48]:
                    if not isinstance(item, dict):
                        continue
                    observed.update(cls._tokenize(" ".join([
                        str(item.get("title", "") or ""),
                        str(item.get("severity", "") or ""),
                        str(item.get("cve", "") or ""),
                        str(item.get("evidence", "") or ""),
                    ])))

            manual_tests = host_ai_state.get("manual_tests", [])
            if isinstance(manual_tests, list):
                for item in manual_tests[:24]:
                    if not isinstance(item, dict):
                        continue
                    observed.update(cls._tokenize(" ".join([
                        str(item.get("why", "") or ""),
                        str(item.get("command", "") or ""),
                        str(item.get("scope_note", "") or ""),
                    ])))

        coverage = context.get("coverage", {})
        if isinstance(coverage, dict):
            observed.update(cls._tokenize(" ".join([
                str(coverage.get("analysis_mode", "") or ""),
                str(coverage.get("stage", "") or ""),
            ])))
            missing = coverage.get("missing", [])
            if isinstance(missing, list):
                observed.update(cls._tokenize(" ".join(str(item or "") for item in missing[:24])))
            recommended = coverage.get("recommended_tool_ids", [])
            if isinstance(recommended, list):
                observed.update(cls._tokenize(" ".join(str(item or "") for item in recommended[:32])))

        cleaned = set()
        for token in observed:
            if token in cls.IGNORED_CONTEXT_TOKENS:
                continue
            if token.isdigit():
                continue
            if len(token) < 3:
                continue
            cleaned.add(token)
        return cleaned

    @staticmethod
    def _tokenize(text: str) -> Set[str]:
        return {match for match in re.findall(r"[a-z0-9]+", str(text or "").lower()) if match}

    @classmethod
    def _is_web_service(cls, service_name: str) -> bool:
        return str(service_name or "").strip().lower() in cls.WEB_SERVICE_IDS

    @classmethod
    def _should_run_web_followup_sidecar(
            cls,
            service_name: str,
            *,
            context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not cls._is_web_service(service_name) or not isinstance(context, dict):
            return False

        coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        analysis_mode = str(
            coverage.get("analysis_mode", "")
            or context.get("analysis_mode", "")
            or "standard"
        ).strip().lower()
        signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
        host_cves = context.get("host_cves", []) if isinstance(context.get("host_cves", []), list) else []
        summary = context.get("context_summary", {}) if isinstance(context.get("context_summary", {}), dict) else {}
        reflection = summary.get("reflection_posture", {}) if isinstance(summary.get("reflection_posture", {}), dict) else {}
        reflection_priority = str(reflection.get("priority_shift", "") or "").strip().lower()
        reflection_promotes = cls._normalize_tool_id_set(reflection.get("promote_tool_ids", []))

        return bool(coverage_missing & {
            "missing_whatweb",
            "missing_nikto",
            "missing_web_content_discovery",
            "missing_followup_after_vuln",
            "missing_http_followup",
            "missing_cpe_cve_enrichment",
        }) or analysis_mode == "dig_deeper" \
            or int(signals.get("vuln_hits", 0) or 0) > 0 \
            or bool(host_cves) \
            or reflection_priority in {"targeted_followup", "manual_validation"} \
            or bool(reflection_promotes)

    @classmethod
    def _web_followup_sidecar_candidates(
            cls,
            candidates: List[Dict[str, Any]],
            *,
            context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not candidates:
            return []

        signals = context.get("signals", {}) if isinstance(context, dict) and isinstance(context.get("signals", {}), dict) else {}
        suppressed_tools = cls._context_suppressed_tool_ids(context)
        selected = []
        seen = set()
        for candidate in candidates:
            tool_id = str(candidate.get("tool_id", "") or "").strip()
            tool_norm = cls._normalized_tool_id(tool_id)
            if (
                    not tool_norm
                    or tool_norm in seen
                    or tool_norm in suppressed_tools
                    or cls._covered_web_followup_tool_already_satisfied(tool_id=tool_id, context=context)
            ):
                continue
            tool_text = " ".join([
                tool_id,
                str(candidate.get("label", "") or ""),
                str(candidate.get("command_template", "") or ""),
            ]).lower()

            include = tool_norm in cls.WEB_AI_SPECIALIST_FOLLOWUP_TOOL_IDS or cls._matches_any_token(
                tool_text,
                (
                    "whatweb",
                    "nikto",
                    "web-content-discovery",
                    "dirsearch",
                    "ffuf",
                    "feroxbuster",
                    "gobuster",
                    "curl-headers",
                    "curl-options",
                    "curl-robots",
                    "wafw00f",
                    "wpscan",
                    "wapiti",
                    "nuclei-cves",
                    "nuclei-exposures",
                    "nuclei-wordpress",
                ),
            )
            if not include:
                for rule in cls.SPECIALIZED_WEB_TOOL_RULES:
                    if not cls._matches_any_token(tool_text, rule.get("tokens", ())):
                        continue
                    if cls._has_any_signal(signals, rule.get("required_signals", ())):
                        include = True
                    break

            if not include:
                continue
            seen.add(tool_norm)
            selected.append(candidate)
            if len(selected) >= 10:
                break
        return selected

    @staticmethod
    def _merge_specialist_sidecar_payload(
            provider_payload: Optional[Dict[str, Any]],
            sidecar_payload: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        merged = dict(provider_payload or {})
        payload = dict(sidecar_payload or {})
        specialist_sidecars = list(merged.get("specialist_sidecars", []) or [])
        specialist_sidecars.append(payload)
        merged["specialist_sidecars"] = specialist_sidecars

        manual_tests = list(merged.get("manual_tests", []) or [])
        seen = {
            str(item.get("command", "") or "").strip().lower()
            for item in manual_tests
            if isinstance(item, dict)
            and str(item.get("command", "") or "").strip()
        }
        for item in list(payload.get("manual_tests", []) or []):
            if not isinstance(item, dict):
                continue
            key = str(item.get("command", "") or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            manual_tests.append(item)
        merged["manual_tests"] = manual_tests
        return merged

    @staticmethod
    def _append_specialist_sidecar_context(
            rationale: str,
            *,
            tool_id: str,
            specialist_reason: str,
    ) -> str:
        if not specialist_reason:
            return rationale
        note = f"Web follow-up specialist favored {tool_id}: {specialist_reason}"
        if note in str(rationale or ""):
            return rationale
        if not rationale:
            return note
        return f"{rationale} {note}"

    @classmethod
    def _apply_web_ai_baseline(
            cls,
            service_name: str,
            decisions: List[PlanStep],
            context: Optional[Dict[str, Any]] = None,
            limit: int = 4,
    ) -> List[PlanStep]:
        if not cls._is_web_service(service_name):
            return decisions[:limit]

        required = list(cls.WEB_AI_BASELINE_TOOL_IDS)
        coverage = context.get("coverage", {}) if isinstance(context, dict) and isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        signals = context.get("signals", {}) if isinstance(context, dict) and isinstance(context.get("signals", {}), dict) else {}
        analysis_mode = str(
            coverage.get("analysis_mode", "")
            or (context.get("analysis_mode", "") if isinstance(context, dict) else "")
            or "standard"
        ).strip().lower()
        host_cves = context.get("host_cves", []) if isinstance(context, dict) and isinstance(context.get("host_cves", []), list) else []
        vuln_hits = int(signals.get("vuln_hits", 0) or 0)
        needs_deep_web = bool(coverage_missing & {
            "missing_whatweb",
            "missing_nikto",
            "missing_web_content_discovery",
            "missing_followup_after_vuln",
        }) or analysis_mode == "dig_deeper" or vuln_hits > 0 or bool(host_cves)
        needs_targeted_nuclei = bool(coverage_missing & {
            "missing_cpe_cve_enrichment",
            "missing_followup_after_vuln",
        }) or analysis_mode == "dig_deeper" or vuln_hits > 0 or bool(host_cves)
        if needs_deep_web:
            required.extend(cls.WEB_AI_DEEP_WEB_TOOL_IDS)
        if needs_targeted_nuclei:
            required.extend(("nuclei-cves", "nuclei-exposures"))
        if bool(signals.get("wordpress_detected")):
            required.extend(("nuclei-wordpress", "wpscan"))
        selected = list(decisions[:limit])
        selected_ids = {item.tool_id for item in selected}

        by_tool = {item.tool_id: item for item in decisions}
        for tool_id in required:
            item = by_tool.get(tool_id)
            if item and tool_id not in selected_ids:
                selected.append(item)
                selected_ids.add(tool_id)

        while len(selected) > limit:
            removable = [item for item in selected if item.tool_id not in required]
            if not removable:
                break
            lowest = min(removable, key=lambda item: float(item.score))
            selected.remove(lowest)

        selected.sort(key=lambda item: item.score, reverse=True)
        return selected[:limit]

    @classmethod
    def _default_ai_limit(
            cls,
            service_name: str,
            *,
            context: Optional[Dict[str, Any]] = None,
    ) -> int:
        if not cls._is_web_service(service_name):
            return 4
        coverage = context.get("coverage", {}) if isinstance(context, dict) and isinstance(context.get("coverage", {}), dict) else {}
        coverage_missing = {
            str(item or "").strip().lower()
            for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
            if str(item or "").strip()
        }
        signals = context.get("signals", {}) if isinstance(context, dict) and isinstance(context.get("signals", {}), dict) else {}
        analysis_mode = str(
            coverage.get("analysis_mode", "")
            or (context.get("analysis_mode", "") if isinstance(context, dict) else "")
            or "standard"
        ).strip().lower()
        host_cves = context.get("host_cves", []) if isinstance(context, dict) and isinstance(context.get("host_cves", []), list) else []
        if (
                analysis_mode == "dig_deeper"
                or bool(host_cves)
                or int(signals.get("vuln_hits", 0) or 0) > 0
                or bool(coverage_missing & {"missing_followup_after_vuln", "missing_cpe_cve_enrichment"})
        ):
            return 6
        return 4

    @staticmethod
    def _policy_snapshot_hash(policy: EngagementPolicy, dangerous_categories: List[str]) -> str:
        payload = {
            "engagement_policy": policy.to_dict(),
            "dangerous_categories": sorted(str(item or "") for item in list(dangerous_categories or []) if str(item or "").strip()),
        }
        rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return build_command_family_id("scheduler-policy", "policy", rendered)

    def _apply_policy_decision(self, step: PlanStep, policy: EngagementPolicy) -> PlanStep:
        family_policy_state = self.config_manager.get_family_policy_state(step.family_id)
        decision = evaluate_policy_for_risk_tags(
            step.risk_tags,
            policy,
            family_policy_state=family_policy_state,
        )
        step.approval_state = (
            "blocked"
            if decision.is_blocked
            else ("approval_required" if decision.requires_approval else "not_required")
        )
        step.risk_tags = list(decision.risk_tags)
        step.policy_reason = str(decision.reason or "")
        step.risk_summary = str(decision.risk_summary or "")
        step.safer_alternative = str(decision.safer_alternative or "")
        step.family_policy_state = str(decision.family_policy_state or "")
        return step

    @classmethod
    def _build_target_ref(
            cls,
            service_name: str,
            protocol_name: str,
            *,
            policy: Optional[EngagementPolicy] = None,
            context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target_ref = {
            "service": str(service_name or ""),
            "protocol": str(protocol_name or "tcp"),
        }
        if isinstance(policy, EngagementPolicy):
            target_ref["scope"] = str(policy.scope)
            target_ref["intent"] = str(policy.intent)
            target_ref["engagement_preset"] = str(policy.preset)
        if not isinstance(context, dict):
            return target_ref
        target = context.get("target", {})
        if isinstance(target, dict):
            for key in (
                    "host_id",
                    "host_ip",
                    "hostname",
                    "port",
                    "service",
                    "protocol",
                    "service_product",
                    "service_version",
                    "service_extrainfo",
            ):
                value = target.get(key)
                if value is None:
                    continue
                text = str(value).strip()
                if text:
                    target_ref[key] = text
        return target_ref

    @staticmethod
    def _build_rationale(
            tool_id: str,
            policy: EngagementPolicy,
            danger_categories: List[str],
            provider_name: str = "",
            provider_error: str = "",
            provider_returned_rankings: bool = True,
            context_signals: Optional[List[str]] = None,
    ) -> str:
        profile_hint = f"prioritizes {policy.scope} {policy.intent} coverage for preset {policy.preset}"
        provider_hint = ""
        if provider_error and provider_name:
            provider_hint = f" Provider '{provider_name}' failed ({provider_error}); heuristic fallback applied."
        elif provider_name and not provider_returned_rankings:
            provider_hint = f" Provider '{provider_name}' returned no ranking; heuristic fallback applied."

        context_hint = ""
        if context_signals:
            picked = [item for item in context_signals if item][:3]
            if picked:
                context_hint = " Context signals: " + ", ".join(picked) + "."

        if danger_categories:
            return (
                f"AI profile {profile_hint}; selected {tool_id} with elevated risk markers: "
                + ", ".join(danger_categories)
                + "."
                + context_hint
                + provider_hint
            )
        return f"AI profile {profile_hint}; selected {tool_id} for highest expected signal.{context_hint}{provider_hint}"

    @staticmethod
    def _append_strategy_context(rationale: str, strategy_guidance) -> str:
        base = str(rationale or "").strip()
        fragments = []
        if getattr(strategy_guidance, "pack_ids", []):
            fragments.append("strategy packs " + ", ".join(list(strategy_guidance.pack_ids or [])[:3]))
        if str(getattr(strategy_guidance, "coverage_notes", "") or "").strip():
            fragments.append(str(strategy_guidance.coverage_notes).strip().rstrip("."))
        evidence_expectations = list(getattr(strategy_guidance, "evidence_expectations", []) or [])
        if evidence_expectations:
            fragments.append("expects " + ", ".join(str(item) for item in evidence_expectations[:2]))
        if not fragments:
            return base
        strategy_text = " ".join(fragment + "." for fragment in fragments if fragment)
        if not base:
            return strategy_text.strip()
        return f"{base} {strategy_text}".strip()

    @classmethod
    def _build_deterministic_rationale(
            cls,
            action,
            selected_packs,
            strategy_guidance,
    ) -> str:
        rationale = "Selected by deterministic scheduler mapping."
        if selected_packs:
            rationale += " Active packs: " + ", ".join(
                str(item.pack.pack_id) for item in list(selected_packs or [])[:3]
            ) + "."
        rationale = cls._append_strategy_context(rationale, strategy_guidance)
        if not str(getattr(strategy_guidance, "coverage_gap", "") or "").strip():
            action_tags = list(getattr(action, "methodology_tags", []) or [])
            if action_tags:
                rationale += " Methodology tags: " + ", ".join(str(item) for item in action_tags[:3]) + "."
        return rationale.strip()

    @staticmethod
    def _context_has_strategy_signals(context: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(context, dict):
            return False
        for key in ("signals", "coverage", "host_cves", "host_ai_state", "inferred_technologies"):
            value = context.get(key)
            if isinstance(value, dict) and value:
                return True
            if isinstance(value, list) and value:
                return True
        return False

    @staticmethod
    def _select_strategy_packs(
            service_name: str,
            protocol_name: str,
            policy: EngagementPolicy,
            *,
            context: Optional[Dict[str, Any]] = None,
    ):
        return select_strategy_packs(
            service_name,
            protocol_name,
            policy,
            context=context,
        )

    @staticmethod
    def _normalized_tool_id(tool_id: str) -> str:
        return str(tool_id or "").strip().lower()

    @staticmethod
    def _normalize_text_token(value: Any) -> str:
        return str(value or "").strip().lower()

    @classmethod
    def _normalize_tool_id_set(cls, values) -> Set[str]:
        if values is None:
            return set()
        if isinstance(values, str):
            values = [values]
        normalized = set()
        for item in values:
            token = cls._normalized_tool_id(str(item or ""))
            if token:
                normalized.add(token)
        return normalized

    @classmethod
    def _normalize_text_token_set(cls, values) -> Set[str]:
        if values is None:
            return set()
        if isinstance(values, str):
            values = [values]
        normalized = set()
        for item in values:
            token = cls._normalize_text_token(item)
            if token:
                normalized.add(token)
        return normalized

    @staticmethod
    def _command_signature(protocol_name: str, command_template: str) -> str:
        rendered = str(command_template or "").strip().lower()
        if not rendered:
            rendered = "unknown"
        return build_command_family_id("scheduler-command", str(protocol_name or "tcp"), rendered)

    @classmethod
    def _active_context_signals(cls, context: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(context, dict):
            return []
        signals = context.get("signals", {})
        if not isinstance(signals, dict):
            return []
        active = []
        for key, value in signals.items():
            if isinstance(value, bool) and value:
                active.append(str(key))
            elif isinstance(value, (int, float)) and value > 0:
                active.append(f"{key}={value}")
            elif isinstance(value, str) and value.strip():
                active.append(f"{key}={value.strip()}")
            elif isinstance(value, list) and value:
                active.append(f"{key}={len(value)}")
        return active
