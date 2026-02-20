import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.scheduler.family import build_command_family_id
from app.scheduler.providers import ProviderError, get_last_provider_payload, rank_actions_with_provider
from app.scheduler.risk import classify_command_danger

logger = logging.getLogger(__name__)


@dataclass
class ScheduledAction:
    tool_id: str
    label: str
    command_template: str
    protocol: str
    score: float
    rationale: str
    mode: str
    goal_profile: str
    family_id: str
    danger_categories: List[str] = field(default_factory=list)
    requires_approval: bool = False


class SchedulerPlanner:
    WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}
    WEB_AI_BASELINE_TOOL_IDS = ("nuclei-web", "nmap-vuln.nse", "screenshooter")
    GENERIC_WEB_TOOL_TOKENS = {
        "http", "https", "ssl", "tls", "web", "proxy", "alt",
        "scan", "scanner", "check", "checker", "test", "testing",
        "enum", "enumerate", "discovery", "discover", "fingerprint",
        "banner", "title", "headers", "robots", "favicon", "version",
        "script", "scripts", "vuln", "vulnerability", "cve", "path", "default",
        "nmap", "nse", "nuclei", "nikto", "whatweb", "wafw00f", "sslscan", "sslyze",
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
            limit: Optional[int] = None,
    ) -> List[ScheduledAction]:
        self._set_last_provider_payload({})
        prefs = self.config_manager.load()
        mode = prefs.get("mode", "deterministic")
        goal_profile = prefs.get("goal_profile", "internal_asset_discovery")
        dangerous_categories = self.config_manager.get_dangerous_categories()
        excluded = self._normalize_tool_id_set(excluded_tool_ids)

        if mode == "ai":
            actions = self._plan_ai(
                service,
                protocol,
                settings,
                goal_profile,
                dangerous_categories,
                context=context,
                excluded_tool_ids=excluded,
                limit=limit,
            )
            if actions:
                return actions
            # deterministic fallback when AI path cannot produce candidates.
            mode = "deterministic"

        return self._plan_deterministic(
            service,
            protocol,
            settings,
            goal_profile,
            dangerous_categories,
            mode=mode,
            excluded_tool_ids=excluded,
            limit=limit,
        )

    def _plan_deterministic(self, service: str, protocol: str, settings, goal_profile: str,
                            dangerous_categories: List[str], mode: str = "deterministic",
                            excluded_tool_ids: Optional[Set[str]] = None,
                            limit: Optional[int] = None) -> List[ScheduledAction]:
        service_name = str(service or "").strip().rstrip("?")
        protocol_name = str(protocol or "tcp").strip().lower()
        port_actions = self._port_actions_by_id(settings.portActions)
        decisions = []
        excluded = set(excluded_tool_ids or set())

        for tool in settings.automatedAttacks:
            tool_id = str(tool[0])
            if self._normalized_tool_id(tool_id) in excluded:
                continue
            service_list = [item.strip() for item in str(tool[1]).split(",") if item.strip()]
            tool_protocol = str(tool[2] if len(tool) > 2 else "tcp").strip().lower()
            if tool_protocol != protocol_name:
                continue
            if service_name not in service_list and "*" not in service_list:
                continue

            action_data = port_actions.get(tool_id, {})
            label = action_data.get("label", tool_id)
            command_template = action_data.get("command", "")
            danger = classify_command_danger(command_template, dangerous_categories)
            family_id = build_command_family_id(tool_id, protocol_name, command_template or tool_id)

            decisions.append(ScheduledAction(
                tool_id=tool_id,
                label=label,
                command_template=command_template,
                protocol=tool_protocol,
                score=1.0,
                rationale="Selected by deterministic scheduler mapping.",
                mode=mode,
                goal_profile=goal_profile,
                family_id=family_id,
                danger_categories=danger,
                requires_approval=bool(danger) and not self.config_manager.is_family_preapproved(family_id),
            ))
        if limit is not None:
            try:
                max_items = int(limit)
            except (TypeError, ValueError):
                max_items = 0
            if max_items > 0:
                return decisions[:max_items]
        return decisions

    def _plan_ai(self, service: str, protocol: str, settings, goal_profile: str,
                 dangerous_categories: List[str],
                 context: Optional[Dict[str, Any]] = None,
                 excluded_tool_ids: Optional[Set[str]] = None,
                 limit: Optional[int] = None) -> List[ScheduledAction]:
        service_name = str(service or "").strip().rstrip("?")
        protocol_name = str(protocol or "tcp").strip().lower()
        port_actions = self._port_actions_by_id(settings.portActions)
        candidates_by_tool = {}
        excluded = set(excluded_tool_ids or set())

        for action in settings.portActions:
            label = str(action[0])
            tool_id = str(action[1])
            if self._normalized_tool_id(tool_id) in excluded:
                continue
            command_template = str(action[2])
            action_services = self._parse_services(str(action[3] if len(action) > 3 else ""))
            if action_services and service_name not in action_services and "*" not in action_services:
                continue

            candidates_by_tool[tool_id] = {
                "tool_id": tool_id,
                "label": label,
                "command_template": command_template,
                "service_scope": ",".join(action_services),
            }

        # Include scheduler-only mappings (like screenshooter) even if they do not have a PortActions command.
        for tool in settings.automatedAttacks:
            tool_id = str(tool[0])
            if self._normalized_tool_id(tool_id) in excluded:
                continue
            service_list = [item.strip() for item in str(tool[1]).split(",") if item.strip()]
            tool_protocol = str(tool[2] if len(tool) > 2 else "tcp").strip().lower()
            if tool_protocol != protocol_name:
                continue
            if service_name not in service_list and "*" not in service_list:
                continue
            if tool_id in candidates_by_tool:
                continue

            action_data = port_actions.get(tool_id, {})
            candidates_by_tool[tool_id] = {
                "tool_id": tool_id,
                "label": action_data.get("label", tool_id),
                "command_template": action_data.get("command", ""),
                "service_scope": ",".join(service_list),
            }

        candidates = list(candidates_by_tool.values())
        candidates = self._filter_candidates_with_context(candidates, context)

        if not candidates:
            return []

        scores_by_tool = {}
        rationales_by_tool = {}
        config = self.config_manager.load()
        provider_name = str(config.get("provider", "none") or "none").strip().lower()
        provider_cfg = config.get("providers", {}).get(provider_name, {}) if isinstance(config.get("providers", {}), dict) else {}
        provider_enabled = bool(provider_cfg.get("enabled", False)) if isinstance(provider_cfg, dict) else False
        provider_error = ""
        try:
            provider_ranked = rank_actions_with_provider(
                config=config,
                goal_profile=goal_profile,
                service=service_name,
                protocol=protocol_name,
                candidates=candidates,
                context=context or {},
            )
            self._set_last_provider_payload(get_last_provider_payload(clear=True))
        except ProviderError as exc:
            provider_error = str(exc)
            logger.warning(
                "AI scheduler provider failed for %s/%s using provider=%s: %s",
                service_name,
                protocol_name,
                provider_name,
                provider_error,
            )
            self._set_last_provider_payload(get_last_provider_payload(clear=True))
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

        decisions = []
        for candidate in candidates:
            tool_id = candidate["tool_id"]
            label = candidate["label"]
            command_template = candidate["command_template"]
            danger = classify_command_danger(command_template, dangerous_categories)
            family_id = build_command_family_id(tool_id, protocol_name, command_template)

            score = scores_by_tool.get(tool_id)
            if score is None:
                score = self._score_candidate(tool_id, label, command_template, goal_profile)
            score = self._score_with_context(
                score,
                tool_id=tool_id,
                label=label,
                command_template=command_template,
                context=context,
            )
            if self._is_web_service(service_name):
                if tool_id == "nuclei-web":
                    score = max(score, 96.0)
                elif tool_id == "nmap-vuln.nse":
                    score = max(score, 94.0)
                elif tool_id == "screenshooter":
                    score = max(score, 92.0)
            rationale = rationales_by_tool.get(tool_id) or self._build_rationale(
                tool_id,
                goal_profile,
                danger,
                provider_name=provider_name if provider_enabled else "",
                provider_error=provider_error,
                provider_returned_rankings=bool(provider_ranked),
                context_signals=self._active_context_signals(context),
            )

            decisions.append(ScheduledAction(
                tool_id=tool_id,
                label=label,
                command_template=command_template,
                protocol=protocol_name,
                score=score,
                rationale=rationale,
                mode="ai",
                goal_profile=goal_profile,
                family_id=family_id,
                danger_categories=danger,
                requires_approval=bool(danger) and not self.config_manager.is_family_preapproved(family_id),
            ))

        decisions.sort(key=lambda item: item.score, reverse=True)
        resolved_limit = 4
        if limit is not None:
            try:
                max_items = int(limit)
            except (TypeError, ValueError):
                max_items = 0
            if max_items > 0:
                resolved_limit = max_items
        return self._apply_web_ai_baseline(service_name, decisions, limit=resolved_limit)

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
    def _score_candidate(tool_id: str, label: str, command_template: str, goal_profile: str) -> float:
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

        if goal_profile == "internal_asset_discovery":
            if any(token in text for token in ["enum", "discover", "info", "list", "scan"]):
                score += 22
            if any(token in text for token in ["smb", "ldap", "rpc", "snmp"]):
                score += 12
            if any(token in text for token in ["brute", "exploit", "flood"]):
                score -= 18
            if has_vuln_signal:
                score += 16
            if has_nuclei_signal:
                score += 10
            if has_web_content_discovery:
                score += 8
        elif goal_profile == "external_pentest":
            if any(token in text for token in ["whatweb", "sslscan", "sslyze", "nikto", "nmap"]):
                score += 20
            if any(token in text for token in ["http", "https", "web"]):
                score += 10
            if any(token in text for token in ["flood", "dos"]):
                score -= 20
            if has_vuln_signal:
                score += 24
            if has_nuclei_signal:
                score += 30
            if has_web_content_discovery:
                score += 12

        if has_legacy_dirbuster:
            score -= 35

        return score

    @classmethod
    def _score_with_context(
            cls,
            score: float,
            *,
            tool_id: str,
            label: str,
            command_template: str,
            context: Optional[Dict[str, Any]],
    ) -> float:
        value = float(score)
        if not isinstance(context, dict):
            return max(0.0, min(value, 100.0))

        tool_norm = cls._normalized_tool_id(tool_id)
        attempted = cls._normalize_tool_id_set(context.get("attempted_tool_ids", []))
        signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
        missing_tools = cls._normalize_tool_id_set(signals.get("missing_tools", []))
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
        if tool_norm in missing_tools:
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
        if "missing_cpe_cve_enrichment" in coverage_missing and cls._matches_any_token(
                text,
                ("nmap-vuln", "nuclei", "vuln", "cve"),
        ):
            value += 24.0
        if "missing_whatweb" in coverage_missing and cls._matches_any_token(text, ("whatweb",)):
            value += 24.0
        if "missing_nikto" in coverage_missing and cls._matches_any_token(text, ("nikto",)):
            value += 24.0
        if "missing_web_content_discovery" in coverage_missing and cls._matches_any_token(text, ("feroxbuster", "gobuster", "web-content-discovery")):
            value += 24.0
        if "missing_smb_signing_checks" in coverage_missing and cls._matches_any_token(text, ("smb-security-mode", "smb2-security-mode")):
            value += 26.0
        if analysis_mode == "dig_deeper" and "missing_followup_after_vuln" in coverage_missing and cls._matches_any_token(
                text,
                ("nikto", "whatweb", "web-content-discovery", "sslscan", "sslyze", "wafw00f"),
        ):
            value += 18.0

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
        if bool(signals.get("directory_listing")) and any(token in text for token in ["feroxbuster", "gobuster", "dirsearch", "web-content"]):
            value += 8.0
        if bool(signals.get("smb_signing_disabled")) and any(token in text for token in ["smb", "crackmapexec", "enum", "rpc"]):
            value += 10.0
        if bool(signals.get("waf_detected")) and "waf" in text:
            value += 10.0
        if int(signals.get("vuln_hits", 0) or 0) > 0 and any(token in text for token in ["vuln", "cve", "nuclei", "exploit"]):
            value += 6.0
        if cls._matches_any_token(text, ("ubiquiti", "unifi", "ubnt")) and bool(signals.get("ubiquiti_detected")):
            value += 10.0
        if cls._matches_any_token(text, ("nginx", "apache", "http")) and bool(signals.get("web_service")):
            value += 2.0

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

            blocked = False
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

            if (
                    not blocked
                    and web_service
                    and observed_tokens
            ):
                specific_tokens = cls._candidate_specific_tokens(
                    tool_id=tool_id,
                    label=label,
                    command_template=command_template,
                )
                if specific_tokens and not (specific_tokens & observed_tokens):
                    blocked = True

            if not blocked:
                filtered.append(candidate)

        # Keep original candidates if pruning would remove everything.
        return filtered or candidates

    @staticmethod
    def _matches_any_token(text: str, tokens) -> bool:
        lowered = str(text or "").lower()
        return any(str(token or "").strip().lower() in lowered for token in list(tokens or []))

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
                    " ".join(str(script or "") for script in item.get("scripts", []) if str(script or "").strip()),
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
                    observed.update(cls._tokenize(" ".join([
                        str(item.get("script_id", "") or ""),
                        str(item.get("excerpt", "") or ""),
                    ])))

        processes = context.get("recent_processes", [])
        if isinstance(processes, list):
            for item in processes[:48]:
                if isinstance(item, dict):
                    observed.update(cls._tokenize(" ".join([
                        str(item.get("tool_id", "") or ""),
                        str(item.get("command_excerpt", "") or ""),
                        str(item.get("output_excerpt", "") or ""),
                    ])))

        host_ai_state = context.get("host_ai_state", {})
        if isinstance(host_ai_state, dict):
            observed.update(cls._tokenize(" ".join([
                str(host_ai_state.get("provider", "") or ""),
                str(host_ai_state.get("goal_profile", "") or ""),
                str(host_ai_state.get("next_phase", "") or ""),
            ])))

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
    def _apply_web_ai_baseline(
            cls,
            service_name: str,
            decisions: List[ScheduledAction],
            limit: int = 4,
    ) -> List[ScheduledAction]:
        if not cls._is_web_service(service_name):
            return decisions[:limit]

        required = list(cls.WEB_AI_BASELINE_TOOL_IDS)
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

    @staticmethod
    def _build_rationale(
            tool_id: str,
            goal_profile: str,
            danger_categories: List[str],
            provider_name: str = "",
            provider_error: str = "",
            provider_returned_rankings: bool = True,
            context_signals: Optional[List[str]] = None,
    ) -> str:
        profile_hint = (
            "prioritizes internal visibility and safe enumeration"
            if goal_profile == "internal_asset_discovery"
            else "prioritizes external attack-surface fingerprinting"
        )
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
    def _normalized_tool_id(tool_id: str) -> str:
        return str(tool_id or "").strip().lower()

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
