import datetime
import json
import re
import shlex
import sys
import threading
import time
from copy import deepcopy
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from app.scheduler.tool_prompt_registry import get_scheduler_tool_prompt_info

MAX_PROVIDER_PROMPT_CHARS = 5200
MAX_PROVIDER_CANDIDATES = 24
MAX_CANDIDATE_TEMPLATE_CHARS = 180
MAX_CANDIDATE_LABEL_CHARS = 96
MAX_CANDIDATE_PURPOSE_CHARS = 72
MAX_CANDIDATE_WHEN_TO_USE_CHARS = 88
MAX_CANDIDATE_ARG_SHAPE_CHARS = 24
MIN_PROVIDER_CANDIDATE_BLOCK_CHARS = 1600
MAX_PROVIDER_RESPONSE_TOKENS = 1000
MAX_PROVIDER_REFLECTION_RESPONSE_TOKENS = 500
MAX_PROVIDER_SPECIALIST_RESPONSE_TOKENS = 420
MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS = 3
MAX_PROVIDER_OPENAI_RETRY_TOKENS = 1600
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
MAX_PROVIDER_CONTEXT_CHARS = 10000
MAX_PROVIDER_CONTEXT_ITEMS = 64
MAX_PROVIDER_LOG_ENTRIES = 600
MAX_PROVIDER_LOG_TEXT_CHARS = 20000
SCHEDULER_PROMPT_VERSION = "scheduler-ranking-v2"
SCHEDULER_REFLECTION_PROMPT_VERSION = "scheduler-reflection-v1"
SCHEDULER_WEB_FOLLOWUP_PROMPT_VERSION = "scheduler-web-followup-v1"
_ALWAYS_INCLUDE_BOOL_SIGNALS = {
    "web_service",
    "rdp_service",
    "vnc_service",
    "tls_detected",
    "shodan_enabled",
    "wordpress_detected",
    "iis_detected",
    "webdav_detected",
    "vmware_detected",
    "coldfusion_detected",
    "huawei_detected",
    "ubiquiti_detected",
}
_WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}
_SCHEDULER_PHASES = (
    "initial_discovery",
    "service_fingerprint",
    "broad_vuln",
    "protocol_checks",
    "targeted_checks",
    "deep_web",
    "external_enrichment",
    "complete",
)
_PROVIDER_IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_STRICT_COVERAGE_GAP_IDS = {
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


class ProviderError(RuntimeError):
    pass


_provider_log_lock = threading.Lock()
_provider_logs = deque(maxlen=MAX_PROVIDER_LOG_ENTRIES)
_provider_thread_state = threading.local()


def _load_requests_module():
    try:
        import requests as requests_module
    except Exception as exc:  # pragma: no cover - depends on local environment packaging
        raise ProviderError(
            f"requests dependency unavailable under {sys.executable} ({sys.version.split()[0]}): {exc}"
        ) from exc
    return requests_module


class _RequestsProxy:
    def get(self, *args, **kwargs):
        return _load_requests_module().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return _load_requests_module().post(*args, **kwargs)

    def request(self, *args, **kwargs):
        return _load_requests_module().request(*args, **kwargs)

    def __getattr__(self, item):
        return getattr(_load_requests_module(), str(item))


requests = _RequestsProxy()


def _get_requests_module():
    return requests


def _set_last_provider_payload(payload: Optional[Dict[str, Any]] = None):
    try:
        _provider_thread_state.last_payload = deepcopy(payload or {})
    except Exception:
        _provider_thread_state.last_payload = {}


def get_last_provider_payload(clear: bool = False) -> Dict[str, Any]:
    payload = getattr(_provider_thread_state, "last_payload", {}) or {}
    try:
        result = deepcopy(payload)
    except Exception:
        result = dict(payload) if isinstance(payload, dict) else {}
    if clear:
        _set_last_provider_payload({})
    return result


def get_provider_logs(limit: int = 200) -> List[Dict[str, Any]]:
    try:
        max_items = int(limit)
    except (TypeError, ValueError):
        max_items = 200
    max_items = max(1, min(max_items, MAX_PROVIDER_LOG_ENTRIES))
    with _provider_log_lock:
        items = list(_provider_logs)
    return items[-max_items:]


def clear_provider_logs():
    with _provider_log_lock:
        _provider_logs.clear()


def _truncate_log_text(value: Any, max_chars: int = MAX_PROVIDER_LOG_TEXT_CHARS) -> str:
    text = str(value or "")
    if len(text) <= int(max_chars):
        return text
    return text[:int(max_chars)].rstrip() + "...[truncated]"


def _sanitize_header_value(name: str, value: Any) -> str:
    key = str(name or "").strip().lower()
    raw = str(value or "")
    if key in {"authorization", "x-api-key", "api-key"}:
        if key == "authorization" and raw.lower().startswith("bearer "):
            return "Bearer ***redacted***"
        return "***redacted***"
    return raw


def _sanitize_headers_for_log(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    safe = {}
    for key, value in headers.items():
        label = str(key or "").strip()
        if not label:
            continue
        safe[label] = _sanitize_header_value(label, value)
    return safe


def _normalize_tool_token(value: Any) -> str:
    return str(value or "").strip().lower()[:120]


def _expand_unavailable_tool_ids(values: Any) -> List[str]:
    expanded = set()
    for item in list(values or []):
        token = _normalize_tool_token(item)
        if not token:
            continue
        expanded.add(token)
        if token in {"whatweb", "whatweb-http", "whatweb-https"}:
            expanded.update({"whatweb", "whatweb-http", "whatweb-https"})
        if token.endswith(".nse"):
            expanded.add("nmap")
    return sorted(expanded)


def _extract_unavailable_tool_ids_from_texts(values: Any) -> List[str]:
    found = set()
    for item in list(values or []):
        text = str(item or "").replace("\r", "\n").strip().lower()
        if not text:
            continue
        patterns = (
            r"(?:^|\n)\s*(?:/bin/sh|bash|zsh|sh|fish):\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+command not found(?:\s|$)",
            r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+not found(?:\s|$)",
        )
        for pattern in patterns:
            for match in re.findall(pattern, text):
                token = _normalize_tool_token(match)
                if token:
                    found.add(token)
    return _expand_unavailable_tool_ids(found)


def _collect_unavailable_tool_ids(context: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(context, dict):
        return []
    rows: List[str] = []

    signals = context.get("signals", {}) if isinstance(context.get("signals", {}), dict) else {}
    rows.extend(list(signals.get("missing_tools", []) or []))
    rows.extend(list(signals.get("audited_missing_tools", []) or []))

    tool_audit = context.get("tool_audit", {}) if isinstance(context.get("tool_audit", {}), dict) else {}
    rows.extend(list(tool_audit.get("unavailable_tool_ids", []) or []))
    found = set(_expand_unavailable_tool_ids(rows))

    for item in list(context.get("recent_processes", []) or [])[:48]:
        if not isinstance(item, dict):
            continue
        tool_id = _normalize_tool_token(item.get("tool_id", ""))
        tool_tokens = set(_expand_unavailable_tool_ids([tool_id])) if tool_id else set()
        status = str(item.get("status", "") or "").strip().lower()
        output_excerpt = str(item.get("output_excerpt", "") or "").strip().lower()

        if "missing" in status and tool_tokens:
            found.update(tool_tokens)

        text_tokens = set(_extract_unavailable_tool_ids_from_texts([status, output_excerpt]))
        if not text_tokens:
            continue
        if tool_tokens:
            if text_tokens & tool_tokens:
                found.update(tool_tokens)
            continue
        found.update(text_tokens)

    return sorted(found)


def _shell_primary_command_token(command: Any) -> str:
    text = str(command or "").strip()
    if not text:
        return ""
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = re.findall(r"[A-Za-z0-9_./+-]+", text)
    wrappers = {"sudo", "env", "timeout", "nohup", "stdbuf", "nice"}
    control_tokens = {"&&", "||", ";", "|", "(", ")", "{", "}"}
    for token in tokens:
        current = str(token or "").strip()
        if not current or current in control_tokens:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", current):
            continue
        base = current.rsplit("/", 1)[-1].strip().lower()
        if not base or base in wrappers:
            continue
        if re.fullmatch(r"[a-z0-9][a-z0-9._+-]*", base):
            return base
    return ""


def _provider_is_ipv4_like(value: Any) -> bool:
    token = str(value or "").strip()
    if not token or not _PROVIDER_IPV4_LIKE_RE.match(token):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in token.split("."))
    except Exception:
        return False


def _sanitize_provider_technology_version(value: Any) -> str:
    token = str(value or "").strip().strip("[](){};,")
    if not token:
        return ""
    if len(token) > 80:
        token = token[:80]
    lowered = token.lower()
    if lowered in {"unknown", "generic", "none", "n/a", "na", "-", "*"}:
        return ""
    if re.fullmatch(r"0+", lowered):
        return ""
    if re.fullmatch(r"0+[a-z]{1,2}", lowered):
        return ""
    if _provider_is_ipv4_like(token):
        return ""
    if "/" in token and not re.search(r"\d", token):
        return ""
    if not re.search(r"[0-9]", token):
        return ""
    return token


def _normalize_provider_cpe_token(value: Any) -> str:
    token = str(value or "").strip().lower()[:220]
    if not token:
        return ""
    if token.startswith("cpe:/"):
        parts = token.split(":")
        if len(parts) >= 5:
            version = _sanitize_provider_technology_version(parts[4])
            if version:
                parts[4] = version.lower()
                return ":".join(parts)
            return ":".join(parts[:4])
        return token
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        if len(parts) >= 6:
            version = _sanitize_provider_technology_version(parts[5])
            if version:
                parts[5] = version.lower()
            else:
                parts[5] = "*"
            return ":".join(parts)
        return token
    return token


def _provider_cpe_base(value: Any) -> str:
    token = _normalize_provider_cpe_token(value)
    if token.startswith("cpe:/"):
        parts = token.split(":")
        return ":".join(parts[:4]) if len(parts) >= 4 else token
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        return ":".join(parts[:5]) if len(parts) >= 5 else token
    return token


def _provider_version_from_cpe(value: Any) -> str:
    token = _normalize_provider_cpe_token(value)
    if token.startswith("cpe:/"):
        parts = token.split(":")
        if len(parts) >= 5:
            return _sanitize_provider_technology_version(parts[4])
        return ""
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        if len(parts) >= 6:
            return _sanitize_provider_technology_version(parts[5])
        return ""
    return ""


def _sanitize_provider_technology_version_for_tech(
        *,
        name: Any,
        version: Any,
        cpe: Any = "",
        evidence: Any = "",
) -> str:
    cleaned = _sanitize_provider_technology_version(version)
    if not cleaned:
        return ""
    lowered_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").strip().lower()).strip()
    cpe_base = _provider_cpe_base(cpe)
    evidence_text = str(evidence or "").strip().lower()
    major_match = re.match(r"^(\d+)", cleaned)
    major = int(major_match.group(1)) if major_match else None

    if major is not None:
        if lowered_name in {"apache", "apache http server"} or "cpe:/a:apache:http_server" in cpe_base:
            if major > 3:
                return ""
        if lowered_name == "nginx" or "cpe:/a:nginx:nginx" in cpe_base:
            if major > 2:
                return ""
        if lowered_name == "php" or "cpe:/a:php:php" in cpe_base:
            if major < 3:
                return ""

    if (
            re.fullmatch(r"[78]\.\d{2}", cleaned)
            and any(marker in evidence_text for marker in ("nmap", ".nse", "output fingerprint", "service fingerprint"))
    ):
        return ""
    return cleaned


def _normalize_next_phase(value: Any, *, current_phase: str = "") -> str:
    phase = str(value or "").strip().lower()[:80]
    current = str(current_phase or "").strip().lower()[:80]
    if not phase:
        return current
    if phase not in _SCHEDULER_PHASES:
        return current
    if current not in _SCHEDULER_PHASES:
        return phase
    current_index = _SCHEDULER_PHASES.index(current)
    phase_index = _SCHEDULER_PHASES.index(phase)
    if phase_index < current_index:
        return current
    if phase_index > current_index + 1:
        return _SCHEDULER_PHASES[min(current_index + 1, len(_SCHEDULER_PHASES) - 1)]
    return phase


def _sanitize_value_for_log(value: Any):
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            label = str(key or "").strip()
            lowered = label.lower()
            if lowered in {"api_key", "apikey", "authorization", "x-api-key"}:
                safe[label] = "***redacted***"
            else:
                safe[label] = _sanitize_value_for_log(item)
        return safe
    if isinstance(value, list):
        return [_sanitize_value_for_log(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_value_for_log(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _json_for_log(value: Any) -> str:
    safe = _sanitize_value_for_log(value)
    try:
        rendered = json.dumps(safe, ensure_ascii=False, default=str, indent=2)
    except Exception:
        rendered = str(safe)
    return _truncate_log_text(rendered)


def _response_text_for_log(response: Any) -> str:
    try:
        text_value = str(getattr(response, "text", "") or "")
    except Exception:
        text_value = ""
    return _truncate_log_text(text_value)


def _record_provider_log(
        *,
        provider: str,
        method: str,
        endpoint: str,
        request_headers: Optional[Dict[str, Any]] = None,
        request_payload: Optional[Any] = None,
        response_status: Optional[int] = None,
        response_body: Optional[str] = None,
        error: str = "",
        api_style: str = "",
        prompt_metadata: Optional[Dict[str, Any]] = None,
):
    row = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provider": str(provider or ""),
        "method": str(method or "").upper(),
        "endpoint": str(endpoint or ""),
        "api_style": str(api_style or ""),
        "request_headers": _sanitize_headers_for_log(request_headers),
        "request_body": _json_for_log(request_payload),
        "response_status": int(response_status) if isinstance(response_status, int) else response_status,
        "response_body": _truncate_log_text(response_body or ""),
        "error": _truncate_log_text(error or ""),
        "prompt_metadata": _sanitize_value_for_log(prompt_metadata or {}),
    }
    with _provider_log_lock:
        _provider_logs.append(row)


def rank_actions_with_provider(config: Dict[str, Any], goal_profile: str, service: str, protocol: str,
                               candidates: List[Dict[str, str]],
                               context: Optional[Dict[str, Any]] = None,
                               *, engagement_preset: str = "") -> List[Dict[str, Any]]:
    _set_last_provider_payload({})
    provider_name = str(config.get("provider", "none") or "none").strip().lower()
    providers_cfg = config.get("providers", {}) if isinstance(config, dict) else {}
    provider_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg, dict) else {}
    feature_flags = config.get("feature_flags", {}) if isinstance(config, dict) else {}
    prompt_profiles_enabled = True
    if isinstance(feature_flags, dict) and "scheduler_prompt_profiles" in feature_flags:
        prompt_profiles_enabled = bool(feature_flags.get("scheduler_prompt_profiles", True))
    context_summary_enabled = _feature_flag_enabled(config, "context_summary_enabled", default=True)
    prompt_package = _build_ranking_prompt_package(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
        service=service,
        protocol=protocol,
        candidates=candidates,
        context=context or {},
        prompt_profiles_enabled=prompt_profiles_enabled,
        context_summary_enabled=context_summary_enabled,
    )
    prompt_metadata = dict(prompt_package.get("metadata", {}) or {})

    if provider_name == "none" or not provider_cfg.get("enabled", False):
        disabled_payload = {
            "provider": provider_name,
            "actions": [],
            "host_updates": {},
            "findings": [],
            "manual_tests": [],
            "technologies": [],
            "next_phase": "",
        }
        disabled_payload.update(prompt_metadata)
        _set_last_provider_payload(disabled_payload)
        return []

    if provider_name in {"openai", "lm_studio"}:
        payload = _call_openai_compatible(
            provider_name,
            provider_cfg,
            prompt_package,
            context=context or {},
        )
        payload["provider"] = provider_name
        payload.update(prompt_metadata)
        _set_last_provider_payload(payload)
        return payload.get("actions", [])
    if provider_name == "claude":
        payload = _call_claude(provider_cfg, prompt_package, context=context or {})
        payload["provider"] = provider_name
        payload.update(prompt_metadata)
        _set_last_provider_payload(payload)
        return payload.get("actions", [])
    raise ProviderError(f"Unsupported provider: {provider_name}")


def reflect_on_scheduler_progress(
        config: Dict[str, Any],
        goal_profile: str,
        service: str,
        protocol: str,
        *,
        engagement_preset: str = "",
        context: Optional[Dict[str, Any]] = None,
        recent_rounds: Optional[List[Dict[str, Any]]] = None,
        trigger_reason: str = "",
        trigger_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    provider_name = str(config.get("provider", "none") or "none").strip().lower()
    providers_cfg = config.get("providers", {}) if isinstance(config, dict) else {}
    provider_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg, dict) else {}

    if provider_name == "none" or not provider_cfg.get("enabled", False):
        return {
            "provider": provider_name,
            "state": "continue",
            "reason": "",
            "priority_shift": "",
            "promote_tool_ids": [],
            "suppress_tool_ids": [],
            "manual_tests": [],
            "prompt_version": SCHEDULER_REFLECTION_PROMPT_VERSION,
            "prompt_type": "reflection",
        }

    prompt_package = _build_reflection_prompt_package(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
        service=service,
        protocol=protocol,
        context=context or {},
        recent_rounds=recent_rounds or [],
        trigger_reason=trigger_reason,
        trigger_context=trigger_context or {},
        context_summary_enabled=_feature_flag_enabled(config, "context_summary_enabled", default=True),
    )
    metadata = dict(prompt_package.get("metadata", {}) or {})

    if provider_name in {"openai", "lm_studio"}:
        content = _request_openai_compatible_content(
            provider_name,
            provider_cfg,
            prompt_package,
            max_tokens=MAX_PROVIDER_REFLECTION_RESPONSE_TOKENS,
            temperature=0.1,
        )
    elif provider_name == "claude":
        content = _request_claude_content(
            provider_cfg,
            prompt_package,
            max_tokens=420,
            temperature=0.1,
        )
    else:
        raise ProviderError(f"Unsupported provider: {provider_name}")

    payload = _parse_reflection_payload(
        content,
        unavailable_tool_ids=_collect_unavailable_tool_ids(context or {}),
    )
    payload["provider"] = provider_name
    payload.update(metadata)
    return payload


def select_web_followup_with_provider(
        config: Dict[str, Any],
        goal_profile: str,
        service: str,
        protocol: str,
        candidates: List[Dict[str, str]],
        *,
        engagement_preset: str = "",
        context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    provider_name = str(config.get("provider", "none") or "none").strip().lower()
    providers_cfg = config.get("providers", {}) if isinstance(config, dict) else {}
    provider_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg, dict) else {}

    if provider_name == "none" or not provider_cfg.get("enabled", False):
        return {
            "provider": provider_name,
            "focus": "",
            "selected_tool_ids": [],
            "reason": "",
            "manual_tests": [],
            "prompt_version": SCHEDULER_WEB_FOLLOWUP_PROMPT_VERSION,
            "prompt_type": "web_followup",
        }

    prompt_package = _build_web_followup_prompt_package(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
        service=service,
        protocol=protocol,
        candidates=candidates,
        context=context or {},
        context_summary_enabled=_feature_flag_enabled(config, "context_summary_enabled", default=True),
    )
    metadata = dict(prompt_package.get("metadata", {}) or {})

    if provider_name in {"openai", "lm_studio"}:
        content = _request_openai_compatible_content(
            provider_name,
            provider_cfg,
            prompt_package,
            max_tokens=MAX_PROVIDER_SPECIALIST_RESPONSE_TOKENS,
            temperature=0.1,
        )
    elif provider_name == "claude":
        content = _request_claude_content(
            provider_cfg,
            prompt_package,
            max_tokens=360,
            temperature=0.1,
        )
    else:
        raise ProviderError(f"Unsupported provider: {provider_name}")

    payload = _parse_web_followup_payload(
        content,
        allowed_tool_ids=list(metadata.get("visible_candidate_tool_ids", []) or []),
        unavailable_tool_ids=_collect_unavailable_tool_ids(context or {}),
    )
    payload["provider"] = provider_name
    payload.update(metadata)
    return payload


def test_provider_connection(config: Dict[str, Any], provider_name: Optional[str] = None) -> Dict[str, Any]:
    selected_provider = str(provider_name or config.get("provider", "none") or "none").strip().lower()
    providers_cfg = config.get("providers", {}) if isinstance(config, dict) else {}
    provider_cfg = providers_cfg.get(selected_provider, {}) if isinstance(providers_cfg, dict) else {}

    if selected_provider == "none":
        return {
            "ok": False,
            "provider": "none",
            "error": "AI provider is set to none.",
        }

    if not isinstance(provider_cfg, dict):
        provider_cfg = {}

    if not provider_cfg.get("enabled", False):
        return {
            "ok": False,
            "provider": selected_provider,
            "error": f"Provider '{selected_provider}' is disabled.",
        }

    started = time.perf_counter()
    if selected_provider in {"openai", "lm_studio"}:
        return _probe_openai_compatible(selected_provider, provider_cfg, started)
    if selected_provider == "claude":
        return _probe_claude(provider_cfg, started)

    return {
        "ok": False,
        "provider": selected_provider,
        "error": f"Unsupported provider: {selected_provider}",
    }


def _normalize_tool_set(values: Any) -> set:
    normalized = set()
    if not isinstance(values, list):
        return normalized
    for item in values:
        token = str(item or "").strip().lower()
        if token:
            normalized.add(token)
    return normalized


def _feature_flag_enabled(config: Optional[Dict[str, Any]], flag_name: str, *, default: bool = True) -> bool:
    if not isinstance(config, dict):
        return bool(default)
    feature_flags = config.get("feature_flags", {})
    if not isinstance(feature_flags, dict):
        return bool(default)
    if flag_name not in feature_flags:
        return bool(default)
    return bool(feature_flags.get(flag_name, default))


def _determine_scheduler_phase(
        *,
        goal_profile: str,
        service: str,
        engagement_preset: str = "",
        context: Optional[Dict[str, Any]] = None,
) -> str:
    ctx = context if isinstance(context, dict) else {}
    signals = ctx.get("signals", {}) if isinstance(ctx.get("signals", {}), dict) else {}
    coverage = ctx.get("coverage", {}) if isinstance(ctx.get("coverage", {}), dict) else {}
    coverage_missing = {
        str(item or "").strip().lower()
        for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
        if str(item or "").strip()
    }
    analysis_mode = str(
        coverage.get("analysis_mode", "")
        or ctx.get("analysis_mode", "")
        or "standard"
    ).strip().lower()
    attempted = _normalize_tool_set(ctx.get("attempted_tool_ids", []))
    service_lower = str(service or "").strip().lower()
    is_web = bool(signals.get("web_service")) or service_lower in _WEB_SERVICE_IDS

    if "missing_discovery" in coverage_missing:
        return "initial_discovery"
    if "missing_screenshot" in coverage_missing or "missing_remote_screenshot" in coverage_missing:
        return "service_fingerprint"
    if {"missing_nmap_vuln", "missing_nuclei_auto"} & coverage_missing:
        return "broad_vuln"
    if "missing_cpe_cve_enrichment" in coverage_missing:
        return "broad_vuln"
    if "missing_smb_signing_checks" in coverage_missing:
        return "protocol_checks"
    if {"missing_whatweb", "missing_nikto", "missing_web_content_discovery"} & coverage_missing:
        return "deep_web"
    if "missing_followup_after_vuln" in coverage_missing:
        return "targeted_checks"

    has_discovery = any(token in attempted for token in {
        "nmap",
        "banner",
        "fingerprint-strings",
        "http-title",
        "ssl-cert",
    })
    has_screenshot = "screenshooter" in attempted
    has_broad_vuln = bool({"nmap-vuln.nse", "nuclei-web"} & attempted)
    has_protocol_checks = any(token in attempted for token in {
        "smb-security-mode",
        "smb-os-discovery",
        "rdp-ntlm-info",
        "ssh-hostkey",
        "ssh-auth-methods.nse",
        "snmp-info",
        "sslscan",
        "testssl.sh",
    })
    has_deep_web = any(token in attempted for token in {
        "whatweb",
        "whatweb-http",
        "whatweb-https",
        "httpx",
        "nikto",
        "web-content-discovery",
        "nuclei-cves",
        "nuclei-exposures",
        "nuclei-wordpress",
        "curl-headers",
        "curl-options",
        "curl-robots",
        "wafw00f",
        "wpscan",
    })

    shodan_enabled = bool(signals.get("shodan_enabled"))
    shodan_checked = any(token in attempted for token in {"shodan-enrichment", "shodan-host", "pyshodan"})
    effective_goal_profile = _effective_prompt_goal_profile(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
    )

    if not has_discovery:
        return "initial_discovery"
    if (is_web or bool(signals.get("rdp_service")) or bool(signals.get("vnc_service"))) and not has_screenshot:
        return "service_fingerprint"
    if not has_broad_vuln:
        return "broad_vuln"
    if not has_protocol_checks:
        return "protocol_checks"
    if is_web and not has_deep_web:
        return "deep_web"
    if effective_goal_profile == "external_pentest" and shodan_enabled and not shodan_checked:
        return "external_enrichment"
    if analysis_mode == "dig_deeper":
        return "deep_validation"
    return "targeted_checks"


def determine_scheduler_phase(
        goal_profile: str,
        service: str,
        engagement_preset: str = "",
        context: Optional[Dict[str, Any]] = None,
) -> str:
    return _determine_scheduler_phase(
        goal_profile=goal_profile,
        service=service,
        engagement_preset=engagement_preset,
        context=context,
    )


def _effective_prompt_goal_profile(*, goal_profile: str, engagement_preset: str = "") -> str:
    preset = str(engagement_preset or "").strip().lower()
    if preset:
        return preset
    return str(goal_profile or "").strip().lower()


def _build_prompt(
        goal_profile: str,
        service: str,
        protocol: str,
        candidates: List[Dict[str, str]],
        context: Optional[Dict[str, Any]] = None,
) -> str:
    return _build_ranking_prompt_package(
        goal_profile=goal_profile,
        service=service,
        protocol=protocol,
        candidates=candidates,
        context=context or {},
        context_summary_enabled=True,
    ).get("user_prompt", "")


def _build_ranking_prompt_package(
        *,
        goal_profile: str,
        engagement_preset: str = "",
        service: str,
        protocol: str,
        candidates: List[Dict[str, str]],
        context: Optional[Dict[str, Any]] = None,
        prompt_profiles_enabled: bool = True,
        context_summary_enabled: bool = True,
) -> Dict[str, Any]:
    ctx = context if isinstance(context, dict) else {}
    effective_goal_profile = _effective_prompt_goal_profile(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
    )
    current_phase = _determine_scheduler_phase(
        goal_profile=goal_profile,
        service=service,
        engagement_preset=engagement_preset,
        context=ctx,
    )
    context_block = _build_context_block(
        ctx,
        current_phase_override=current_phase,
        include_summary=bool(context_summary_enabled),
    )
    service_profile = _resolve_prompt_profile(service=service, context=ctx) if prompt_profiles_enabled else "generic"
    phase_profile = current_phase if prompt_profiles_enabled and current_phase in {"broad_vuln", "deep_web"} else "default"
    prompt_profile = service_profile if phase_profile == "default" else f"{service_profile}:{phase_profile}"

    system_prompt = _build_scheduler_system_prompt()
    prefix = _build_ranking_user_prompt_prefix(
        goal_profile=effective_goal_profile,
        service=service,
        protocol=protocol,
        current_phase=current_phase,
        service_profile=service_profile,
        phase_profile=phase_profile,
        prompt_profile=prompt_profile,
        context_block=context_block,
    )
    candidate_block, omitted_count, visible_candidate_tool_ids = _build_candidate_block(
        candidates,
        prefix,
        context=ctx,
        prompt_type="ranking",
    )
    metadata = {
        "prompt_version": SCHEDULER_PROMPT_VERSION,
        "prompt_type": "ranking",
        "goal_profile": effective_goal_profile,
        "legacy_goal_profile": str(goal_profile or "").strip().lower(),
        "engagement_preset": str(engagement_preset or "").strip().lower(),
        "prompt_profile": prompt_profile,
        "service_profile": service_profile,
        "phase_profile": phase_profile,
        "current_phase": current_phase,
        "context_chars": len(context_block),
        "candidate_count": len(candidates or []),
        "visible_candidate_count": len(visible_candidate_tool_ids),
        "omitted_candidate_count": int(omitted_count or 0),
        "service_prompt_overlays_enabled": bool(prompt_profiles_enabled),
        "visible_candidate_tool_ids": visible_candidate_tool_ids,
    }
    return {
        "system_prompt": system_prompt,
        "user_prompt": prefix + candidate_block,
        "metadata": metadata,
    }


def _build_scheduler_system_prompt() -> str:
    return (
        "You are a penetration-testing scheduler assistant operating inside a governed workflow.\n"
        "Return strict JSON only.\n"
        "Rank only the supplied candidates and never invent tools or actions outside that list.\n"
        "Prefer closing baseline coverage gaps and immediate follow-up dependencies before niche checks.\n"
        "Use concise rationales grounded in the supplied context.\n"
        "Do not add markdown, prose, or extra commentary outside the JSON object."
    )


def _resolve_prompt_profile(*, service: str, context: Optional[Dict[str, Any]] = None) -> str:
    ctx = context if isinstance(context, dict) else {}
    signals = ctx.get("signals", {}) if isinstance(ctx.get("signals", {}), dict) else {}
    service_lower = str(service or "").strip().lower()
    if bool(signals.get("web_service")) or service_lower in _WEB_SERVICE_IDS:
        return "web"
    if bool(signals.get("rdp_service")) or bool(signals.get("vnc_service")) or service_lower in {
        "ms-wbt-server",
        "rdp",
        "vnc",
        "vnc-http",
    }:
        return "rdp_vnc"
    if service_lower in {"microsoft-ds", "netbios-ssn", "smb"}:
        return "smb"
    return "generic"


def _build_ranking_user_prompt_prefix(
        *,
        goal_profile: str,
        service: str,
        protocol: str,
        current_phase: str,
        service_profile: str,
        phase_profile: str,
        prompt_profile: str,
        context_block: str,
) -> str:
    profile_overlay = _build_prompt_profile_overlay(
        goal_profile=goal_profile,
        service_profile=service_profile,
        phase_profile=phase_profile,
    )
    return (
        "Task: rank scheduler-generated candidates for the next safe, high-value actions.\n"
        f"Prompt version: {SCHEDULER_PROMPT_VERSION}\n"
        f"Goal profile: {goal_profile}\n"
        f"Service: {service}\n"
        f"Protocol: {protocol}\n"
        f"Current phase: {current_phase}\n"
        f"Prompt profile: {prompt_profile}\n"
        "Lifecycle phases: initial_discovery -> service_fingerprint -> broad_vuln -> protocol_checks "
        "-> targeted_checks -> deep_web -> external_enrichment -> complete.\n"
        "Ranking priorities:\n"
        "1. Close missing baseline coverage first.\n"
        "2. Prefer immediate follow-up dependencies from existing evidence.\n"
        "3. Use technology-specific or vendor-specific checks only when the context supports them.\n"
        "4. Avoid rerunning tools that already executed successfully or are known missing.\n"
        "5. When analysis_mode is dig_deeper, reason over the full host context rather than the target port alone.\n"
        "6. Never recommend manual tests that directly invoke tools marked unavailable or command not found.\n"
        "7. If the remaining coverage gaps cannot be closed by any supplied candidate, return actions as [] instead of recommending unrelated retries.\n"
        "Ignore tool names mentioned elsewhere in the context if they are not present in the Candidates section.\n"
        f"{profile_overlay}"
        "Return ONLY JSON with this schema:\n"
        "{\"actions\":[{\"tool_id\":\"...\",\"score\":0-100,\"rationale\":\"...\"}],"
        "\"host_updates\":{\"hostname\":\"...\",\"hostname_confidence\":0-100,\"os\":\"...\",\"os_confidence\":0-100,"
        "\"technologies\":[{\"name\":\"...\",\"version\":\"...\",\"cpe\":\"...\",\"evidence\":\"...\"}]},"
        "\"findings\":[{\"title\":\"...\",\"severity\":\"critical|high|medium|low|info\",\"cvss\":0-10,"
        "\"cve\":\"...\",\"evidence\":\"...\"}],"
        "\"manual_tests\":[{\"why\":\"...\",\"command\":\"...\",\"scope_note\":\"...\"}],"
        "\"next_phase\":\"...\"}\n"
        "If no safe or high-value action remains, return actions as [] and use manual_tests for suggestions.\n"
        f"{context_block}"
        "Candidates:\n"
    )


def _build_prompt_profile_overlay(*, goal_profile: str, service_profile: str, phase_profile: str) -> str:
    lines = []
    if service_profile == "web":
        lines.append(
            "Service overlay: web. Prefer screenshot, broad web vuln coverage, tech fingerprinting, content "
            "discovery, then evidence-driven follow-up."
        )
    elif service_profile == "smb":
        lines.append(
            "Service overlay: smb. Prefer signing checks, safe enumeration, and identity posture before deeper or "
            "specialized checks."
        )
    elif service_profile == "rdp_vnc":
        lines.append(
            "Service overlay: rdp_vnc. Prefer screenshot, banner, protocol metadata, TLS posture, and safe identity "
            "checks before niche follow-up."
        )
    else:
        lines.append(
            "Service overlay: generic. Prefer broad discovery, banners, vuln baselines, and protocol checks before "
            "specialized tools."
        )

    if phase_profile == "broad_vuln":
        lines.append(
            "Phase overlay: broad_vuln. Favor broad vuln discovery, CPE-to-CVE enrichment, and immediate follow-up "
            "dependencies before niche checks."
        )
    elif phase_profile == "deep_web":
        lines.append(
            "Phase overlay: deep_web. Favor bounded web follow-up such as whatweb, nikto, content discovery, and "
            "evidence-driven nuclei follow-up."
        )

    if str(goal_profile or "").strip().lower() == "external_pentest":
        lines.append(
            "Goal overlay: external_pentest. When Shodan or external enrichment is available and high-value, "
            "consider it after core baseline coverage is satisfied."
        )

    return "\n".join(lines) + "\n"


def _normalize_tool_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _coverage_missing_ids(context: Optional[Dict[str, Any]]) -> Set[str]:
    if not isinstance(context, dict):
        return set()
    coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
    return {
        _normalize_tool_token(item)
        for item in (coverage.get("missing", []) if isinstance(coverage.get("missing", []), list) else [])
        if _normalize_tool_token(item)
    }


def _coverage_recommended_tool_ids(context: Optional[Dict[str, Any]]) -> Set[str]:
    if not isinstance(context, dict):
        return set()
    coverage = context.get("coverage", {}) if isinstance(context.get("coverage", {}), dict) else {}
    return {
        _normalize_tool_token(item)
        for item in (coverage.get("recommended_tool_ids", []) if isinstance(coverage.get("recommended_tool_ids", []), list) else [])
        if _normalize_tool_token(item)
    }


def _tool_matches_coverage_gap(tool_id: str, coverage_missing: Set[str]) -> bool:
    tool_norm = _normalize_tool_token(tool_id)
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
    if "missing_cpe_cve_enrichment" in coverage_missing and tool_norm in {"nmap-vuln.nse", "nuclei-web", "nuclei-cves", "nuclei-exposures"}:
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
        "netexec",
        "smb-enum-users.nse",
    }:
        return True
    return False


def _candidate_visibility_priority(
        candidate: Dict[str, str],
        *,
        context: Optional[Dict[str, Any]] = None,
        prompt_type: str = "",
) -> int:
    tool_id = str(candidate.get("tool_id", "") or "")
    tool_norm = _normalize_tool_token(tool_id)
    if not tool_norm:
        return 0

    coverage_missing = _coverage_missing_ids(context)
    coverage_recommended = _coverage_recommended_tool_ids(context)
    priority = 0

    if tool_norm in coverage_recommended:
        priority += 220
    if _tool_matches_coverage_gap(tool_norm, coverage_missing):
        priority += 320

    if {"missing_screenshot", "missing_remote_screenshot"} & coverage_missing and tool_norm in {"screenshooter", "x11screen"}:
        priority += 120
    if "missing_nmap_vuln" in coverage_missing and tool_norm == "nmap-vuln.nse":
        priority += 110
    if "missing_nuclei_auto" in coverage_missing and tool_norm == "nuclei-web":
        priority += 110
    if "missing_whatweb" in coverage_missing and tool_norm in {"whatweb", "whatweb-http", "whatweb-https"}:
        priority += 100
    if "missing_nikto" in coverage_missing and tool_norm == "nikto":
        priority += 100
    if "missing_http_followup" in coverage_missing and tool_norm in {"curl-headers", "curl-options", "curl-robots"}:
        priority += 80
    if prompt_type == "ranking" and tool_norm in {"banner", "nmap"} and (coverage_missing & _STRICT_COVERAGE_GAP_IDS):
        priority -= 40

    return priority


def _prioritize_candidates_for_prompt(
        candidates: List[Dict[str, str]],
        *,
        context: Optional[Dict[str, Any]] = None,
        prompt_type: str = "",
) -> List[Dict[str, str]]:
    if not candidates:
        return []
    ranked = []
    for index, candidate in enumerate(candidates):
        ranked.append((
            -int(_candidate_visibility_priority(candidate, context=context, prompt_type=prompt_type)),
            index,
            candidate,
        ))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ranked]


def _build_candidate_block(
        candidates: List[Dict[str, str]],
        prefix: str,
        *,
        context: Optional[Dict[str, Any]] = None,
        prompt_type: str = "",
) -> Tuple[str, int, List[str]]:
    if not candidates:
        return "", 0, []

    ordered_candidates = _prioritize_candidates_for_prompt(
        candidates,
        context=context,
        prompt_type=prompt_type,
    )
    candidate_lines = []
    visible_tool_ids = []
    omitted = 0
    budget = max(MIN_PROVIDER_CANDIDATE_BLOCK_CHARS, MAX_PROVIDER_PROMPT_CHARS - len(prefix) - 120)
    target_visible = min(
        len(ordered_candidates),
        MAX_PROVIDER_CANDIDATES,
        6 if prompt_type == "web_followup" else 8,
    )

    def _candidate_line(candidate: Dict[str, str], *, detail_level: int) -> Tuple[str, str]:
        tool_id = str(candidate.get("tool_id", "")).strip()[:120]
        prompt_info = get_scheduler_tool_prompt_info(
            tool_id,
            label=str(candidate.get("label", "")).strip(),
            command_template=str(candidate.get("command_template", "")),
            service_scope=str(candidate.get("service_scope", "")).strip(),
        )
        label_limit = 64 if detail_level <= 1 else MAX_CANDIDATE_LABEL_CHARS
        purpose_limit = 56 if detail_level <= 1 else MAX_CANDIDATE_PURPOSE_CHARS
        when_limit = 64 if detail_level == 2 else 0
        template_limit = 96 if detail_level == 2 else 0
        payload: Dict[str, Any] = {
            "tool_id": tool_id,
            "label": str(candidate.get("label", "")).strip()[:label_limit],
            "purpose": _normalize_prompt_text(prompt_info.purpose, purpose_limit),
        }
        arg_shape = str(prompt_info.arg_shape or "").strip()[:MAX_CANDIDATE_ARG_SHAPE_CHARS]
        if arg_shape:
            payload["arg_shape"] = arg_shape
        phase_tags = list(prompt_info.phase_tags[:3 if detail_level <= 1 else 4])
        if phase_tags:
            payload["phase_tags"] = phase_tags
        if bool(prompt_info.safe_parallel):
            payload["safe_parallel"] = True
        if detail_level >= 1:
            service_scope = str(candidate.get("service_scope", "")).strip()[:72]
            if service_scope:
                payload["service_scope"] = service_scope
        if when_limit > 0:
            payload["when_to_use"] = _normalize_prompt_text(prompt_info.when_to_use, when_limit)
        if template_limit > 0:
            payload["command_template_excerpt"] = _normalize_prompt_text(
                str(candidate.get("command_template", "")),
                template_limit,
            )
        return json.dumps(payload, separators=(",", ":")), tool_id

    best_lines: List[str] = []
    best_visible_tool_ids: List[str] = []
    best_omitted = max(0, len(ordered_candidates) - MAX_PROVIDER_CANDIDATES)

    for detail_level in (2, 1, 0):
        current_lines: List[str] = []
        current_visible_tool_ids: List[str] = []
        current_used = 0
        current_omitted = 0
        for index, candidate in enumerate(ordered_candidates):
            if index >= MAX_PROVIDER_CANDIDATES:
                current_omitted = len(ordered_candidates) - index
                break
            line, tool_id = _candidate_line(candidate, detail_level=detail_level)
            projected = current_used + len(line) + 1
            if projected > budget:
                current_omitted = len(ordered_candidates) - index
                break
            current_lines.append(line)
            if tool_id:
                current_visible_tool_ids.append(tool_id)
            current_used = projected

        if current_lines:
            best_lines = current_lines
            best_visible_tool_ids = current_visible_tool_ids
            best_omitted = current_omitted
        if len(current_visible_tool_ids) >= target_visible:
            break

    candidate_lines = list(best_lines)
    visible_tool_ids = list(best_visible_tool_ids)
    omitted = int(best_omitted or 0)

    if not candidate_lines:
        first = ordered_candidates[0]
        line, tool_id = _candidate_line(first, detail_level=0)
        candidate_lines.append(line)
        if tool_id:
            visible_tool_ids.append(tool_id)
        omitted = max(0, len(ordered_candidates) - 1)

    if omitted > 0:
        candidate_lines.append(
            json.dumps({"note": f"{omitted} candidates omitted due to context budget"}, separators=(",", ":"))
        )

    return "\n".join(candidate_lines), omitted, _unique_strings(visible_tool_ids)


def _prompt_package_parts(
        prompt_package: Dict[str, Any],
        *,
        default_system_prompt: str = "Return strict JSON only.",
) -> Tuple[str, str, Dict[str, Any]]:
    if not isinstance(prompt_package, dict):
        return str(default_system_prompt or ""), str(prompt_package or ""), {}
    system_prompt = str(prompt_package.get("system_prompt", "") or default_system_prompt or "")
    user_prompt = str(prompt_package.get("user_prompt", "") or "")
    metadata = prompt_package.get("metadata", {}) if isinstance(prompt_package.get("metadata", {}), dict) else {}
    return system_prompt, user_prompt, metadata


def _openai_structured_outputs_enabled(provider_name: str, provider_cfg: Dict[str, Any]) -> bool:
    if str(provider_name or "").strip().lower() != "openai":
        return False
    if not isinstance(provider_cfg, dict):
        return False
    return bool(provider_cfg.get("structured_outputs", False))


def _scheduler_ranking_response_format(*, allowed_tool_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "scheduler_ranking_response",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["actions", "host_updates", "findings", "manual_tests", "next_phase"],
                "properties": {
                    "actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["tool_id", "score", "rationale"],
                            "properties": {
                                "tool_id": {"type": "string"},
                                "score": {"type": "number"},
                                "rationale": {"type": "string"},
                            },
                        },
                    },
                    "host_updates": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["hostname", "hostname_confidence", "os", "os_confidence", "technologies"],
                        "properties": {
                            "hostname": {"type": "string"},
                            "hostname_confidence": {"type": "number"},
                            "os": {"type": "string"},
                            "os_confidence": {"type": "number"},
                            "technologies": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["name", "version", "cpe", "evidence"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "version": {"type": "string"},
                                        "cpe": {"type": "string"},
                                        "evidence": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["title", "severity", "cvss", "cve", "evidence"],
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"],
                                },
                                "cvss": {"type": "number"},
                                "cve": {"type": "string"},
                                "evidence": {"type": "string"},
                            },
                        },
                    },
                    "manual_tests": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["why", "command", "scope_note"],
                            "properties": {
                                "why": {"type": "string"},
                                "command": {"type": "string"},
                                "scope_note": {"type": "string"},
                            },
                        },
                    },
                    "next_phase": {"type": "string"},
                },
            },
        },
    }
    allowed = _normalized_tool_id_map(allowed_tool_ids)
    if allowed:
        response_format["json_schema"]["schema"]["properties"]["actions"]["items"]["properties"]["tool_id"] = {
            "type": "string",
            "enum": list(allowed.values()),
        }
    return response_format


def _should_fallback_from_structured_outputs(exc: ProviderError) -> bool:
    message = str(exc or "").strip().lower()
    if "400" not in message:
        return False
    markers = (
        "response_format",
        "json_schema",
        "strict",
        "unsupported",
        "unknown parameter",
        "invalid parameter",
    )
    return any(marker in message for marker in markers)


def _call_openai_compatible(
        provider_name: str,
        provider_cfg: Dict[str, Any],
        prompt_package: Dict[str, Any],
        *,
        context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base_url, headers, model, _models, _auto_selected = _openai_compatible_context(provider_name, provider_cfg)
    system_prompt, user_prompt, prompt_metadata = _prompt_package_parts(prompt_package)
    allowed_tool_ids = _visible_candidate_tool_ids_from_metadata(prompt_metadata)
    normalized_context = context if isinstance(context, dict) else {}
    unavailable_tool_ids = _collect_unavailable_tool_ids(normalized_context)
    current_phase = str(prompt_metadata.get("current_phase", "") or "").strip().lower() if normalized_context else ""
    structured_outputs_enabled = _openai_structured_outputs_enabled(provider_name, provider_cfg)
    if provider_name == "lm_studio":
        result = _post_lmstudio_chat_with_fallback(
            base_url=base_url,
            headers=headers,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=MAX_PROVIDER_RESPONSE_TOKENS,
            prompt_metadata=prompt_metadata,
        )
        content = str(result.get("content", "") or "")
    else:
        endpoint = f"{base_url}/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        _set_chat_completion_temperature(payload, provider_name=provider_name, temperature=0.2)
        _set_chat_completion_token_limit(payload, provider_name=provider_name, max_tokens=MAX_PROVIDER_RESPONSE_TOKENS)
        request_metadata = dict(prompt_metadata)
        request_metadata.update({
            "structured_output_requested": bool(structured_outputs_enabled),
            "structured_output_used": False,
            "structured_output_fallback": False,
        })
        if structured_outputs_enabled:
            payload["response_format"] = _scheduler_ranking_response_format(allowed_tool_ids=allowed_tool_ids)
            request_metadata["structured_output_used"] = True
        try:
            content = _post_openai_compatible_chat_with_retry(
                provider_name,
                endpoint,
                headers,
                payload,
                prompt_metadata=request_metadata,
            )
        except ProviderError as exc:
            if not structured_outputs_enabled or not _should_fallback_from_structured_outputs(exc):
                raise
            fallback_payload = dict(payload)
            fallback_payload.pop("response_format", None)
            fallback_metadata = dict(request_metadata)
            fallback_metadata["structured_output_used"] = False
            fallback_metadata["structured_output_fallback"] = True
            content = _post_openai_compatible_chat_with_retry(
                provider_name,
                endpoint,
                headers,
                fallback_payload,
                prompt_metadata=fallback_metadata,
            )
            request_metadata = fallback_metadata
    parsed = _parse_provider_payload(
        content,
        allowed_tool_ids=allowed_tool_ids,
        unavailable_tool_ids=unavailable_tool_ids,
        current_phase=current_phase,
    )
    parsed["structured_output_requested"] = bool(structured_outputs_enabled)
    parsed["structured_output_used"] = bool(
        structured_outputs_enabled and not request_metadata.get("structured_output_fallback", False)
    ) if provider_name == "openai" else False
    parsed["structured_output_fallback"] = bool(request_metadata.get("structured_output_fallback", False)) \
        if provider_name == "openai" else False
    return parsed


def _request_openai_compatible_content(
        provider_name: str,
        provider_cfg: Dict[str, Any],
        prompt_package: Dict[str, Any],
        *,
        max_tokens: int,
        temperature: float,
) -> str:
    base_url, headers, model, _models, _auto_selected = _openai_compatible_context(provider_name, provider_cfg)
    system_prompt, user_prompt, prompt_metadata = _prompt_package_parts(prompt_package)
    if provider_name == "lm_studio":
        result = _post_lmstudio_chat_with_fallback(
            base_url=base_url,
            headers=headers,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            prompt_metadata=prompt_metadata,
        )
        return str(result.get("content", "") or "")

    endpoint = f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    _set_chat_completion_temperature(payload, provider_name=provider_name, temperature=temperature)
    _set_chat_completion_token_limit(payload, provider_name=provider_name, max_tokens=max_tokens)
    return _post_openai_compatible_chat_with_retry(
        provider_name,
        endpoint,
        headers,
        payload,
        prompt_metadata=prompt_metadata,
    )


def _build_reflection_prompt_package(
        *,
        goal_profile: str,
        engagement_preset: str = "",
        service: str,
        protocol: str,
        context: Optional[Dict[str, Any]] = None,
        recent_rounds: Optional[List[Dict[str, Any]]] = None,
        trigger_reason: str = "",
        trigger_context: Optional[Dict[str, Any]] = None,
        context_summary_enabled: bool = True,
) -> Dict[str, Any]:
    ctx = context if isinstance(context, dict) else {}
    effective_goal_profile = _effective_prompt_goal_profile(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
    )
    rounds = recent_rounds if isinstance(recent_rounds, list) else []
    trigger_reason_token = str(trigger_reason or "").strip().lower()[:64]
    trigger_payload = {}
    if trigger_reason_token:
        trigger_payload["reason"] = trigger_reason_token
    if isinstance(trigger_context, dict):
        for key in (
                "round_number",
                "current_phase",
                "previous_phase",
                "window_size",
                "repeated_selection_count",
        ):
            value = trigger_context.get(key, "")
            if value in ("", None):
                continue
            trigger_payload[key] = value
        recent_failures = [
            _normalize_prompt_text(str(item or "").strip(), 120)
            for item in list(trigger_context.get("recent_failures", []) or [])[:6]
            if str(item or "").strip()
        ]
        if recent_failures:
            trigger_payload["recent_failures"] = recent_failures
    current_phase = _determine_scheduler_phase(
        goal_profile=goal_profile,
        service=service,
        engagement_preset=engagement_preset,
        context=ctx,
    )
    service_profile = _resolve_prompt_profile(service=service, context=ctx)
    context_block = _build_context_block(
        ctx,
        current_phase_override=current_phase,
        include_summary=bool(context_summary_enabled),
    )
    recent_rounds_payload = _build_recent_rounds_block(rounds)
    trigger_block = ""
    if trigger_payload:
        rendered_trigger = json.dumps(trigger_payload, separators=(",", ":"))
        trigger_block = f"Reflection trigger:\n{_truncate_block_text(rendered_trigger, 640)}\n"
    system_prompt = (
        "You are an execution monitor for a governed penetration-testing scheduler.\n"
        "Return strict JSON only.\n"
        "Assess whether recent rounds are still productive.\n"
        "Do not invent tools outside the supplied recent decisions.\n"
        "Prefer continue unless the evidence clearly indicates a stall or completion.\n"
        "Manual tests must be safe validation suggestions only.\n"
        "Do not suggest manual tests that directly invoke tools marked unavailable or command not found."
    )
    user_prompt = (
        "Task: assess recent scheduler progress and detect stalls.\n"
        f"Prompt version: {SCHEDULER_REFLECTION_PROMPT_VERSION}\n"
        f"Goal profile: {effective_goal_profile}\n"
        f"Service: {service}\n"
        f"Protocol: {protocol}\n"
        f"Current phase: {current_phase}\n"
        f"Service profile: {service_profile}\n"
        "Return ONLY JSON with this schema:\n"
        "{\"state\":\"continue|stalled|complete\","
        "\"reason\":\"...\","
        "\"priority_shift\":\"coverage_first|targeted_followup|manual_validation|stop\","
        "\"promote_tool_ids\":[\"...\"],"
        "\"suppress_tool_ids\":[\"...\"],"
        "\"manual_tests\":[{\"why\":\"...\",\"command\":\"...\",\"scope_note\":\"...\"}]}\n"
        f"{trigger_block}"
        f"{recent_rounds_payload}"
        f"{context_block}"
    )
    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "metadata": {
            "prompt_version": SCHEDULER_REFLECTION_PROMPT_VERSION,
            "prompt_type": "reflection",
            "goal_profile": effective_goal_profile,
            "legacy_goal_profile": str(goal_profile or "").strip().lower(),
            "engagement_preset": str(engagement_preset or "").strip().lower(),
            "current_phase": current_phase,
            "service_profile": service_profile,
            "recent_round_count": len(rounds[:8]),
            "context_chars": len(context_block),
            "trigger_reason": trigger_reason_token,
            "trigger_context": trigger_payload,
        },
    }


def _build_web_followup_prompt_package(
        *,
        goal_profile: str,
        engagement_preset: str = "",
        service: str,
        protocol: str,
        candidates: List[Dict[str, str]],
        context: Optional[Dict[str, Any]] = None,
        context_summary_enabled: bool = True,
) -> Dict[str, Any]:
    ctx = context if isinstance(context, dict) else {}
    effective_goal_profile = _effective_prompt_goal_profile(
        goal_profile=goal_profile,
        engagement_preset=engagement_preset,
    )
    current_phase = _determine_scheduler_phase(
        goal_profile=goal_profile,
        service=service,
        engagement_preset=engagement_preset,
        context=ctx,
    )
    context_block = _build_context_block(
        ctx,
        current_phase_override=current_phase,
        include_summary=bool(context_summary_enabled),
    )
    system_prompt = (
        "You are a specialist web follow-up advisor operating inside a governed penetration-testing scheduler.\n"
        "Return strict JSON only.\n"
        "Choose only from the supplied candidate list and never invent tools or actions.\n"
        "Favor bounded, evidence-driven follow-up that closes concrete coverage gaps or validates observed web signals.\n"
        "Do not re-run broad baseline scans unless the context still shows they are missing.\n"
        "Manual tests must be safe validation suggestions only.\n"
        "Do not suggest manual tests that directly invoke tools marked unavailable or command not found."
    )
    prefix = (
        "Task: choose the strongest bounded web follow-up actions from the supplied candidates.\n"
        f"Prompt version: {SCHEDULER_WEB_FOLLOWUP_PROMPT_VERSION}\n"
        f"Goal profile: {effective_goal_profile}\n"
        f"Service: {service}\n"
        f"Protocol: {protocol}\n"
        f"Current phase: {current_phase}\n"
        "Selection priorities:\n"
        "1. Close missing web follow-up coverage before niche checks.\n"
        "2. Prefer technology, finding, CVE, or reflection-driven validation over generic retries.\n"
        "3. Choose a small bounded set of follow-up tools rather than broad rescan behavior.\n"
        "Return ONLY JSON with this schema:\n"
        "{\"focus\":\"coverage_gap|tech_validation|vuln_followup|content_discovery|manual_review\","
        "\"selected_tool_ids\":[\"...\"],"
        "\"reason\":\"...\","
        "\"manual_tests\":[{\"why\":\"...\",\"command\":\"...\",\"scope_note\":\"...\"}]}\n"
        "If no specialist follow-up boost is warranted, return selected_tool_ids as [] and explain why.\n"
        f"{context_block}"
        "Candidates:\n"
    )
    candidate_block, omitted_count, _visible_candidate_tool_ids = _build_candidate_block(
        candidates,
        prefix,
        context=ctx,
        prompt_type="web_followup",
    )
    return {
        "system_prompt": system_prompt,
        "user_prompt": prefix + candidate_block,
        "metadata": {
            "prompt_version": SCHEDULER_WEB_FOLLOWUP_PROMPT_VERSION,
            "prompt_type": "web_followup",
            "goal_profile": effective_goal_profile,
            "legacy_goal_profile": str(goal_profile or "").strip().lower(),
            "engagement_preset": str(engagement_preset or "").strip().lower(),
            "current_phase": current_phase,
            "service_profile": "web",
            "candidate_count": len(candidates or []),
            "visible_candidate_count": len(_visible_candidate_tool_ids),
            "visible_candidate_tool_ids": _visible_candidate_tool_ids,
            "omitted_candidate_count": int(omitted_count or 0),
            "context_chars": len(context_block),
        },
    }


def _build_recent_rounds_block(rounds: List[Dict[str, Any]]) -> str:
    compact_rounds = []
    for item in list(rounds or [])[-8:]:
        if not isinstance(item, dict):
            continue
        payload = {
            "round": int(item.get("round", 0) or 0),
            "coverage_missing": [
                str(entry).strip().lower()[:64]
                for entry in list(item.get("coverage_missing", []) or [])[:24]
                if str(entry).strip()
            ],
            "findings_count": int(item.get("findings_count", 0) or 0),
            "manual_tests_count": int(item.get("manual_tests_count", 0) or 0),
            "technologies_count": int(item.get("technologies_count", 0) or 0),
            "next_phase": str(item.get("next_phase", "") or "")[:64],
            "observed_phase": str(item.get("observed_phase", "") or "")[:64],
            "recent_failures": [
                str(entry).strip().lower()[:120]
                for entry in list(item.get("recent_failures", []) or [])[:8]
                if str(entry).strip()
            ],
            "decision_tool_ids": [
                str(entry).strip().lower()[:80]
                for entry in list(item.get("decision_tool_ids", []) or [])[:16]
                if str(entry).strip()
            ],
            "decision_family_ids": [
                str(entry).strip().lower()[:80]
                for entry in list(item.get("decision_family_ids", []) or [])[:16]
                if str(entry).strip()
            ],
            "signal_key": str(item.get("signal_key", "") or "")[:240],
            "repeated_selection_count": int(item.get("repeated_selection_count", 0) or 0),
            "progress_score": int(item.get("progress_score", 0) or 0),
        }
        compact_rounds.append(payload)
    if not compact_rounds:
        return "Recent rounds:\n[]\n"
    rendered = json.dumps(compact_rounds, separators=(",", ":"))
    return f"Recent rounds:\n{_truncate_block_text(rendered, 2400)}\n"


def _parse_reflection_payload(
        content: str,
        *,
        unavailable_tool_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payload_obj = _extract_json(content)
    state = str(payload_obj.get("state", "continue") or "continue").strip().lower()
    if state not in {"continue", "stalled", "complete"}:
        state = "continue"
    priority_shift = str(payload_obj.get("priority_shift", "") or "").strip().lower()
    if priority_shift not in {"coverage_first", "targeted_followup", "manual_validation", "stop"}:
        priority_shift = ""
    promote_tool_ids = _normalize_tool_id_list(payload_obj.get("promote_tool_ids", []), limit=32)
    suppress_tool_ids = _normalize_tool_id_list(payload_obj.get("suppress_tool_ids", []), limit=32)
    manual_tests = _normalize_manual_tests(
        payload_obj.get("manual_tests", []),
        unavailable_tool_ids=unavailable_tool_ids,
    )
    return {
        "state": state,
        "reason": _normalize_prompt_text(str(payload_obj.get("reason", "") or "").strip(), 320),
        "priority_shift": priority_shift,
        "promote_tool_ids": promote_tool_ids,
        "suppress_tool_ids": suppress_tool_ids,
        "manual_tests": manual_tests,
    }


def _parse_web_followup_payload(
        content: str,
        *,
        allowed_tool_ids: Optional[List[str]] = None,
        unavailable_tool_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payload_obj = _extract_json(content)
    focus = str(payload_obj.get("focus", "") or "").strip().lower()
    if focus not in {
        "coverage_gap",
        "tech_validation",
        "vuln_followup",
        "content_discovery",
        "manual_review",
    }:
        focus = ""
    return {
        "focus": focus,
        "selected_tool_ids": _normalize_tool_id_list(
            payload_obj.get("selected_tool_ids", []),
            limit=6,
            allowed_tool_ids=allowed_tool_ids,
        ),
        "reason": _normalize_prompt_text(str(payload_obj.get("reason", "") or "").strip(), 320),
        "manual_tests": _normalize_manual_tests(
            payload_obj.get("manual_tests", []),
            unavailable_tool_ids=unavailable_tool_ids,
        ),
    }


def _normalize_tool_id_list(values: Any, *, limit: int, allowed_tool_ids: Optional[List[str]] = None) -> List[str]:
    if not isinstance(values, list):
        return []
    allowed_tool_id_map = _normalized_tool_id_map(allowed_tool_ids)
    rows = []
    seen = set()
    for item in values:
        token = str(item or "").strip().lower()
        if not token or token in seen:
            continue
        if allowed_tool_id_map and token not in allowed_tool_id_map:
            continue
        seen.add(token)
        rows.append(str(allowed_tool_id_map.get(token, token))[:120])
        if len(rows) >= int(limit):
            break
    return rows


def _probe_openai_compatible(provider_name: str, provider_cfg: Dict[str, Any], started: float) -> Dict[str, Any]:
    auth_header_sent = False
    endpoint_used = ""
    api_style = "openai_compatible"
    structured_output_requested = False
    structured_output_used = False
    structured_output_fallback = False
    try:
        base_url, headers, model, discovered_models, auto_selected = _openai_compatible_context(provider_name, provider_cfg)
        auth_header_sent = _has_authorization_header(headers)
        test_prompt = (
            "Return only this JSON:\n"
            "{\"actions\":[{\"tool_id\":\"healthcheck\",\"score\":100,\"rationale\":\"ok\"}]}"
        )
        if provider_name == "lm_studio":
            result = _post_lmstudio_chat_with_fallback(
                base_url=base_url,
                headers=headers,
                model=model,
                system_prompt="Return strict JSON only.",
                user_prompt=test_prompt,
                temperature=0.0,
                max_tokens=120,
            )
            content = str(result.get("content", "") or "")
            endpoint_used = str(result.get("endpoint", "") or "")
            api_style = str(result.get("api_style", "lmstudio_native") or "lmstudio_native")
        else:
            endpoint = f"{base_url}/chat/completions"
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "Return strict JSON only."},
                    {"role": "user", "content": test_prompt},
                ],
            }
            _set_chat_completion_temperature(payload, provider_name=provider_name, temperature=0.0)
            _set_chat_completion_token_limit(payload, provider_name=provider_name, max_tokens=120)
            structured_outputs_enabled = _openai_structured_outputs_enabled(provider_name, provider_cfg)
            structured_output_requested = bool(structured_outputs_enabled)
            if structured_outputs_enabled:
                payload["response_format"] = _scheduler_ranking_response_format()
            request_metadata = {
                "prompt_version": SCHEDULER_PROMPT_VERSION,
                "prompt_type": "healthcheck",
                "structured_output_requested": bool(structured_outputs_enabled),
                "structured_output_used": bool(structured_outputs_enabled),
                "structured_output_fallback": False,
            }
            try:
                content = _post_openai_compatible_chat_with_retry(
                    provider_name,
                    endpoint,
                    headers,
                    payload,
                    prompt_metadata=request_metadata,
                )
            except ProviderError as exc:
                if not structured_outputs_enabled or not _should_fallback_from_structured_outputs(exc):
                    raise
                fallback_payload = dict(payload)
                fallback_payload.pop("response_format", None)
                request_metadata["structured_output_used"] = False
                request_metadata["structured_output_fallback"] = True
                structured_output_fallback = True
                content = _post_openai_compatible_chat_with_retry(
                    provider_name,
                    endpoint,
                    headers,
                    fallback_payload,
                    prompt_metadata=request_metadata,
                )
            structured_output_used = bool(structured_outputs_enabled and not structured_output_fallback)
            endpoint_used = endpoint

        actions = _parse_provider_payload(content).get("actions", [])
        if not actions:
            raise ProviderError("Provider returned an empty actions list.")
    except ProviderError as exc:
        return {
            "ok": False,
            "provider": provider_name,
            "auth_header_sent": auth_header_sent,
            "error": str(exc),
        }

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "ok": True,
        "provider": provider_name,
        "base_url": base_url,
        "model": model,
        "auth_header_sent": auth_header_sent,
        "endpoint": endpoint_used,
        "api_style": api_style,
        "auto_selected_model": bool(auto_selected),
        "discovered_models": discovered_models[:12],
        "latency_ms": elapsed_ms,
        "structured_output_requested": structured_output_requested,
        "structured_output_used": structured_output_used,
        "structured_output_fallback": structured_output_fallback,
    }


def _openai_compatible_context(provider_name: str, provider_cfg: Dict[str, Any]) -> Tuple[str, Dict[str, str], str, List[str], bool]:
    base_url = str(provider_cfg.get("base_url", "")).rstrip("/")
    if not base_url:
        raise ProviderError(f"Base URL is required for provider {provider_name}.")

    api_key = str(provider_cfg.get("api_key", "")).strip()
    if provider_name == "openai" and not api_key:
        raise ProviderError("API key is required for provider openai.")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    model, discovered_models, auto_selected = _resolve_openai_compatible_model(
        provider_name=provider_name,
        provider_cfg=provider_cfg,
        base_url=base_url,
        headers=headers,
    )
    return base_url, headers, model, discovered_models, auto_selected


def _resolve_openai_compatible_model(
        provider_name: str,
        provider_cfg: Dict[str, Any],
        base_url: str,
        headers: Dict[str, str],
) -> Tuple[str, List[str], bool]:
    model = str(provider_cfg.get("model", "")).strip()
    if model:
        return model, [], False

    if provider_name == "openai":
        return DEFAULT_OPENAI_MODEL, [], True

    if provider_name != "lm_studio":
        raise ProviderError(f"Model is required for provider {provider_name}.")

    discovered_models = _fetch_lmstudio_models(base_url, headers)
    if not discovered_models:
        raise ProviderError(
            "LM Studio model is empty and no models were returned from /models. "
            "Load a model in LM Studio or set the model explicitly."
        )
    selected = _select_preferred_lmstudio_model(discovered_models)
    return selected, discovered_models, True


def _fetch_lmstudio_models(base_url: str, headers: Dict[str, str]) -> List[str]:
    requests_module = _get_requests_module()
    auth_state = _auth_state_text(headers)
    errors = []
    for endpoint in _lmstudio_models_endpoints(base_url):
        request_headers = dict(headers or {})
        try:
            response = requests_module.get(endpoint, headers=headers, timeout=15)
        except Exception as exc:
            _record_provider_log(
                provider="lm_studio",
                method="GET",
                endpoint=endpoint,
                request_headers=request_headers,
                request_payload={},
                response_status=None,
                response_body="",
                error=str(exc),
                api_style="model_discovery",
            )
            errors.append(f"{endpoint}: {exc}")
            continue

        _record_provider_log(
            provider="lm_studio",
            method="GET",
            endpoint=endpoint,
            request_headers=request_headers,
            request_payload={},
            response_status=int(getattr(response, "status_code", 0) or 0),
            response_body=_response_text_for_log(response),
            error="",
            api_style="model_discovery",
        )

        if response.status_code >= 300:
            errors.append(f"{endpoint}: {response.status_code} {response.text}")
            continue

        try:
            payload = response.json()
        except Exception as exc:
            errors.append(f"{endpoint}: non-JSON response ({exc})")
            continue

        models = _extract_model_ids(payload)
        if models:
            return models
        errors.append(f"{endpoint}: no model ids in payload")

    details = "; ".join(errors) if errors else "no successful model endpoint response"
    raise ProviderError(f"Model listing failed ({auth_state}): {details}")


def _select_preferred_lmstudio_model(models: List[str]) -> str:
    if not models:
        return ""

    def score(model_id: str) -> int:
        name = str(model_id).lower()
        value = 0
        if "o3" in name:
            value += 100
        if "7b" in name:
            value += 35
        if "instruct" in name:
            value += 12
        if "chat" in name:
            value += 8
        return value

    best = models[0]
    best_score = score(best)
    for model_id in models[1:]:
        current_score = score(model_id)
        if current_score > best_score:
            best = model_id
            best_score = current_score
    return best


def _post_openai_compatible_chat_with_retry(
        provider_name: str,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        *,
        prompt_metadata: Optional[Dict[str, Any]] = None,
) -> str:
    retriable_provider = str(provider_name or "").strip().lower() == "openai"
    request_payload = dict(payload or {})
    token_limit = _extract_chat_completion_token_limit(request_payload)
    retry_reason = "initial_request"

    for attempt in range(1, MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS + 1):
        attempt_prompt_metadata = dict(prompt_metadata or {})
        attempt_prompt_metadata.update({
            "retry_attempt": int(attempt),
            "retry_reason": str(retry_reason or "initial_request"),
            "effective_max_completion_tokens": int(token_limit),
        })
        result = _post_openai_compatible_chat_detailed(
            provider_name,
            endpoint,
            headers,
            request_payload,
            prompt_metadata=attempt_prompt_metadata,
        )
        content = str(result.get("content", "") or "")
        finish_reason = str(result.get("finish_reason", "")).strip().lower()

        if not retriable_provider or finish_reason != "length":
            return content
        if attempt >= MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS:
            return content
        if _response_is_complete_for_prompt(content, prompt_metadata):
            return content

        token_limit = min(
            MAX_PROVIDER_OPENAI_RETRY_TOKENS,
            max(token_limit + 200, token_limit * 2),
        )
        _set_chat_completion_token_limit(request_payload, provider_name=provider_name, max_tokens=token_limit)
        _append_retry_instruction(request_payload)
        retry_reason = f"finish_reason:{finish_reason or 'unknown'}"

    return ""


def _post_openai_compatible_chat(
        provider_name: str,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        *,
        prompt_metadata: Optional[Dict[str, Any]] = None,
) -> str:
    result = _post_openai_compatible_chat_detailed(
        provider_name,
        endpoint,
        headers,
        payload,
        prompt_metadata=prompt_metadata,
    )
    return str(result.get("content", "") or "")


def _post_openai_compatible_chat_detailed(
        provider_name: str,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        *,
        prompt_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    requests_module = _get_requests_module()
    auth_state = _auth_state_text(headers)
    request_headers = dict(headers or {})
    request_payload = dict(payload or {})
    try:
        response = requests_module.post(endpoint, headers=headers, json=payload, timeout=25)
    except Exception as exc:
        _record_provider_log(
            provider=provider_name,
            method="POST",
            endpoint=endpoint,
            request_headers=request_headers,
            request_payload=request_payload,
            response_status=None,
            response_body="",
            error=str(exc),
            api_style="openai_compatible",
            prompt_metadata=prompt_metadata,
        )
        raise ProviderError(f"{provider_name} request failed ({auth_state}): {exc}") from exc

    _record_provider_log(
        provider=provider_name,
        method="POST",
        endpoint=endpoint,
        request_headers=request_headers,
        request_payload=request_payload,
        response_status=int(getattr(response, "status_code", 0) or 0),
        response_body=_response_text_for_log(response),
        error="",
        api_style="openai_compatible",
        prompt_metadata=prompt_metadata,
    )

    if response.status_code >= 300:
        raise ProviderError(f"{provider_name} API error ({auth_state}): {response.status_code} {response.text}")

    try:
        data = response.json()
    except Exception as exc:
        raise ProviderError(f"{provider_name} API returned non-JSON response: {exc}") from exc

    choices = data.get("choices", [])
    if not choices:
        raise ProviderError(f"{provider_name} response has no choices.")
    first_choice = choices[0] if isinstance(choices[0], dict) else {}
    message = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}
    content = message.get("content", "")
    if isinstance(content, list):
        chunks = []
        for item in content:
            if isinstance(item, dict):
                chunks.append(str(item.get("text", "")))
            else:
                chunks.append(str(item))
        content = "".join(chunks)

    finish_reason = ""
    if isinstance(first_choice, dict):
        finish_reason = str(first_choice.get("finish_reason", "")).strip().lower()

    return {
        "content": str(content or ""),
        "finish_reason": finish_reason,
    }


def _extract_chat_completion_token_limit(payload: Dict[str, Any]) -> int:
    for key in ("max_completion_tokens", "max_tokens"):
        try:
            value = int(payload.get(key, 0))
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return MAX_PROVIDER_RESPONSE_TOKENS


def _append_retry_instruction(payload: Dict[str, Any]):
    messages = payload.get("messages", [])
    if not isinstance(messages, list) or not messages:
        return
    for index in range(len(messages) - 1, -1, -1):
        item = messages[index]
        if not isinstance(item, dict):
            continue
        if str(item.get("role", "")).strip().lower() != "user":
            continue
        content = str(item.get("content", "") or "")
        marker = "IMPORTANT RETRY:"
        if marker in content:
            return
        item["content"] = (
            f"{content}\n\n"
            "IMPORTANT RETRY: Return compact JSON only, with short rationales and no extra text."
        )
        return


def _set_chat_completion_token_limit(payload: Dict[str, Any], *, provider_name: str, max_tokens: int):
    token_value = int(max_tokens)
    if str(provider_name or "").strip().lower() == "openai":
        payload["max_completion_tokens"] = token_value
        payload.pop("max_tokens", None)
    else:
        payload["max_tokens"] = token_value


def _set_chat_completion_temperature(payload: Dict[str, Any], *, provider_name: str, temperature: float):
    # Some OpenAI GPT-5 endpoints reject explicit temperature values and only
    # accept model defaults, so omit temperature for provider=openai.
    if str(provider_name or "").strip().lower() == "openai":
        payload.pop("temperature", None)
        return
    payload["temperature"] = float(temperature)


def _post_lmstudio_chat_with_fallback(
        *,
        base_url: str,
        headers: Dict[str, str],
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float],
        max_tokens: Optional[int],
        prompt_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    errors = []

    prefer_native_first = str(base_url or "").rstrip("/").endswith("/api/v1")
    styles = ["native", "openai"] if prefer_native_first else ["openai", "native"]
    for style in styles:
        if style == "openai":
            for endpoint in _lmstudio_openai_chat_endpoints(base_url):
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }
                if temperature is not None:
                    payload["temperature"] = float(temperature)
                if max_tokens is not None:
                    payload["max_tokens"] = int(max_tokens)
                try:
                    content = _post_openai_compatible_chat(
                        "lm_studio",
                        endpoint,
                        headers,
                        payload,
                        prompt_metadata=prompt_metadata,
                    )
                    return {
                        "content": content,
                        "endpoint": endpoint,
                        "api_style": "openai_compatible",
                    }
                except ProviderError as exc:
                    errors.append(f"{endpoint}: {exc}")
        else:
            for endpoint in _lmstudio_native_chat_endpoints(base_url):
                payload = {
                    "model": model,
                    "system_prompt": system_prompt,
                    "input": user_prompt,
                }
                if temperature is not None:
                    payload["temperature"] = float(temperature)
                try:
                    content = _post_lmstudio_native_chat(
                        endpoint,
                        headers,
                        payload,
                        prompt_metadata=prompt_metadata,
                    )
                    return {
                        "content": content,
                        "endpoint": endpoint,
                        "api_style": "lmstudio_native",
                    }
                except ProviderError as exc:
                    errors.append(f"{endpoint}: {exc}")

    raise ProviderError(
        "LM Studio request failed across endpoints: " + "; ".join(errors)
    )


def _post_lmstudio_native_chat(
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        *,
        prompt_metadata: Optional[Dict[str, Any]] = None,
) -> str:
    requests_module = _get_requests_module()
    auth_state = _auth_state_text(headers)
    request_headers = dict(headers or {})
    request_payload = dict(payload or {})
    try:
        response = requests_module.post(endpoint, headers=headers, json=payload, timeout=25)
    except Exception as exc:
        _record_provider_log(
            provider="lm_studio",
            method="POST",
            endpoint=endpoint,
            request_headers=request_headers,
            request_payload=request_payload,
            response_status=None,
            response_body="",
            error=str(exc),
            api_style="lmstudio_native",
            prompt_metadata=prompt_metadata,
        )
        raise ProviderError(f"lm_studio request failed ({auth_state}): {exc}") from exc

    _record_provider_log(
        provider="lm_studio",
        method="POST",
        endpoint=endpoint,
        request_headers=request_headers,
        request_payload=request_payload,
        response_status=int(getattr(response, "status_code", 0) or 0),
        response_body=_response_text_for_log(response),
        error="",
        api_style="lmstudio_native",
        prompt_metadata=prompt_metadata,
    )

    if response.status_code >= 300:
        raise ProviderError(f"lm_studio API error ({auth_state}): {response.status_code} {response.text}")

    try:
        data = response.json()
    except Exception as exc:
        raise ProviderError(f"lm_studio API returned non-JSON response: {exc}") from exc

    output = data.get("output", [])
    if isinstance(output, str):
        return output

    if isinstance(output, list):
        chunks = []
        for item in output:
            if isinstance(item, dict):
                chunks.append(str(item.get("content", "")))
            else:
                chunks.append(str(item))
        joined = "\n".join([chunk for chunk in chunks if chunk.strip()])
        if joined.strip():
            return joined

    message = data.get("message")
    if isinstance(message, str) and message.strip():
        return message

    raise ProviderError("lm_studio native chat response had no output content.")


def _call_claude(
        provider_cfg: Dict[str, Any],
        prompt_package: Any,
        *,
        context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    content = _request_claude_content(
        provider_cfg,
        prompt_package,
        max_tokens=600,
        temperature=0.2,
    )
    prompt_metadata = prompt_package.get("metadata", {}) if isinstance(prompt_package, dict) else {}
    allowed_tool_ids = _visible_candidate_tool_ids_from_metadata(prompt_metadata)
    normalized_context = context if isinstance(context, dict) else {}
    return _parse_provider_payload(
        content,
        allowed_tool_ids=allowed_tool_ids,
        unavailable_tool_ids=_collect_unavailable_tool_ids(normalized_context),
        current_phase=str(prompt_metadata.get("current_phase", "") or "").strip().lower() if normalized_context else "",
    )


def _request_claude_content(
        provider_cfg: Dict[str, Any],
        prompt_package: Any,
        *,
        max_tokens: int,
        temperature: float,
) -> str:
    requests_module = _get_requests_module()
    model = str(provider_cfg.get("model", "")).strip()
    if not model:
        raise ProviderError("Model is required for provider claude.")

    base_url = str(provider_cfg.get("base_url", "")).rstrip("/")
    if not base_url:
        raise ProviderError("Base URL is required for provider claude.")
    endpoint = f"{base_url}/v1/messages"

    api_key = str(provider_cfg.get("api_key", "")).strip()
    if not api_key:
        raise ProviderError("API key is required for provider claude.")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    system_prompt = ""
    user_prompt = ""
    prompt_metadata: Dict[str, Any] = {}
    if isinstance(prompt_package, dict):
        system_prompt = str(prompt_package.get("system_prompt", "") or "")
        user_prompt = str(prompt_package.get("user_prompt", "") or "")
        prompt_metadata = prompt_package.get("metadata", {}) if isinstance(prompt_package.get("metadata", {}), dict) else {}
    else:
        user_prompt = str(prompt_package or "")
    payload = {
        "model": model,
        "max_tokens": max(1, int(max_tokens or 1)),
        "temperature": float(temperature),
        "messages": [
            {"role": "user", "content": user_prompt},
        ],
    }
    if system_prompt:
        payload["system"] = system_prompt

    try:
        response = requests_module.post(endpoint, headers=headers, json=payload, timeout=25)
    except Exception as exc:
        _record_provider_log(
            provider="claude",
            method="POST",
            endpoint=endpoint,
            request_headers=dict(headers or {}),
            request_payload=dict(payload or {}),
            response_status=None,
            response_body="",
            error=str(exc),
            api_style="anthropic_messages",
            prompt_metadata=prompt_metadata,
        )
        raise ProviderError(f"claude request failed: {exc}") from exc

    _record_provider_log(
        provider="claude",
        method="POST",
        endpoint=endpoint,
        request_headers=dict(headers or {}),
        request_payload=dict(payload or {}),
        response_status=int(getattr(response, "status_code", 0) or 0),
        response_body=_response_text_for_log(response),
        error="",
        api_style="anthropic_messages",
        prompt_metadata=prompt_metadata,
    )

    if response.status_code >= 300:
        raise ProviderError(f"claude API error: {response.status_code} {response.text}")

    data = response.json()
    parts = data.get("content", [])
    text_chunks = []
    for part in parts:
        if isinstance(part, dict) and part.get("type") == "text":
            text_chunks.append(str(part.get("text", "")))
    content = "\n".join(text_chunks)
    return content


def _probe_claude(provider_cfg: Dict[str, Any], started: float) -> Dict[str, Any]:
    try:
        actions = _call_claude(
            provider_cfg,
            (
                "Return only this JSON:\n"
                "{\"actions\":[{\"tool_id\":\"healthcheck\",\"score\":100,\"rationale\":\"ok\"}]}"
            ),
        ).get("actions", [])
        if not actions:
            raise ProviderError("Provider returned an empty actions list.")
    except ProviderError as exc:
        return {
            "ok": False,
            "provider": "claude",
            "error": str(exc),
        }

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "ok": True,
        "provider": "claude",
        "base_url": str(provider_cfg.get("base_url", "")).rstrip("/"),
        "model": str(provider_cfg.get("model", "")).strip(),
        "auto_selected_model": False,
        "discovered_models": [],
        "latency_ms": elapsed_ms,
    }


def _parse_actions_payload(content: str) -> List[Dict[str, Any]]:
    return _parse_provider_payload(content).get("actions", [])


def _parse_provider_payload(
        content: str,
        *,
        allowed_tool_ids: Optional[List[str]] = None,
        unavailable_tool_ids: Optional[List[str]] = None,
        current_phase: str = "",
) -> Dict[str, Any]:
    payload_obj = _extract_json(content)
    actions = payload_obj.get("actions", [])
    if not isinstance(actions, list):
        actions = []

    allowed_tool_id_map = _normalized_tool_id_map(allowed_tool_ids)
    unavailable_tool_id_map = _normalized_tool_id_map(_expand_unavailable_tool_ids(unavailable_tool_ids or []))
    rejected_tool_ids = []
    parsed = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id", "")).strip()
        if not tool_id:
            continue
        normalized_tool_id = tool_id.lower()
        if allowed_tool_id_map and normalized_tool_id not in allowed_tool_id_map:
            rejected_tool_ids.append(tool_id[:120])
            continue
        if unavailable_tool_id_map and normalized_tool_id in unavailable_tool_id_map:
            rejected_tool_ids.append(tool_id[:120])
            continue
        canonical_tool_id = allowed_tool_id_map.get(normalized_tool_id, tool_id)
        score_value = item.get("score", 50)
        try:
            score = float(score_value)
        except (TypeError, ValueError):
            score = 50.0
        rationale = str(item.get("rationale", "")).strip()
        parsed.append({
            "tool_id": canonical_tool_id,
            "score": score,
            "rationale": rationale,
        })

    host_updates = payload_obj.get("host_updates", {})
    if not isinstance(host_updates, dict):
        host_updates = {}

    technologies = _normalize_technologies(host_updates.get("technologies", []))
    if not technologies:
        technologies = _normalize_technologies(payload_obj.get("technologies", []))

    normalized_host_updates = {}
    hostname = str(host_updates.get("hostname", "")).strip()
    if hostname:
        normalized_host_updates["hostname"] = hostname[:160]
    hostname_conf = _safe_float(host_updates.get("hostname_confidence"), minimum=0.0, maximum=100.0, default=0.0)
    if hostname_conf > 0:
        normalized_host_updates["hostname_confidence"] = hostname_conf

    os_value = str(host_updates.get("os", "")).strip()
    if os_value:
        normalized_host_updates["os"] = os_value[:120]
    os_conf = _safe_float(host_updates.get("os_confidence"), minimum=0.0, maximum=100.0, default=0.0)
    if os_conf > 0:
        normalized_host_updates["os_confidence"] = os_conf
    if technologies:
        normalized_host_updates["technologies"] = technologies

    findings = _normalize_findings(payload_obj.get("findings", []))
    manual_tests = _normalize_manual_tests(
        payload_obj.get("manual_tests", []),
        unavailable_tool_ids=unavailable_tool_ids,
    )
    next_phase = _normalize_next_phase(
        payload_obj.get("next_phase", ""),
        current_phase=current_phase,
    )

    return {
        "actions": parsed,
        "host_updates": normalized_host_updates,
        "technologies": technologies,
        "findings": findings,
        "manual_tests": manual_tests,
        "next_phase": next_phase,
        "rejected_action_tool_ids": _unique_strings(rejected_tool_ids),
    }


def _safe_float(value: Any, *, minimum: float, maximum: float, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return float(default)
    if parsed < float(minimum):
        return float(minimum)
    if parsed > float(maximum):
        return float(maximum)
    return parsed


def _normalize_technologies(items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()[:120]
        evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 420)
        cpe = _normalize_provider_cpe_token(item.get("cpe", ""))
        version = _sanitize_provider_technology_version_for_tech(
            name=name,
            version=item.get("version", ""),
            cpe=cpe,
            evidence=evidence,
        )
        if not version and cpe:
            cpe_version = _sanitize_provider_technology_version_for_tech(
                name=name,
                version=_provider_version_from_cpe(cpe),
                cpe=cpe,
                evidence=evidence,
            )
            if cpe_version:
                version = cpe_version
            else:
                cpe = _provider_cpe_base(cpe)
        if not name and not cpe:
            continue
        key = "|".join([name.lower(), version.lower(), cpe.lower()])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "name": name,
            "version": version,
            "cpe": cpe,
            "evidence": evidence,
        })
        if len(rows) >= 120:
            break
    return rows


def _normalize_findings(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    allowed_severity = {"critical", "high", "medium", "low", "info"}
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()[:220]
        severity = str(item.get("severity", "info")).strip().lower()
        if severity not in allowed_severity:
            severity = "info"
        cve = str(item.get("cve", "")).strip()[:64]
        cvss = _safe_float(item.get("cvss"), minimum=0.0, maximum=10.0, default=0.0)
        evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 520)
        if not title and not cve:
            continue
        key = "|".join([title.lower(), cve.lower(), severity])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "cve": cve,
            "evidence": evidence,
        })
        if len(rows) >= 200:
            break
    return rows


def _normalize_manual_tests(
        items: Any,
        *,
        unavailable_tool_ids: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    unavailable = set(_expand_unavailable_tool_ids(unavailable_tool_ids or []))
    rows: List[Dict[str, str]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        why = _normalize_prompt_text(str(item.get("why", "")).strip(), 280)
        command = _normalize_prompt_text(str(item.get("command", "")).strip(), 420)
        scope_note = _normalize_prompt_text(str(item.get("scope_note", "")).strip(), 260)
        if not command and not why:
            continue
        primary_command = _shell_primary_command_token(command)
        if primary_command and primary_command in unavailable:
            continue
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "why": why,
            "command": command,
            "scope_note": scope_note,
        })
        if len(rows) >= 120:
            break
    return rows


def _extract_json(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        raise ProviderError("Provider response was empty.")

    candidates = [raw]
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw, flags=re.DOTALL | re.IGNORECASE)
    candidates.extend(fenced)

    first_brace = raw.find("{")
    last_brace = raw.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidates.append(raw[first_brace:last_brace + 1])

    for candidate in candidates:
        if not _looks_like_complete_json(candidate):
            continue
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ProviderError("Provider returned non-JSON payload.")


def _looks_like_complete_json(candidate: str) -> bool:
    raw = str(candidate or "").strip()
    if not raw or raw[0] != "{" or raw[-1] != "}":
        return False

    depth = 0
    in_string = False
    escaped = False
    for char in raw:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not in_string and not escaped


def _response_is_complete_for_prompt(text: str, prompt_metadata: Optional[Dict[str, Any]] = None) -> bool:
    try:
        payload = _extract_json(text)
    except ProviderError:
        return False
    if not isinstance(payload, dict):
        return False
    metadata = prompt_metadata if isinstance(prompt_metadata, dict) else {}
    prompt_type = str(metadata.get("prompt_type", "") or "").strip().lower()
    required_by_prompt_type = {
        "ranking": {"actions", "host_updates", "findings", "manual_tests", "next_phase"},
        "healthcheck": {"actions"},
        "reflection": {"state", "reason", "priority_shift", "promote_tool_ids", "suppress_tool_ids", "manual_tests"},
        "web_followup": {"focus", "selected_tool_ids", "reason", "manual_tests"},
    }
    required = required_by_prompt_type.get(prompt_type, set())
    if not required:
        return True
    return required.issubset(set(payload.keys()))


def _normalized_tool_id_map(values: Optional[List[str]]) -> Dict[str, str]:
    if not isinstance(values, list):
        return {}
    normalized = {}
    for item in values:
        token = str(item or "").strip()
        key = token.lower()
        if not token or key in normalized:
            continue
        normalized[key] = token[:120]
    return normalized


def _visible_candidate_tool_ids_from_metadata(metadata: Dict[str, Any]) -> List[str]:
    if not isinstance(metadata, dict):
        return []
    values = metadata.get("visible_candidate_tool_ids", [])
    if not isinstance(values, list):
        return []
    return list(_normalized_tool_id_map(values).values())[:MAX_PROVIDER_CANDIDATES]


def _normalize_prompt_text(value: str, max_chars: int) -> str:
    text = str(value or "").replace("\n", " ").replace("\r", " ")
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "...[truncated]"


def _truncate_block_text(value: str, max_chars: int) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n...[truncated]"


def _build_context_block(context: Dict[str, Any], *, current_phase_override: str = "", include_summary: bool = True) -> str:
    if not isinstance(context, dict) or not context:
        return ""

    lines = []
    unavailable_tool_ids = set(_collect_unavailable_tool_ids(context))
    context_summary = context.get("context_summary", {})
    if include_summary and isinstance(context_summary, dict) and context_summary:
        summary_payload: Dict[str, Any] = {}
        focus = context_summary.get("focus", {})
        if isinstance(focus, dict):
            compact_focus = {}
            for key, max_chars in (
                    ("analysis_mode", 24),
                    ("service", 64),
                    ("service_product", 120),
                    ("service_version", 80),
                    ("coverage_stage", 32),
                    ("current_phase", 64),
            ):
                value = str(focus.get(key, "")).strip()
                if key == "current_phase" and str(current_phase_override or "").strip():
                    value = str(current_phase_override or "").strip()
                if value:
                    compact_focus[key] = value[:max_chars]
            if str(current_phase_override or "").strip() and "current_phase" not in compact_focus:
                compact_focus["current_phase"] = str(current_phase_override or "").strip()[:64]
            if compact_focus:
                summary_payload["focus"] = compact_focus
        elif str(current_phase_override or "").strip():
            summary_payload["focus"] = {"current_phase": str(current_phase_override or "").strip()[:64]}

        for output_key, source_keys, limit, max_chars in (
                ("confirmed_facts", ("confirmed_facts",), 6, 140),
                ("missing_coverage", ("missing_coverage", "coverage_missing"), 8, 64),
                ("followup_candidates", ("followup_candidates", "recommended_tools"), 8, 80),
                ("active_signals", ("active_signals",), 10, 48),
                ("likely_technologies", ("likely_technologies", "known_technologies"), 8, 96),
                ("important_findings", ("important_findings", "top_findings"), 8, 120),
                ("attempted_families", ("attempted_families",), 8, 80),
                ("recent_attempts", ("recent_attempts",), 10, 80),
                ("recent_failures", ("recent_failures",), 6, 120),
                ("manual_tests", ("manual_tests",), 4, 140),
        ):
            values = []
            for source_key in source_keys:
                candidate_values = context_summary.get(source_key, [])
                if isinstance(candidate_values, list) and candidate_values:
                    values = candidate_values
                    break
            if not isinstance(values, list):
                continue
            compact_values = []
            for item in values[:limit]:
                token = _normalize_prompt_text(str(item).strip(), max_chars)
                if not token:
                    continue
                if output_key == "manual_tests":
                    primary_command = _shell_primary_command_token(token)
                    if primary_command and primary_command in unavailable_tool_ids:
                        continue
                compact_values.append(token)
            if compact_values:
                summary_payload[output_key] = compact_values

        reflection_posture = context_summary.get("reflection_posture", {})
        if isinstance(reflection_posture, dict) and reflection_posture:
            reflection_payload = {}
            for key, max_chars in (
                    ("state", 24),
                    ("priority_shift", 64),
                    ("reason", 180),
            ):
                value = _normalize_prompt_text(str(reflection_posture.get(key, "")).strip(), max_chars)
                if value:
                    reflection_payload[key] = value
            for key in ("suppress_tool_ids", "promote_tool_ids"):
                values = reflection_posture.get(key, [])
                if not isinstance(values, list):
                    continue
                compact_values = [
                    _normalize_prompt_text(str(item).strip(), 80)
                    for item in values[:6]
                    if str(item).strip()
                ]
                if compact_values:
                    reflection_payload[key] = compact_values
            if reflection_payload:
                summary_payload["reflection_posture"] = reflection_payload

        if summary_payload:
            lines.append(json.dumps({"context_summary": summary_payload}, separators=(",", ":")))

    target = context.get("target", {})
    if isinstance(target, dict):
        target_payload = {
            "host_ip": str(target.get("host_ip", "")).strip()[:80],
            "hostname": str(target.get("hostname", "")).strip()[:120],
            "os": str(target.get("os", "")).strip()[:80],
            "port": str(target.get("port", "")).strip()[:20],
            "protocol": str(target.get("protocol", "")).strip()[:12],
            "service": str(target.get("service", "")).strip()[:64],
            "service_product": str(target.get("service_product", "")).strip()[:120],
            "service_version": str(target.get("service_version", "")).strip()[:80],
            "service_extrainfo": str(target.get("service_extrainfo", "")).strip()[:120],
            "shodan_enabled": bool(target.get("shodan_enabled", False)),
        }
        host_open_services = target.get("host_open_services", [])
        if isinstance(host_open_services, list):
            target_payload["host_open_services"] = [
                str(item).strip()[:48]
                for item in host_open_services[:64]
                if str(item).strip()
            ]
        host_open_ports = target.get("host_open_ports", [])
        if isinstance(host_open_ports, list):
            target_payload["host_open_ports"] = [
                str(item).strip()[:96]
                for item in host_open_ports[:120]
                if str(item).strip()
            ]
        host_banners = target.get("host_banners", [])
        if isinstance(host_banners, list):
            target_payload["host_banners"] = [
                _normalize_prompt_text(str(item).strip(), 220)
                for item in host_banners[:96]
                if str(item).strip()
            ]
        if any(target_payload.values()):
            lines.append(json.dumps({"target": target_payload}, separators=(",", ":")))

    analysis_mode = str(context.get("analysis_mode", "")).strip().lower()
    if analysis_mode:
        lines.append(json.dumps({"analysis_mode": analysis_mode[:32]}, separators=(",", ":")))

    host_ports = context.get("host_ports", [])
    if isinstance(host_ports, list):
        compact_ports = []
        for item in host_ports[:MAX_PROVIDER_CONTEXT_ITEMS]:
            if not isinstance(item, dict):
                continue
            port_payload = {
                "port": str(item.get("port", "")).strip()[:20],
                "protocol": str(item.get("protocol", "")).strip()[:12],
                "state": str(item.get("state", "")).strip()[:32],
                "service": str(item.get("service", "")).strip()[:64],
                "service_product": str(item.get("service_product", "")).strip()[:120],
                "service_version": str(item.get("service_version", "")).strip()[:80],
                "service_extrainfo": str(item.get("service_extrainfo", "")).strip()[:120],
                "banner": _normalize_prompt_text(str(item.get("banner", "")).strip(), 220),
            }
            scripts = item.get("scripts", [])
            if isinstance(scripts, list):
                compact_scripts = [str(entry).strip()[:96] for entry in scripts if str(entry).strip()]
                if compact_scripts:
                    port_payload["scripts"] = compact_scripts[:16]
            if any(value for value in port_payload.values()):
                compact_ports.append(port_payload)
        if compact_ports:
            lines.append(json.dumps({"host_ports": compact_ports}, separators=(",", ":")))

    inferred_technologies = context.get("inferred_technologies", [])
    if isinstance(inferred_technologies, list):
        compact_inferred = []
        for item in inferred_technologies[:24]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()[:120]
            evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 220)
            cpe = _normalize_provider_cpe_token(item.get("cpe", ""))
            version = _sanitize_provider_technology_version_for_tech(
                name=name,
                version=item.get("version", ""),
                cpe=cpe,
                evidence=evidence,
            )
            if not version and cpe and not _sanitize_provider_technology_version_for_tech(
                    name=name,
                    version=_provider_version_from_cpe(cpe),
                    cpe=cpe,
                    evidence=evidence,
            ):
                cpe = _provider_cpe_base(cpe)
            if not name and not cpe:
                continue
            compact_inferred.append({
                "name": name,
                "version": version,
                "cpe": cpe,
                "evidence": evidence,
            })
        if compact_inferred:
            lines.append(json.dumps({"inferred_technologies": compact_inferred}, separators=(",", ":")))

    host_cves = context.get("host_cves", [])
    if isinstance(host_cves, list):
        compact_cves = []
        for item in host_cves[:MAX_PROVIDER_CONTEXT_ITEMS]:
            if not isinstance(item, dict):
                continue
            row = {
                "name": str(item.get("name", "")).strip()[:96],
                "severity": str(item.get("severity", "")).strip().lower()[:24],
                "product": str(item.get("product", "")).strip()[:120],
                "version": str(item.get("version", "")).strip()[:80],
                "url": str(item.get("url", "")).strip()[:220],
            }
            if any(row.values()):
                compact_cves.append(row)
        if compact_cves:
            lines.append(json.dumps({"host_cves": compact_cves}, separators=(",", ":")))

    coverage = context.get("coverage", {})
    if isinstance(coverage, dict) and coverage:
        payload: Dict[str, Any] = {
            "analysis_mode": str(coverage.get("analysis_mode", "")).strip().lower()[:24],
            "stage": str(coverage.get("stage", "")).strip().lower()[:32],
            "host_cve_count": int(coverage.get("host_cve_count", 0) or 0),
        }
        missing = coverage.get("missing", [])
        if isinstance(missing, list):
            compact_missing = [str(item).strip().lower()[:64] for item in missing[:24] if str(item).strip()]
            if compact_missing:
                payload["missing"] = compact_missing
        recommended = coverage.get("recommended_tool_ids", [])
        if isinstance(recommended, list):
            compact_rec = [str(item).strip().lower()[:80] for item in recommended[:32] if str(item).strip()]
            if compact_rec:
                payload["recommended_tool_ids"] = compact_rec
        has_map = coverage.get("has", {})
        if isinstance(has_map, dict):
            compact_has = {}
            for key, value in has_map.items():
                if isinstance(value, bool):
                    compact_has[str(key).strip()[:40]] = bool(value)
            if compact_has:
                payload["has"] = compact_has
        if any(payload.values()):
            lines.append(json.dumps({"coverage": payload}, separators=(",", ":")))

    signals = context.get("signals", {})
    if isinstance(signals, dict) and signals:
        signal_payload = {}
        for key, value in signals.items():
            if isinstance(value, bool):
                normalized_key = str(key)
                if value or normalized_key in _ALWAYS_INCLUDE_BOOL_SIGNALS:
                    signal_payload[normalized_key] = bool(value)
            elif isinstance(value, (int, float)):
                if value:
                    signal_payload[str(key)] = value
            elif isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    signal_payload[str(key)] = cleaned[:120]
            elif isinstance(value, list):
                compact = [str(item).strip()[:80] for item in value if str(item).strip()]
                if compact:
                    signal_payload[str(key)] = compact[:24]
        if signal_payload:
            lines.append(json.dumps({"signals": signal_payload}, separators=(",", ":")))

    host_ai_state = context.get("host_ai_state", {})
    if isinstance(host_ai_state, dict) and host_ai_state:
        ai_payload: Dict[str, Any] = {
            "updated_at": str(host_ai_state.get("updated_at", "")).strip()[:64],
            "provider": str(host_ai_state.get("provider", "")).strip()[:40],
            "goal_profile": str(host_ai_state.get("goal_profile", "")).strip()[:64],
            "next_phase": str(host_ai_state.get("next_phase", "")).strip()[:64],
        }
        host_updates = host_ai_state.get("host_updates", {})
        if isinstance(host_updates, dict):
            ai_payload["host_updates"] = {
                "hostname": str(host_updates.get("hostname", "")).strip()[:120],
                "hostname_confidence": _safe_float(host_updates.get("hostname_confidence"), minimum=0.0, maximum=100.0, default=0.0),
                "os": str(host_updates.get("os", "")).strip()[:80],
                "os_confidence": _safe_float(host_updates.get("os_confidence"), minimum=0.0, maximum=100.0, default=0.0),
            }

        technologies = host_ai_state.get("technologies", [])
        if isinstance(technologies, list):
            compact_technologies = []
            for item in technologies[:24]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()[:120]
                evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 220)
                cpe = _normalize_provider_cpe_token(item.get("cpe", ""))
                version = _sanitize_provider_technology_version_for_tech(
                    name=name,
                    version=item.get("version", ""),
                    cpe=cpe,
                    evidence=evidence,
                )
                if not version and cpe and not _sanitize_provider_technology_version_for_tech(
                        name=name,
                        version=_provider_version_from_cpe(cpe),
                        cpe=cpe,
                        evidence=evidence,
                ):
                    cpe = _provider_cpe_base(cpe)
                if not name and not cpe:
                    continue
                compact_technologies.append({
                    "name": name,
                    "version": version,
                    "cpe": cpe,
                    "evidence": evidence,
                })
            if compact_technologies:
                ai_payload["technologies"] = compact_technologies

        findings = host_ai_state.get("findings", [])
        if isinstance(findings, list):
            compact_findings = []
            for item in findings[:24]:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "")).strip()[:220]
                severity = str(item.get("severity", "")).strip().lower()[:16]
                cve = str(item.get("cve", "")).strip()[:64]
                evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 220)
                if not title and not cve:
                    continue
                compact_findings.append({
                    "title": title,
                    "severity": severity,
                    "cve": cve,
                    "evidence": evidence,
                })
            if compact_findings:
                ai_payload["findings"] = compact_findings

        manual_tests = host_ai_state.get("manual_tests", [])
        if isinstance(manual_tests, list):
            compact_manual = []
            for item in manual_tests[:16]:
                if not isinstance(item, dict):
                    continue
                command = _normalize_prompt_text(str(item.get("command", "")).strip(), 220)
                why = _normalize_prompt_text(str(item.get("why", "")).strip(), 180)
                scope_note = _normalize_prompt_text(str(item.get("scope_note", "")).strip(), 140)
                if not command and not why:
                    continue
                primary_command = _shell_primary_command_token(command)
                if primary_command and primary_command in unavailable_tool_ids:
                    continue
                compact_manual.append({
                    "command": command,
                    "why": why,
                    "scope_note": scope_note,
                })
            if compact_manual:
                ai_payload["manual_tests"] = compact_manual

        reflection = host_ai_state.get("reflection", {})
        if isinstance(reflection, dict) and reflection:
            reflection_payload = {
                "state": str(reflection.get("state", "")).strip().lower()[:24],
                "priority_shift": str(reflection.get("priority_shift", "")).strip().lower()[:64],
                "reason": _normalize_prompt_text(str(reflection.get("reason", "")).strip(), 220),
            }
            promote_tool_ids = [
                str(item).strip().lower()[:80]
                for item in list(reflection.get("promote_tool_ids", []) or [])[:8]
                if str(item).strip()
            ]
            if promote_tool_ids:
                reflection_payload["promote_tool_ids"] = promote_tool_ids
            suppress_tool_ids = [
                str(item).strip().lower()[:80]
                for item in list(reflection.get("suppress_tool_ids", []) or [])[:8]
                if str(item).strip()
            ]
            if suppress_tool_ids:
                reflection_payload["suppress_tool_ids"] = suppress_tool_ids
            if any(value for value in reflection_payload.values()):
                ai_payload["reflection"] = reflection_payload

        if any(value for value in ai_payload.values()):
            lines.append(json.dumps({"host_ai_state": ai_payload}, separators=(",", ":")))

    attempted = context.get("attempted_tool_ids", [])
    if isinstance(attempted, list):
        attempted_values = [str(item).strip()[:80] for item in attempted if str(item).strip()]
        if attempted_values:
            lines.append(json.dumps({"attempted_tools": attempted_values[:120]}, separators=(",", ":")))

    script_signals = context.get("scripts", [])
    if isinstance(script_signals, list):
        for item in script_signals[:MAX_PROVIDER_CONTEXT_ITEMS]:
            if not isinstance(item, dict):
                continue
            script_id = str(item.get("script_id", "")).strip()
            excerpt = _normalize_prompt_text(str(item.get("excerpt", "")), 680)
            script_port = str(item.get("port", "")).strip()
            script_protocol = str(item.get("protocol", "")).strip().lower()
            if not script_id and not excerpt:
                continue
            lines.append(json.dumps({
                "script_signal": {
                    "script_id": script_id[:96],
                    "port": script_port[:20],
                    "protocol": script_protocol[:12],
                    "excerpt": excerpt,
                }
            }, separators=(",", ":")))

    process_signals = context.get("recent_processes", [])
    if isinstance(process_signals, list):
        for item in process_signals[:MAX_PROVIDER_CONTEXT_ITEMS]:
            if not isinstance(item, dict):
                continue
            tool_id = str(item.get("tool_id", "")).strip()
            status = str(item.get("status", "")).strip()
            process_port = str(item.get("port", "")).strip()
            process_protocol = str(item.get("protocol", "")).strip().lower()
            command_excerpt = _normalize_prompt_text(str(item.get("command_excerpt", "")), 300)
            excerpt = _normalize_prompt_text(str(item.get("output_excerpt", "")), 680)
            if not tool_id and not excerpt:
                continue
            lines.append(json.dumps({
                "process_signal": {
                    "tool_id": tool_id[:96],
                    "status": status[:40],
                    "port": process_port[:20],
                    "protocol": process_protocol[:12],
                    "command_excerpt": command_excerpt,
                    "output_excerpt": excerpt,
                }
            }, separators=(",", ":")))

    target_scripts = context.get("target_scripts", [])
    if isinstance(target_scripts, list):
        compact_target_scripts = []
        for item in target_scripts[:24]:
            if not isinstance(item, dict):
                continue
            script_id = str(item.get("script_id", "")).strip()
            excerpt = _normalize_prompt_text(str(item.get("excerpt", "")), 320)
            if not script_id and not excerpt:
                continue
            compact_target_scripts.append({
                "script_id": script_id[:96],
                "port": str(item.get("port", "")).strip()[:20],
                "protocol": str(item.get("protocol", "")).strip().lower()[:12],
                "excerpt": excerpt,
            })
        if compact_target_scripts:
            lines.append(json.dumps({"target_scripts": compact_target_scripts}, separators=(",", ":")))

    target_processes = context.get("target_recent_processes", [])
    if isinstance(target_processes, list):
        compact_target_processes = []
        for item in target_processes[:24]:
            if not isinstance(item, dict):
                continue
            tool_id = str(item.get("tool_id", "")).strip()
            excerpt = _normalize_prompt_text(str(item.get("output_excerpt", "")), 320)
            if not tool_id and not excerpt:
                continue
            compact_target_processes.append({
                "tool_id": tool_id[:96],
                "status": str(item.get("status", "")).strip()[:40],
                "port": str(item.get("port", "")).strip()[:20],
                "protocol": str(item.get("protocol", "")).strip().lower()[:12],
                "output_excerpt": excerpt,
            })
        if compact_target_processes:
            lines.append(json.dumps({"target_processes": compact_target_processes}, separators=(",", ":")))

    if not lines:
        return ""

    rendered = "\n".join(lines)
    bounded = _truncate_block_text(rendered, MAX_PROVIDER_CONTEXT_CHARS)
    return f"Context:\n{bounded}\n"


def _lmstudio_models_endpoints(base_url: str) -> List[str]:
    return [f"{base}/models" for base in _lmstudio_base_candidates(base_url)]


def _lmstudio_openai_chat_endpoints(base_url: str) -> List[str]:
    return [f"{base}/chat/completions" for base in _lmstudio_base_candidates(base_url)]


def _lmstudio_native_chat_endpoints(base_url: str) -> List[str]:
    api_bases = []
    for base in _lmstudio_base_candidates(base_url):
        if base.endswith("/api/v1"):
            api_bases.append(base)
    if not api_bases:
        for base in _lmstudio_base_candidates(base_url):
            if base.endswith("/v1"):
                api_bases.append(base[:-3] + "/api/v1")
    return [f"{base}/chat" for base in _unique_strings(api_bases)]


def _lmstudio_base_candidates(base_url: str) -> List[str]:
    raw = str(base_url or "").rstrip("/")
    if not raw:
        return []

    candidates = [raw]
    if raw.endswith("/api/v1"):
        candidates.append(raw[:-7] + "/v1")
    elif raw.endswith("/v1"):
        candidates.append(raw[:-3] + "/api/v1")
    else:
        candidates.append(raw + "/v1")
        candidates.append(raw + "/api/v1")
    return _unique_strings([item.rstrip("/") for item in candidates if item.strip()])


def _unique_strings(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _extract_model_ids(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        return []

    models = []
    items = payload.get("data", [])
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                model_id = str(item.get("id", "")).strip()
            else:
                model_id = str(item).strip()
            if model_id:
                models.append(model_id)

    legacy_items = payload.get("models", [])
    if isinstance(legacy_items, list):
        for item in legacy_items:
            if isinstance(item, dict):
                model_id = (
                    str(item.get("id", "")).strip()
                    or str(item.get("key", "")).strip()
                    or str(item.get("display_name", "")).strip()
                )
            else:
                model_id = str(item).strip()
            if model_id:
                models.append(model_id)

    return _unique_strings(models)


def _has_authorization_header(headers: Dict[str, str]) -> bool:
    auth = str(headers.get("Authorization", "") or "").strip()
    return bool(auth)


def _auth_state_text(headers: Dict[str, str]) -> str:
    return "auth header sent" if _has_authorization_header(headers) else "auth header missing"
