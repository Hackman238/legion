import datetime
import json
import re
import threading
import time
from copy import deepcopy
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import requests

MAX_PROVIDER_PROMPT_CHARS = 3200
MAX_PROVIDER_CANDIDATES = 18
MAX_CANDIDATE_TEMPLATE_CHARS = 180
MAX_CANDIDATE_LABEL_CHARS = 96
MAX_PROVIDER_RESPONSE_TOKENS = 280
MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS = 3
MAX_PROVIDER_OPENAI_RETRY_TOKENS = 1600
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
MAX_PROVIDER_CONTEXT_CHARS = 6200
MAX_PROVIDER_CONTEXT_ITEMS = 64
MAX_PROVIDER_LOG_ENTRIES = 600
MAX_PROVIDER_LOG_TEXT_CHARS = 20000
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


class ProviderError(RuntimeError):
    pass


_provider_log_lock = threading.Lock()
_provider_logs = deque(maxlen=MAX_PROVIDER_LOG_ENTRIES)
_provider_thread_state = threading.local()


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
    }
    with _provider_log_lock:
        _provider_logs.append(row)


def rank_actions_with_provider(config: Dict[str, Any], goal_profile: str, service: str, protocol: str,
                               candidates: List[Dict[str, str]],
                               context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    _set_last_provider_payload({})
    provider_name = str(config.get("provider", "none") or "none").strip().lower()
    providers_cfg = config.get("providers", {}) if isinstance(config, dict) else {}
    provider_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg, dict) else {}

    if provider_name == "none" or not provider_cfg.get("enabled", False):
        _set_last_provider_payload({
            "provider": provider_name,
            "actions": [],
            "host_updates": {},
            "findings": [],
            "manual_tests": [],
            "technologies": [],
            "next_phase": "",
        })
        return []

    prompt = _build_prompt(goal_profile, service, protocol, candidates, context=context or {})
    if provider_name in {"openai", "lm_studio"}:
        payload = _call_openai_compatible(provider_name, provider_cfg, prompt)
        payload["provider"] = provider_name
        _set_last_provider_payload(payload)
        return payload.get("actions", [])
    if provider_name == "claude":
        payload = _call_claude(provider_cfg, prompt)
        payload["provider"] = provider_name
        _set_last_provider_payload(payload)
        return payload.get("actions", [])
    raise ProviderError(f"Unsupported provider: {provider_name}")


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


def _determine_scheduler_phase(
        *,
        goal_profile: str,
        service: str,
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
        "sslyze",
    })
    has_deep_web = any(token in attempted for token in {
        "whatweb",
        "whatweb-http",
        "whatweb-https",
        "nikto",
        "web-content-discovery",
        "wafw00f",
        "wpscan",
        "http-wapiti",
        "https-wapiti",
    })

    shodan_enabled = bool(signals.get("shodan_enabled"))
    shodan_checked = any(token in attempted for token in {"shodan-enrichment", "shodan-host", "pyshodan"})

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
    if str(goal_profile or "").strip().lower() == "external_pentest" and shodan_enabled and not shodan_checked:
        return "external_enrichment"
    if analysis_mode == "dig_deeper":
        return "deep_validation"
    return "targeted_checks"


def _build_prompt(
        goal_profile: str,
        service: str,
        protocol: str,
        candidates: List[Dict[str, str]],
        context: Optional[Dict[str, Any]] = None,
) -> str:
    context_block = _build_context_block(context or {})
    current_phase = _determine_scheduler_phase(
        goal_profile=goal_profile,
        service=service,
        context=context,
    )
    prefix = (
        "You are a penetration-testing scheduler assistant.\n"
        f"Goal profile: {goal_profile}\n"
        f"Service: {service}\n"
        f"Protocol: {protocol}\n"
        f"Current phase: {current_phase}\n"
        "Rank the candidates by expected signal-to-noise and safety.\n"
        "Second-stage review: identify what baseline coverage is still missing from prior results and prioritize "
        "those missing scans plus immediate follow-up dependencies before niche checks.\n"
        "When context.coverage.missing is present, satisfy those gaps first.\n"
        "When analysis_mode is dig_deeper, reason over full host context (all open ports/services/scripts/process "
        "results/findings/CVEs) and choose the highest-value next actions.\n"
        "Lifecycle phases: initial_discovery -> service_fingerprint -> broad_vuln -> protocol_checks "
        "-> targeted_checks -> deep_web -> external_enrichment -> complete.\n"
        "Initial discovery priorities: nmap discovery/service+OS (if enabled), screenshots for HTTP/HTTPS and "
        "RDP/VNC when available, banners for other services.\n"
        "Use broad vuln discovery early: nmap vuln+vulners and nuclei automatic scan.\n"
        "When confident CPE/technology evidence exists but CVE correlation is weak, prioritize CPE-to-CVE enrichment "
        "and related follow-up scans before niche checks.\n"
        "Then run protocol checks (for example SMB signing/state checks) and targeted checks driven by identified "
        "technology/vendor/CPE/CVE evidence.\n"
        "For web services, include deeper checks like whatweb, nikto, and web content discovery.\n"
        "If goal profile is external and Shodan is available, include external enrichment when high-value.\n"
        "Continuously reassess hostname/OS/technology/version confidence from cumulative host evidence.\n"
        "Only choose technology/vendor-specific tools when context contains matching evidence.\n"
        "If matching evidence is absent, avoid specialized checks and prefer broad recon/vuln tools.\n"
        "Avoid rerunning tools that already executed successfully or are known missing.\n"
        "Return ONLY JSON with this schema:\n"
        "{\"actions\":[{\"tool_id\":\"...\",\"score\":0-100,\"rationale\":\"...\"}],"
        "\"host_updates\":{\"hostname\":\"...\",\"hostname_confidence\":0-100,\"os\":\"...\",\"os_confidence\":0-100,"
        "\"technologies\":[{\"name\":\"...\",\"version\":\"...\",\"cpe\":\"...\",\"evidence\":\"...\"}]},"
        "\"findings\":[{\"title\":\"...\",\"severity\":\"critical|high|medium|low|info\",\"cvss\":0-10,"
        "\"cve\":\"...\",\"evidence\":\"...\"}],"
        "\"manual_tests\":[{\"why\":\"...\",\"command\":\"...\",\"scope_note\":\"...\"}],"
        "\"next_phase\":\"...\"}\n"
        "If no safe/high-value action remains, return actions as [] and provide manual_tests command suggestions.\n"
        "Do not include tools not present in candidates.\n"
        f"{context_block}"
        "Candidates:\n"
    )
    if not candidates:
        return prefix

    candidate_lines = []
    omitted = 0
    budget = max(800, MAX_PROVIDER_PROMPT_CHARS - len(prefix) - 120)
    used = 0

    for index, candidate in enumerate(candidates):
        if index >= MAX_PROVIDER_CANDIDATES:
            omitted = len(candidates) - index
            break

        line = json.dumps({
            "tool_id": str(candidate.get("tool_id", "")).strip()[:120],
            "label": str(candidate.get("label", "")).strip()[:MAX_CANDIDATE_LABEL_CHARS],
            "service_scope": str(candidate.get("service_scope", "")).strip()[:120],
            "command_template_excerpt": _normalize_prompt_text(
                str(candidate.get("command_template", "")),
                MAX_CANDIDATE_TEMPLATE_CHARS,
            ),
        }, separators=(",", ":"))

        projected = used + len(line) + 1
        if projected > budget:
            omitted = len(candidates) - index
            break

        candidate_lines.append(line)
        used = projected

    if not candidate_lines:
        first = candidates[0]
        candidate_lines.append(
            json.dumps({
                "tool_id": str(first.get("tool_id", "")).strip()[:120],
                "label": str(first.get("label", "")).strip()[:MAX_CANDIDATE_LABEL_CHARS],
                "service_scope": str(first.get("service_scope", "")).strip()[:120],
                "command_template_excerpt": _normalize_prompt_text(
                    str(first.get("command_template", "")),
                    96,
                ),
            }, separators=(",", ":"))
        )
        omitted = max(0, len(candidates) - 1)

    if omitted > 0:
        candidate_lines.append(
            json.dumps({"note": f"{omitted} candidates omitted due to context budget"}, separators=(",", ":"))
        )

    return prefix + "\n".join(candidate_lines)


def _call_openai_compatible(provider_name: str, provider_cfg: Dict[str, Any], prompt: str) -> Dict[str, Any]:
    base_url, headers, model, _models, _auto_selected = _openai_compatible_context(provider_name, provider_cfg)
    if provider_name == "lm_studio":
        result = _post_lmstudio_chat_with_fallback(
            base_url=base_url,
            headers=headers,
            model=model,
            prompt=prompt,
            temperature=0.2,
            max_tokens=MAX_PROVIDER_RESPONSE_TOKENS,
        )
        content = str(result.get("content", "") or "")
    else:
        endpoint = f"{base_url}/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "Return strict JSON only."},
                {"role": "user", "content": prompt},
            ],
        }
        _set_chat_completion_temperature(payload, provider_name=provider_name, temperature=0.2)
        _set_chat_completion_token_limit(payload, provider_name=provider_name, max_tokens=MAX_PROVIDER_RESPONSE_TOKENS)
        content = _post_openai_compatible_chat_with_retry(provider_name, endpoint, headers, payload)
    return _parse_provider_payload(content)


def _probe_openai_compatible(provider_name: str, provider_cfg: Dict[str, Any], started: float) -> Dict[str, Any]:
    auth_header_sent = False
    endpoint_used = ""
    api_style = "openai_compatible"
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
                prompt=test_prompt,
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
            content = _post_openai_compatible_chat_with_retry(provider_name, endpoint, headers, payload)
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
    auth_state = _auth_state_text(headers)
    errors = []
    for endpoint in _lmstudio_models_endpoints(base_url):
        request_headers = dict(headers or {})
        try:
            response = requests.get(endpoint, headers=headers, timeout=15)
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
) -> str:
    retriable_provider = str(provider_name or "").strip().lower() == "openai"
    request_payload = dict(payload or {})
    token_limit = _extract_chat_completion_token_limit(request_payload)

    for attempt in range(1, MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS + 1):
        result = _post_openai_compatible_chat_detailed(provider_name, endpoint, headers, request_payload)
        content = str(result.get("content", "") or "")
        finish_reason = str(result.get("finish_reason", "")).strip().lower()

        if content.strip():
            return content
        if not retriable_provider or finish_reason != "length":
            return content
        if attempt >= MAX_PROVIDER_OPENAI_RETRY_ATTEMPTS:
            return content

        token_limit = min(
            MAX_PROVIDER_OPENAI_RETRY_TOKENS,
            max(token_limit + 200, token_limit * 2),
        )
        _set_chat_completion_token_limit(request_payload, provider_name=provider_name, max_tokens=token_limit)
        _append_retry_instruction(request_payload)

    return ""


def _post_openai_compatible_chat(provider_name: str, endpoint: str, headers: Dict[str, str], payload: Dict[str, Any]) -> str:
    result = _post_openai_compatible_chat_detailed(provider_name, endpoint, headers, payload)
    return str(result.get("content", "") or "")


def _post_openai_compatible_chat_detailed(
        provider_name: str,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
) -> Dict[str, Any]:
    auth_state = _auth_state_text(headers)
    request_headers = dict(headers or {})
    request_payload = dict(payload or {})
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=25)
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
        prompt: str,
        temperature: Optional[float],
        max_tokens: Optional[int],
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
                        {"role": "system", "content": "Return strict JSON only."},
                        {"role": "user", "content": prompt},
                    ],
                }
                if temperature is not None:
                    payload["temperature"] = float(temperature)
                if max_tokens is not None:
                    payload["max_tokens"] = int(max_tokens)
                try:
                    content = _post_openai_compatible_chat("lm_studio", endpoint, headers, payload)
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
                    "system_prompt": "Return strict JSON only.",
                    "input": prompt,
                }
                if temperature is not None:
                    payload["temperature"] = float(temperature)
                try:
                    content = _post_lmstudio_native_chat(endpoint, headers, payload)
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


def _post_lmstudio_native_chat(endpoint: str, headers: Dict[str, str], payload: Dict[str, Any]) -> str:
    auth_state = _auth_state_text(headers)
    request_headers = dict(headers or {})
    request_payload = dict(payload or {})
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=25)
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


def _call_claude(provider_cfg: Dict[str, Any], prompt: str) -> Dict[str, Any]:
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
    payload = {
        "model": model,
        "max_tokens": 600,
        "temperature": 0.2,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }

    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=25)
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
    return _parse_provider_payload(content)


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


def _parse_provider_payload(content: str) -> Dict[str, Any]:
    payload_obj = _extract_json(content)
    actions = payload_obj.get("actions", [])
    if not isinstance(actions, list):
        actions = []

    parsed = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id", "")).strip()
        if not tool_id:
            continue
        score_value = item.get("score", 50)
        try:
            score = float(score_value)
        except (TypeError, ValueError):
            score = 50.0
        rationale = str(item.get("rationale", "")).strip()
        parsed.append({
            "tool_id": tool_id,
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
    manual_tests = _normalize_manual_tests(payload_obj.get("manual_tests", []))
    next_phase = str(payload_obj.get("next_phase", "")).strip()[:80]

    return {
        "actions": parsed,
        "host_updates": normalized_host_updates,
        "technologies": technologies,
        "findings": findings,
        "manual_tests": manual_tests,
        "next_phase": next_phase,
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
        version = str(item.get("version", "")).strip()[:120]
        cpe = str(item.get("cpe", "")).strip()[:220]
        evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 420)
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


def _normalize_manual_tests(items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
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
        key = "|".join([command.lower(), why.lower()])
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
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ProviderError("Provider returned non-JSON payload.")


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


def _build_context_block(context: Dict[str, Any]) -> str:
    if not isinstance(context, dict) or not context:
        return ""

    lines = []
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
            version = str(item.get("version", "")).strip()[:80]
            cpe = str(item.get("cpe", "")).strip()[:180]
            evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 220)
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
                version = str(item.get("version", "")).strip()[:80]
                cpe = str(item.get("cpe", "")).strip()[:180]
                evidence = _normalize_prompt_text(str(item.get("evidence", "")).strip(), 220)
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
                compact_manual.append({
                    "command": command,
                    "why": why,
                    "scope_note": scope_note,
                })
            if compact_manual:
                ai_payload["manual_tests"] = compact_manual

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
