from __future__ import annotations

import importlib
from typing import Any, Dict, List, Optional

from app.scheduler.planner import SchedulerPlanner
from app.web import runtime_scheduler_excerpt as web_runtime_scheduler_excerpt
from app.web import runtime_scheduler_state as web_runtime_scheduler_state


def _web_runtime_module():
    return importlib.import_module("app.web.runtime")


def build_scheduler_context_summary(
        *,
        target: Optional[Dict[str, Any]],
        analysis_mode: str,
        coverage: Optional[Dict[str, Any]],
        signals: Optional[Dict[str, Any]],
        current_phase: str = "",
        attempted_tool_ids: Any,
        attempted_family_ids: Any = None,
        summary_technologies: Optional[List[Dict[str, Any]]] = None,
        host_cves: Optional[List[Dict[str, Any]]] = None,
        host_ai_state: Optional[Dict[str, Any]] = None,
        recent_processes: Optional[List[Dict[str, Any]]] = None,
        target_recent_processes: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    runtime_module = _web_runtime_module()
    target_payload = target if isinstance(target, dict) else {}
    coverage_payload = coverage if isinstance(coverage, dict) else {}
    signals_payload = signals if isinstance(signals, dict) else {}
    ai_payload = host_ai_state if isinstance(host_ai_state, dict) else {}
    technology_rows = summary_technologies if isinstance(summary_technologies, list) else []
    host_cve_rows = host_cves if isinstance(host_cves, list) else []
    all_recent_processes = recent_processes if isinstance(recent_processes, list) else []
    scoped_recent_processes = target_recent_processes if isinstance(target_recent_processes, list) else []

    def _unique_strings(values: Any, *, limit: int, max_chars: int, lowercase: bool = False) -> List[str]:
        rows: List[str] = []
        seen = set()
        for item in list(values or []):
            token = web_runtime_scheduler_excerpt.truncate_scheduler_text(item, max_chars)
            if lowercase:
                token = token.lower()
            if not token:
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            rows.append(token)
            if len(rows) >= int(limit):
                break
        return rows

    focus = {}
    analysis_mode_value = str(analysis_mode or coverage_payload.get("analysis_mode", "") or "").strip().lower()
    if analysis_mode_value:
        focus["analysis_mode"] = analysis_mode_value[:24]
    service_value = str(target_payload.get("service", "") or "").strip()
    if service_value:
        focus["service"] = service_value[:64]
    service_product = str(target_payload.get("service_product", "") or "").strip()
    if service_product:
        focus["service_product"] = service_product[:120]
    service_version = str(target_payload.get("service_version", "") or "").strip()
    if service_version:
        focus["service_version"] = service_version[:80]
    coverage_stage = str(coverage_payload.get("stage", "") or "").strip().lower()
    if coverage_stage:
        focus["coverage_stage"] = coverage_stage[:32]
    current_phase_value = str(current_phase or ai_payload.get("next_phase", "") or "").strip().lower()
    if current_phase_value:
        focus["current_phase"] = current_phase_value[:64]

    confirmed_facts = []
    hostname_value = str(target_payload.get("hostname", "") or "").strip()
    if hostname_value:
        confirmed_facts.append(f"hostname: {hostname_value}")
    os_value = str(target_payload.get("os", "") or "").strip()
    if os_value:
        confirmed_facts.append(f"os: {os_value}")
    service_fact = str(target_payload.get("service", "") or "").strip()
    port_value = str(target_payload.get("port", "") or "").strip()
    protocol_value = str(target_payload.get("protocol", "") or "").strip().lower()
    service_stack = " ".join(
        part for part in [
            str(target_payload.get("service_product", "") or "").strip(),
            str(target_payload.get("service_version", "") or "").strip(),
        ]
        if part
    ).strip()
    service_location = ""
    if port_value and protocol_value:
        service_location = f"{port_value}/{protocol_value}"
    elif port_value:
        service_location = port_value
    if service_fact:
        detail_bits = []
        if service_location:
            detail_bits.append(f"on {service_location}")
        if service_stack:
            detail_bits.append(f"({service_stack})")
        confirmed_facts.append(
            " ".join(part for part in [f"service: {service_fact}", " ".join(detail_bits).strip()] if part).strip()
        )
    elif service_stack:
        confirmed_facts.append(f"service stack: {service_stack}")
    confirmed_facts = _unique_strings(confirmed_facts, limit=6, max_chars=140)

    coverage_missing = _unique_strings(
        coverage_payload.get("missing", []),
        limit=8,
        max_chars=64,
        lowercase=True,
    )
    recommended_tools = _unique_strings(
        coverage_payload.get("recommended_tool_ids", []),
        limit=8,
        max_chars=80,
        lowercase=True,
    )

    active_signals = []
    for key, value in sorted(signals_payload.items(), key=lambda item: str(item[0] or "").lower()):
        if isinstance(value, bool) and value:
            active_signals.append(str(key or "").strip().lower()[:48])
        if len(active_signals) >= 10:
            break

    technology_labels = []
    for item in technology_rows[:16]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        version = str(item.get("version", "") or "").strip()
        cpe = str(item.get("cpe", "") or "").strip()
        label = " ".join(part for part in [name, version] if part).strip() or cpe
        label = web_runtime_scheduler_excerpt.truncate_scheduler_text(label, 96)
        if label:
            technology_labels.append(label)
    known_technologies = _unique_strings(technology_labels, limit=8, max_chars=96)
    likely_technologies = list(known_technologies)

    finding_labels = []
    ai_findings = ai_payload.get("findings", []) if isinstance(ai_payload.get("findings", []), list) else []
    sorted_findings = sorted(
        [item for item in ai_findings if isinstance(item, dict)],
        key=lambda row: runtime_module.WebRuntime._finding_sort_key(row),
        reverse=True,
    )
    for item in sorted_findings[:10]:
        title = str(item.get("title", "") or item.get("cve", "") or "").strip()
        severity = str(item.get("severity", "") or "").strip().lower()
        label = title
        if severity:
            label = f"{label} [{severity}]".strip()
        label = web_runtime_scheduler_excerpt.truncate_scheduler_text(label, 120)
        if label:
            finding_labels.append(label)
    for item in host_cve_rows[:8]:
        if not isinstance(item, dict):
            continue
        cve_name = str(item.get("name", "") or "").strip()
        severity = str(item.get("severity", "") or "").strip().lower()
        label = cve_name or str(item.get("product", "") or "").strip()
        if severity and label:
            label = f"{label} [{severity}]"
        label = web_runtime_scheduler_excerpt.truncate_scheduler_text(label, 120)
        if label:
            finding_labels.append(label)
    top_findings = _unique_strings(finding_labels, limit=8, max_chars=120)
    important_findings = list(top_findings)

    attempted_values = sorted({
        str(item or "").strip().lower()
        for item in list(attempted_tool_ids or set())
        if str(item or "").strip()
    })
    recent_attempts = _unique_strings(attempted_values, limit=10, max_chars=80, lowercase=True)
    attempted_families = _unique_strings(
        sorted({
            str(item or "").strip().lower()
            for item in list(attempted_family_ids or set())
            if str(item or "").strip()
        }),
        limit=8,
        max_chars=80,
        lowercase=True,
    )

    def _failure_labels(process_rows: List[Dict[str, Any]]) -> List[str]:
        rows = []
        for item in process_rows[:32]:
            if not isinstance(item, dict):
                continue
            tool_id = str(item.get("tool_id", "") or "").strip().lower()
            status = str(item.get("status", "") or "").strip().lower()
            output_excerpt = str(item.get("output_excerpt", "") or "").strip().lower()
            failure_reason = ""
            if any(token in status for token in ["crash", "fail", "error", "timeout", "cancel", "kill", "missing"]):
                failure_reason = status
            missing_scripts = web_runtime_scheduler_excerpt.extract_missing_nse_script_tokens(output_excerpt)
            if not failure_reason and missing_scripts and (
                    (tool_id.endswith(".nse") and tool_id in missing_scripts)
                    or not tool_id
            ):
                failure_reason = "missing script"
            elif not failure_reason:
                unavailable_tokens = web_runtime_scheduler_excerpt.extract_unavailable_tool_tokens(output_excerpt)
                if unavailable_tokens and (
                        not tool_id
                        or bool(unavailable_tokens & web_runtime_scheduler_excerpt.scheduler_tool_alias_tokens(tool_id))
                ):
                    failure_reason = "command not found"
            if not failure_reason and web_runtime_scheduler_excerpt.looks_like_local_tool_dependency_failure(output_excerpt):
                failure_reason = "dependency failure"
            if not failure_reason and "no such file" in output_excerpt:
                failure_reason = "missing file"
            elif not failure_reason and ("traceback" in output_excerpt or "exception" in output_excerpt):
                failure_reason = "exception"
            if not failure_reason:
                continue
            label = ": ".join(part for part in [tool_id[:80], failure_reason[:80]] if part)
            if label:
                rows.append(label)
        return rows

    recent_failures = _unique_strings(
        _failure_labels(scoped_recent_processes) + _failure_labels(all_recent_processes),
        limit=6,
        max_chars=120,
        lowercase=True,
    )

    manual_tests = []
    for item in list(ai_payload.get("manual_tests", []) or [])[:6]:
        if not isinstance(item, dict):
            continue
        command = web_runtime_scheduler_excerpt.truncate_scheduler_text(item.get("command", ""), 140)
        if command:
            manual_tests.append(command)
    manual_tests = _unique_strings(manual_tests, limit=4, max_chars=140)

    reflection_posture = {}
    reflection = ai_payload.get("reflection", {}) if isinstance(ai_payload.get("reflection", {}), dict) else {}
    if reflection:
        reflection_state = str(reflection.get("state", "") or "").strip().lower()
        if reflection_state:
            reflection_posture["state"] = reflection_state[:24]
        priority_shift = str(reflection.get("priority_shift", "") or "").strip().lower()
        if priority_shift:
            reflection_posture["priority_shift"] = priority_shift[:64]
        trigger_reason = str(reflection.get("trigger_reason", "") or "").strip().lower()
        if trigger_reason:
            reflection_posture["trigger_reason"] = trigger_reason[:64]
        reason = web_runtime_scheduler_excerpt.truncate_scheduler_text(reflection.get("reason", ""), 180)
        if reason:
            reflection_posture["reason"] = reason
        suppress_tool_ids = _unique_strings(
            reflection.get("suppress_tool_ids", []),
            limit=6,
            max_chars=80,
            lowercase=True,
        )
        if suppress_tool_ids:
            reflection_posture["suppress_tool_ids"] = suppress_tool_ids
        promote_tool_ids = _unique_strings(
            reflection.get("promote_tool_ids", []),
            limit=6,
            max_chars=80,
            lowercase=True,
        )
        if promote_tool_ids:
            reflection_posture["promote_tool_ids"] = promote_tool_ids

    summary = {}
    if focus:
        summary["focus"] = focus
    if confirmed_facts:
        summary["confirmed_facts"] = confirmed_facts
    if coverage_missing:
        summary["missing_coverage"] = list(coverage_missing)
        summary["coverage_missing"] = coverage_missing
    if recommended_tools:
        summary["followup_candidates"] = list(recommended_tools)
        summary["recommended_tools"] = recommended_tools
    if active_signals:
        summary["active_signals"] = active_signals
    if known_technologies:
        summary["likely_technologies"] = list(likely_technologies)
        summary["known_technologies"] = known_technologies
    if top_findings:
        summary["important_findings"] = list(important_findings)
        summary["top_findings"] = top_findings
    if attempted_families:
        summary["attempted_families"] = attempted_families
    if recent_attempts:
        summary["recent_attempts"] = recent_attempts
    if recent_failures:
        summary["recent_failures"] = recent_failures
    if manual_tests:
        summary["manual_tests"] = manual_tests
    if reflection_posture:
        summary["reflection_posture"] = reflection_posture
    return summary


def build_scheduler_coverage_summary(
        *,
        service_name: str,
        signals: Dict[str, Any],
        observed_tool_ids: set,
        host_cves: List[Dict[str, Any]],
        inferred_technologies: List[Dict[str, str]],
        analysis_mode: str,
) -> Dict[str, Any]:
    runtime_module = _web_runtime_module()
    tool_ids = {str(item or "").strip().lower() for item in list(observed_tool_ids or set()) if str(item or "").strip()}
    service_lower = str(service_name or "").strip().rstrip("?").lower()
    signal_map = signals if isinstance(signals, dict) else {}

    is_web = bool(signal_map.get("web_service")) or service_lower in SchedulerPlanner.WEB_SERVICE_IDS
    is_rdp = bool(signal_map.get("rdp_service"))
    is_vnc = bool(signal_map.get("vnc_service"))
    is_smb = service_lower in {"microsoft-ds", "netbios-ssn", "smb"}

    def _has_tool_prefix(prefix: str) -> bool:
        token = str(prefix or "").strip().lower()
        return any(item.startswith(token) for item in tool_ids)

    def _has_any(*tool_names: str) -> bool:
        for tool_name in tool_names:
            token = str(tool_name or "").strip().lower()
            if token and (token in tool_ids or _has_tool_prefix(token)):
                return True
        return False

    has_discovery = _has_any("nmap", "banner", "fingerprint-strings", "http-title", "ssl-cert")
    has_screenshot = _has_any("screenshooter")
    has_nmap_vuln = _has_any("nmap-vuln.nse")
    has_nuclei = _has_any("nuclei-web", "nuclei")
    has_targeted_nuclei = _has_any("nuclei-cves", "nuclei-exposures", "nuclei-wordpress")
    has_whatweb = _has_any("whatweb", "whatweb-http", "whatweb-https")
    has_nikto = _has_any("nikto")
    has_web_content = _has_any("web-content-discovery", "dirsearch", "ffuf")
    has_http_followup = _has_any("curl-headers", "curl-options", "curl-robots")
    has_smb_signing_checks = _has_any("smb-security-mode", "smb2-security-mode")
    has_internal_safe_enum = _has_any("enum4linux-ng", "smbmap", "rpcclient-enum", "smb-enum-users.nse")
    confident_cpe_count = 0
    for item in inferred_technologies[:120]:
        if not isinstance(item, dict):
            continue
        cpe = str(item.get("cpe", "") or "").strip()
        if not cpe:
            continue
        quality = runtime_module.WebRuntime._technology_quality_score(
            name=item.get("name", ""),
            version=item.get("version", ""),
            cpe=cpe,
            evidence=item.get("evidence", ""),
        )
        if quality >= 52:
            confident_cpe_count += 1

    missing: List[str] = []
    recommended_tool_ids: List[str] = []

    def _add_gap(reason: str, *recommended: str):
        token = str(reason or "").strip().lower()
        if token and token not in missing:
            missing.append(token)
        for item in recommended:
            tool_id = str(item or "").strip().lower()
            if tool_id and tool_id not in recommended_tool_ids:
                recommended_tool_ids.append(tool_id)

    if not has_discovery:
        _add_gap("missing_discovery", "nmap")

    if is_web:
        if not has_screenshot:
            _add_gap("missing_screenshot", "screenshooter")
        if not has_nmap_vuln:
            _add_gap("missing_nmap_vuln", "nmap-vuln.nse")
        if not has_nuclei:
            _add_gap("missing_nuclei_auto", "nuclei-web")
        if (
                confident_cpe_count > 0
                and not (has_nmap_vuln and (has_nuclei or has_targeted_nuclei))
                and int(len(host_cves or [])) == 0
                and int(signal_map.get("vuln_hits", 0) or 0) == 0
        ):
            _add_gap("missing_cpe_cve_enrichment", "nmap-vuln.nse", "nuclei-web", "nuclei-cves", "nuclei-exposures")
        if not inferred_technologies and not has_whatweb:
            _add_gap("missing_technology_fingerprint", "whatweb")
        if has_nmap_vuln or has_nuclei or has_targeted_nuclei:
            if not has_whatweb:
                _add_gap("missing_whatweb", "whatweb", "whatweb-http", "whatweb-https")
            if not has_nikto:
                _add_gap("missing_nikto", "nikto")
            if not has_web_content:
                _add_gap("missing_web_content_discovery", "web-content-discovery", "dirsearch", "ffuf")
            if not has_http_followup:
                _add_gap("missing_http_followup", "curl-headers", "curl-options", "curl-robots")
    else:
        if not has_screenshot and (is_rdp or is_vnc):
            _add_gap("missing_remote_screenshot", "screenshooter")
        if not (is_rdp or is_vnc) and not _has_any("banner"):
            _add_gap("missing_banner", "banner")
        if is_smb and not has_smb_signing_checks:
            _add_gap("missing_smb_signing_checks", "smb-security-mode", "smb2-security-mode")
        if is_smb and not has_internal_safe_enum:
            _add_gap("missing_internal_safe_enum", "enum4linux-ng", "smbmap", "rpcclient-enum")

    if int(len(host_cves or [])) > 0:
        if is_web and not (has_whatweb and has_nikto and has_web_content and (has_targeted_nuclei or has_http_followup)):
            _add_gap(
                "missing_followup_after_vuln",
                "whatweb",
                "nikto",
                "web-content-discovery",
                "dirsearch",
                "ffuf",
                "nuclei-cves",
                "nuclei-exposures",
                "curl-headers",
                "curl-options",
                "curl-robots",
            )
        if is_smb and not has_smb_signing_checks:
            _add_gap("missing_smb_followup_after_vuln", "smb-security-mode", "smb2-security-mode")
        if is_smb and not has_internal_safe_enum:
            _add_gap("missing_internal_safe_enum", "enum4linux-ng", "smbmap", "rpcclient-enum")

    if str(analysis_mode or "").strip().lower() == "dig_deeper" and not missing:
        if is_web and not _has_any("wafw00f", "sslscan", "testssl.sh", "sslyze"):
            _add_gap("missing_deep_tls_waf_checks", "wafw00f", "sslscan", "testssl.sh")

    stage = "baseline"
    if not missing:
        stage = "post_baseline"
    if str(analysis_mode or "").strip().lower() == "dig_deeper":
        stage = "dig_deeper" if missing else "deep_analysis"

    return {
        "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
        "stage": stage,
        "missing": missing[:24],
        "recommended_tool_ids": recommended_tool_ids[:32],
        "observed_tool_ids": sorted(tool_ids)[:180],
        "has": {
            "discovery": bool(has_discovery),
            "screenshot": bool(has_screenshot),
            "nmap_vuln": bool(has_nmap_vuln),
            "nuclei_auto": bool(has_nuclei),
            "whatweb": bool(has_whatweb),
            "nikto": bool(has_nikto),
            "web_content_discovery": bool(has_web_content),
            "smb_signing_checks": bool(has_smb_signing_checks),
            "internal_safe_enum": bool(has_internal_safe_enum),
            "confident_cpe_count": int(confident_cpe_count),
        },
        "host_cve_count": int(len(host_cves or [])),
    }
