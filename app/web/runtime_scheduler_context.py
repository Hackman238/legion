from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import text

from app.hostsfile import registrable_root_domain
from app.scheduler.planner import SchedulerPlanner
from app.scheduler.providers import determine_scheduler_phase


def _web_runtime_module():
    return importlib.import_module("app.web.runtime")


def truncate_scheduler_text(value: Any, max_chars: int) -> str:
    text_value = str(value or "").replace("\r", " ").replace("\x00", " ")
    text_value = " ".join(text_value.split())
    if len(text_value) <= int(max_chars):
        return text_value
    return text_value[:int(max_chars)].rstrip() + "...[truncated]"


def scheduler_output_lines(value: Any, *, max_line_chars: int = 240, max_lines: int = 320) -> List[str]:
    raw_value = str(value or "").replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for raw_line in raw_value.split("\n"):
        cleaned = " ".join(str(raw_line or "").split()).strip()
        if not cleaned:
            continue
        if len(cleaned) > int(max_line_chars):
            cleaned = cleaned[:int(max_line_chars)].rstrip() + "...[truncated]"
        lines.append(cleaned)
        if len(lines) >= int(max_lines):
            break
    return lines


def scheduler_line_signal_score(value: Any) -> int:
    runtime_module = _web_runtime_module()
    line = str(value or "").strip()
    if not line:
        return 0
    lowered = line.lower()
    score = 0
    if runtime_module._CVE_TOKEN_RE.search(line):
        score += 4
    if runtime_module._CPE22_TOKEN_RE.search(line) or runtime_module._CPE23_TOKEN_RE.search(line):
        score += 4
    if "http://" in lowered or "https://" in lowered:
        score += 2
    if runtime_module._SCHEDULER_METHOD_PATH_RE.search(line) or runtime_module._SCHEDULER_STATUS_PATH_RE.search(line):
        score += 3
    for token in (
            "server:",
            "x-powered-by:",
            "location:",
            "allow:",
            "title:",
            "set-cookie:",
            "content-type:",
            "vulnerable",
            "vulnerability",
            "found",
            "interesting",
            "detected",
            "warning",
            "error",
            "exception",
            "traceback",
            "timeout",
            "redirect",
            "wordpress",
            "wp-content",
            "wp-json",
            "jetty",
            "nginx",
            "apache",
            "traccar",
            "pihole",
            "pi-hole",
            "webdav",
            "propfind",
            "tls",
            "ssl",
            "certificate",
            "waf",
            "plugin",
            "theme",
    ):
        if token in lowered:
            score += 1
    return score


def build_scheduler_excerpt(
        value: Any,
        max_chars: int,
        *,
        multiline: bool,
        head_lines: int,
        signal_lines: int,
        tail_lines: int,
        max_line_chars: int,
) -> str:
    lines = scheduler_output_lines(
        value,
        max_line_chars=max_line_chars,
        max_lines=400 if multiline else 260,
    )
    if not lines:
        return ""
    separator = "\n" if multiline else " | "
    joined = separator.join(lines)
    if len(joined) <= int(max_chars):
        return joined

    selected: List[str] = []
    seen: Set[str] = set()

    def _add(line: str) -> None:
        token = str(line or "").strip()
        key = token.lower()
        if not token or key in seen:
            return
        seen.add(key)
        selected.append(token)

    for line in lines[:int(head_lines)]:
        _add(line)

    middle_start = int(head_lines)
    middle_end = len(lines) - int(tail_lines) if int(tail_lines) > 0 else len(lines)
    middle = lines[middle_start:middle_end]
    scored_middle = [
        (scheduler_line_signal_score(line), index, line)
        for index, line in enumerate(middle)
    ]
    scored_middle = [item for item in scored_middle if item[0] > 0]
    scored_middle.sort(key=lambda item: (-item[0], item[1]))
    for _, _, line in scored_middle[:int(signal_lines)]:
        _add(line)

    if len(selected) <= int(head_lines) and middle:
        _add(middle[0])

    if int(tail_lines) > 0:
        for line in lines[-int(tail_lines):]:
            _add(line)

    rendered = separator.join(selected)
    if not rendered:
        rendered = joined

    truncated = len(selected) < len(lines) or len(joined) > int(max_chars)
    marker = "\n...[truncated]" if multiline else " ...[truncated]"
    if truncated and len(rendered) + len(marker) <= int(max_chars):
        return rendered + marker
    if len(rendered) <= int(max_chars):
        return rendered
    budget = max(0, int(max_chars) - len(marker))
    if budget <= 0:
        return marker.strip()
    if multiline and budget >= 80:
        body_budget = max(0, budget - 1)
        head_budget = max(40, body_budget // 2)
        tail_budget = max(20, body_budget - head_budget)
        return (
            rendered[:head_budget].rstrip()
            + marker
            + "\n"
            + rendered[-tail_budget:].lstrip()
        )
    return rendered[:budget].rstrip() + marker


def build_scheduler_prompt_excerpt(value: Any, max_chars: int) -> str:
    return build_scheduler_excerpt(
        value,
        max_chars,
        multiline=False,
        head_lines=2,
        signal_lines=6,
        tail_lines=1,
        max_line_chars=220,
    )


def build_scheduler_analysis_excerpt(value: Any, max_chars: int) -> str:
    return build_scheduler_excerpt(
        value,
        max_chars,
        multiline=True,
        head_lines=3,
        signal_lines=10,
        tail_lines=2,
        max_line_chars=260,
    )


def scheduler_tool_alias_tokens(tool_id: Any) -> Set[str]:
    token = str(tool_id or "").strip().lower()
    if not token:
        return set()
    aliases = {token}
    if token in {"whatweb", "whatweb-http", "whatweb-https"}:
        aliases.update({"whatweb", "whatweb-http", "whatweb-https"})
    elif token.endswith(".nse"):
        aliases.add("nmap")
    return aliases


def extract_unavailable_tool_tokens(text: Any) -> Set[str]:
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized:
        return set()

    found = set()
    patterns = (
        r"(?:^|\n)\s*(?:/bin/sh|bash|zsh|sh|fish):\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+command not found(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+not found(?:\s|$)",
    )
    for pattern in patterns:
        for match in re.findall(pattern, normalized):
            token = str(match or "").strip().lower()
            if token:
                found.add(token[:48])
    return found


def extract_missing_nse_script_tokens(text: Any) -> Set[str]:
    runtime_module = _web_runtime_module()
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized:
        return set()
    return {
        str(match or "").strip().lower()[:96]
        for match in runtime_module._MISSING_NSE_SCRIPT_RE.findall(normalized)
        if str(match or "").strip()
    }


def looks_like_local_tool_dependency_failure(text: Any) -> bool:
    runtime_module = _web_runtime_module()
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized or "traceback" not in normalized:
        return False
    return bool(runtime_module._PYTHON_TOOL_IMPORT_FAILURE_RE.search(normalized))


def scheduler_banner_from_evidence(source_id: Any, text_value: Any) -> str:
    source = str(source_id or "").strip().lower()
    if not source:
        return ""

    interesting = (
        source == "banner"
        or source.startswith("banner-")
        or source in {
            "http-title",
            "http-server-header",
            "ssl-cert",
            "ssh-hostkey",
            "smb-os-discovery",
            "fingerprint-strings",
            "smtp-commands",
            "imap-capabilities",
            "pop3-capabilities",
        }
    )
    if not interesting:
        return ""

    cleaned = truncate_scheduler_text(text_value, 280)
    if not cleaned:
        return ""
    if cleaned.lower().startswith("starting nmap"):
        return ""
    return cleaned


def scheduler_service_banner_fallback(*, service_name: str, product: str, version: str, extrainfo: str) -> str:
    parts = []
    product_value = str(product or "").strip()
    version_value = str(version or "").strip()
    extra_value = str(extrainfo or "").strip()
    service_value = str(service_name or "").strip()

    if product_value:
        parts.append(product_value)
    if version_value and version_value.lower() not in product_value.lower():
        parts.append(version_value)
    if extra_value:
        parts.append(extra_value)
    if not parts and service_value:
        parts.append(service_value)

    if not parts:
        return ""
    return truncate_scheduler_text(" ".join(parts), 200)


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
            token = truncate_scheduler_text(item, max_chars)
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
        label = truncate_scheduler_text(label, 96)
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
        label = truncate_scheduler_text(label, 120)
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
        label = truncate_scheduler_text(label, 120)
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
            missing_scripts = extract_missing_nse_script_tokens(output_excerpt)
            if not failure_reason and missing_scripts and (
                    (tool_id.endswith(".nse") and tool_id in missing_scripts)
                    or not tool_id
            ):
                failure_reason = "missing script"
            elif not failure_reason:
                unavailable_tokens = extract_unavailable_tool_tokens(output_excerpt)
                if unavailable_tokens and (
                        not tool_id
                        or bool(unavailable_tokens & scheduler_tool_alias_tokens(tool_id))
                ):
                    failure_reason = "command not found"
            if not failure_reason and looks_like_local_tool_dependency_failure(output_excerpt):
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
        command = truncate_scheduler_text(item.get("command", ""), 140)
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
        reason = truncate_scheduler_text(reflection.get("reason", ""), 180)
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


def extract_scheduler_signals(
        runtime,
        *,
        service_name: str,
        scripts: List[Dict[str, Any]],
        recent_processes: List[Dict[str, Any]],
        target: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    service_lower = str(service_name or "").strip().lower()
    target_meta = target if isinstance(target, dict) else {}
    target_blob = " ".join([
        str(target_meta.get("hostname", "") or ""),
        str(target_meta.get("os", "") or ""),
        str(target_meta.get("service", "") or ""),
        str(target_meta.get("service_product", "") or ""),
        str(target_meta.get("service_version", "") or ""),
        str(target_meta.get("service_extrainfo", "") or ""),
        " ".join(str(item or "") for item in target_meta.get("host_open_services", []) if str(item or "").strip()),
        " ".join(str(item or "") for item in target_meta.get("host_open_ports", []) if str(item or "").strip()),
        " ".join(str(item or "") for item in target_meta.get("host_banners", []) if str(item or "").strip()),
    ]).lower()
    script_blob = "\n".join(
        " ".join([
            str(item.get("script_id", "")).strip(),
            runtime._observation_text_for_analysis(
                item.get("script_id", ""),
                item.get("analysis_excerpt", "") or item.get("excerpt", ""),
            ),
        ]).strip()
        for item in scripts
    ).lower()
    process_blob = "\n".join(
        " ".join([
            str(item.get("tool_id", "")).strip(),
            str(item.get("status", "")).strip(),
            runtime._observation_text_for_analysis(
                item.get("tool_id", ""),
                item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
            ),
        ]).strip()
        for item in recent_processes
    ).lower()
    signal_evidence_blob = "\n".join(
        text_value
        for text_value in (
            str(service_name or "").strip().lower(),
            target_blob,
            "\n".join(
                runtime._observation_text_for_analysis(
                    item.get("script_id", ""),
                    item.get("analysis_excerpt", "") or item.get("excerpt", ""),
                )
                for item in scripts
                if isinstance(item, dict)
            ).lower(),
            "\n".join(
                runtime._observation_text_for_analysis(
                    item.get("tool_id", ""),
                    item.get("analysis_excerpt", "") or item.get("output_excerpt", ""),
                )
                for item in recent_processes
                if isinstance(item, dict)
            ).lower(),
        )
        if str(text_value or "").strip()
    )
    combined = f"{target_blob}\n{script_blob}\n{process_blob}"

    missing_tools = set()
    missing_tools.update(extract_unavailable_tool_tokens(target_blob))
    missing_tools.update(extract_unavailable_tool_tokens(script_blob))
    for item in recent_processes:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id", "") or "").strip().lower()
        tool_tokens = scheduler_tool_alias_tokens(item.get("tool_id", ""))
        process_failure_blob = "\n".join([
            str(item.get("status", "") or ""),
            str(item.get("output_excerpt", "") or ""),
        ])
        missing_nse_scripts = extract_missing_nse_script_tokens(process_failure_blob)
        if missing_nse_scripts:
            missing_tools.update(token for token in missing_nse_scripts if token.endswith(".nse"))
            if tool_id.endswith(".nse"):
                missing_tools.add(tool_id)
            continue
        if looks_like_local_tool_dependency_failure(process_failure_blob):
            if tool_tokens:
                missing_tools.update(tool_tokens)
            elif tool_id:
                missing_tools.add(tool_id)
            continue
        detected = extract_unavailable_tool_tokens(process_failure_blob)
        if not detected:
            continue
        if tool_tokens and detected & tool_tokens:
            missing_tools.update(tool_tokens)
        else:
            missing_tools.update(detected)

    cve_hits = set(re.findall(r"\bcve-\d{4}-\d+\b", signal_evidence_blob))
    allow_blob = ""
    allow_match = re.search(r"allow:\s*([^\n]+)", signal_evidence_blob)
    if allow_match:
        allow_blob = str(allow_match.group(1) or "").lower()
    webdav_via_allow = any(token in allow_blob for token in ["propfind", "proppatch", "mkcol", "copy", "move"])

    iis_detected = any(token in signal_evidence_blob for token in [
        "microsoft-iis",
        " iis ",
        "iis/7",
        "iis/8",
        "iis/10",
    ])
    webdav_detected = (
        "webdav" in signal_evidence_blob
        or webdav_via_allow
        or ("dav" in signal_evidence_blob and ("propfind" in signal_evidence_blob or "proppatch" in signal_evidence_blob))
    )
    vmware_detected = any(token in signal_evidence_blob for token in ["vmware", "vsphere", "vcenter", "esxi"])
    coldfusion_detected = any(token in signal_evidence_blob for token in ["coldfusion", "cfusion", "adobe coldfusion", "jrun"])
    huawei_detected = any(token in signal_evidence_blob for token in ["huawei", "hg5x", "hgw"])
    ubiquiti_detected = any(token in signal_evidence_blob for token in ["ubiquiti", "unifi", "dream machine", "udm"])
    wordpress_detected = any(
        token in signal_evidence_blob
        for token in ["wordpress", "wp-content", "wp-includes", "wp-json", "/wp-admin", "xmlrpc.php"]
    )
    aws_detected = any(token in signal_evidence_blob for token in [
        "amazon web services",
        "amazonaws.com",
        "aws ",
        " aws",
        "x-amz-",
        "amazon rds",
        "amazon aurora",
        "rds.amazonaws.com",
    ])
    azure_detected = any(token in signal_evidence_blob for token in [
        "microsoft azure",
        "azure",
        "blob.core.windows.net",
        "dfs.core.windows.net",
        "x-ms-",
        "documents.azure.com",
        "cosmos db",
        "cosmosdb",
    ])
    gcp_detected = any(token in signal_evidence_blob for token in [
        "google cloud",
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "googleapis.com",
        "x-goog-",
        " gcp ",
        "cloudsql",
        "google cloud sql",
    ])
    rds_detected = any(token in signal_evidence_blob for token in [
        "amazon rds",
        "aws rds",
        "rds.amazonaws.com",
        "relational database service",
    ])
    aurora_detected = any(token in signal_evidence_blob for token in [
        "amazon aurora",
        "aws aurora",
        "aurora mysql",
        "aurora postgresql",
    ]) or (
        "rds.amazonaws.com" in signal_evidence_blob
        and any(token in signal_evidence_blob for token in [".cluster-", ".cluster-ro-", "aurora"])
    )
    cosmos_detected = any(token in signal_evidence_blob for token in [
        "azure cosmos",
        "cosmos db",
        "cosmosdb",
        "documents.azure.com",
        "mongo.cosmos.azure.com",
        "cassandra.cosmos.azure.com",
        "gremlin.cosmos.azure.com",
        "table.cosmos.azure.com",
    ])
    cloudsql_detected = any(token in signal_evidence_blob for token in [
        "google cloud sql",
        "cloudsql",
        "sqladmin.googleapis.com",
    ])
    mysql_detected = service_lower == "mysql" or any(token in signal_evidence_blob for token in ["mysql", "mariadb"])
    postgresql_detected = service_lower in {"postgres", "postgresql"} or any(
        token in signal_evidence_blob for token in ["postgresql", "postgres ", "pgsql"]
    )
    mssql_detected = service_lower in {"ms-sql", "ms-sql-s", "codasrv-se", "mssql"} or any(
        token in signal_evidence_blob for token in ["microsoft sql server", "ms-sql", "mssql"]
    )
    aws_storage_detected = any(token in signal_evidence_blob for token in [
        "s3.amazonaws.com",
        "amazon s3",
        "aws s3",
        "s3 bucket",
        "bucket.s3",
        "x-amz-bucket",
        "x-amz-request-id",
    ])
    azure_storage_detected = any(token in signal_evidence_blob for token in [
        "blob.core.windows.net",
        "dfs.core.windows.net",
        "azure blob",
        "azure storage",
        "x-ms-blob",
        "x-ms-version",
    ])
    gcp_storage_detected = any(token in signal_evidence_blob for token in [
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "google cloud storage",
        "gcs bucket",
        "x-goog-",
    ])
    cloud_public_negation_detected = any(token in signal_evidence_blob for token in [
        "not publicly accessible",
        "public access disabled",
        "anonymous access disabled",
        "private bucket",
        "private container",
        "authentication required",
    ])
    public_exposure_markers_detected = any(token in signal_evidence_blob for token in [
        "public bucket",
        "bucket listing exposed",
        "container listing exposed",
        "blob listing exposed",
        "publicly accessible",
        "public access enabled",
        "anonymous access",
        "anonymous read",
        "anonymous list",
        "unauthenticated access",
        "world-readable",
        "world readable",
        "allusers",
        "authenticatedusers",
        "public acl",
    ]) and not cloud_public_negation_detected
    managed_db_public_markers_detected = any(token in signal_evidence_blob for token in [
        "publicly accessible",
        "public access enabled",
        "public endpoint",
        "public network access",
        "internet reachable",
        "internet exposed",
    ]) and not cloud_public_negation_detected
    cosmos_risk_markers_detected = any(token in signal_evidence_blob for token in [
        "master key",
        "read-only key",
        "readonly key",
        "publicly accessible",
        "public access enabled",
        "public network access",
        "anonymous access",
    ]) and not cloud_public_negation_detected
    aws_storage_exposure_candidate = bool(aws_storage_detected and public_exposure_markers_detected)
    azure_storage_exposure_candidate = bool(azure_storage_detected and public_exposure_markers_detected)
    gcp_storage_exposure_candidate = bool(gcp_storage_detected and public_exposure_markers_detected)
    rds_public_access_candidate = bool(rds_detected and managed_db_public_markers_detected)
    aurora_public_access_candidate = bool(aurora_detected and managed_db_public_markers_detected)
    cosmos_exposure_candidate = bool(cosmos_detected and cosmos_risk_markers_detected)
    cloudsql_public_access_candidate = bool(cloudsql_detected and managed_db_public_markers_detected)
    cloud_provider_detected = bool(aws_detected or azure_detected or gcp_detected)
    storage_service_detected = bool(aws_storage_detected or azure_storage_detected or gcp_storage_detected)
    storage_exposure_candidate = bool(
        aws_storage_exposure_candidate or azure_storage_exposure_candidate or gcp_storage_exposure_candidate
    )
    managed_db_exposure_candidate = bool(
        rds_public_access_candidate
        or aurora_public_access_candidate
        or cosmos_exposure_candidate
        or cloudsql_public_access_candidate
    )
    cloud_exposure_candidate = bool(storage_exposure_candidate or managed_db_exposure_candidate)

    observed_technologies = []
    for marker, present in (
            ("iis", iis_detected),
            ("webdav", webdav_detected),
            ("vmware", vmware_detected),
            ("coldfusion", coldfusion_detected),
            ("huawei", huawei_detected),
            ("ubiquiti", ubiquiti_detected),
            ("wordpress", wordpress_detected),
            ("aws", aws_detected),
            ("azure", azure_detected),
            ("gcp", gcp_detected),
            ("rds", rds_detected),
            ("aurora", aurora_detected),
            ("cosmos", cosmos_detected),
            ("cloudsql", cloudsql_detected),
            ("cloud_storage", storage_service_detected),
            ("cloud_exposure", cloud_exposure_candidate),
            ("mysql", mysql_detected),
            ("postgresql", postgresql_detected),
            ("mssql", mssql_detected),
            ("nginx", "nginx" in signal_evidence_blob),
            ("apache", "apache" in signal_evidence_blob),
    ):
        if present:
            observed_technologies.append(marker)

    return {
        "web_service": service_lower in SchedulerPlanner.WEB_SERVICE_IDS,
        "rdp_service": service_lower in {"rdp", "ms-wbt-server", "vmrdp"},
        "vnc_service": service_lower in {"vnc", "vnc-http", "rfb"},
        "tls_detected": any(token in signal_evidence_blob for token in ["ssl", "tls", "certificate", "https"]),
        "smb_signing_disabled": any(token in combined for token in [
            "message signing enabled but not required",
            "smb signing disabled",
            "signing: disabled",
            "signing: false",
        ]),
        "directory_listing": "index of /" in signal_evidence_blob or "directory listing" in signal_evidence_blob,
        "waf_detected": "waf" in signal_evidence_blob,
        "shodan_enabled": bool(target_meta.get("shodan_enabled", False)),
        "wordpress_detected": wordpress_detected,
        "iis_detected": iis_detected,
        "webdav_detected": webdav_detected,
        "vmware_detected": vmware_detected,
        "coldfusion_detected": coldfusion_detected,
        "huawei_detected": huawei_detected,
        "ubiquiti_detected": ubiquiti_detected,
        "cloud_provider_detected": cloud_provider_detected,
        "storage_service_detected": storage_service_detected,
        "cloud_exposure_candidate": cloud_exposure_candidate,
        "storage_exposure_candidate": storage_exposure_candidate,
        "managed_db_exposure_candidate": managed_db_exposure_candidate,
        "aws_detected": aws_detected,
        "azure_detected": azure_detected,
        "gcp_detected": gcp_detected,
        "rds_detected": rds_detected,
        "aurora_detected": aurora_detected,
        "cosmos_detected": cosmos_detected,
        "cloudsql_detected": cloudsql_detected,
        "aws_storage_detected": aws_storage_detected,
        "azure_storage_detected": azure_storage_detected,
        "gcp_storage_detected": gcp_storage_detected,
        "aws_storage_exposure_candidate": aws_storage_exposure_candidate,
        "azure_storage_exposure_candidate": azure_storage_exposure_candidate,
        "gcp_storage_exposure_candidate": gcp_storage_exposure_candidate,
        "rds_public_access_candidate": rds_public_access_candidate,
        "aurora_public_access_candidate": aurora_public_access_candidate,
        "cosmos_exposure_candidate": cosmos_exposure_candidate,
        "cloudsql_public_access_candidate": cloudsql_public_access_candidate,
        "mysql_detected": mysql_detected,
        "postgresql_detected": postgresql_detected,
        "mssql_detected": mssql_detected,
        "observed_technologies": observed_technologies[:12],
        "vuln_hits": len(cve_hits),
        "missing_tools": sorted(missing_tools),
    }


def build_scheduler_target_context(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        goal_profile: str = "internal_asset_discovery",
        engagement_preset: str = "",
        attempted_tool_ids: set,
        attempted_family_ids: Optional[set] = None,
        attempted_command_signatures: Optional[set] = None,
        recent_output_chars: int = 900,
        analysis_mode: str = "standard",
) -> Dict[str, Any]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if not project:
            return {}
        scheduler_preferences = runtime.scheduler_config.load()

        session = project.database.session()
        try:
            host_result = session.execute(text(
                "SELECT COALESCE(h.hostname, '') AS hostname, "
                "COALESCE(h.osMatch, '') AS os_match "
                "FROM hostObj AS h WHERE h.id = :host_id LIMIT 1"
            ), {"host_id": int(host_id or 0)}).fetchone()
            hostname = str(host_result[0] or "") if host_result else ""
            os_match = str(host_result[1] or "") if host_result else ""

            service_result = session.execute(text(
                "SELECT COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "AND COALESCE(p.portId, '') = :port "
                "AND LOWER(COALESCE(p.protocol, '')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "host_id": int(host_id or 0),
                "port": str(port or ""),
                "protocol": str(protocol or "tcp"),
            }).fetchone()
            service_name_db = str(service_result[0] or "") if service_result else ""
            service_product = str(service_result[1] or "") if service_result else ""
            service_version = str(service_result[2] or "") if service_result else ""
            service_extrainfo = str(service_result[3] or "") if service_result else ""
            target_service = str(service_name or service_name_db or "").strip()

            host_port_rows = session.execute(text(
                "SELECT COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol, "
                "COALESCE(p.state, '') AS state, "
                "COALESCE(s.name, '') AS service_name, "
                "COALESCE(s.product, '') AS service_product, "
                "COALESCE(s.version, '') AS service_version, "
                "COALESCE(s.extrainfo, '') AS service_extrainfo "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "ORDER BY p.id ASC LIMIT 280"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            script_rows = session.execute(text(
                "SELECT COALESCE(s.scriptId, '') AS script_id, "
                "COALESCE(s.output, '') AS output, "
                "COALESCE(p.portId, '') AS port_id, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM l1ScriptObj AS s "
                "LEFT JOIN portObj AS p ON p.id = s.portId "
                "WHERE s.hostId = :host_id "
                "ORDER BY s.id DESC LIMIT 260"
            ), {
                "host_id": int(host_id or 0),
            }).fetchall()

            process_rows = session.execute(text(
                "SELECT COALESCE(p.name, '') AS tool_id, "
                "COALESCE(p.status, '') AS status, "
                "COALESCE(p.command, '') AS command_text, "
                "COALESCE(o.output, '') AS output_text, "
                "COALESCE(p.port, '') AS port, "
                "COALESCE(p.protocol, '') AS protocol "
                "FROM process AS p "
                "LEFT JOIN process_output AS o ON o.processId = p.id "
                "WHERE COALESCE(p.hostIp, '') = :host_ip "
                "ORDER BY p.id DESC LIMIT 180"
            ), {
                "host_ip": str(host_ip or ""),
            }).fetchall()
        finally:
            session.close()

    try:
        host_cves_raw = runtime._load_cves_for_host(project, int(host_id or 0))
    except Exception:
        host_cves_raw = []

    target_port_value = str(port or "")
    target_protocol_value = str(protocol or "tcp").lower()

    port_scripts: Dict[Tuple[str, str], List[str]] = {}
    port_banners: Dict[Tuple[str, str], str] = {}
    scripts = []
    target_scripts = []
    analysis_output_chars = max(int(recent_output_chars) * 4, 1600)
    for row in script_rows:
        script_id = str(row[0] or "").strip()
        output = build_scheduler_prompt_excerpt(row[1], int(recent_output_chars))
        analysis_output = build_scheduler_analysis_excerpt(row[1], int(analysis_output_chars))
        script_port = str(row[2] or "").strip()
        script_protocol = str(row[3] or "tcp").strip().lower() or "tcp"
        if not script_id and not output and not analysis_output:
            continue
        item = {
            "script_id": script_id,
            "port": script_port,
            "protocol": script_protocol,
            "excerpt": output,
            "analysis_excerpt": analysis_output,
        }
        scripts.append(item)
        if not script_port or (script_port == target_port_value and script_protocol == target_protocol_value):
            target_scripts.append(item)

        if script_port:
            key = (script_port, script_protocol)
            if script_id:
                port_scripts.setdefault(key, []).append(script_id)
            if key not in port_banners:
                candidate_banner = scheduler_banner_from_evidence(script_id, analysis_output or output)
                if candidate_banner:
                    port_banners[key] = candidate_banner

    recent_processes = []
    target_recent_processes = []
    for row in process_rows:
        tool_id = str(row[0] or "").strip()
        status = str(row[1] or "").strip()
        command_text = truncate_scheduler_text(row[2], 220)
        output_text = build_scheduler_prompt_excerpt(row[3], int(recent_output_chars))
        analysis_output = build_scheduler_analysis_excerpt(row[3], int(analysis_output_chars))
        process_port = str(row[4] or "").strip()
        process_protocol = str(row[5] or "tcp").strip().lower() or "tcp"
        if not tool_id and not output_text and not analysis_output:
            continue
        item = {
            "tool_id": tool_id,
            "status": status,
            "port": process_port,
            "protocol": process_protocol,
            "command_excerpt": command_text,
            "output_excerpt": output_text,
            "analysis_excerpt": analysis_output,
        }
        recent_processes.append(item)
        if process_port == target_port_value and process_protocol == target_protocol_value:
            target_recent_processes.append(item)

        if process_port:
            key = (process_port, process_protocol)
            if key not in port_banners:
                candidate_banner = scheduler_banner_from_evidence(tool_id, analysis_output or output_text)
                if candidate_banner:
                    port_banners[key] = candidate_banner

    host_port_inventory = []
    host_open_services = set()
    host_open_ports = []
    host_banner_hints = []
    for row in host_port_rows:
        port_value = str(row[0] or "").strip()
        port_protocol = str(row[1] or "tcp").strip().lower() or "tcp"
        state_value = str(row[2] or "").strip()
        service_value = str(row[3] or "").strip()
        product_value = str(row[4] or "").strip()
        version_value = str(row[5] or "").strip()
        extra_value = str(row[6] or "").strip()

        key = (port_value, port_protocol)
        banner_value = str(port_banners.get(key, "") or "")
        if not banner_value:
            banner_value = scheduler_service_banner_fallback(
                service_name=service_value,
                product=product_value,
                version=version_value,
                extrainfo=extra_value,
            )
        if state_value in {"open", "open|filtered"}:
            if service_value:
                host_open_services.add(service_value)
            if port_value:
                host_open_ports.append(f"{port_value}/{port_protocol}:{service_value or 'unknown'}")
            if banner_value:
                host_banner_hints.append(f"{port_value}/{port_protocol}:{banner_value}")

        host_port_inventory.append({
            "port": port_value,
            "protocol": port_protocol,
            "state": state_value,
            "service": service_value,
            "service_product": product_value,
            "service_version": version_value,
            "service_extrainfo": extra_value,
            "banner": banner_value,
            "scripts": port_scripts.get(key, [])[:12],
        })

    inferred_technologies = runtime._infer_technologies_from_observations(
        service_records=[
            {
                "port": str(item.get("port", "") or ""),
                "protocol": str(item.get("protocol", "") or ""),
                "service_name": str(item.get("service", "") or ""),
                "service_product": str(item.get("service_product", "") or ""),
                "service_version": str(item.get("service_version", "") or ""),
                "service_extrainfo": str(item.get("service_extrainfo", "") or ""),
                "banner": str(item.get("banner", "") or ""),
            }
            for item in host_port_inventory
            if isinstance(item, dict)
        ],
        script_records=scripts,
        process_records=recent_processes,
        limit=64,
    )

    target_data = {
        "host_ip": str(host_ip or ""),
        "hostname": str(hostname or ""),
        "root_domain": registrable_root_domain(str(hostname or "").strip()) or registrable_root_domain(str(host_ip or "").strip()),
        "os": str(os_match or ""),
        "port": str(port or ""),
        "protocol": str(protocol or "tcp"),
        "service": str(target_service or service_name or ""),
        "service_product": str(service_product or ""),
        "service_version": str(service_version or ""),
        "service_extrainfo": str(service_extrainfo or ""),
        "engagement_preset": str(engagement_preset or "").strip().lower(),
        "host_open_services": sorted(host_open_services)[:48],
        "host_open_ports": host_open_ports[:120],
        "host_banners": host_banner_hints[:80],
        "grayhatwarfare_enabled": runtime._grayhatwarfare_integration_enabled(scheduler_preferences),
        "shodan_enabled": runtime._shodan_integration_enabled(scheduler_preferences),
    }
    signals = extract_scheduler_signals(
        runtime,
        service_name=target_data["service"],
        scripts=scripts,
        recent_processes=recent_processes,
        target=target_data,
    )
    tool_audit = runtime._scheduler_tool_audit_snapshot()

    ai_state = runtime._load_host_ai_analysis(project, int(host_id or 0), str(host_ip or ""))
    ai_context_state = {}
    if isinstance(ai_state, dict) and ai_state:
        host_updates = ai_state.get("host_updates", {}) if isinstance(ai_state.get("host_updates", {}), dict) else {}

        ai_tech = []
        for item in ai_state.get("technologies", [])[:24]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()[:120]
            version = str(item.get("version", "")).strip()[:120]
            cpe = str(item.get("cpe", "")).strip()[:220]
            evidence = truncate_scheduler_text(item.get("evidence", ""), 260)
            if not name and not cpe:
                continue
            ai_tech.append({
                "name": name,
                "version": version,
                "cpe": cpe,
                "evidence": evidence,
            })

        ai_findings = []
        for item in ai_state.get("findings", [])[:24]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()[:240]
            severity = str(item.get("severity", "")).strip().lower()[:16]
            cve_id = str(item.get("cve", "")).strip()[:64]
            evidence = truncate_scheduler_text(item.get("evidence", ""), 260)
            if not title and not cve_id:
                continue
            ai_findings.append({
                "title": title,
                "severity": severity,
                "cve": cve_id,
                "evidence": evidence,
            })

        ai_manual_tests = []
        for item in ai_state.get("manual_tests", [])[:16]:
            if not isinstance(item, dict):
                continue
            command = truncate_scheduler_text(item.get("command", ""), 260)
            why = truncate_scheduler_text(item.get("why", ""), 180)
            if not command and not why:
                continue
            ai_manual_tests.append({
                "command": command,
                "why": why,
                "scope_note": truncate_scheduler_text(item.get("scope_note", ""), 160),
            })

        merged_context_tech = runtime._merge_technologies(
            existing=inferred_technologies,
            incoming=ai_tech,
            limit=64,
        )

        ai_context_state = {
            "updated_at": str(ai_state.get("updated_at", "") or ""),
            "provider": str(ai_state.get("provider", "") or ""),
            "goal_profile": str(ai_state.get("goal_profile", "") or ""),
            "next_phase": str(ai_state.get("next_phase", "") or ""),
            "host_updates": {
                "hostname": str(host_updates.get("hostname", "") or ""),
                "hostname_confidence": runtime._ai_confidence_value(host_updates.get("hostname_confidence", 0.0)),
                "os": str(host_updates.get("os", "") or ""),
                "os_confidence": runtime._ai_confidence_value(host_updates.get("os_confidence", 0.0)),
            },
            "technologies": merged_context_tech,
            "findings": ai_findings,
            "manual_tests": ai_manual_tests,
        }
        reflection = ai_state.get("reflection", {}) if isinstance(ai_state.get("reflection", {}), dict) else {}
        if reflection:
            ai_context_state["reflection"] = {
                "state": str(reflection.get("state", "") or "")[:24],
                "priority_shift": str(reflection.get("priority_shift", "") or "")[:64],
                "reason": truncate_scheduler_text(reflection.get("reason", ""), 220),
                "promote_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("promote_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
                "suppress_tool_ids": [
                    str(item or "").strip().lower()[:80]
                    for item in list(reflection.get("suppress_tool_ids", []) or [])[:8]
                    if str(item or "").strip()
                ],
            }

        ai_observed_tech = [
            str(item.get("name", "")).strip().lower()
            for item in merged_context_tech
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
        if ai_observed_tech:
            existing_observed = signals.get("observed_technologies", [])
            if not isinstance(existing_observed, list):
                existing_observed = []
            merged_observed = []
            seen_observed = set()
            for marker in existing_observed + ai_observed_tech:
                token = str(marker or "").strip().lower()
                if not token or token in seen_observed:
                    continue
                seen_observed.add(token)
                merged_observed.append(token)
            if merged_observed:
                signals["observed_technologies"] = merged_observed[:24]
    elif inferred_technologies:
        ai_context_state = {
            "updated_at": "",
            "provider": "",
            "goal_profile": "",
            "next_phase": "",
            "host_updates": {
                "hostname": "",
                "hostname_confidence": 0.0,
                "os": "",
                "os_confidence": 0.0,
            },
            "technologies": inferred_technologies,
            "findings": [],
            "manual_tests": [],
        }
        inferred_names = [
            str(item.get("name", "")).strip().lower()
            for item in inferred_technologies
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
        if inferred_names:
            existing_observed = signals.get("observed_technologies", [])
            if not isinstance(existing_observed, list):
                existing_observed = []
            merged_observed = []
            seen_observed = set()
            for marker in existing_observed + inferred_names:
                token = str(marker or "").strip().lower()
                if not token or token in seen_observed:
                    continue
                seen_observed.add(token)
                merged_observed.append(token)
            if merged_observed:
                signals["observed_technologies"] = merged_observed[:24]

    host_cves = []
    for row in host_cves_raw[:120]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name", "") or "").strip()[:96]
        severity = str(row.get("severity", "") or "").strip().lower()[:24]
        product = str(row.get("product", "") or "").strip()[:120]
        version = str(row.get("version", "") or "").strip()[:80]
        url = str(row.get("url", "") or "").strip()[:220]
        if not any([name, severity, product, version, url]):
            continue
        host_cves.append({
            "name": name,
            "severity": severity,
            "product": product,
            "version": version,
            "url": url,
        })

    observed_tool_ids = set()
    observed_tool_ids.update({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()})
    for item in scripts:
        if not isinstance(item, dict):
            continue
        token = str(item.get("script_id", "")).strip().lower()
        if token:
            observed_tool_ids.add(token)
    for item in recent_processes:
        if not isinstance(item, dict):
            continue
        token = str(item.get("tool_id", "")).strip().lower()
        if token:
            observed_tool_ids.add(token)

    coverage = build_scheduler_coverage_summary(
        service_name=str(target_data.get("service", "") or service_name or ""),
        signals=signals,
        observed_tool_ids=observed_tool_ids,
        host_cves=host_cves,
        inferred_technologies=inferred_technologies,
        analysis_mode=analysis_mode,
    )
    current_phase = determine_scheduler_phase(
        goal_profile=str(goal_profile or "internal_asset_discovery"),
        service=str(target_data.get("service", "") or service_name or ""),
        engagement_preset=str(engagement_preset or ""),
        context={
            "analysis_mode": str(analysis_mode or "standard"),
            "signals": signals,
            "coverage": coverage,
            "attempted_tool_ids": sorted(
                {str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}
            ),
        },
    )
    context_summary = build_scheduler_context_summary(
        target=target_data,
        analysis_mode=str(analysis_mode or "standard"),
        coverage=coverage,
        signals=signals,
        current_phase=current_phase,
        attempted_tool_ids=attempted_tool_ids,
        attempted_family_ids=attempted_family_ids,
        summary_technologies=(
            ai_context_state.get("technologies", [])
            if isinstance(ai_context_state.get("technologies", []), list) and ai_context_state.get("technologies", [])
            else inferred_technologies
        ),
        host_cves=host_cves,
        host_ai_state=ai_context_state,
        recent_processes=recent_processes,
        target_recent_processes=target_recent_processes,
    )
    runtime._persist_shared_target_state(
        host_id=int(host_id or 0),
        host_ip=str(host_ip or ""),
        port=str(port or ""),
        protocol=str(protocol or "tcp"),
        service_name=str(target_data.get("service", "") or service_name or ""),
        hostname=str(target_data.get("hostname", "") or ""),
        hostname_confidence=95.0 if str(target_data.get("hostname", "") or "").strip() else 0.0,
        os_match=str(target_data.get("os", "") or ""),
        os_confidence=70.0 if str(target_data.get("os", "") or "").strip() else 0.0,
        technologies=inferred_technologies[:64],
        service_inventory=host_port_inventory,
        coverage=coverage,
    )

    return {
        "target": target_data,
        "engagement_preset": str(engagement_preset or "").strip().lower(),
        "signals": signals,
        "tool_audit": tool_audit,
        "attempted_tool_ids": sorted({str(item).strip().lower() for item in attempted_tool_ids if str(item).strip()}),
        "attempted_family_ids": sorted({str(item).strip().lower() for item in list(attempted_family_ids or set()) if str(item).strip()}),
        "attempted_command_signatures": sorted({str(item).strip().lower() for item in list(attempted_command_signatures or set()) if str(item).strip()}),
        "host_ports": host_port_inventory,
        "scripts": scripts,
        "recent_processes": recent_processes,
        "target_scripts": target_scripts,
        "target_recent_processes": target_recent_processes,
        "inferred_technologies": inferred_technologies[:64],
        "host_cves": host_cves,
        "coverage": coverage,
        "analysis_mode": str(analysis_mode or "standard").strip().lower() or "standard",
        "context_summary": context_summary,
        "host_ai_state": ai_context_state,
    }
