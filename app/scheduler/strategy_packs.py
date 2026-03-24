from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from app.scheduler.models import ActionSpec


WEB_SERVICE_IDS = {"http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"}
TLS_SERVICE_IDS = {"https", "ssl", "https-alt"}
INTERNAL_SERVICE_IDS = {
    "smb",
    "microsoft-ds",
    "netbios-ssn",
    "ldap",
    "kerberos",
    "msrpc",
    "rdp",
    "ms-wbt-server",
    "winrm",
    "snmp",
    "rpcbind",
}
SPECIALIZED_ACTION_SIGNAL_TOKENS = {
    "wordpress_detected": ("wpscan", "wordpress", "wp-"),
    "vmware_detected": ("vmware", "vsphere", "vcenter", "esxi"),
    "coldfusion_detected": ("coldfusion", "cfusion"),
    "webdav_detected": ("webdav", "dav"),
    "iis_detected": ("iis", "microsoft-iis"),
    "huawei_detected": ("huawei", "hg5x"),
    "ubiquiti_detected": ("ubiquiti", "unifi", "ubnt"),
}

_COVERAGE_GAP_LABELS = {
    "missing_discovery": "initial discovery coverage",
    "missing_screenshot": "visual capture coverage",
    "missing_remote_screenshot": "remote-access screenshot coverage",
    "missing_nmap_vuln": "baseline vulnerability validation",
    "missing_nuclei_auto": "web validation automation",
    "missing_cpe_cve_enrichment": "CPE/CVE enrichment",
    "missing_technology_fingerprint": "technology fingerprinting",
    "missing_whatweb": "web technology validation",
    "missing_nikto": "HTTP validation follow-up",
    "missing_web_content_discovery": "content discovery follow-up",
    "missing_smb_signing_checks": "SMB signing validation",
    "missing_followup_after_vuln": "vulnerability follow-up evidence",
    "missing_smb_followup_after_vuln": "SMB vulnerability follow-up evidence",
    "missing_deep_tls_waf_checks": "deep TLS/WAF exposure checks",
    "missing_banner": "banner validation",
}


def _normalize_set(values: Any) -> Set[str]:
    if values is None:
        return set()
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    result = set()
    for item in list(values or []):
        token = str(item or "").strip().lower()
        if token:
            result.add(token)
    return result


def _matches_any(text: str, tokens: Sequence[str]) -> bool:
    lowered = str(text or "").lower()
    return any(str(token or "").strip().lower() in lowered for token in list(tokens or []))


def describe_coverage_gap(gap_id: str) -> str:
    token = str(gap_id or "").strip().lower()
    return _COVERAGE_GAP_LABELS.get(token, token.replace("_", " ").strip())


def _context_signals(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    signals = context.get("signals", {})
    return signals if isinstance(signals, dict) else {}


def _context_coverage(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    coverage = context.get("coverage", {})
    return coverage if isinstance(coverage, dict) else {}


def _context_blob(context: Optional[Dict[str, Any]]) -> str:
    if not isinstance(context, dict):
        return ""
    parts: List[str] = []
    for key in ("target", "signals", "coverage", "host_ai_state"):
        value = context.get(key, {})
        if isinstance(value, dict):
            parts.extend(str(item or "") for item in value.values())
        elif isinstance(value, list):
            parts.extend(str(item or "") for item in value)
    host_cves = context.get("host_cves", [])
    if isinstance(host_cves, list):
        for item in host_cves[:32]:
            if isinstance(item, dict):
                parts.extend(str(value or "") for value in item.values())
    return " ".join(parts).lower()


@dataclass(frozen=True)
class StrategyPack:
    pack_id: str
    label: str
    methodology_tags: List[str] = field(default_factory=list)
    trigger_services: List[str] = field(default_factory=list)
    trigger_signals: List[str] = field(default_factory=list)
    trigger_observed_technologies: List[str] = field(default_factory=list)
    preferred_tool_ids: List[str] = field(default_factory=list)
    preferred_tool_tokens: List[str] = field(default_factory=list)
    blocked_tool_tokens: List[str] = field(default_factory=list)
    coverage_gap_tools: Dict[str, List[str]] = field(default_factory=dict)
    evidence_expectations: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class StrategyPackSelection:
    pack: StrategyPack
    score: float
    reasons: List[str] = field(default_factory=list)
    coverage_gaps: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class StrategyActionGuidance:
    bonus: float = 0.0
    pack_ids: List[str] = field(default_factory=list)
    coverage_gap: str = ""
    coverage_notes: str = ""
    evidence_expectations: List[str] = field(default_factory=list)
    rationale_fragments: List[str] = field(default_factory=list)


DEFAULT_STRATEGY_PACKS: Tuple[StrategyPack, ...] = (
    StrategyPack(
        pack_id="external_surface",
        label="External Surface",
        methodology_tags=["web", "enumeration", "validation"],
        trigger_services=["http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"],
        trigger_signals=["web_service", "tls_detected", "directory_listing", "waf_detected"],
        trigger_observed_technologies=["nginx", "apache", "wordpress", "iis", "ubiquiti"],
        preferred_tool_ids=[
            "subfinder",
            "nmap",
            "banner",
            "screenshooter",
            "nmap-vuln.nse",
            "nuclei-web",
            "nuclei-cloud",
            "nuclei-cves",
            "nuclei-exposures",
            "whatweb",
            "whatweb-http",
            "whatweb-https",
            "httpx",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "curl-headers",
            "curl-options",
            "curl-robots",
            "sslscan",
            "testssl.sh",
            "wafw00f",
        ],
        preferred_tool_tokens=["http", "https", "web", "ssl", "tls", "headers", "title", "content", "favicon", "httpx", "subfinder", "cloud"],
        blocked_tool_tokens=["smb", "ldap", "kerberos", "winrm", "msrpc", "relay", "responder", "spray", "hydra"],
        coverage_gap_tools={
            "missing_discovery": ["nmap", "banner"],
            "missing_screenshot": ["screenshooter"],
            "missing_nmap_vuln": ["nmap-vuln.nse"],
            "missing_nuclei_auto": ["nuclei-web"],
            "missing_cpe_cve_enrichment": ["nmap-vuln.nse", "nuclei-web"],
            "missing_whatweb": ["whatweb", "whatweb-http", "whatweb-https"],
            "missing_nikto": ["nikto"],
            "missing_web_content_discovery": ["web-content-discovery", "dirsearch", "ffuf"],
            "missing_http_followup": ["curl-headers", "curl-options", "curl-robots"],
        },
        evidence_expectations=["service fingerprint", "screenshots", "TLS evidence", "validation artifacts"],
    ),
    StrategyPack(
        pack_id="web_app_api",
        label="Web App / API",
        methodology_tags=["web", "enumeration", "validation"],
        trigger_services=["http", "https", "ssl", "soap", "http-proxy", "http-alt", "https-alt"],
        trigger_signals=[
            "web_service",
            "wordpress_detected",
            "vmware_detected",
            "coldfusion_detected",
            "webdav_detected",
            "iis_detected",
            "huawei_detected",
            "ubiquiti_detected",
            "directory_listing",
        ],
        trigger_observed_technologies=["wordpress", "vmware", "coldfusion", "iis", "webdav", "ubiquiti", "nginx", "apache"],
        preferred_tool_ids=[
            "screenshooter",
            "nuclei-web",
            "nuclei-cves",
            "nuclei-exposures",
            "nuclei-wordpress",
            "whatweb",
            "whatweb-http",
            "whatweb-https",
            "httpx",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "curl-headers",
            "curl-options",
            "curl-robots",
            "wpscan",
        ],
        preferred_tool_tokens=["http", "https", "web", "api", "graphql", "swagger", "wordpress", "wp", "nikto", "whatweb", "httpx", "gobuster", "feroxbuster", "dirsearch", "ffuf", "wpscan"],
        blocked_tool_tokens=["smb", "ldap", "kerberos", "msrpc", "winrm"],
        coverage_gap_tools={
            "missing_screenshot": ["screenshooter"],
            "missing_nmap_vuln": ["nmap-vuln.nse"],
            "missing_nuclei_auto": ["nuclei-web"],
            "missing_technology_fingerprint": ["whatweb", "whatweb-http", "whatweb-https", "httpx"],
            "missing_whatweb": ["whatweb", "whatweb-http", "whatweb-https"],
            "missing_nikto": ["nikto"],
            "missing_web_content_discovery": ["web-content-discovery", "dirsearch", "ffuf"],
            "missing_http_followup": ["curl-headers", "curl-options", "curl-robots"],
            "missing_followup_after_vuln": [
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
            ],
        },
        evidence_expectations=["technology fingerprints", "content map", "HTTP findings", "screenshots"],
    ),
    StrategyPack(
        pack_id="internal_network",
        label="Internal Network",
        methodology_tags=["enumeration", "credential_access"],
        trigger_services=["smb", "microsoft-ds", "netbios-ssn", "ldap", "kerberos", "msrpc", "rdp", "ms-wbt-server", "winrm", "snmp"],
        trigger_signals=["smb_signing_disabled", "rdp_service", "vnc_service"],
        trigger_observed_technologies=["active", "directory", "windows", "smb"],
        preferred_tool_ids=["banner", "screenshooter", "smb-security-mode", "smb2-security-mode", "smb-enum-users.nse", "enum4linux-ng", "smbmap", "rpcclient-enum", "netexec"],
        preferred_tool_tokens=["smb", "ldap", "kerberos", "rpc", "winrm", "rdp", "snmp", "enum", "banner", "screenshot", "enum4linux", "smbmap", "rpcclient", "netexec", "nxc"],
        blocked_tool_tokens=["nikto", "whatweb", "wpscan", "web-content-discovery", "dirsearch", "ffuf"],
        coverage_gap_tools={
            "missing_banner": ["banner"],
            "missing_remote_screenshot": ["screenshooter"],
            "missing_smb_signing_checks": ["smb-security-mode", "smb2-security-mode"],
            "missing_smb_followup_after_vuln": ["smb-security-mode", "smb2-security-mode"],
            "missing_internal_safe_enum": ["enum4linux-ng", "smbmap", "rpcclient-enum", "netexec"],
        },
        evidence_expectations=["identity/trust evidence", "SMB posture checks", "service banners", "remote screenshots"],
    ),
    StrategyPack(
        pack_id="credentials_and_relay",
        label="Credentials and Relay",
        methodology_tags=["credential_access", "enumeration"],
        trigger_services=["smb", "microsoft-ds", "netbios-ssn", "ldap", "kerberos", "winrm"],
        trigger_signals=["smb_signing_disabled"],
        trigger_observed_technologies=["active", "directory", "windows"],
        preferred_tool_ids=["smb-security-mode", "smb2-security-mode", "smb-enum-users.nse", "enum4linux-ng", "smbmap", "rpcclient-enum", "netexec", "responder", "ntlmrelayx"],
        preferred_tool_tokens=["smb", "ldap", "kerberos", "ntlm", "relay", "auth", "credential", "signing", "responder", "enum4linux", "smbmap", "rpcclient", "netexec", "nxc"],
        blocked_tool_tokens=["nikto", "whatweb", "wpscan", "dirsearch", "ffuf"],
        coverage_gap_tools={
            "missing_smb_signing_checks": ["smb-security-mode", "smb2-security-mode"],
            "missing_smb_followup_after_vuln": ["smb-security-mode", "smb2-security-mode"],
            "missing_internal_safe_enum": ["enum4linux-ng", "smbmap", "rpcclient-enum", "netexec"],
        },
        evidence_expectations=["authentication posture", "credential exposure indicators", "relay preconditions"],
    ),
    StrategyPack(
        pack_id="vuln_validation",
        label="Vulnerability Validation",
        methodology_tags=["validation", "exploitation"],
        trigger_services=["http", "https", "ssl", "smb", "microsoft-ds", "netbios-ssn"],
        trigger_signals=["tls_detected"],
        trigger_observed_technologies=["wordpress", "vmware", "coldfusion", "nginx", "apache"],
        preferred_tool_ids=[
            "nmap-vuln.nse",
            "nuclei-web",
            "nuclei-cves",
            "nuclei-exposures",
            "whatweb",
            "nikto",
            "web-content-discovery",
            "dirsearch",
            "ffuf",
            "curl-headers",
            "curl-options",
            "curl-robots",
        ],
        preferred_tool_tokens=["vuln", "cve", "exploit", "nuclei", "nikto", "validate", "check"],
        blocked_tool_tokens=["discovery-only"],
        coverage_gap_tools={
            "missing_nmap_vuln": ["nmap-vuln.nse"],
            "missing_nuclei_auto": ["nuclei-web"],
            "missing_cpe_cve_enrichment": ["nmap-vuln.nse", "nuclei-web", "nuclei-cves", "nuclei-exposures"],
            "missing_http_followup": ["curl-headers", "curl-options", "curl-robots"],
            "missing_followup_after_vuln": [
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
            ],
            "missing_smb_followup_after_vuln": ["smb-security-mode", "smb2-security-mode"],
        },
        evidence_expectations=["validation transcripts", "CVE references", "reproduction notes"],
    ),
    StrategyPack(
        pack_id="tls_and_exposure",
        label="TLS and Exposure",
        methodology_tags=["web", "validation"],
        trigger_services=["https", "ssl", "https-alt"],
        trigger_signals=["tls_detected", "waf_detected"],
        trigger_observed_technologies=["nginx", "apache", "iis", "ubiquiti"],
        preferred_tool_ids=["sslscan", "testssl.sh", "wafw00f", "nmap-vuln.nse", "nuclei-web", "screenshooter"],
        preferred_tool_tokens=["ssl", "tls", "cert", "cipher", "waf", "https"],
        blocked_tool_tokens=["smb", "ldap", "kerberos"],
        coverage_gap_tools={
            "missing_nmap_vuln": ["nmap-vuln.nse"],
            "missing_nuclei_auto": ["nuclei-web"],
            "missing_cpe_cve_enrichment": ["nmap-vuln.nse", "nuclei-web"],
            "missing_deep_tls_waf_checks": ["sslscan", "testssl.sh", "wafw00f"],
        },
        evidence_expectations=["TLS posture", "certificate evidence", "WAF fingerprints"],
    ),
)


def get_default_strategy_packs() -> List[StrategyPack]:
    return list(DEFAULT_STRATEGY_PACKS)


def select_strategy_packs(
        service_name: str,
        protocol_name: str,
        policy,
        context: Optional[Dict[str, Any]] = None,
) -> List[StrategyPackSelection]:
    service_lower = str(service_name or "").strip().rstrip("?").lower()
    protocol_lower = str(protocol_name or "tcp").strip().lower()
    signals = _context_signals(context)
    coverage = _context_coverage(context)
    coverage_missing = _normalize_set(coverage.get("missing", []))
    observed_technologies = _normalize_set(signals.get("observed_technologies", []))
    host_cves = context.get("host_cves", []) if isinstance(context, dict) else []
    host_ai_state = context.get("host_ai_state", {}) if isinstance(context, dict) else {}
    host_findings = host_ai_state.get("findings", []) if isinstance(host_ai_state, dict) else []
    next_phase = str(host_ai_state.get("next_phase", "") if isinstance(host_ai_state, dict) else "").strip().lower()
    context_blob = _context_blob(context)

    selections: List[StrategyPackSelection] = []
    for pack in DEFAULT_STRATEGY_PACKS:
        score = 0.0
        reasons: List[str] = []
        matched_gaps = [gap for gap in pack.coverage_gap_tools.keys() if gap in coverage_missing]

        if service_lower in _normalize_set(pack.trigger_services):
            score += 22.0
            reasons.append(f"service {service_lower} matches {pack.pack_id}")

        if protocol_lower == "tcp" and service_lower in WEB_SERVICE_IDS and pack.pack_id in {"external_surface", "web_app_api", "tls_and_exposure"}:
            score += 4.0

        if str(getattr(policy, "scope", "") or "").strip().lower() == "external" and pack.pack_id == "external_surface":
            score += 14.0
            reasons.append("external scope")
        if str(getattr(policy, "scope", "") or "").strip().lower() == "internal" and pack.pack_id in {"internal_network", "credentials_and_relay"}:
            score += 14.0
            reasons.append("internal scope")

        if str(getattr(policy, "intent", "") or "").strip().lower() == "pentest" and pack.pack_id in {"vuln_validation", "credentials_and_relay"}:
            score += 8.0
        if str(getattr(policy, "intent", "") or "").strip().lower() == "recon" and pack.pack_id in {"external_surface", "internal_network", "tls_and_exposure"}:
            score += 6.0

        matched_signals = sorted(name for name in pack.trigger_signals if bool(signals.get(name)))
        if matched_signals:
            score += min(18.0, 10.0 + (4.0 * float(len(matched_signals))))
            reasons.append("signals " + ", ".join(matched_signals[:3]))

        matched_tech = sorted(observed_technologies & _normalize_set(pack.trigger_observed_technologies))
        if matched_tech:
            score += min(12.0, 8.0 + (2.0 * float(len(matched_tech))))
            reasons.append("technologies " + ", ".join(matched_tech[:3]))

        if matched_gaps:
            score += min(18.0, 8.0 + (4.0 * float(len(matched_gaps))))
            reasons.append("coverage gaps " + ", ".join(matched_gaps[:2]))

        if pack.pack_id == "web_app_api" and (
                service_lower in WEB_SERVICE_IDS or bool(signals.get("web_service"))
        ):
            score += 12.0
        if pack.pack_id == "internal_network" and service_lower in INTERNAL_SERVICE_IDS:
            score += 10.0
        if pack.pack_id == "credentials_and_relay":
            if service_lower in {"smb", "microsoft-ds", "netbios-ssn", "ldap", "kerberos", "winrm"}:
                score += 14.0
            if bool(signals.get("smb_signing_disabled")):
                score += 12.0
                reasons.append("SMB signing posture needs credential-safe follow-up")
            if any(token in context_blob for token in ("relay", "ntlm", "credential", "kerberoast", "lockout")):
                score += 6.0
        if pack.pack_id == "vuln_validation":
            vuln_hits = int(signals.get("vuln_hits", 0) or 0)
            if vuln_hits > 0:
                score += min(16.0, 8.0 + (4.0 * float(vuln_hits)))
                reasons.append("vulnerability evidence already observed")
            if isinstance(host_cves, list) and host_cves:
                score += 16.0
                reasons.append("host CVEs already present")
            if isinstance(host_findings, list) and host_findings:
                score += 12.0
                reasons.append("findings already collected")
        if pack.pack_id == "tls_and_exposure":
            if service_lower in TLS_SERVICE_IDS or bool(signals.get("tls_detected")):
                score += 16.0
            if str(coverage.get("analysis_mode", "") or "").strip().lower() == "dig_deeper":
                score += 6.0
        if next_phase and (_matches_any(next_phase, pack.methodology_tags) or pack.pack_id.replace("_", " ") in next_phase):
            score += 5.0

        if score >= 16.0:
            selections.append(StrategyPackSelection(
                pack=pack,
                score=score,
                reasons=reasons[:4],
                coverage_gaps=matched_gaps[:4],
            ))

    if not selections:
        if service_lower in WEB_SERVICE_IDS:
            fallback = next(pack for pack in DEFAULT_STRATEGY_PACKS if pack.pack_id == "web_app_api")
        elif service_lower in INTERNAL_SERVICE_IDS or str(getattr(policy, "scope", "") or "").strip().lower() == "internal":
            fallback = next(pack for pack in DEFAULT_STRATEGY_PACKS if pack.pack_id == "internal_network")
        else:
            fallback = next(pack for pack in DEFAULT_STRATEGY_PACKS if pack.pack_id == "external_surface")
        selections.append(StrategyPackSelection(
            pack=fallback,
            score=12.0,
            reasons=["fallback pack selected from service and policy"],
            coverage_gaps=[],
        ))

    selections.sort(key=lambda item: (item.score, item.pack.label), reverse=True)
    return selections


def evaluate_action_strategy(
        action: ActionSpec,
        selections: Sequence[StrategyPackSelection],
        policy,
        context: Optional[Dict[str, Any]] = None,
) -> StrategyActionGuidance:
    tool_id = str(action.tool_id or "").strip().lower()
    tool_text = " ".join([
        str(action.tool_id or ""),
        str(action.label or ""),
        str(action.command_template or ""),
        " ".join(str(item or "") for item in list(action.service_scope or [])),
    ]).lower()
    coverage = _context_coverage(context)
    signals = _context_signals(context)
    coverage_missing = _normalize_set(coverage.get("missing", []))
    coverage_recommended = _normalize_set(coverage.get("recommended_tool_ids", []))
    action_pack_tags = _normalize_set(action.pack_tags)
    action_methodology = _normalize_set(action.methodology_tags)
    action_risk_tags = _normalize_set(action.risk_tags)

    bonus = 0.0
    matched_pack_ids: List[str] = []
    evidence_expectations: List[str] = []
    rationale_fragments: List[str] = []
    coverage_gap = ""

    for selection in list(selections or []):
        pack = selection.pack
        matched = False
        preferred = False

        if pack.pack_id in action_pack_tags:
            bonus += 9.0
            matched = True
        if tool_id in _normalize_set(pack.preferred_tool_ids):
            bonus += 14.0
            matched = True
            preferred = True
        if _matches_any(tool_text, pack.preferred_tool_tokens):
            bonus += 6.0
            matched = True
            preferred = True
        if action_methodology & _normalize_set(pack.methodology_tags):
            bonus += 4.0
            matched = True

        for gap_id in list(selection.coverage_gaps or []):
            if gap_id not in coverage_missing:
                continue
            expected = pack.coverage_gap_tools.get(gap_id, [])
            if tool_id in _normalize_set(expected) or _matches_any(tool_text, expected):
                bonus += 18.0
                matched = True
                coverage_gap = coverage_gap or str(gap_id)

        if _matches_any(tool_text, pack.blocked_tool_tokens) and not preferred:
            bonus -= 12.0

        if matched:
            if pack.pack_id not in matched_pack_ids:
                matched_pack_ids.append(pack.pack_id)
            for item in pack.evidence_expectations:
                token = str(item or "").strip()
                if token and token not in evidence_expectations:
                    evidence_expectations.append(token)
            rationale_fragments.append(pack.label)

    if tool_id in coverage_recommended:
        bonus += 10.0

    specialized_signal_hits = []
    for signal_name, tokens in SPECIALIZED_ACTION_SIGNAL_TOKENS.items():
        if not bool(signals.get(signal_name)):
            continue
        if _matches_any(tool_text, tokens):
            specialized_signal_hits.append(signal_name)
    if specialized_signal_hits:
        bonus += min(36.0, 24.0 + (8.0 * float(len(specialized_signal_hits))))

    if not coverage_gap:
        for selection in list(selections or []):
            for gap_id, expected in selection.pack.coverage_gap_tools.items():
                if gap_id not in coverage_missing:
                    continue
                if tool_id in _normalize_set(expected) or _matches_any(tool_text, expected):
                    coverage_gap = str(gap_id)
                    break
            if coverage_gap:
                break

    if str(getattr(policy, "intent", "") or "").strip().lower() == "recon" and {
        "credential_bruteforce",
        "password_spray",
        "exploit_execution",
        "lateral_movement",
    } & action_risk_tags:
        bonus -= 10.0

    if str(getattr(policy, "scope", "") or "").strip().lower() == "internal" and "web" in action_methodology and any(
            selection.pack.pack_id == "internal_network" for selection in list(selections or [])
    ) and not matched_pack_ids:
        bonus -= 6.0

    if str(getattr(policy, "scope", "") or "").strip().lower() == "external" and {
        "credential_access",
        "exploitation",
    } & action_methodology and any(
            selection.pack.pack_id == "external_surface" for selection in list(selections or [])
    ) and not matched_pack_ids:
        bonus -= 6.0

    coverage_notes = ""
    if coverage_gap:
        coverage_notes = f"Closes {describe_coverage_gap(coverage_gap)}."

    if matched_pack_ids:
        rationale_fragments = [f"packs {', '.join(matched_pack_ids[:3])}"]
    if specialized_signal_hits:
        rationale_fragments.append("specialized signals " + ", ".join(specialized_signal_hits[:2]))
    if coverage_notes:
        rationale_fragments.append(coverage_notes.rstrip("."))

    return StrategyActionGuidance(
        bonus=bonus,
        pack_ids=matched_pack_ids[:4],
        coverage_gap=coverage_gap,
        coverage_notes=coverage_notes,
        evidence_expectations=evidence_expectations[:6],
        rationale_fragments=rationale_fragments[:4],
    )
