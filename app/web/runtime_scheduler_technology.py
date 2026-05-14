from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Tuple


CPE22_TOKEN_RE = re.compile(r"\bcpe:/[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
CPE23_TOKEN_RE = re.compile(r"\bcpe:2\.3:[aho]:[a-z0-9._:-]+\b", flags=re.IGNORECASE)
CVE_TOKEN_RE = re.compile(r"\bcve-\d{4}-\d+\b", flags=re.IGNORECASE)
TECH_VERSION_RE = re.compile(r"\b(\d+(?:[._-][0-9a-z]+){0,4})\b", flags=re.IGNORECASE)
REFERENCE_ONLY_FINDING_RE = re.compile(
    r"^(?:https?://|//|bid:\d+\s+cve:cve-\d{4}-\d+|cve:cve-\d{4}-\d+)",
    flags=re.IGNORECASE,
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
IPV4_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TECH_CPE_HINTS = (
    (("jetty",), "Jetty", "cpe:/a:eclipse:jetty"),
    (("traccar",), "Traccar", "cpe:/a:traccar:traccar"),
    (("pi-hole", "pihole", "pi.hole"), "Pi-hole", ""),
    (("openssh",), "OpenSSH", "cpe:/a:openbsd:openssh"),
    (("nginx",), "nginx", "cpe:/a:nginx:nginx"),
    (("apache http server", "apache httpd"), "Apache HTTP Server", "cpe:/a:apache:http_server"),
    (("apache",), "Apache HTTP Server", "cpe:/a:apache:http_server"),
    (("microsoft-iis", "microsoft iis", " iis "), "Microsoft IIS", "cpe:/a:microsoft:iis"),
    (("node.js", "nodejs", "node js"), "Node.js", "cpe:/a:nodejs:node.js"),
    (("php",), "PHP", "cpe:/a:php:php"),
)
WEAK_TECH_NAME_TOKENS = {
    "domain",
    "webdav",
    "commplex-link",
    "rfe",
    "filemaker",
    "avt-profile-1",
    "airport-admin",
    "surfpass",
    "jtnetd-server",
    "mmcc",
    "ida-agent",
    "rlm-admin",
    "sip",
    "sip-tls",
    "onscreen",
    "biotic",
    "admd",
    "admdog",
    "admeng",
    "barracuda-bbs",
    "targus-getdata",
    "3exmp",
    "xmpp-client",
    "hp-server",
    "hp-status",
}
TECH_STRONG_EVIDENCE_MARKERS = (
    "ssh banner",
    "service ",
    "whatweb",
    "http-title",
    "ssl-cert",
    "nuclei",
    "nmap",
    "fingerprint",
    "output cpe",
    "server header",
)
PSEUDO_TECH_NAME_TOKENS = {
    "cache-control",
    "content-language",
    "content-security-policy",
    "content-type",
    "etag",
    "referrer-policy",
    "strict-transport-security",
    "uncommonheaders",
    "vary",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
    "true",
    "false",
    "truncated",
}
GENERIC_TECH_NAME_TOKENS = {
    "unknown",
    "generic",
    "service",
    "tcpwrapped",
    "http",
    "https",
    "ssl",
    "ssh",
    "smtp",
    "imap",
    "pop3",
    "domain",
    "msrpc",
    "rpc",
    "vmrdp",
    "rdp",
    "vnc",
}
AI_HOST_UPDATE_MIN_CONFIDENCE = 70.0


def _web_runtime_module():
    return importlib.import_module("app.web.runtime")


def ai_confidence_value(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(parsed, 100.0))


def sanitize_ai_hostname(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "", raw)
    if len(cleaned) < 2:
        return ""
    return cleaned[:160]


def extract_cpe_tokens(value: Any, limit: int = 8) -> List[str]:
    text_value = str(value or "").strip()
    if not text_value:
        return []
    found = []
    seen = set()
    for pattern in (CPE22_TOKEN_RE, CPE23_TOKEN_RE):
        for match in pattern.findall(text_value):
            token = str(match or "").strip().lower()
            if not token or token in seen:
                continue
            seen.add(token)
            found.append(token[:220])
            if len(found) >= int(limit):
                return found
    return found


def extract_version_token(value: Any) -> str:
    text_value = str(value or "").strip()
    if not text_value:
        return ""
    match = TECH_VERSION_RE.search(text_value)
    if not match:
        return ""
    return sanitize_technology_version(match.group(1))


def is_ipv4_like(value: Any) -> bool:
    token = str(value or "").strip()
    if not token or not IPV4_LIKE_RE.match(token):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in token.split("."))
    except Exception:
        return False


def sanitize_technology_version(value: Any) -> str:
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
    if is_ipv4_like(token):
        return ""
    if "/" in token and not re.search(r"\d", token):
        return ""
    if not re.search(r"[0-9]", token):
        return ""
    return token


def sanitize_technology_version_for_tech(
        *,
        name: Any,
        version: Any,
        cpe: Any = "",
        evidence: Any = "",
) -> str:
    cleaned = sanitize_technology_version(version)
    if not cleaned:
        return ""
    lowered_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").strip().lower()).strip()
    cpe_base_value = cpe_base(cpe)
    evidence_text = str(evidence or "").strip().lower()
    major_match = re.match(r"^(\d+)", cleaned)
    major = int(major_match.group(1)) if major_match else None

    if major is not None:
        if lowered_name in {"apache", "apache http server"} or "cpe:/a:apache:http_server" in cpe_base_value:
            if major > 3:
                return ""
        if lowered_name == "nginx" or "cpe:/a:nginx:nginx" in cpe_base_value:
            if major > 2:
                return ""
        if lowered_name == "php" or "cpe:/a:php:php" in cpe_base_value:
            if major < 3:
                return ""

    if (
            re.fullmatch(r"[78]\.\d{2}", cleaned)
            and any(marker in evidence_text for marker in ("nmap", ".nse", "output fingerprint", "service fingerprint"))
    ):
        return ""
    return cleaned


def observation_text_for_analysis(
        source_id: Any,
        output_text: Any,
        *,
        strip_nmap_preamble_fn=None,
) -> str:
    runtime_module = _web_runtime_module()
    cleaned = ANSI_ESCAPE_RE.sub("", str(output_text or ""))
    if not cleaned.strip():
        return ""
    source_token = str(source_id or "").strip().lower()
    lowered = cleaned.lower()
    if (
            "nmap" in source_token
            or "nse" in source_token
            or "starting nmap" in lowered
            or "nmap done:" in lowered
    ):
        strip_fn = strip_nmap_preamble_fn or runtime_module.WebRuntime._strip_nmap_preamble
        cleaned = strip_fn(cleaned)
    return cleaned.strip()


def technology_hint_source_text(
        source_id: Any,
        output_text: Any,
        *,
        strip_nmap_preamble_fn=None,
) -> str:
    return observation_text_for_analysis(
        source_id,
        output_text,
        strip_nmap_preamble_fn=strip_nmap_preamble_fn,
    )


def cve_evidence_lines(
        source_id: Any,
        output_text: Any,
        limit: int = 24,
        *,
        strip_nmap_preamble_fn=None,
) -> List[Tuple[str, str]]:
    cleaned = observation_text_for_analysis(
        source_id,
        output_text,
        strip_nmap_preamble_fn=strip_nmap_preamble_fn,
    )
    if not cleaned:
        return []
    rows: List[Tuple[str, str]] = []
    seen = set()
    for raw_line in cleaned.splitlines():
        line = ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("stats:", "initiating ", "completed ", "discovered open port ")):
            continue
        if "nmap.org" in lowered:
            continue
        for match in CVE_TOKEN_RE.findall(line):
            cve_id = str(match or "").strip().upper()
            if not cve_id:
                continue
            key = (cve_id, line.lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append((cve_id, line))
            if len(rows) >= int(limit):
                return rows
    return rows


def extract_version_near_tokens(value: Any, tokens: Any) -> str:
    text_value = str(value or "")
    if not text_value:
        return ""
    for raw_token in list(tokens or []):
        token = str(raw_token or "").strip().lower()
        if not token:
            continue
        token_pattern = re.escape(token)
        direct_match = re.search(
            rf"{token_pattern}(?:[^a-z0-9]{{0,24}})(?:version\s*)?v?(\d+(?:[._-][0-9a-z]+)+|\d+[a-z]+\d*)",
            text_value,
            flags=re.IGNORECASE,
        )
        if direct_match:
            version = sanitize_technology_version(direct_match.group(1))
            if version:
                return version

        lowered = text_value.lower()
        search_at = lowered.find(token)
        while search_at >= 0:
            window = text_value[search_at: search_at + 160]
            version = extract_version_token(window)
            if version and (("." in version) or bool(re.search(r"[a-z]", version, flags=re.IGNORECASE))):
                return version
            search_at = lowered.find(token, search_at + len(token))
    return ""


def normalize_cpe_token(value: Any) -> str:
    token = str(value or "").strip().lower()[:220]
    if not token:
        return ""
    if token.startswith("cpe:/"):
        parts = token.split(":")
        if len(parts) >= 5:
            version = sanitize_technology_version(parts[4])
            if version:
                parts[4] = version.lower()
                return ":".join(parts)
            return ":".join(parts[:4])
        return token
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        if len(parts) >= 6:
            version = sanitize_technology_version(parts[5])
            if version:
                parts[5] = version.lower()
            else:
                parts[5] = "*"
            return ":".join(parts)
        return token
    return token


def cpe_base(value: Any) -> str:
    token = normalize_cpe_token(value)
    if token.startswith("cpe:/"):
        parts = token.split(":")
        return ":".join(parts[:4]) if len(parts) >= 4 else token
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        return ":".join(parts[:5]) if len(parts) >= 5 else token
    return token


def is_weak_technology_name(value: Any) -> bool:
    token = str(value or "").strip().lower()
    if not token:
        return False
    return token in WEAK_TECH_NAME_TOKENS or token in GENERIC_TECH_NAME_TOKENS


def technology_canonical_key(name: Any, cpe: Any) -> str:
    normalized_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").strip().lower()).strip()
    cpe_base_value = cpe_base(cpe)
    if normalized_name:
        return f"name:{normalized_name}"
    if cpe_base_value:
        return f"cpe:{cpe_base_value}"
    return ""


def technology_quality_score(*, name: Any, version: Any, cpe: Any, evidence: Any) -> int:
    score = 0
    tech_name = str(name or "").strip().lower()
    tech_version = sanitize_technology_version(version)
    tech_cpe = normalize_cpe_token(cpe)
    evidence_text = str(evidence or "").strip().lower()

    if tech_name and not is_weak_technology_name(tech_name):
        score += 18
    if tech_version:
        score += 18
    if tech_cpe:
        score += 32
        if version_from_cpe(tech_cpe):
            score += 6

    if "ssh banner" in evidence_text:
        score += 48
    elif "banner" in evidence_text:
        score += 22
    if "service " in evidence_text:
        score += 28
    if "output cpe" in evidence_text or "service cpe" in evidence_text:
        score += 20
    if "fingerprint" in evidence_text:
        score += 14
    if "whatweb" in evidence_text or "http-title" in evidence_text or "ssl-cert" in evidence_text:
        score += 12

    if is_weak_technology_name(tech_name) and not tech_cpe:
        score -= 42
    if not tech_name and not tech_cpe:
        score -= 60

    return int(score)


def name_from_cpe(cpe: str) -> str:
    token = str(cpe or "").strip().lower()
    if token.startswith("cpe:/"):
        parts = token.split(":")
        if len(parts) >= 4:
            product = str(parts[3] or "").replace("_", " ").strip()
            return product[:120]
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        if len(parts) >= 5:
            product = str(parts[4] or "").replace("_", " ").strip()
            return product[:120]
    return ""


def version_from_cpe(cpe: str) -> str:
    token = normalize_cpe_token(cpe)
    if token.startswith("cpe:/"):
        parts = token.split(":")
        if len(parts) >= 5:
            return sanitize_technology_version(parts[4])
        return ""
    if token.startswith("cpe:2.3:"):
        parts = token.split(":")
        if len(parts) >= 6:
            return sanitize_technology_version(parts[5])
        return ""
    return ""


def guess_technology_hints(name_or_text: Any, version_hint: Any = "") -> List[Tuple[str, str]]:
    blob = str(name_or_text or "").strip().lower()
    version_text = str(version_hint or "")
    version = extract_version_token(version_text)
    if version and ("." not in version) and (not re.search(r"[a-z]", version, flags=re.IGNORECASE)):
        version = ""
    if not blob:
        return []
    rows: List[Tuple[str, str]] = []
    seen = set()
    for tokens, normalized_name, cpe_base_value in TECH_CPE_HINTS:
        if any(str(token).lower() in blob for token in tokens):
            version_candidate = extract_version_near_tokens(version_text, tokens) or version
            normalized_cpe_base = str(cpe_base_value or "").strip().lower()
            if version_candidate and normalized_cpe_base:
                cpe = f"{normalized_cpe_base}:{version_candidate}".lower()
            elif normalized_cpe_base:
                cpe = normalized_cpe_base
            else:
                cpe = ""
            key = f"{str(normalized_name).lower()}|{cpe}"
            if key in seen:
                continue
            seen.add(key)
            rows.append((str(normalized_name), cpe))
    return rows


def guess_technology_hint(name_or_text: Any, version_hint: Any = "") -> Tuple[str, str]:
    hints = guess_technology_hints(name_or_text, version_hint=version_hint)
    if hints:
        return hints[0]
    return "", ""


def severity_from_text(value: Any) -> str:
    token = str(value or "").strip().lower()
    if "critical" in token:
        return "critical"
    if "high" in token:
        return "high"
    if "medium" in token:
        return "medium"
    if "low" in token:
        return "low"
    return "info"


def finding_sort_key(item: Dict[str, Any]) -> Tuple[int, float]:
    severity_rank = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(str(item.get("severity", "info")).strip().lower(), 0)
    try:
        cvss = float(item.get("cvss", 0.0) or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    return severity_rank, cvss


def is_placeholder_scheduler_text(value: Any) -> bool:
    token = str(value or "").strip().lower()
    if not token:
        return False
    if token in {"true", "false", "null", "none", "nil", "truncated", "...", "[truncated]", "...[truncated]"}:
        return True
    if "[truncated]" in token:
        trimmed = token.replace("...[truncated]", "").replace("[truncated]", "").strip(" .:-")
        return not trimmed or trimmed == "truncated"
    return token.endswith("...")
