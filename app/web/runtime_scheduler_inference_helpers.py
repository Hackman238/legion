from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Optional, Tuple


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


def normalize_ai_technologies(runtime, items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    best_rows: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()[:120]
        cpe = runtime._normalize_cpe_token(item.get("cpe", ""))
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 520)
        version = runtime._sanitize_technology_version_for_tech(
            name=name,
            version=item.get("version", ""),
            cpe=cpe,
            evidence=evidence,
        )
        if is_placeholder_scheduler_text(name) and not cpe:
            continue
        if is_placeholder_scheduler_text(version):
            version = ""
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not name and not cpe:
            continue
        if not name and cpe:
            name = runtime._name_from_cpe(cpe)
        if str(name or "").strip().lower() in PSEUDO_TECH_NAME_TOKENS and not cpe:
            continue
        if not version and cpe:
            cpe_version = runtime._sanitize_technology_version_for_tech(
                name=name,
                version=runtime._version_from_cpe(cpe),
                cpe=cpe,
                evidence=evidence,
            )
            if cpe_version:
                version = cpe_version
            else:
                cpe = runtime._cpe_base(cpe)
        if not cpe and name:
            hinted_name, hinted_cpe = runtime._guess_technology_hint(name, version)
            if hinted_name and not name:
                name = hinted_name
            if hinted_cpe:
                cpe = runtime._normalize_cpe_token(hinted_cpe)
                if cpe and not version:
                    version = runtime._version_from_cpe(cpe)

        if runtime._is_weak_technology_name(name) and not cpe:
            if not any(marker in evidence.lower() for marker in TECH_STRONG_EVIDENCE_MARKERS):
                continue

        quality = runtime._technology_quality_score(
            name=name,
            version=version,
            cpe=cpe,
            evidence=evidence,
        )
        if quality < 20:
            continue

        canonical = runtime._technology_canonical_key(name, cpe) or "|".join([name.lower(), version.lower(), cpe.lower()])
        candidate = {
            "name": name,
            "version": version,
            "cpe": cpe,
            "evidence": evidence,
            "_quality": quality,
        }
        current = best_rows.get(canonical)
        if current is None:
            best_rows[canonical] = candidate
            continue

        if int(candidate["_quality"]) > int(current.get("_quality", 0)):
            best_rows[canonical] = candidate
            continue
        if int(candidate["_quality"]) == int(current.get("_quality", 0)):
            current_version = str(current.get("version", "") or "")
            if len(version) > len(current_version):
                best_rows[canonical] = candidate
                continue
            if cpe and not str(current.get("cpe", "") or ""):
                best_rows[canonical] = candidate

    rows = sorted(
        list(best_rows.values()),
        key=lambda row: (
            -int(row.get("_quality", 0) or 0),
            str(row.get("name", "") or "").lower(),
            str(row.get("version", "") or "").lower(),
            str(row.get("cpe", "") or "").lower(),
        ),
    )
    trimmed: List[Dict[str, str]] = []
    for row in rows:
        trimmed.append({
            "name": str(row.get("name", "") or "")[:120],
            "version": str(row.get("version", "") or "")[:120],
            "cpe": str(row.get("cpe", "") or "")[:220],
            "evidence": runtime._truncate_scheduler_text(row.get("evidence", ""), 520),
        })
        if len(trimmed) >= 180:
            break
    return trimmed


def merge_technologies(
        runtime,
        *,
        existing: Any,
        incoming: Any,
        limit: int = 220,
) -> List[Dict[str, str]]:
    combined: List[Dict[str, Any]] = []
    if isinstance(incoming, list):
        for item in incoming:
            if isinstance(item, dict):
                combined.append(dict(item))
    if isinstance(existing, list):
        for item in existing:
            if isinstance(item, dict):
                combined.append(dict(item))
    rows = normalize_ai_technologies(runtime, combined)
    return rows[:int(limit)]


def normalize_ai_findings(runtime, items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    allowed = {"critical", "high", "medium", "low", "info"}
    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()[:260]
        severity = str(item.get("severity", "info")).strip().lower()
        if severity not in allowed:
            severity = "info"
        cve_id = str(item.get("cve", "")).strip()[:64]
        cvss_value = runtime._ai_confidence_value(item.get("cvss"))
        if cvss_value > 10.0:
            cvss_value = 10.0
        evidence = runtime._truncate_scheduler_text(item.get("evidence", ""), 640)
        if is_placeholder_scheduler_text(title) and not cve_id:
            continue
        if is_placeholder_scheduler_text(evidence):
            evidence = ""
        if not title and not cve_id:
            continue
        evidence_lower = str(evidence or "").strip().lower()
        if REFERENCE_ONLY_FINDING_RE.match(title) or evidence_lower in {"previous scan result", "previous tls scan result"}:
            continue
        key = "|".join([title.lower(), cve_id.lower(), severity])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "title": title or cve_id,
            "severity": severity,
            "cvss": cvss_value,
            "cve": cve_id,
            "evidence": evidence or title or cve_id,
        })
        if len(rows) >= 220:
            break
    rows.sort(key=lambda row: runtime._finding_sort_key(row), reverse=True)
    return rows


def normalize_ai_manual_tests(runtime, items: Any) -> List[Dict[str, str]]:
    if not isinstance(items, list):
        return []
    rows: List[Dict[str, str]] = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        why = runtime._truncate_scheduler_text(item.get("why", ""), 320)
        command = runtime._truncate_scheduler_text(item.get("command", ""), 520)
        scope_note = runtime._truncate_scheduler_text(item.get("scope_note", ""), 280)
        if not command and not why:
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
        if len(rows) >= 160:
            break
    return rows


def merge_ai_items(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], *, key_fields: List[str], limit: int) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for source in (incoming, existing):
        for item in source:
            if not isinstance(item, dict):
                continue
            key_parts = [str(item.get(field, "")).strip().lower() for field in key_fields]
            key = "|".join(key_parts)
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
            if len(merged) >= int(limit):
                return merged
    return merged
