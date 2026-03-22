import csv
import io
import json
import os
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urljoin, urlparse

from app.hostsfile import normalize_hostname_alias
from app.url_normalization import normalize_discovered_url


_URL_RE = re.compile(r"https?://[^\s<>()\"']+", flags=re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", flags=re.IGNORECASE)
_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info", "informational"}
_NUCLEI_PROTOCOL_TOKENS = {"http", "https", "dns", "tcp", "ssl", "tls", "network", "headless", "file"}
_NUCLEI_STATS_RE = re.compile(r"^\[[0-9:]+\]\s*\|\s*templates:\s*\d+\s*\|\s*hosts:\s*\d+\s*\|", flags=re.IGNORECASE)
_NUCLEI_LOG_LEVELS = {"wrn", "inf", "err", "dbg", "ftl"}
_NUCLEI_QUALITY_ACTIONS = {"suppressed", "downgraded"}
_NUCLEI_RATE_LIMIT_STATUS_MARKERS = (
    "[429]",
    "status: 429",
    "status code 429",
    "http 429",
    "http/1.1 429",
    "http/2 429",
    "retry-after",
)
_NUCLEI_RATE_LIMIT_PHRASES = (
    "too many requests",
    "rate limit",
    "rate-limit",
    "ratelimit",
    "retry later",
    "quota exceeded",
    "request quota",
    "throttled",
    "throttle limit",
)
_NUCLEI_WAF_VENDOR_MARKERS = (
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "f5",
    "big-ip",
)
_NUCLEI_WAF_BLOCK_MARKERS = (
    "attention required",
    "sorry, you have been blocked",
    "request blocked",
    "blocked by security",
    "security challenge",
    "security check",
    "web application firewall",
    "captcha",
)
_NUCLEI_REFLECTION_MARKERS = (
    "payload reflected",
    "payload is reflected",
    "input is reflected",
    "reflected in response",
    "reflection-only",
    "echoed back",
    "echo endpoint",
    "debug echo",
)
_WHATWEB_PAIR_RE = re.compile(r"([A-Za-z][A-Za-z0-9+_. -]{1,48})\[([^\]]{1,180})\]")
_WHATWEB_IGNORED_NAMES = {
    "cache-control",
    "content-language",
    "content-security-policy",
    "content-type",
    "country",
    "cookies",
    "email",
    "etag",
    "httponly",
    "html5",
    "httpcountry",
    "ip",
    "meta-generator",
    "referrer-policy",
    "redirectlocation",
    "script",
    "strict-transport-security",
    "title",
    "uncommonheaders",
    "vary",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
}
_LEGACY_TLS_FINDINGS = {
    "sslv2": ("SSLv2 supported", "high"),
    "sslv3": ("SSLv3 supported", "high"),
    "tlsv1.0": ("TLSv1.0 supported", "medium"),
    "tlsv1.1": ("TLSv1.1 supported", "medium"),
}
_PRODUCT_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9+_.-]{1,64})(?:/([0-9][A-Za-z0-9._-]{0,31}))?")
_NMAP_BLOCK_HEADER_RE = re.compile(r"^\s*\|_?\s?([a-z0-9_.-]+(?:\.nse)?)\s*:\s*(.*)$", flags=re.IGNORECASE)
_NIKTO_OSVDB_RE = re.compile(
    r"^\+\s*(OSVDB-\d+)\s*:\s*((?:https?://[^\s:]+|/[^:\s]+))\s*:\s*(.+)$",
    flags=re.IGNORECASE,
)
_NIKTO_PATH_RE = re.compile(r"^\+\s*((?:https?://[^\s:]+|/[^:\s]+))\s*:\s*(.+)$", flags=re.IGNORECASE)
_NIKTO_VERB_PATH_RE = re.compile(
    r"^\+\s*(?:-\d+\s*:\s*)?(?:(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT|PATCH)\s+)?"
    r"((?:https?://[^\s:]+|/[^:\s]*|\.))\s*:\s*(.+)$",
    flags=re.IGNORECASE,
)
_NIKTO_SERVER_RE = re.compile(r"^\+\s*Server\s*:\s*(.+)$", flags=re.IGNORECASE)
_NIKTO_POWERED_BY_RE = re.compile(
    r"(?:x-powered-by|powered by)(?:\s+header)?\s*:\s*([A-Za-z][A-Za-z0-9+_.-]{1,64}(?:/[0-9][A-Za-z0-9._-]{0,31})?)",
    flags=re.IGNORECASE,
)
_WPSCAN_URL_RE = re.compile(r"^\[\+\]\s*URL:\s*(https?://\S+)", flags=re.IGNORECASE)
_WPSCAN_VERSION_RE = re.compile(
    r"\bWordPress(?:\s+version)?\s+([0-9][A-Za-z0-9._-]{0,31})\s+identified\b",
    flags=re.IGNORECASE,
)
_WPSCAN_LOCATION_RE = re.compile(r"^\|\s*Location:\s*(https?://\S+)", flags=re.IGNORECASE)
_WAF_VENDOR_RE = re.compile(
    r"\bbehind\s+(?:a\s+)?([A-Za-z0-9][A-Za-z0-9 ._()/+-]{1,80}?)(?:\s+\(|\s+waf\b|[.!]|\s*$)",
    flags=re.IGNORECASE,
)
_FEROX_LINE_RE = re.compile(
    r"^(?P<status>\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(?P<url>https?://\S+?)(?:\s+=>\s+(?P<redirect>https?://\S+))?$",
    flags=re.IGNORECASE,
)
_GOBUSTER_LINE_RE = re.compile(
    r"^(?P<path>/\S+?)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*\d+\])?(?:\s+\[-->\s*(?P<redirect>https?://\S+)\])?$",
    flags=re.IGNORECASE,
)
_TLS_WEAK_CIPHER_RE = re.compile(r"(?:RC4|3DES|DES-CBC|NULL|EXPORT|aNULL|anon)", flags=re.IGNORECASE)
_TLS_SHA1_RE = re.compile(r"\bsha-?1\b", flags=re.IGNORECASE)
_TLS_MD5_RE = re.compile(r"\bmd5\b", flags=re.IGNORECASE)
_TLS_RSA_KEY_RE = re.compile(r"rsa key strength:\s*(\d+)", flags=re.IGNORECASE)
_TLS_SUBJECT_RE = re.compile(r"^subject:\s*(.+)$", flags=re.IGNORECASE)
_TLS_ISSUER_RE = re.compile(r"^issuer:\s*(.+)$", flags=re.IGNORECASE)
_IGNORED_PRODUCT_NAMES = {"http", "https", "tls", "ssl", "html", "json"}
_IGNORED_DISCOVERY_URL_HOSTS = {"nmap.org", "www.nmap.org", "http", "https"}
_SUPPORTED_ARTIFACT_PARSE_PREFIXES = (
    "whatweb",
    "httpx",
    "nikto",
    "nuclei",
    "nmap-vuln",
    "http-vuln-",
    "sslscan",
    "sslyze",
    "wafw00f",
    "web-content-discovery",
    "dirsearch",
    "ffuf",
    "wpscan",
    "enum4linux-ng",
    "smbmap",
    "rpcclient-enum",
)
_DISCOVERY_PATH_RE = re.compile(r"(?i)(?:\"path\"|path|location|redirectlocation)\s*[:=]\s*['\"]?(/[^\"'\s,|]+)")
_SMB_USER_RE = re.compile(r"(?i)(?:user(?:name)?|account)\s*[:=\[]\s*['\"]?([A-Za-z0-9_. $-]{1,96})")
_SMB_RPC_USER_RE = re.compile(r"(?i)\buser:\[([^\]]{1,96})\]")
_SMB_SHARE_RE = re.compile(r"(?i)(?:share(?:name)?|netname)\s*[:=\[]\s*['\"]?([A-Za-z0-9_. $-]{1,128})")
_SMB_DOMAIN_RE = re.compile(r"(?i)(?:domain(?:\s+name)?|workgroup)\s*[:=]\s*['\"]?([A-Za-z0-9_.-]{1,96})")
_HTTP_HEADER_RE = re.compile(r"^([A-Za-z0-9-]+):\s*(.+)$")
_HTML_TITLE_RE = re.compile(r"<title>([^<]{1,200})</title>", flags=re.IGNORECASE)


def _clean_text(value: Any, limit: int = 320) -> str:
    text = _ANSI_ESCAPE_RE.sub("", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:int(limit)] if limit > 0 else text


def _clean_url(value: Any) -> str:
    text = normalize_discovered_url(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        hostname = str(parsed.hostname or "").strip().lower()
        if hostname in _IGNORED_DISCOVERY_URL_HOSTS:
            return ""
    except Exception:
        return ""
    return text[:320]


def _artifact_reader_supported(tool_id: str) -> bool:
    token = str(tool_id or "").strip().lower()
    return any(token.startswith(prefix) for prefix in _SUPPORTED_ARTIFACT_PARSE_PREFIXES)


def _select_artifact_refs_for_tool(tool_id: str, artifact_refs: Iterable[Any]) -> List[str]:
    refs = [str(ref or "").strip() for ref in list(artifact_refs or []) if str(ref or "").strip()]
    if not refs:
        return []
    token = str(tool_id or "").strip().lower()

    def _with_exts(*exts: str) -> List[str]:
        allowed = {str(ext or "").strip().lower() for ext in exts if str(ext or "").strip()}
        return [ref for ref in refs if os.path.splitext(ref)[1].strip().lower() in allowed]

    if token == "nmap-vuln.nse" or token.startswith("http-vuln-"):
        preferred = _with_exts(".nmap")
        if preferred:
            return preferred
    if token == "wpscan":
        preferred = _with_exts(".json")
        if preferred:
            return preferred + [ref for ref in refs if ref not in preferred]
    if token.startswith("httpx"):
        preferred = _with_exts(".jsonl")
        if preferred:
            return preferred
    return refs


def _load_artifact_texts(artifact_refs: Iterable[Any], *, max_files: int = 6, max_chars: int = 160000) -> List[str]:
    texts: List[str] = []
    allowed_exts = {".txt", ".json", ".jsonl", ".log", ".csv", ".xml", ".html", ".md", ".nmap", ".gnmap"}
    for ref in list(artifact_refs or [])[:int(max_files)]:
        path = str(ref or "").strip()
        if not path or not os.path.exists(path):
            continue
        ext = os.path.splitext(path)[1].strip().lower()
        if ext and ext not in allowed_exts:
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read(int(max_chars))
        except Exception:
            continue
        if str(content or "").strip():
            texts.append(str(content))
    return texts


def _merge_results(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "technologies": list(left.get("technologies", []) or []) + list(right.get("technologies", []) or []),
        "findings": list(left.get("findings", []) or []) + list(right.get("findings", []) or []),
        "urls": list(left.get("urls", []) or []) + list(right.get("urls", []) or []),
        "finding_quality_events": list(left.get("finding_quality_events", []) or []) + list(right.get("finding_quality_events", []) or []),
    }


def _iter_json_payloads(text: str) -> List[Any]:
    payloads: List[Any] = []
    stripped = str(text or "").strip()
    if not stripped:
        return payloads
    if stripped[:1] in {"{", "["}:
        try:
            payloads.append(json.loads(stripped))
        except Exception:
            pass
    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line or line[:1] not in {"{", "["}:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        payloads.append(payload)
    return payloads


def _iter_discovery_records(payload: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(payload, dict):
        if any(key in payload for key in ("url", "path", "redirect", "redirectlocation", "status", "status_code")):
            yield payload
        for value in payload.values():
            yield from _iter_discovery_records(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_discovery_records(item)


def _build_base_web_url(*, host_ip: Any = "", hostname: Any = "", port: Any = "", service: Any = "") -> str:
    resolved_host = normalize_hostname_alias(hostname) or str(host_ip or "").strip()
    if not resolved_host:
        return ""
    service_token = str(service or "").strip().rstrip("?").lower()
    scheme = "https" if (service_token.startswith("https") or "ssl" in service_token or "tls" in service_token) else "http"
    if str(port or "").strip():
        return _clean_url(f"{scheme}://{resolved_host}:{str(port).strip()}")
    return _clean_url(f"{scheme}://{resolved_host}")


def _severity_token(value: Any, default: str = "info") -> str:
    token = str(value or "").strip().lower()
    if token == "informational":
        token = "info"
    if token in _SEVERITY_LEVELS:
        return "info" if token == "informational" else token
    return str(default or "info")


def _append_url(rows: List[Dict[str, Any]], url: str, *, port: str = "", protocol: str = "tcp", service: str = "", label: str = ""):
    normalized_url = _clean_url(url)
    if not normalized_url:
        return
    rows.append({
        "url": normalized_url,
        "port": str(port or "").strip(),
        "protocol": str(protocol or "tcp").strip().lower() or "tcp",
        "service": str(service or "").strip(),
        "label": _clean_text(label, 120),
        "confidence": 92.0,
        "source_kind": "observed",
        "observed": True,
    })


def _append_technology(rows: List[Dict[str, Any]], name: str, *, version: str = "", cpe: str = "", evidence: str = ""):
    tech_name = _clean_text(name, 120)
    tech_version = _clean_text(version, 80)
    tech_cpe = _clean_text(cpe, 220)
    tech_evidence = _clean_text(evidence, 520)
    if not tech_name and not tech_cpe:
        return
    rows.append({
        "name": tech_name,
        "version": tech_version,
        "cpe": tech_cpe,
        "evidence": tech_evidence,
        "source_kind": "observed",
        "observed": True,
    })


def _append_finding(
        rows: List[Dict[str, Any]],
        title: str,
        *,
        severity: str = "info",
        cve: str = "",
        evidence: str = "",
        evidence_items: Any = None,
        quality_action: str = "",
        quality_reason: str = "",
        severity_before: str = "",
):
    finding_title = _clean_text(title, 260)
    finding_cve = _clean_text(cve, 64).upper()
    finding_evidence = _clean_text(evidence, 640)
    if not finding_title and not finding_cve:
        return
    row = {
        "title": finding_title or finding_cve,
        "severity": _severity_token(severity, "info"),
        "cvss": 0.0,
        "cve": finding_cve,
        "evidence": finding_evidence or finding_title or finding_cve,
        "source_kind": "observed",
        "observed": True,
    }
    normalized_items: List[str] = []
    seen_items = set()
    for token in list(evidence_items or []):
        cleaned = _clean_text(token, 160)
        if not cleaned:
            continue
        lowered = cleaned.lower()
        if lowered in seen_items:
            continue
        seen_items.add(lowered)
        normalized_items.append(cleaned)
        if len(normalized_items) >= 16:
            break
    if normalized_items:
        row["evidence_items"] = normalized_items
    quality_action_token = str(quality_action or "").strip().lower()
    quality_reason_token = str(quality_reason or "").strip().lower()[:96]
    if quality_action_token in _NUCLEI_QUALITY_ACTIONS and quality_reason_token:
        row["quality_action"] = quality_action_token
        row["quality_reason"] = quality_reason_token
        if quality_action_token == "downgraded":
            row["severity_before"] = _severity_token(severity_before or "info", "info")
    rows.append(row)


def _dedupe_rows(rows: List[Dict[str, Any]], key_fields: Tuple[str, ...], limit: int) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = tuple(str(row.get(field, "") or "").strip().lower() for field in key_fields)
        if not any(key):
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(row))
        if len(deduped) >= int(limit):
            break
    return deduped


def _append_finding_quality_event(
        rows: List[Dict[str, Any]],
        title: str,
        *,
        action: str,
        reason: str,
        severity_before: str = "",
        severity_after: str = "",
        cve: str = "",
        evidence: str = "",
        matched_url: str = "",
):
    action_token = str(action or "").strip().lower()
    reason_token = str(reason or "").strip().lower()[:96]
    if action_token not in _NUCLEI_QUALITY_ACTIONS or not reason_token:
        return
    finding_title = _clean_text(title, 260)
    finding_cve = _clean_text(cve, 64).upper()
    finding_evidence = _clean_text(evidence, 640)
    matched_url_value = _clean_url(matched_url)
    if not any([finding_title, finding_cve, finding_evidence, matched_url_value]):
        return
    row = {
        "title": finding_title or finding_cve,
        "cve": finding_cve,
        "action": action_token,
        "reason": reason_token,
        "severity_before": _severity_token(severity_before or "info", "info"),
        "evidence": finding_evidence or finding_title or finding_cve,
        "source_kind": "observed",
        "observed": True,
    }
    severity_after_token = str(severity_after or "").strip().lower()
    if severity_after_token:
        row["severity_after"] = _severity_token(severity_after_token, "info")
    if matched_url_value:
        row["matched_url"] = matched_url_value
    rows.append(row)


def _append_product_technology(rows: List[Dict[str, Any]], value: Any, *, evidence: str = ""):
    text = _clean_text(value, 160)
    if not text:
        return
    match = _PRODUCT_TOKEN_RE.search(text)
    if not match:
        return
    name = _clean_text(match.group(1), 96)
    if not name or name.lower() in _IGNORED_PRODUCT_NAMES:
        return
    version = _clean_text(match.group(2) or "", 80)
    _append_technology(rows, name, version=version, evidence=evidence or text)


def _strip_nmap_preamble(output_text: Any) -> str:
    text_value = str(output_text or "")
    if not text_value.strip():
        return ""
    filtered = []
    for raw_line in text_value.splitlines():
        line = str(raw_line or "")
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            if filtered:
                filtered.append("")
            continue
        if re.match(r"(?i)^#\s*Nmap\b", stripped):
            continue
        if re.match(r"(?i)^Scanned at\b", stripped):
            continue
        if re.match(r"(?i)^Starting Nmap\b", stripped):
            continue
        if re.match(r"(?i)^Nmap scan report for\b", stripped):
            continue
        if re.match(r"(?i)^Host is up\b", stripped):
            continue
        if re.match(r"(?i)^Not shown:\b", stripped):
            continue
        if re.match(r"(?i)^All \d+ scanned ports\b", stripped):
            continue
        if re.match(r"(?i)^NSE:\s+(Loaded|Script Pre-scanning|Starting runlevel|Ending runlevel)\b", stripped):
            continue
        if re.match(r"(?i)^Service detection performed\b", stripped):
            continue
        if "nmap.org" in lowered and (
                lowered.startswith("starting nmap")
                or lowered.startswith("service detection performed")
                or lowered.startswith("read data files from")
                or lowered.startswith("please report")
        ):
            continue
        if re.match(r"(?i)^PORT\s+STATE\s+SERVICE\b", stripped):
            continue
        if re.match(r"(?i)^Nmap done:", stripped):
            continue
        filtered.append(line)
    cleaned = "\n".join(filtered).strip()
    return cleaned or text_value.strip()


def _infer_finding_severity(value: Any, default: str = "info") -> str:
    lowered = _clean_text(value, 320).lower()
    if not lowered:
        return _severity_token(default, "info")
    if _CVE_RE.search(lowered):
        return "medium"
    if any(token in lowered for token in ("critical", "rce", "remote code", "auth bypass", "sql injection", "xss", "vulnerable", "exposure")):
        return "medium"
    if any(token in lowered for token in ("missing", "self-signed", "expired", "directory listing", "xml-rpc", "weak cipher", "compression")):
        return "low"
    return _severity_token(default, "info")


def _nuclei_quality_text(*values: Any) -> str:
    parts = []
    for value in list(values or []):
        cleaned = _clean_text(value, 320)
        if cleaned:
            parts.append(cleaned)
    return " | ".join(parts)[:2400]


def _evaluate_nuclei_finding_quality(
        *,
        title: str,
        severity: str,
        evidence: str,
        matched_url: str = "",
        evidence_items: Any = None,
) -> Dict[str, str]:
    evidence_tokens = [
        _clean_text(token, 160)
        for token in list(evidence_items or [])
        if _clean_text(token, 160)
    ][:16]
    corpus = _nuclei_quality_text(title, evidence, matched_url, *evidence_tokens).lower()
    title_token = _clean_text(title, 240).lower()
    if not corpus:
        return {}

    has_rate_limit_status = any(marker in corpus for marker in _NUCLEI_RATE_LIMIT_STATUS_MARKERS) or bool(
        re.search(r"(?:^|[^0-9])429(?:[^0-9]|$)", corpus)
    )
    has_rate_limit_phrase = any(marker in corpus for marker in _NUCLEI_RATE_LIMIT_PHRASES)
    if has_rate_limit_phrase or (has_rate_limit_status and any(
            marker in corpus for marker in ("retry", "too many requests", "rate", "throttl", "quota")
    )):
        return {
            "action": "suppressed",
            "reason": "rate_limited_response",
            "severity_before": _severity_token(severity, "info"),
        }

    has_waf_vendor = any(marker in corpus for marker in _NUCLEI_WAF_VENDOR_MARKERS)
    has_waf_block = any(marker in corpus for marker in _NUCLEI_WAF_BLOCK_MARKERS)
    title_mentions_waf = "waf" in title_token or any(marker in title_token for marker in _NUCLEI_WAF_VENDOR_MARKERS)
    if has_waf_block and (has_waf_vendor or "waf" in corpus or "captcha" in corpus or "blocked" in corpus):
        if not title_mentions_waf:
            return {
                "action": "suppressed",
                "reason": "waf_block_page",
                "severity_before": _severity_token(severity, "info"),
            }

    if any(marker in corpus for marker in _NUCLEI_REFLECTION_MARKERS):
        current_severity = _severity_token(severity, "info")
        if current_severity != "info":
            return {
                "action": "downgraded",
                "reason": "reflection_only_response",
                "severity_before": current_severity,
                "severity_after": "info",
            }

    return {}


def _is_interesting_web_path(path: str) -> bool:
    lowered = str(path or "").strip().lower()
    return bool(
        lowered
        and any(token in lowered for token in ("admin", "login", "portal", "api", "graphql", "swagger", "actuator", "wp-", "xmlrpc"))
    )


def _parse_whatweb_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    for raw_line in str(output_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        url_match = _URL_RE.search(line)
        if url_match:
            _append_url(urls, url_match.group(0), label=f"{tool_id} fingerprint")
        for name, value in _WHATWEB_PAIR_RE.findall(line):
            name_token = _clean_text(name, 64)
            value_token = _clean_text(value, 180)
            if not name_token or not value_token:
                continue
            if name_token.lower() in _WHATWEB_IGNORED_NAMES:
                continue
            lowered_name = name_token.lower()
            if lowered_name.endswith((".jsp", ".php", ".asp", ".aspx", ".cgi", ".html", ".htm")):
                continue
            if re.fullmatch(r"\d{3}\s+[A-Za-z][A-Za-z ]{1,40}", value_token):
                continue
            if name_token.lower() == "httpserver":
                server_match = re.search(r"([A-Za-z][A-Za-z0-9+_.-]+)(?:/([0-9][A-Za-z0-9._-]*))?", value_token)
                if server_match:
                    _append_technology(
                        technologies,
                        server_match.group(1),
                        version=server_match.group(2) or "",
                        evidence=f"{tool_id} httpserver {value_token}",
                    )
                continue
            version = ""
            if (
                    re.fullmatch(r"[0-9][A-Za-z0-9._-]{0,31}", value_token)
                    and ("." in value_token or bool(re.search(r"[A-Za-z]", value_token)))
            ):
                version = value_token
            _append_technology(
                technologies,
                name_token,
                version=version,
                evidence=f"{tool_id} {name_token}[{value_token}]",
            )
    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=48),
        "findings": [],
        "urls": _dedupe_rows(urls, ("url",), limit=48),
    }


def _parse_httpx_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    for raw_line in str(output_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parsed = None
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except Exception:
                parsed = None
        if isinstance(parsed, dict):
            url = parsed.get("url") or parsed.get("input") or parsed.get("host") or ""
            _append_url(
                urls,
                url,
                port=str(parsed.get("port", "") or ""),
                service="https" if str(url).startswith("https://") else "http",
                label=str(parsed.get("title", "") or "httpx"),
            )
            tech_list = parsed.get("tech") if isinstance(parsed.get("tech"), list) else parsed.get("technologies", [])
            if isinstance(tech_list, list):
                for item in tech_list[:24]:
                    _append_technology(technologies, str(item or ""), evidence=f"{tool_id} fingerprint tech detect")
            webserver = _clean_text(parsed.get("webserver", "") or parsed.get("server", ""), 120)
            if webserver:
                server_match = re.search(r"([A-Za-z][A-Za-z0-9+_.-]+)(?:/([0-9][A-Za-z0-9._-]*))?", webserver)
                if server_match:
                    _append_technology(
                        technologies,
                        server_match.group(1),
                        version=server_match.group(2) or "",
                        evidence=f"{tool_id} fingerprint webserver {webserver}",
                    )
            continue
        for url in _URL_RE.findall(line):
            _append_url(urls, url, label=f"{tool_id} response")
    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=48),
        "findings": [],
        "urls": _dedupe_rows(urls, ("url",), limit=48),
    }


def _parse_nikto_output(
        tool_id: str,
        output_text: str,
        *,
        base_url: str = "",
        port: str = "",
        protocol: str = "tcp",
        service: str = "",
) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    root_base = f"{base_url.rstrip('/')}/" if base_url else ""

    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("- nikto", "+ target ", "+ start time", "+ end time", "+ 1 host(s) tested", "+ host(s) tested")):
            continue

        for url in _URL_RE.findall(line):
            _append_url(urls, url, port=port, protocol=protocol, service=service, label=f"{tool_id} finding")

        server_match = _NIKTO_SERVER_RE.match(line)
        if server_match:
            _append_product_technology(technologies, server_match.group(1), evidence=f"{tool_id}: {line}")
            continue

        powered_by_match = _NIKTO_POWERED_BY_RE.search(line)
        if powered_by_match:
            _append_product_technology(technologies, powered_by_match.group(1), evidence=f"{tool_id}: {line}")

        osvdb_match = _NIKTO_OSVDB_RE.match(line)
        if osvdb_match:
            path_or_url = osvdb_match.group(2)
            if path_or_url.startswith("/") and base_url:
                _append_url(urls, urljoin(f"{base_url.rstrip('/')}/", path_or_url.lstrip("/")), port=port, protocol=protocol, service=service, label=f"{tool_id} finding")
            else:
                _append_url(urls, path_or_url, port=port, protocol=protocol, service=service, label=f"{tool_id} finding")
            _append_finding(
                findings,
                osvdb_match.group(3),
                severity=_infer_finding_severity(osvdb_match.group(3)),
                evidence=line,
            )
            continue

        path_match = _NIKTO_PATH_RE.match(line)
        if not path_match:
            path_match = _NIKTO_VERB_PATH_RE.match(line)
        if path_match:
            path_or_url = path_match.group(1)
            detail = path_match.group(2)
            normalized_path = "/" if path_or_url == "." else path_or_url
            if normalized_path.startswith("/") and base_url:
                _append_url(urls, urljoin(root_base, normalized_path.lstrip("/")), port=port, protocol=protocol, service=service, label=f"{tool_id} finding")
            else:
                _append_url(urls, normalized_path, port=port, protocol=protocol, service=service, label=f"{tool_id} finding")
            if detail and not detail.lower().startswith(("retrieved x-powered-by header", "server leaks inodes via etags")):
                if detail.lower().startswith("uncommon header '"):
                    continue
                title = detail
                if "allowed http methods" in detail.lower():
                    title = "HTTP methods exposed"
                _append_finding(
                    findings,
                    title,
                    severity=_infer_finding_severity(detail),
                    cve=_CVE_RE.search(detail).group(0).upper() if _CVE_RE.search(detail) else "",
                    evidence=line,
                )
            continue

        if "allowed http methods" in lowered:
            _append_finding(findings, "HTTP methods exposed", severity="low", evidence=line)
        elif any(token in lowered for token in ("phpinfo()", "xmlrpc", "directory indexing", "directory listing")):
            _append_finding(findings, _clean_text(line.lstrip("+ "), 240), severity=_infer_finding_severity(line), evidence=line)

    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=24),
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=48),
        "urls": _dedupe_rows(urls, ("url",), limit=64),
    }


def _parse_nuclei_output(tool_id: str, output_text: str, *, port: str = "", protocol: str = "tcp", service: str = "") -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    quality_events: List[Dict[str, Any]] = []
    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        if _NUCLEI_STATS_RE.match(line):
            continue
        parsed = None
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except Exception:
                parsed = None
        if isinstance(parsed, dict):
            info = parsed.get("info", {}) if isinstance(parsed.get("info"), dict) else {}
            classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
            cve_list = classification.get("cve-id", []) if isinstance(classification.get("cve-id"), list) else []
            cve_id = str(cve_list[0] or "").strip().upper() if cve_list else ""
            severity = _severity_token(info.get("severity", "") or parsed.get("severity", ""), "info")
            title = str(info.get("name", "") or parsed.get("template-id", "") or parsed.get("matcher-name", "") or cve_id).strip()
            matched_at = parsed.get("matched-at") or parsed.get("host") or parsed.get("matched") or ""
            extracted_results = parsed.get("extracted-results", [])
            evidence_items = extracted_results if isinstance(extracted_results, list) else [extracted_results]
            _append_url(urls, matched_at, port=port, protocol=protocol, service=service, label=title or cve_id)
            quality = _evaluate_nuclei_finding_quality(
                title=title or cve_id or "Nuclei match",
                severity=severity,
                evidence=line,
                matched_url=matched_at,
                evidence_items=evidence_items,
            )
            if str(quality.get("action", "") or "") == "suppressed":
                _append_finding_quality_event(
                    quality_events,
                    title or cve_id or "Nuclei match",
                    action=quality.get("action", ""),
                    reason=quality.get("reason", ""),
                    severity_before=quality.get("severity_before", severity),
                    severity_after=quality.get("severity_after", ""),
                    cve=cve_id,
                    evidence=line,
                    matched_url=matched_at,
                )
                continue
            adjusted_severity = str(quality.get("severity_after", "") or severity)
            _append_finding(
                findings,
                title or cve_id or "Nuclei match",
                severity=adjusted_severity,
                cve=cve_id,
                evidence=line,
                evidence_items=evidence_items,
                quality_action=quality.get("action", ""),
                quality_reason=quality.get("reason", ""),
                severity_before=quality.get("severity_before", severity),
            )
            if str(quality.get("action", "") or "") == "downgraded":
                _append_finding_quality_event(
                    quality_events,
                    title or cve_id or "Nuclei match",
                    action=quality.get("action", ""),
                    reason=quality.get("reason", ""),
                    severity_before=quality.get("severity_before", severity),
                    severity_after=quality.get("severity_after", ""),
                    cve=cve_id,
                    evidence=line,
                    matched_url=matched_at,
                )
            continue
        brackets = [token.strip() for token in re.findall(r"\[([^\]]+)\]", line) if str(token or "").strip()]
        severity = "info"
        for token in brackets:
            token_lower = str(token).strip().lower()
            if token_lower in _SEVERITY_LEVELS:
                severity = _severity_token(token_lower, "info")
                break
        cve_match = _CVE_RE.search(line)
        cve_id = cve_match.group(0).upper() if cve_match else ""
        title = ""
        for token in brackets:
            token_lower = str(token).strip().lower()
            if token_lower in _SEVERITY_LEVELS or token_lower in _NUCLEI_PROTOCOL_TOKENS:
                continue
            if token_lower.startswith("http://") or token_lower.startswith("https://"):
                continue
            title = str(token).strip()
            break
        matched_url = _clean_url(_URL_RE.search(line).group(0)) if _URL_RE.search(line) else ""
        if not matched_url and not cve_id:
            lowered_tokens = {str(token or "").strip().lower() for token in brackets}
            if lowered_tokens and (
                    lowered_tokens <= _NUCLEI_LOG_LEVELS
                    or all(re.fullmatch(r"[0-9:]+", token or "") for token in lowered_tokens)
                    or lowered_tokens <= (_NUCLEI_LOG_LEVELS | {"info"})
            ):
                continue
        if not matched_url and not cve_id and title and re.fullmatch(r"[0-9:]+", title):
            continue
        _append_url(urls, matched_url, port=port, protocol=protocol, service=service, label=title or cve_id or "nuclei")
        if cve_id or title or matched_url:
            quality = _evaluate_nuclei_finding_quality(
                title=cve_id or title or "Nuclei match",
                severity=severity,
                evidence=line,
                matched_url=matched_url,
            )
            if str(quality.get("action", "") or "") == "suppressed":
                _append_finding_quality_event(
                    quality_events,
                    cve_id or title or "Nuclei match",
                    action=quality.get("action", ""),
                    reason=quality.get("reason", ""),
                    severity_before=quality.get("severity_before", severity),
                    severity_after=quality.get("severity_after", ""),
                    cve=cve_id,
                    evidence=line,
                    matched_url=matched_url,
                )
                continue
            _append_finding(
                findings,
                cve_id or title or "Nuclei match",
                severity=str(quality.get("severity_after", "") or severity),
                cve=cve_id,
                evidence=line,
                quality_action=quality.get("action", ""),
                quality_reason=quality.get("reason", ""),
                severity_before=quality.get("severity_before", severity),
            )
            if str(quality.get("action", "") or "") == "downgraded":
                _append_finding_quality_event(
                    quality_events,
                    cve_id or title or "Nuclei match",
                    action=quality.get("action", ""),
                    reason=quality.get("reason", ""),
                    severity_before=quality.get("severity_before", severity),
                    severity_after=quality.get("severity_after", ""),
                    cve=cve_id,
                    evidence=line,
                    matched_url=matched_url,
                )
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=64),
        "urls": _dedupe_rows(urls, ("url",), limit=64),
        "finding_quality_events": _dedupe_rows(quality_events, ("title", "cve", "action", "reason", "evidence"), limit=96),
    }


def _parse_tls_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    subject_name = ""
    issuer_name = ""
    explicit_self_signed = False
    seen_legacy_protocol_titles: Set[str] = set()
    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        lowered = line.lower()
        subject_match = _TLS_SUBJECT_RE.match(line)
        if subject_match:
            subject_name = _clean_text(subject_match.group(1), 180)
        issuer_match = _TLS_ISSUER_RE.match(line)
        if issuer_match:
            issuer_name = _clean_text(issuer_match.group(1), 180)
        for protocol_token, (title, severity) in _LEGACY_TLS_FINDINGS.items():
            if protocol_token in lowered and any(marker in lowered for marker in ("enabled", "accepted", "offered", "supported")):
                if "disabled" in lowered or "not supported" in lowered or "rejected" in lowered:
                    continue
                if title in seen_legacy_protocol_titles:
                    continue
                seen_legacy_protocol_titles.add(title)
                _append_finding(findings, title, severity=severity, evidence=f"{tool_id}: {line}")
        if "self-signed" in lowered or "self signed" in lowered:
            explicit_self_signed = True
            _append_finding(findings, "Self-signed TLS certificate", severity="low", evidence=f"{tool_id}: {line}")
        if "certificate expired" in lowered or "expired certificate" in lowered:
            _append_finding(findings, "Expired TLS certificate", severity="medium", evidence=f"{tool_id}: {line}")
        if "heartbleed" in lowered and "not vulnerable" not in lowered and any(token in lowered for token in ("vulnerable", "exploitable", "affected")):
            cve_id = "CVE-2014-0160" if "cve-2014-0160" in lowered or "heartbleed" in lowered else ""
            _append_finding(findings, "Heartbleed exposure", severity="high", cve=cve_id, evidence=f"{tool_id}: {line}")
        if _TLS_WEAK_CIPHER_RE.search(line) and any(marker in lowered for marker in ("accepted", "offered", "supported", "preferred")):
            _append_finding(findings, "Weak TLS cipher supported", severity="medium", evidence=f"{tool_id}: {line}")
        if "compression" in lowered and any(marker in lowered for marker in ("enabled", "supported", "available")) and "disabled" not in lowered:
            _append_finding(findings, "TLS compression enabled", severity="medium", evidence=f"{tool_id}: {line}")
        if "tls fallback scsv" in lowered and any(marker in lowered for marker in ("does not support", "not support", "unsupported")):
            _append_finding(findings, "TLS downgrade protection missing", severity="low", evidence=f"{tool_id}: {line}")
        if "renegotiation" in lowered and (
                "insecure" in lowered
                or "vulnerable" in lowered
                or ("secure" in lowered and "not supported" in lowered)
        ):
            _append_finding(findings, "Insecure TLS renegotiation", severity="medium", evidence=f"{tool_id}: {line}")
        key_match = _TLS_RSA_KEY_RE.search(line)
        if key_match:
            try:
                key_bits = int(key_match.group(1) or 0)
            except (TypeError, ValueError):
                key_bits = 0
            if 0 < key_bits < 2048:
                _append_finding(
                    findings,
                    "Weak TLS certificate key size",
                    severity="medium",
                    evidence=f"{tool_id}: {line}",
                )
        if ("hostname mismatch" in lowered or "does not match" in lowered) and "certificate" in lowered:
            _append_finding(findings, "TLS certificate hostname mismatch", severity="medium", evidence=f"{tool_id}: {line}")
        if _TLS_SHA1_RE.search(line) and any(marker in lowered for marker in ("signature", "signed", "algorithm")):
            _append_finding(findings, "TLS certificate uses SHA-1", severity="low", evidence=f"{tool_id}: {line}")
        if _TLS_MD5_RE.search(line) and any(marker in lowered for marker in ("signature", "signed", "algorithm")):
            _append_finding(findings, "TLS certificate uses MD5", severity="medium", evidence=f"{tool_id}: {line}")
        if any(token in lowered for token in ("untrusted", "not trusted", "failed chain validation", "unable to build verified chain")):
            _append_finding(findings, "Untrusted TLS certificate chain", severity="medium", evidence=f"{tool_id}: {line}")
    if subject_name and issuer_name:
        normalized_subject = re.sub(r"\s+", " ", subject_name).strip().lower()
        normalized_issuer = re.sub(r"\s+", " ", issuer_name).strip().lower()
        if normalized_subject and normalized_subject == normalized_issuer and not explicit_self_signed:
            _append_finding(
                findings,
                "Self-signed TLS certificate",
                severity="low",
                evidence=f"{tool_id}: subject={subject_name}; issuer={issuer_name}",
            )
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=32),
        "urls": [],
    }


def _parse_curl_output(
        tool_id: str,
        output_text: str,
        *,
        port: str = "",
        protocol: str = "tcp",
        service: str = "",
) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    header_lines = 0

    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        header_match = _HTTP_HEADER_RE.match(line)
        if header_match:
            header_lines += 1
            key = str(header_match.group(1) or "").strip().lower()
            value = _clean_text(header_match.group(2), 240)
            if key == "server":
                _append_product_technology(technologies, value, evidence=f"{tool_id} header server {value}")
            elif key == "x-powered-by":
                _append_product_technology(technologies, value, evidence=f"{tool_id} header x-powered-by {value}")
            elif key == "location":
                _append_url(urls, value, port=port, protocol=protocol, service=service, label=f"{tool_id} redirect")
            elif key == "allow" and value:
                _append_finding(findings, "HTTP methods exposed", severity="low", evidence=line)
            elif key == "sitemap":
                _append_url(urls, value, port=port, protocol=protocol, service=service, label=f"{tool_id} sitemap")
            continue

        if tool_id == "curl-robots":
            sitemap_match = re.match(r"(?i)^sitemap:\s*(https?://\S+)$", line)
            if sitemap_match:
                _append_url(urls, sitemap_match.group(1), port=port, protocol=protocol, service=service, label=f"{tool_id} sitemap")
                continue
            if re.match(r"(?i)^user-agent:\s*", line) or re.match(r"(?i)^disallow:\s*", line):
                _append_finding(findings, "robots.txt directives exposed", severity="info", evidence=line)
                continue

    if not header_lines:
        title_match = _HTML_TITLE_RE.search(str(output_text or ""))
        if title_match:
            title = _clean_text(title_match.group(1), 180)
            if "plain http request was sent to https port" in title.lower():
                _append_finding(findings, title, severity="info", evidence=title)

    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=24),
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=16),
        "urls": _dedupe_rows(urls, ("url",), limit=32),
    }


def _parse_waf_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []

    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        lowered = line.lower()
        for url in _URL_RE.findall(line):
            _append_url(urls, url, label=f"{tool_id} target")
        if "no waf" in lowered or "not behind a waf" in lowered:
            continue
        vendor_match = _WAF_VENDOR_RE.search(line)
        if vendor_match:
            vendor = _clean_text(vendor_match.group(1), 96).strip(" .")
            if vendor and "some sort of security" not in vendor.lower():
                _append_technology(technologies, f"{vendor} WAF", evidence=f"{tool_id}: {line}")
                _append_finding(findings, f"WAF detected: {vendor}", severity="info", evidence=line)
                continue
        if "waf" in lowered and any(token in lowered for token in ("detected", "behind", "generic detection")):
            _append_finding(findings, "WAF detected", severity="info", evidence=line)

    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=12),
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=16),
        "urls": _dedupe_rows(urls, ("url",), limit=16),
    }


def _parse_vuln_script_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    suite_tool = str(tool_id or "").strip().lower()
    stripped_input = str(output_text or "").lstrip()
    if stripped_input.startswith("<?xml") or stripped_input.startswith("<nmaprun"):
        return {"technologies": [], "findings": [], "urls": []}
    cleaned = _strip_nmap_preamble(output_text)
    if not cleaned:
        return {"technologies": [], "findings": [], "urls": []}

    known_tech_markers = {
        "apache http server": "Apache HTTP Server",
        "nginx": "nginx",
        "jetty": "Jetty",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "tomcat": "Apache Tomcat",
        "jenkins": "Jenkins",
    }

    blocks: List[Tuple[str, List[str]]] = []
    current_id = str(tool_id or "").strip().lower()
    current_lines: List[str] = []
    saw_script_block = False
    for raw_line in cleaned.splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).rstrip()
        stripped = re.sub(r"^[|_ ]+", "", line).strip()
        if not stripped:
            continue
        header_match = _NMAP_BLOCK_HEADER_RE.match(line)
        if header_match:
            block_id = str(header_match.group(1) or "").strip().lower()
            if block_id and (suite_tool == "nmap-vuln.nse" or block_id.endswith(".nse") or "vuln" in block_id):
                saw_script_block = True
                if current_lines and current_id != str(tool_id or "").strip().lower():
                    blocks.append((current_id, list(current_lines)))
                current_id = block_id
                current_lines = []
                header_detail = _clean_text(header_match.group(2), 240)
                if header_detail:
                    current_lines.append(header_detail)
                continue
        current_lines.append(stripped)
    if current_lines:
        blocks.append((current_id, list(current_lines)))
    if not saw_script_block:
        return {"technologies": [], "findings": [], "urls": []}

    for block_id, lines in blocks:
        block_text = "\n".join(line for line in lines if str(line or "").strip())
        lowered = block_text.lower()
        if not block_text.strip():
            continue
        negative = any(
            token in lowered for token in (
                "no finding",
                "not vulnerable",
                "no vulnerabilities found",
                "not exploitable",
                "not found",
                "couldn't find",
                "might not be vulnerable",
                "script execution failed",
                "[error]",
            )
        )
        positive = (
            any(token in lowered for token in ("vulnerable", "likely vulnerable", "state: vulnerable", "state: likely vulnerable"))
            and not negative
        )
        if block_id == "http-csrf" and "possible csrf vulnerab" in lowered:
            positive = True
        cve_ids = [str(match or "").strip().upper() for match in _CVE_RE.findall(block_text)]
        risk_match = re.search(r"risk factor\s*:\s*(critical|high|medium|low|info)", block_text, flags=re.IGNORECASE)
        severity = _severity_token(risk_match.group(1) if risk_match else ("medium" if cve_ids else "info"))

        for marker, tech_name in known_tech_markers.items():
            if marker in lowered and not negative:
                _append_technology(technologies, tech_name, evidence=f"{block_id} output fingerprint")

        if negative and not positive:
            continue

        title = ""
        if block_id == "http-csrf" and "possible csrf vulnerab" in lowered:
            title = "Possible CSRF vulnerabilities detected"
        if not title:
            for line in lines:
                candidate = _clean_text(line, 240)
                lowered_candidate = candidate.lower()
                if not candidate:
                    continue
                if candidate.startswith(("# ", "<?xml", "<nmaprun")):
                    continue
                if re.match(r"^\d+/(tcp|udp)\s+open\b", lowered_candidate):
                    continue
                if lowered_candidate in {"vulnerable:", "vulnerable", "ids", "description", "references"}:
                    continue
                if lowered_candidate.startswith(("state:", "risk factor:", "description:", "references:", "ids:")):
                    continue
                title = candidate
                break

        evidence = ""
        for line in lines:
            candidate = _clean_text(line, 320)
            if candidate and _CVE_RE.search(candidate):
                evidence = candidate
                break
        if not evidence:
            for line in lines:
                candidate = _clean_text(line, 320)
                if not candidate:
                    continue
                if candidate.lower().startswith(("vulnerable", "state:", "risk factor:")):
                    evidence = candidate
                    break
        evidence = evidence or _clean_text(block_text, 520)

        if cve_ids or positive:
            for url in _URL_RE.findall(block_text):
                _append_url(urls, url, label=f"{block_id} reference")
        if cve_ids:
            for cve_id in cve_ids[:6]:
                _append_finding(
                    findings,
                    title or cve_id,
                    severity=severity,
                    cve=cve_id,
                    evidence=evidence,
                )
        elif positive:
            _append_finding(
                findings,
                title or _clean_text(block_id, 160),
                severity=severity,
                evidence=evidence,
            )

    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=24),
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=32),
        "urls": _dedupe_rows(urls, ("url",), limit=24),
    }


def _parse_content_discovery_output(
        tool_id: str,
        output_text: str,
        *,
        base_url: str = "",
        port: str = "",
        protocol: str = "tcp",
        service: str = "",
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    interesting_paths = []

    for payload in _iter_json_payloads(output_text):
        for item in _iter_discovery_records(payload):
            if not isinstance(item, dict):
                continue
            if "results" in item and not any(key in item for key in ("status", "status_code", "path", "location", "redirect", "redirectlocation")):
                continue
            url = item.get("url") or item.get("input") or item.get("host") or ""
            path = item.get("path") or item.get("location") or ""
            status = str(item.get("status") or item.get("status_code") or "").strip()
            normalized_url = str(url or "").strip()
            if normalized_url and "FUZZ" not in normalized_url.upper():
                _append_url(urls, normalized_url, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered content")
            joined_path_url = ""
            if path:
                join_base = normalized_url or base_url
                if join_base:
                    joined_path_url = urljoin(f"{str(join_base).rstrip('/')}/", str(path).lstrip("/"))
                    _append_url(urls, joined_path_url, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered path")
            elif not normalized_url and base_url:
                joined_path_url = urljoin(f"{base_url.rstrip('/')}/", str(path).lstrip("/"))
            redirect_target = item.get("redirect") or item.get("redirectlocation") or item.get("redirect_url") or ""
            if redirect_target:
                _append_url(urls, redirect_target, port=port, protocol=protocol, service=service, label=f"{tool_id} redirect")
            candidate_path = str(path or urlparse(str(joined_path_url or normalized_url or "")).path or "").strip()
            if (
                    candidate_path
                    and status in {"200", "204", "301", "302", "307", "308", "401", "403"}
                    and any(token in candidate_path.lower() for token in ("admin", "login", "portal", "api", "graphql", "swagger", "actuator"))
            ):
                interesting_paths.append(f"{candidate_path} ({status})")

    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        if line[:1] in {"{", "["}:
            continue
        ferox_match = _FEROX_LINE_RE.match(line)
        if ferox_match:
            status = str(ferox_match.group("status") or "").strip()
            target_url = _clean_url(ferox_match.group("url") or "")
            redirect_url = _clean_url(ferox_match.group("redirect") or "")
            if target_url:
                _append_url(urls, target_url, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered content")
                candidate_path = str(urlparse(target_url).path or "").strip()
                if candidate_path and status in {"200", "204", "301", "302", "307", "308", "401", "403"} and _is_interesting_web_path(candidate_path):
                    interesting_paths.append(f"{candidate_path} ({status})")
            if redirect_url:
                _append_url(urls, redirect_url, port=port, protocol=protocol, service=service, label=f"{tool_id} redirect")
            continue
        gobuster_match = _GOBUSTER_LINE_RE.match(line)
        if gobuster_match and base_url:
            path = str(gobuster_match.group("path") or "").strip()
            status = str(gobuster_match.group("status") or "").strip()
            redirect_url = _clean_url(gobuster_match.group("redirect") or "")
            if path:
                joined = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
                _append_url(urls, joined, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered path")
                if status in {"200", "204", "301", "302", "307", "308", "401", "403"} and _is_interesting_web_path(path):
                    interesting_paths.append(f"{path} ({status})")
            if redirect_url:
                _append_url(urls, redirect_url, port=port, protocol=protocol, service=service, label=f"{tool_id} redirect")
            continue
        for url in _URL_RE.findall(line):
            _append_url(urls, url, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered url")
        if base_url:
            for path in _DISCOVERY_PATH_RE.findall(line):
                joined = urljoin(f"{base_url.rstrip('/')}/", str(path).lstrip("/"))
                _append_url(urls, joined, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered path")

    if interesting_paths:
        _append_finding(
            findings,
            f"Interesting web paths discovered ({len(set(interesting_paths))})",
            severity="info",
            evidence=f"{tool_id}: {', '.join(sorted(set(interesting_paths))[:8])}",
            evidence_items=sorted(set(interesting_paths)),
        )
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "evidence"), limit=16),
        "urls": _dedupe_rows(urls, ("url",), limit=96),
    }


def _parse_wpscan_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
    section = ""

    for payload in _iter_json_payloads(output_text):
        if not isinstance(payload, dict):
            continue
        target_url = payload.get("target_url") or payload.get("url") or ""
        _append_url(urls, target_url, label=f"{tool_id} target")
        aborted_reason = _clean_text(payload.get("scan_aborted") or payload.get("message") or "", 260)
        if aborted_reason:
            title = aborted_reason
            lowered_reason = aborted_reason.lower()
            if "not seem to be running wordpress" in lowered_reason or "not a wordpress site" in lowered_reason:
                title = "WPScan: target does not appear to be WordPress"
            _append_finding(findings, title, severity="info", evidence=aborted_reason)

        version_info = payload.get("version")
        if isinstance(version_info, dict):
            number = version_info.get("number") or version_info.get("release_date") or ""
            _append_technology(technologies, "WordPress", version=str(number or "").strip(), evidence=f"{tool_id} wordpress version")

        interesting = payload.get("interesting_findings")
        if isinstance(interesting, list):
            for item in interesting[:24]:
                if not isinstance(item, dict):
                    continue
                title = item.get("to_s") or item.get("type") or item.get("url") or ""
                _append_finding(findings, title, severity="info", evidence=_clean_text(json.dumps(item), 420))
                _append_url(urls, item.get("url") or item.get("location") or "", label=f"{tool_id} finding")

        for plugin_name, plugin_data in list((payload.get("plugins") or {}).items())[:32]:
            if not isinstance(plugin_data, dict):
                continue
            _append_technology(technologies, _clean_text(plugin_name, 96), evidence=f"{tool_id} wordpress plugin")
            _append_url(urls, plugin_data.get("location") or "", label=f"{tool_id} plugin")
            vulnerabilities = plugin_data.get("vulnerabilities")
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities[:8]:
                    if not isinstance(vuln, dict):
                        continue
                    title = vuln.get("title") or plugin_name
                    fixed_in = _clean_text(vuln.get("fixed_in") or "", 48)
                    if fixed_in:
                        title = f"{title} (fixed in {fixed_in})"
                    _append_finding(findings, title, severity="medium", cve=_CVE_RE.search(str(vuln or "")).group(0).upper() if _CVE_RE.search(str(vuln or "")) else "", evidence=_clean_text(json.dumps(vuln), 420))

    for raw_line in str(output_text or "").splitlines():
        line = _ANSI_ESCAPE_RE.sub("", str(raw_line or "")).strip()
        if not line:
            continue
        lowered = line.lower()
        if line.startswith("[+] ") or line.startswith("| Location:"):
            for url in _URL_RE.findall(line):
                _append_url(urls, url, label=f"{tool_id} output")

        url_match = _WPSCAN_URL_RE.match(line)
        if url_match:
            _append_url(urls, url_match.group(1), label=f"{tool_id} target")
            continue

        version_match = _WPSCAN_VERSION_RE.search(line)
        if version_match:
            _append_technology(technologies, "WordPress", version=version_match.group(1), evidence=f"{tool_id}: {line}")

        location_match = _WPSCAN_LOCATION_RE.match(line)
        if location_match:
            _append_url(urls, location_match.group(1), label=f"{tool_id} location")

        if lowered.startswith("[i] plugin(s) identified"):
            section = "plugins"
            continue
        if lowered.startswith("[i] theme(s) identified"):
            section = "themes"
            continue

        if line.startswith("[+] "):
            content = _clean_text(line[4:], 220)
            if section == "plugins" and content and ":" not in content and not content.lower().startswith(("url", "started", "headers", "interesting finding")):
                _append_technology(technologies, content, evidence=f"{tool_id} wordpress plugin")
                continue
            if section == "themes" and content and ":" not in content and not content.lower().startswith(("url", "started")):
                _append_technology(technologies, content, evidence=f"{tool_id} wordpress theme")
                continue
            if any(token in lowered for token in ("xml-rpc seems to be enabled", "registration is enabled", "directory has listing enabled", "debug log found")):
                _append_finding(findings, content, severity="low", evidence=line)
                continue

        if "[!] title:" in lowered:
            title = _clean_text(line.split("Title:", 1)[1], 260) if "Title:" in line else _clean_text(line.split("title:", 1)[1], 260)
            _append_finding(
                findings,
                title,
                severity="medium",
                cve=_CVE_RE.search(title).group(0).upper() if _CVE_RE.search(title) else "",
                evidence=line,
            )

    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=48),
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=48),
        "urls": _dedupe_rows(urls, ("url",), limit=64),
    }


def _parse_smb_enum_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    technologies: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    lowered = str(output_text or "").lower()

    if "windows" in lowered:
        _append_technology(technologies, "Windows", evidence=f"{tool_id} smb enumeration")
    if "samba" in lowered:
        _append_technology(technologies, "Samba", evidence=f"{tool_id} smb enumeration")
    if "active directory" in lowered:
        _append_technology(technologies, "Active Directory", evidence=f"{tool_id} smb enumeration")

    domains = {
        _clean_text(match, 96)
        for match in _SMB_DOMAIN_RE.findall(str(output_text or ""))
        if _clean_text(match, 96) and _clean_text(match, 96).upper() not in {"WORKGROUP", "UNKNOWN"}
    }
    for domain in sorted(domains)[:4]:
        _append_technology(technologies, "Active Directory", evidence=f"{tool_id} domain {domain}")
        _append_finding(findings, f"SMB domain identified: {domain}", severity="info", evidence=f"{tool_id}: {domain}")

    share_names = {
        _clean_text(match, 96)
        for match in _SMB_SHARE_RE.findall(str(output_text or ""))
        if _clean_text(match, 96)
    }
    try:
        if "," in str(output_text or "") and "\n" in str(output_text or ""):
            reader = csv.DictReader(io.StringIO(str(output_text or "")))
            for row in list(reader or [])[:64]:
                if not isinstance(row, dict):
                    continue
                for key in ("share", "share name", "netname", "name"):
                    value = _clean_text(row.get(key, "") or row.get(key.title(), ""), 96)
                    if value:
                        share_names.add(value)
    except Exception:
        pass

    user_names = {
        _clean_text(match, 96)
        for match in list(_SMB_RPC_USER_RE.findall(str(output_text or ""))) + list(_SMB_USER_RE.findall(str(output_text or "")))
        if _clean_text(match, 96) and _clean_text(match, 96).lower() not in {"user", "username", "account"}
    }

    if share_names:
        _append_finding(
            findings,
            f"SMB shares enumerated ({len(share_names)})",
            severity="info",
            evidence=f"{tool_id}: {', '.join(sorted(share_names)[:8])}",
            evidence_items=sorted(share_names),
        )
    if user_names:
        _append_finding(
            findings,
            f"SMB users enumerated ({len(user_names)})",
            severity="info",
            evidence=f"{tool_id}: {', '.join(sorted(user_names)[:8])}",
            evidence_items=sorted(user_names),
        )
    return {
        "technologies": _dedupe_rows(technologies, ("name", "version", "cpe"), limit=24),
        "findings": _dedupe_rows(findings, ("title", "evidence"), limit=24),
        "urls": [],
    }


def extract_tool_observations(
        tool_id: Any,
        output_text: Any,
        *,
        port: Any = "",
        protocol: Any = "tcp",
        service: Any = "",
        artifact_refs: Any = None,
        host_ip: Any = "",
        hostname: Any = "",
) -> Dict[str, Any]:
    normalized_tool = str(tool_id or "").strip().lower()
    text = str(output_text or "")
    if not normalized_tool or (not text.strip() and not list(artifact_refs or [])):
        return {"technologies": [], "findings": [], "urls": [], "finding_quality_events": []}

    base_url = _build_base_web_url(
        host_ip=host_ip,
        hostname=hostname,
        port=port,
        service=service,
    )
    sources = [text]
    if _artifact_reader_supported(normalized_tool):
        sources.extend(_load_artifact_texts(_select_artifact_refs_for_tool(normalized_tool, artifact_refs or [])))

    result = {"technologies": [], "findings": [], "urls": [], "finding_quality_events": []}
    for source_text in sources:
        source = str(source_text or "")
        if not source.strip():
            continue
        current = {"technologies": [], "findings": [], "urls": [], "finding_quality_events": []}
        if normalized_tool.startswith("whatweb"):
            current = _parse_whatweb_output(normalized_tool, source)
        elif normalized_tool.startswith("httpx"):
            current = _parse_httpx_output(normalized_tool, source)
        elif normalized_tool == "nikto":
            current = _parse_nikto_output(
                normalized_tool,
                source,
                base_url=base_url,
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
                service=str(service or ""),
            )
        elif "nuclei" in normalized_tool:
            current = _parse_nuclei_output(normalized_tool, source, port=str(port or ""), protocol=str(protocol or "tcp"), service=str(service or ""))
        elif normalized_tool == "nmap-vuln.nse" or normalized_tool.startswith("http-vuln-"):
            current = _parse_vuln_script_output(normalized_tool, source)
        elif normalized_tool in {"sslscan", "sslyze"}:
            current = _parse_tls_output(normalized_tool, source)
        elif normalized_tool == "wafw00f":
            current = _parse_waf_output(normalized_tool, source)
        elif normalized_tool in {"curl-headers", "curl-options", "curl-robots"}:
            current = _parse_curl_output(
                normalized_tool,
                source,
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
                service=str(service or ""),
            )
        elif normalized_tool in {"web-content-discovery", "dirsearch", "ffuf"}:
            current = _parse_content_discovery_output(
                normalized_tool,
                source,
                base_url=base_url,
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
                service=str(service or ""),
            )
        elif normalized_tool == "wpscan":
            current = _parse_wpscan_output(normalized_tool, source)
        elif normalized_tool in {"enum4linux-ng", "smbmap", "rpcclient-enum"} or normalized_tool.startswith("rpcclient"):
            current = _parse_smb_enum_output(normalized_tool, source)
        result = _merge_results(result, current)

    # Generic URL harvesting helps the graph even when the tool-specific parser
    # does not expose structured URLs.
    extra_urls = list(result.get("urls", []))
    for source_text in sources:
        if not (normalized_tool == "nmap-vuln.nse" or normalized_tool.startswith("http-vuln-") or normalized_tool == "wpscan"):
            for url in _URL_RE.findall(str(source_text or "")):
                if normalized_tool in {"web-content-discovery", "dirsearch", "ffuf"} and "FUZZ" in str(url or "").upper():
                    continue
                _append_url(extra_urls, url, port=str(port or ""), protocol=str(protocol or "tcp"), service=str(service or ""), label=normalized_tool)
        if base_url and normalized_tool in {"web-content-discovery", "dirsearch", "ffuf"}:
            for path in _DISCOVERY_PATH_RE.findall(str(source_text or "")):
                _append_url(
                    extra_urls,
                    urljoin(f"{base_url.rstrip('/')}/", str(path).lstrip("/")),
                    port=str(port or ""),
                    protocol=str(protocol or "tcp"),
                    service=str(service or ""),
                    label=f"{normalized_tool} path",
                )
    result["technologies"] = _dedupe_rows(list(result.get("technologies", []) or []), ("name", "version", "cpe", "evidence"), limit=64)
    result["findings"] = _dedupe_rows(list(result.get("findings", []) or []), ("title", "cve", "evidence"), limit=64)
    result["urls"] = _dedupe_rows(extra_urls, ("url",), limit=96)
    result["finding_quality_events"] = _dedupe_rows(
        list(result.get("finding_quality_events", []) or []),
        ("title", "cve", "action", "reason", "evidence"),
        limit=96,
    )
    return result
