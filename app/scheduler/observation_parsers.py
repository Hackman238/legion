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
_WHATWEB_PAIR_RE = re.compile(r"([A-Za-z][A-Za-z0-9+_. -]{1,48})\[([^\]]{1,180})\]")
_WHATWEB_IGNORED_NAMES = {
    "country",
    "cookies",
    "email",
    "httpcountry",
    "ip",
    "meta-generator",
    "script",
    "title",
    "uncommonheaders",
    "x-powered-by",
}
_LEGACY_TLS_FINDINGS = {
    "sslv2": ("SSLv2 supported", "high"),
    "sslv3": ("SSLv3 supported", "high"),
    "tlsv1.0": ("TLSv1.0 supported", "medium"),
    "tlsv1.1": ("TLSv1.1 supported", "medium"),
}
_IGNORED_DISCOVERY_URL_HOSTS = {"nmap.org", "www.nmap.org"}
_SUPPORTED_ARTIFACT_PARSE_PREFIXES = (
    "whatweb",
    "httpx",
    "nuclei",
    "sslscan",
    "sslyze",
    "web-content-discovery",
    "dirsearch",
    "ffuf",
    "enum4linux-ng",
    "smbmap",
    "rpcclient-enum",
)
_DISCOVERY_PATH_RE = re.compile(r"(?i)(?:\"path\"|path|location|redirectlocation)\s*[:=]\s*['\"]?(/[^\"'\s,|]+)")
_SMB_USER_RE = re.compile(r"(?i)(?:user(?:name)?|account)\s*[:=\[]\s*['\"]?([A-Za-z0-9_. $-]{1,96})")
_SMB_RPC_USER_RE = re.compile(r"(?i)\buser:\[([^\]]{1,96})\]")
_SMB_SHARE_RE = re.compile(r"(?i)(?:share(?:name)?|netname)\s*[:=\[]\s*['\"]?([A-Za-z0-9_. $-]{1,128})")
_SMB_DOMAIN_RE = re.compile(r"(?i)(?:domain(?:\s+name)?|workgroup)\s*[:=]\s*['\"]?([A-Za-z0-9_.-]{1,96})")


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


def _load_artifact_texts(artifact_refs: Iterable[Any], *, max_files: int = 6, max_chars: int = 160000) -> List[str]:
    texts: List[str] = []
    allowed_exts = {".txt", ".json", ".jsonl", ".log", ".csv", ".xml", ".html", ".md"}
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


def _append_finding(rows: List[Dict[str, Any]], title: str, *, severity: str = "info", cve: str = "", evidence: str = ""):
    finding_title = _clean_text(title, 260)
    finding_cve = _clean_text(cve, 64).upper()
    finding_evidence = _clean_text(evidence, 640)
    if not finding_title and not finding_cve:
        return
    rows.append({
        "title": finding_title or finding_cve,
        "severity": _severity_token(severity, "info"),
        "cvss": 0.0,
        "cve": finding_cve,
        "evidence": finding_evidence or finding_title or finding_cve,
        "source_kind": "observed",
        "observed": True,
    })


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
            if re.fullmatch(r"[0-9][A-Za-z0-9._-]{0,31}", value_token):
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


def _parse_nuclei_output(tool_id: str, output_text: str, *, port: str = "", protocol: str = "tcp", service: str = "") -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    urls: List[Dict[str, Any]] = []
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
            _append_url(urls, matched_at, port=port, protocol=protocol, service=service, label=title or cve_id)
            _append_finding(
                findings,
                title or cve_id or "Nuclei match",
                severity=severity,
                cve=cve_id,
                evidence=line,
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
            _append_finding(
                findings,
                cve_id or title or "Nuclei match",
                severity=severity,
                cve=cve_id,
                evidence=line,
            )
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=64),
        "urls": _dedupe_rows(urls, ("url",), limit=64),
    }


def _parse_tls_output(tool_id: str, output_text: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for raw_line in str(output_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        for protocol_token, (title, severity) in _LEGACY_TLS_FINDINGS.items():
            if protocol_token in lowered and any(marker in lowered for marker in ("enabled", "accepted", "offered", "supported")):
                if "disabled" in lowered or "not supported" in lowered or "rejected" in lowered:
                    continue
                _append_finding(findings, title, severity=severity, evidence=f"{tool_id}: {line}")
        if "self-signed" in lowered or "self signed" in lowered:
            _append_finding(findings, "Self-signed TLS certificate", severity="low", evidence=f"{tool_id}: {line}")
        if "certificate expired" in lowered or "expired certificate" in lowered:
            _append_finding(findings, "Expired TLS certificate", severity="medium", evidence=f"{tool_id}: {line}")
        if "heartbleed" in lowered and "not vulnerable" not in lowered:
            cve_id = "CVE-2014-0160" if "cve-2014-0160" in lowered or "heartbleed" in lowered else ""
            _append_finding(findings, "Heartbleed exposure", severity="high", cve=cve_id, evidence=f"{tool_id}: {line}")
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "cve", "evidence"), limit=32),
        "urls": [],
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
            url = item.get("url") or item.get("input") or item.get("host") or ""
            path = item.get("path") or item.get("location") or ""
            if not url and path and base_url:
                url = urljoin(f"{base_url.rstrip('/')}/", str(path).lstrip("/"))
            _append_url(urls, url, port=port, protocol=protocol, service=service, label=f"{tool_id} discovered content")
            redirect_target = item.get("redirect") or item.get("redirectlocation") or item.get("redirect_url") or ""
            if redirect_target:
                _append_url(urls, redirect_target, port=port, protocol=protocol, service=service, label=f"{tool_id} redirect")
            status = str(item.get("status") or item.get("status_code") or "").strip()
            candidate_path = str(path or urlparse(str(url or "")).path or "").strip()
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
        )
    return {
        "technologies": [],
        "findings": _dedupe_rows(findings, ("title", "evidence"), limit=16),
        "urls": _dedupe_rows(urls, ("url",), limit=96),
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
        )
    if user_names:
        _append_finding(
            findings,
            f"SMB users enumerated ({len(user_names)})",
            severity="info",
            evidence=f"{tool_id}: {', '.join(sorted(user_names)[:8])}",
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
        return {"technologies": [], "findings": [], "urls": []}

    base_url = _build_base_web_url(
        host_ip=host_ip,
        hostname=hostname,
        port=port,
        service=service,
    )
    sources = [text]
    if _artifact_reader_supported(normalized_tool):
        sources.extend(_load_artifact_texts(artifact_refs or []))

    result = {"technologies": [], "findings": [], "urls": []}
    for source_text in sources:
        source = str(source_text or "")
        if not source.strip():
            continue
        current = {"technologies": [], "findings": [], "urls": []}
        if normalized_tool.startswith("whatweb"):
            current = _parse_whatweb_output(normalized_tool, source)
        elif normalized_tool.startswith("httpx"):
            current = _parse_httpx_output(normalized_tool, source)
        elif "nuclei" in normalized_tool:
            current = _parse_nuclei_output(normalized_tool, source, port=str(port or ""), protocol=str(protocol or "tcp"), service=str(service or ""))
        elif normalized_tool in {"sslscan", "sslyze"}:
            current = _parse_tls_output(normalized_tool, source)
        elif normalized_tool in {"web-content-discovery", "dirsearch", "ffuf"}:
            current = _parse_content_discovery_output(
                normalized_tool,
                source,
                base_url=base_url,
                port=str(port or ""),
                protocol=str(protocol or "tcp"),
                service=str(service or ""),
            )
        elif normalized_tool in {"enum4linux-ng", "smbmap", "rpcclient-enum"} or normalized_tool.startswith("rpcclient"):
            current = _parse_smb_enum_output(normalized_tool, source)
        result = _merge_results(result, current)

    # Generic URL harvesting helps the graph even when the tool-specific parser
    # does not expose structured URLs.
    extra_urls = list(result.get("urls", []))
    for source_text in sources:
        for url in _URL_RE.findall(str(source_text or "")):
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
    return result
