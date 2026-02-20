#!/usr/bin/env python
"""
Nmap enrichment helpers used to infer hostnames and OS hints from script output.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence, Tuple

from app.hostsfile import normalize_hostname_alias
from app.osclassification import DEFAULT_CATEGORY, classify_os

UNKNOWN_HOSTNAME_VALUES = {"", "unknown", "(unknown)", "none", "null", "n/a"}

_HOSTNAME_PATTERNS = (
    (re.compile(r"\bDNS:([A-Za-z0-9*][A-Za-z0-9*.-]{0,252})"), 50),
    (re.compile(r"commonName\s*=\s*([A-Za-z0-9*][A-Za-z0-9*.-]{0,252})", re.IGNORECASE), 45),
    (re.compile(r"\bCN\s*=\s*([A-Za-z0-9*][A-Za-z0-9*.-]{0,252})", re.IGNORECASE), 40),
    (re.compile(r"\bhostname\s*[:=]\s*([A-Za-z0-9*][A-Za-z0-9*.-]{0,252})", re.IGNORECASE), 25),
)

_OS_PATTERNS = (
    (re.compile(r"\b(?:microsoft\s+)?windows(?:\s+server|\s+\d+)?\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\b(?:ubuntu|debian|centos|red hat|rhel|fedora|alpine|linux)\b", re.IGNORECASE), "Linux"),
    (re.compile(r"\b(?:solaris|sunos)\b", re.IGNORECASE), "Solaris"),
    (re.compile(r"\b(?:mac\s?os|os\s?x|macos|darwin)\b", re.IGNORECASE), "Darwin"),
    (re.compile(r"\b(?:freebsd|openbsd|netbsd)\b", re.IGNORECASE), "Unix"),
)

_TRUSTED_HOSTNAME_SCRIPT_TOKENS = ("ssl-cert", "rdp-ntlm-info", "nbstat", "smb-os-discovery")
_TRUSTED_OS_SCRIPT_TOKENS = ("smb-os-discovery", "smb-system-info", "rdp-ntlm-info", "nmap")
_SERVICE_OS_PATTERNS = (
    (re.compile(r"\b(?:microsoft\s+windows|windows\s+rpc|msrpc|netbios|smb|cifs|ntlm|rdp|termsrv|winrm)\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\b(?:openssh|linux|ubuntu|debian|centos|fedora|red\s*hat|rhel)\b", re.IGNORECASE), "Linux"),
    (re.compile(r"\b(?:solaris|sunos)\b", re.IGNORECASE), "Solaris"),
    (re.compile(r"\b(?:mac\s?os|os\s?x|macos|darwin)\b", re.IGNORECASE), "Darwin"),
    (re.compile(r"\b(?:freebsd|openbsd|netbsd)\b", re.IGNORECASE), "Unix"),
)


def is_unknown_hostname(value: str) -> bool:
    token = str(value or "").strip().lower()
    return token in UNKNOWN_HOSTNAME_VALUES


def is_unknown_os_match(value: str) -> bool:
    return classify_os(str(value or "")) == DEFAULT_CATEGORY


def infer_hostname_from_nmap_data(primary_hostname: str, script_records: Sequence[Tuple[str, str]]) -> str:
    candidates: List[Tuple[int, str]] = []

    primary = normalize_hostname_alias(primary_hostname)
    if primary:
        candidates.append((500, primary))

    for script_id, output in script_records:
        script_text = str(script_id or "").strip().lower()
        output_text = str(output or "")
        if not output_text:
            continue

        trusted_bonus = 70 if any(token in script_text for token in _TRUSTED_HOSTNAME_SCRIPT_TOKENS) else 0
        for pattern, base_score in _HOSTNAME_PATTERNS:
            for match in pattern.findall(output_text):
                normalized = normalize_hostname_alias(match)
                if not normalized:
                    continue
                score = base_score + trusted_bonus
                if "." in normalized:
                    score += 8
                candidates.append((score, normalized))

    if not candidates:
        return ""

    candidates.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
    return candidates[0][1]


def infer_os_from_nmap_scripts(script_records: Iterable[Tuple[str, str]]) -> str:
    ranked: List[Tuple[int, str]] = []

    for script_id, output in script_records:
        script_text = str(script_id or "").strip().lower()
        output_text = str(output or "")
        if not output_text:
            continue

        trusted = any(token in script_text for token in _TRUSTED_OS_SCRIPT_TOKENS)
        has_explicit_os_line = bool(re.search(r"\bos\s*:\s*", output_text, flags=re.IGNORECASE))
        if not trusted and not has_explicit_os_line:
            continue

        for pattern, label in _OS_PATTERNS:
            if pattern.search(output_text):
                score = 100 if has_explicit_os_line else 80
                if trusted:
                    score += 10
                ranked.append((score, label))
                break

        inferred = classify_os(output_text)
        if inferred != DEFAULT_CATEGORY:
            ranked.append((65 if trusted else 55, inferred))

    if not ranked:
        return ""

    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]


def infer_os_from_service_inventory(service_records: Iterable[Tuple[str, str, str, str]]) -> str:
    ranked: List[Tuple[int, str]] = []

    for service_name, product, version, extrainfo in service_records:
        service_text = " ".join([
            str(service_name or ""),
            str(product or ""),
            str(version or ""),
            str(extrainfo or ""),
        ]).strip()
        if not service_text:
            continue

        lowered = service_text.lower()
        for pattern, label in _SERVICE_OS_PATTERNS:
            if pattern.search(service_text):
                score = 75
                if label == "Windows" and any(token in lowered for token in ("msrpc", "microsoft", "windows", "vmrdp", "rdp")):
                    score += 15
                elif label == "Linux" and any(token in lowered for token in ("openssh", "linux", "ubuntu", "debian")):
                    score += 10
                ranked.append((score, label))
                break

    if not ranked:
        return ""

    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1]
