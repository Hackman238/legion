"""
Shared helpers for choosing hostname-vs-IP targets for commands and URLs.
"""

from __future__ import annotations

import re
import socket
from functools import lru_cache
from typing import Optional, Tuple

from app.hostsfile import normalize_hostname_alias
from app.nmap_enrichment import is_unknown_hostname

_NUMERIC_TARGET_COMMAND_PATTERNS = (
    re.compile(r"(?i)\blegion_banner_target="),
    re.compile(r"(?i)\b(?:nc|netcat)\b(?:(?![;&|()]).)*\s-n(?:\s|$)"),
    re.compile(r"(?i)\b(?:nc|netcat)\b(?:(?![;&|()]).)*\s-[A-Za-z]*n[A-Za-z]*(?:\s|$)"),
    re.compile(r"(?i)^\s*nbtscan\b"),
    re.compile(r"(?i)^\s*unicornscan\b"),
)
_TLS_WEB_SERVICE_IDS = {"https", "ssl", "https-alt", "https?", "ssl/http", "ssl|http"}


@lru_cache(maxsize=1024)
def resolve_hostname_addresses(hostname: str) -> Tuple[str, ...]:
    candidate = normalize_hostname_alias(hostname)
    if not candidate or is_unknown_hostname(candidate):
        return tuple()

    resolved = []
    seen = set()
    try:
        records = socket.getaddrinfo(candidate, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return tuple()
    except Exception:
        return tuple()

    for record in records:
        try:
            sockaddr = record[4]
            address = str(sockaddr[0]).strip()
        except Exception:
            continue
        if not address or address in seen:
            continue
        seen.add(address)
        resolved.append(address)
    return tuple(resolved)


def choose_preferred_host(hostname: str, ip: str, *, prefer_unresolved_hostname: bool = False) -> str:
    ip_text = str(ip or "").strip()
    candidate = normalize_hostname_alias(hostname)
    if not candidate or is_unknown_hostname(candidate):
        return ip_text or candidate
    if resolve_hostname_addresses(candidate):
        return candidate
    if prefer_unresolved_hostname:
        return candidate
    return ip_text or candidate


def command_prefers_numeric_target(command_template: str) -> bool:
    raw = str(command_template or "").strip()
    if not raw:
        return False
    return any(pattern.search(raw) for pattern in _NUMERIC_TARGET_COMMAND_PATTERNS)


def choose_preferred_command_host(hostname: str, ip: str, command_template: str) -> str:
    if command_prefers_numeric_target(command_template):
        return str(ip or "").strip() or normalize_hostname_alias(hostname)
    return choose_preferred_host(hostname, ip, prefer_unresolved_hostname=True)


def choose_preferred_web_scheme(service_name: str) -> str:
    token = str(service_name or "").strip().rstrip("?").lower()
    if token in _TLS_WEB_SERVICE_IDS:
        return "https"
    if token.startswith("https") or token.endswith("ssl") or token.endswith("tls"):
        return "https"
    return "http"


def apply_preferred_target_placeholders(
        template: str,
        *,
        hostname: str,
        ip: str,
        port: Optional[str] = None,
        output: Optional[str] = None,
        service_name: str = "",
) -> Tuple[str, str]:
    command = str(template or "")
    target_host = choose_preferred_command_host(hostname, ip, command)
    command = command.replace("[IP]", target_host)
    if port is not None:
        command = command.replace("[PORT]", str(port))
        command = command.replace(
            "[WEB_URL]",
            f"{choose_preferred_web_scheme(service_name)}://{target_host}:{str(port)}",
        )
    if output is not None:
        command = command.replace("[OUTPUT]", str(output))
    return command, target_host


def choose_preferred_screenshot_host(hostname: str, ip: str) -> str:
    return choose_preferred_host(hostname, ip, prefer_unresolved_hostname=True)
