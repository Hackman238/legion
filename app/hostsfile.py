#!/usr/bin/env python
"""
Helpers for appending temporary Legion-managed host aliases to /etc/hosts
without overwriting or colliding with existing entries.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

LEGION_TEMP_BEGIN = "# --- LEGION TEMP HOSTS BEGIN ---"
LEGION_TEMP_END = "# --- LEGION TEMP HOSTS END ---"
LEGION_TEMP_TAG = "# legion-temp"

_INVALID_HOSTS = {
    "",
    "unknown",
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
}


def normalize_hostname_alias(raw_value: str) -> str:
    value = str(raw_value or "").strip().strip(".").lower()
    if value.startswith("*."):
        value = value[2:]
    value = value.strip().strip(",;")
    if not value or value in _INVALID_HOSTS:
        return ""
    if any(ch.isspace() for ch in value):
        return ""
    if "/" in value or "\\" in value:
        return ""
    if len(value) > 253:
        return ""

    try:
        ipaddress.ip_address(value)
        return ""
    except ValueError:
        pass

    labels = value.split(".")
    for label in labels:
        if not re.fullmatch(r"[a-z0-9-]{1,63}", label):
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""

    if not any(ch.isalpha() for ch in value):
        return ""
    return value


def add_temporary_host_alias(ip_value: str, hostname_value: str, hosts_path: str = "/etc/hosts") -> Tuple[bool, str]:
    ip_text = str(ip_value or "").strip()
    alias = normalize_hostname_alias(hostname_value)
    if not alias:
        return False, "invalid-hostname"

    try:
        ipaddress.ip_address(ip_text)
    except ValueError:
        return False, "invalid-ip"

    try:
        with open(hosts_path, "r", encoding="utf-8") as handle:
            existing_text = handle.read()
    except FileNotFoundError:
        existing_text = ""
    except PermissionError:
        return False, "permission-denied"
    except OSError as exc:
        return False, f"read-failed: {exc}"

    lines = existing_text.splitlines()
    hostname_to_ips, ip_to_hostnames = _parse_hosts_entries(lines)
    alias_ips = hostname_to_ips.get(alias, set())

    if alias_ips and ip_text not in alias_ips:
        return False, "hostname-collision"
    if ip_text in ip_to_hostnames and alias in ip_to_hostnames[ip_text]:
        return True, "already-present"

    begin_index, end_index = _find_legion_block(lines)
    updated_lines = list(lines)
    new_entry = f"{ip_text}\t{alias}\t{LEGION_TEMP_TAG}"

    if begin_index is None or end_index is None or end_index <= begin_index:
        if updated_lines and updated_lines[-1].strip():
            updated_lines.append("")
        updated_lines.append(LEGION_TEMP_BEGIN)
        updated_lines.append(new_entry)
        updated_lines.append(LEGION_TEMP_END)
    else:
        if _block_contains_alias(updated_lines[begin_index + 1:end_index], ip_text, alias):
            return True, "already-present"
        updated_lines.insert(end_index, new_entry)

    serialized = "\n".join(updated_lines).rstrip("\n") + "\n"
    try:
        with open(hosts_path, "w", encoding="utf-8") as handle:
            handle.write(serialized)
    except PermissionError:
        return False, "permission-denied"
    except OSError as exc:
        return False, f"write-failed: {exc}"

    return True, "added"


def _parse_hosts_entries(lines: List[str]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    hostname_to_ips: Dict[str, Set[str]] = {}
    ip_to_hostnames: Dict[str, Set[str]] = {}

    for raw_line in lines:
        line = str(raw_line or "")
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = [p for p in content.split() if p]
        if len(parts) < 2:
            continue
        rec_ip = parts[0]
        for raw_hostname in parts[1:]:
            hostname = normalize_hostname_alias(raw_hostname)
            if not hostname:
                continue
            hostname_to_ips.setdefault(hostname, set()).add(rec_ip)
            ip_to_hostnames.setdefault(rec_ip, set()).add(hostname)

    return hostname_to_ips, ip_to_hostnames


def _find_legion_block(lines: List[str]) -> Tuple[Optional[int], Optional[int]]:
    begin_index = None
    end_index = None
    for idx, line in enumerate(lines):
        stripped = str(line or "").strip()
        if stripped == LEGION_TEMP_BEGIN:
            begin_index = idx
        if stripped == LEGION_TEMP_END and begin_index is not None and idx > begin_index:
            end_index = idx
            break
    return begin_index, end_index


def _block_contains_alias(lines: List[str], ip_text: str, alias: str) -> bool:
    for raw_line in lines:
        content = str(raw_line or "").split("#", 1)[0].strip()
        if not content:
            continue
        parts = [p for p in content.split() if p]
        if len(parts) < 2:
            continue
        if parts[0] != ip_text:
            continue
        normalized = {normalize_hostname_alias(item) for item in parts[1:]}
        if alias in normalized:
            return True
    return False
