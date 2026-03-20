"""
Helpers for locating optional security tooling in local-first installs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

SUPPORTED_TOOL_INSTALL_PLATFORMS = ("kali", "ubuntu")


def _candidate_go_bin_paths(env: Optional[Dict[str, str]] = None) -> List[str]:
    source = env if isinstance(env, dict) else os.environ
    candidates: List[str] = []

    gobin = str(source.get("GOBIN", "") or "").strip()
    if gobin:
        candidates.append(os.path.abspath(os.path.expanduser(gobin)))

    gopath = str(source.get("GOPATH", "") or "").strip()
    if gopath:
        for entry in gopath.split(os.pathsep):
            entry = str(entry or "").strip()
            if entry:
                candidates.append(os.path.abspath(os.path.expanduser(os.path.join(entry, "bin"))))

    home = str(source.get("HOME", "") or "").strip()
    if home:
        candidates.append(os.path.abspath(os.path.expanduser(os.path.join(home, "go", "bin"))))

    default_go_bin = os.path.abspath(os.path.expanduser("~/go/bin"))
    candidates.append(default_go_bin)

    seen = set()
    normalized: List[str] = []
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def augment_path_for_legion_tools(path_value: str = "", *, env: Optional[Dict[str, str]] = None) -> str:
    existing_parts = [part for part in str(path_value or "").split(os.pathsep) if str(part or "").strip()]
    seen = set()
    ordered: List[str] = []

    for part in list(_candidate_go_bin_paths(env)) + existing_parts:
        normalized = os.path.abspath(os.path.expanduser(str(part or "").strip()))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)

    return os.pathsep.join(ordered)


def build_tool_execution_env(base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(base_env or os.environ)
    env["PATH"] = augment_path_for_legion_tools(env.get("PATH", ""), env=env)
    return env


@dataclass(frozen=True)
class ToolSpec:
    key: str
    label: str
    commands: Tuple[str, ...]
    category: str
    purpose: str
    configured_setting: str = ""
    kali_install: str = ""
    ubuntu_install: str = ""
    notes: str = ""
    optional: bool = True


@dataclass(frozen=True)
class ToolAuditEntry:
    key: str
    label: str
    category: str
    purpose: str
    status: str
    resolved_path: str
    resolved_command: str
    configured_value: str
    kali_install: str
    ubuntu_install: str
    notes: str
    optional: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "label": self.label,
            "category": self.category,
            "purpose": self.purpose,
            "status": self.status,
            "resolved_path": self.resolved_path,
            "resolved_command": self.resolved_command,
            "configured_value": self.configured_value,
            "kali_install": self.kali_install,
            "ubuntu_install": self.ubuntu_install,
            "notes": self.notes,
            "optional": self.optional,
        }


def normalize_tool_install_platform(platform: str = "") -> str:
    token = str(platform or "").strip().lower()
    if token in SUPPORTED_TOOL_INSTALL_PLATFORMS:
        return token
    return "kali"


def detect_supported_tool_install_platform(
        *,
        os_release_path: str = "/etc/os-release",
        base_env: Optional[Dict[str, str]] = None,
) -> str:
    env = dict(base_env or os.environ)
    candidates = [
        str(env.get("LEGION_TOOL_AUDIT_PLATFORM", "") or "").strip().lower(),
        str(env.get("ID", "") or "").strip().lower(),
        str(env.get("DISTRO_ID", "") or "").strip().lower(),
    ]
    for candidate in candidates:
        if candidate in SUPPORTED_TOOL_INSTALL_PLATFORMS:
            return candidate

    try:
        with open(os_release_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except Exception:
        return "kali"

    id_match = re.search(r"(?im)^ID=(.+)$", content)
    like_match = re.search(r"(?im)^ID_LIKE=(.+)$", content)
    tokens: List[str] = []
    for match in (id_match, like_match):
        if not match:
            continue
        raw = str(match.group(1) or "").strip().strip("\"'")
        tokens.extend(part.strip().lower() for part in raw.split() if part.strip())

    if "kali" in tokens:
        return "kali"
    if "ubuntu" in tokens:
        return "ubuntu"
    return "kali"


def tool_install_hint_for_platform(entry: ToolAuditEntry, platform: str) -> str:
    normalized = normalize_tool_install_platform(platform)
    if normalized == "ubuntu":
        return str(entry.ubuntu_install or "").strip()
    return str(entry.kali_install or "").strip()


def _normalize_install_command(command: str) -> str:
    text = str(command or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("install ") or lowered.startswith("use ") or lowered.startswith("projectdiscovery ") or lowered.startswith("not yet "):
        return ""

    def _rewrite_apt(match: re.Match) -> str:
        package_expr = str(match.group(1) or "").strip()
        return f"sudo -n apt-get install -y {package_expr}"

    rewritten = re.sub(r"(?i)\bsudo\s+apt\s+install\s+(.+?)(?=(?:\s*\|\||\s*&&|$))", _rewrite_apt, text)
    if rewritten != text:
        return rewritten
    return text


def build_tool_install_plan(
        entries: Sequence[ToolAuditEntry],
        *,
        platform: str = "kali",
        scope: str = "missing",
        tool_keys: Optional[Sequence[str]] = None,
        base_env: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    normalized_platform = normalize_tool_install_platform(platform)
    normalized_scope = str(scope or "missing").strip().lower() or "missing"
    selected_keys = {
        str(item or "").strip().lower()
        for item in list(tool_keys or [])
        if str(item or "").strip()
    }

    rows = list(entries or [])
    if selected_keys:
        rows = [entry for entry in rows if str(entry.key or "").strip().lower() in selected_keys]

    if normalized_scope == "all":
        candidate_rows = [entry for entry in rows if entry.status != "installed"]
    elif normalized_scope == "configured_missing":
        candidate_rows = [entry for entry in rows if entry.status == "configured-missing"]
    else:
        candidate_rows = [entry for entry in rows if entry.status in {"missing", "configured-missing"}]

    commands: List[Dict[str, str]] = []
    manual: List[Dict[str, str]] = []
    seen_commands = set()
    needs_go_bootstrap = False
    execution_env = build_tool_execution_env(base_env)
    go_path = shutil.which("go", path=execution_env.get("PATH", ""))

    for entry in candidate_rows:
        hint = tool_install_hint_for_platform(entry, normalized_platform)
        normalized_command = _normalize_install_command(hint)
        if normalized_command:
            if normalized_command.startswith("go install ") and not go_path:
                needs_go_bootstrap = True
            if normalized_command in seen_commands:
                continue
            seen_commands.add(normalized_command)
            commands.append({
                "tool_key": str(entry.key or ""),
                "label": str(entry.label or entry.key or "tool"),
                "command": normalized_command,
                "hint": hint,
            })
            continue
        manual.append({
            "tool_key": str(entry.key or ""),
            "label": str(entry.label or entry.key or "tool"),
            "hint": hint or str(entry.notes or "").strip() or "No curated install hint is available for this tool.",
        })

    if needs_go_bootstrap:
        bootstrap_command = "sudo -n apt-get install -y golang-go"
        if bootstrap_command not in seen_commands:
            seen_commands.add(bootstrap_command)
            commands.insert(0, {
                "tool_key": "golang-go",
                "label": "Go toolchain",
                "command": bootstrap_command,
                "hint": "sudo apt install golang-go",
            })

    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Generated by Legion Tool Audit",
        f"# Platform: {normalized_platform}",
        f"# Scope: {normalized_scope}",
        "",
    ]
    script_lines.extend(item["command"] for item in commands)
    if manual:
        script_lines.extend([
            "",
            "# Manual follow-up required for:",
        ])
        script_lines.extend(f"# - {item['label']}: {item['hint']}" for item in manual)

    return {
        "platform": normalized_platform,
        "scope": normalized_scope,
        "supported_platforms": list(SUPPORTED_TOOL_INSTALL_PLATFORMS),
        "selected_tool_count": len(candidate_rows),
        "command_count": len(commands),
        "manual_count": len(manual),
        "commands": commands,
        "manual": manual,
        "script": "\n".join(script_lines).strip() + "\n",
    }


def execute_tool_install_plan(
        plan: Dict[str, Any],
        *,
        base_env: Optional[Dict[str, str]] = None,
        is_cancel_requested: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    resolved_plan = dict(plan or {})
    commands = list(resolved_plan.get("commands", []) or [])
    manual = list(resolved_plan.get("manual", []) or [])
    platform = str(resolved_plan.get("platform", "kali") or "kali")
    scope = str(resolved_plan.get("scope", "missing") or "missing")
    script = str(resolved_plan.get("script", "") or "")
    if not commands:
        return {
            "platform": platform,
            "scope": scope,
            "command_count": 0,
            "manual_count": len(manual),
            "completed_commands": [],
            "manual": manual,
            "script": script,
            "message": "No installable missing tools matched the selected scope.",
        }

    env = build_tool_execution_env(base_env)
    completed_commands: List[Dict[str, Any]] = []
    cancel_check = is_cancel_requested if callable(is_cancel_requested) else None

    for index, item in enumerate(commands, start=1):
        if cancel_check and cancel_check():
            return {
                "platform": platform,
                "scope": scope,
                "command_count": len(commands),
                "manual_count": len(manual),
                "completed_commands": completed_commands,
                "manual": manual,
                "script": script,
                "cancelled": True,
                "message": "Tool installation cancelled before all commands completed.",
            }

        label = str(item.get("label", item.get("tool_key", f"tool-{index}")) or f"tool-{index}")
        command = str(item.get("command", "") or "").strip()
        if not command:
            continue

        process = subprocess.Popen(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        while process.poll() is None:
            if cancel_check and cancel_check():
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                return {
                    "platform": platform,
                    "scope": scope,
                    "command_count": len(commands),
                    "manual_count": len(manual),
                    "completed_commands": completed_commands,
                    "manual": manual,
                    "script": script,
                    "cancelled": True,
                    "message": f"Tool installation cancelled while running '{label}'.",
                }
            time.sleep(0.25)

        stdout_text, stderr_text = process.communicate()
        exit_code = int(process.returncode or 0)
        completed_commands.append({
            "index": int(index),
            "label": label,
            "command": command,
            "exit_code": exit_code,
            "stdout_tail": str(stdout_text or "")[-6000:],
            "stderr_tail": str(stderr_text or "")[-6000:],
        })
        if exit_code != 0:
            failure_output = str(stderr_text or stdout_text or "").strip()
            if len(failure_output) > 400:
                failure_output = failure_output[-400:]
            raise RuntimeError(
                f"Tool install failed while running '{label}' (exit {exit_code}). "
                f"{failure_output or command}"
            )

    return {
        "platform": platform,
        "scope": scope,
        "command_count": len(commands),
        "manual_count": len(manual),
        "completed_commands": completed_commands,
        "manual": manual,
        "script": script,
        "message": (
            f"Completed {len(completed_commands)} install command"
            f"{'' if len(completed_commands) == 1 else 's'}"
            + (f"; {len(manual)} tool{'s' if len(manual) != 1 else ''} still require manual follow-up." if manual else ".")
        ),
    }


def _tool_specs() -> List[ToolSpec]:
    return [
        ToolSpec(
            "nmap",
            "Nmap",
            ("nmap",),
            "core",
            "Host discovery, service detection, XML import parity, and most NSE-driven actions.",
            configured_setting="tools_path_nmap",
            kali_install="sudo apt install nmap",
            ubuntu_install="sudo apt install nmap",
            notes="This is the baseline requirement for most Legion workflows.",
            optional=False,
        ),
        ToolSpec(
            "hydra",
            "Hydra",
            ("hydra",),
            "credentials",
            "Credential brute-force and validation workflows.",
            configured_setting="tools_path_hydra",
            kali_install="sudo apt install hydra",
            ubuntu_install="sudo apt install hydra",
        ),
        ToolSpec(
            "curl",
            "curl",
            ("curl",),
            "core",
            "HTTP headers, OPTIONS, robots.txt, and fallback content checks.",
            kali_install="sudo apt install curl",
            ubuntu_install="sudo apt install curl",
            optional=False,
        ),
        ToolSpec(
            "nuclei",
            "Nuclei",
            ("nuclei",),
            "web",
            "Governed web, CVE, exposure, and targeted validation follow-up.",
            kali_install="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -up && nuclei -ut",
            ubuntu_install="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -up && nuclei -ut",
            notes="ProjectDiscovery currently documents the v3 install path and template update flow.",
        ),
        ToolSpec(
            "whatweb",
            "WhatWeb",
            ("whatweb",),
            "web",
            "Technology fingerprinting and graph/state enrichment.",
            kali_install="sudo apt install whatweb",
            ubuntu_install="sudo apt install whatweb",
        ),
        ToolSpec(
            "nikto",
            "Nikto",
            ("nikto",),
            "web",
            "Broad HTTP validation and known issue checks.",
            kali_install="sudo apt install nikto",
            ubuntu_install="sudo apt install nikto",
        ),
        ToolSpec(
            "wafw00f",
            "WAFW00F",
            ("wafw00f",),
            "web",
            "WAF detection and exposure fingerprinting.",
            kali_install="sudo apt install wafw00f",
            ubuntu_install="sudo apt install wafw00f",
        ),
        ToolSpec(
            "sslscan",
            "sslscan",
            ("sslscan",),
            "web",
            "TLS posture checks.",
            kali_install="sudo apt install sslscan",
            ubuntu_install="sudo apt install sslscan",
        ),
        ToolSpec(
            "sslyze",
            "sslyze",
            ("sslyze",),
            "web",
            "TLS protocol, certificate, and cipher validation.",
            kali_install="sudo apt install sslyze",
            ubuntu_install="sudo apt install sslyze",
        ),
        ToolSpec(
            "wpscan",
            "WPScan",
            ("wpscan",),
            "web",
            "WordPress-focused follow-up and validation.",
            kali_install="sudo apt install wpscan",
            ubuntu_install="sudo apt install wpscan",
        ),
        ToolSpec(
            "wapiti",
            "Wapiti",
            ("wapiti",),
            "web",
            "Application follow-up scanning for HTTP/HTTPS services.",
            kali_install="sudo apt install wapiti",
            ubuntu_install="sudo apt install wapiti",
        ),
        ToolSpec(
            "gobuster",
            "Gobuster",
            ("gobuster",),
            "web",
            "Legacy web content discovery fallback.",
            kali_install="sudo apt install gobuster",
            ubuntu_install="sudo apt install gobuster",
        ),
        ToolSpec(
            "feroxbuster",
            "Feroxbuster",
            ("feroxbuster",),
            "web",
            "Legacy web content discovery fallback.",
            kali_install="sudo apt install feroxbuster",
            ubuntu_install="sudo apt install feroxbuster",
        ),
        ToolSpec(
            "dirsearch",
            "dirsearch",
            ("dirsearch",),
            "web",
            "Governed directory/content discovery follow-up.",
            kali_install="sudo apt install dirsearch",
            ubuntu_install="sudo apt install dirsearch",
            notes="If not packaged on your Ubuntu release, install from the upstream dirsearch project.",
        ),
        ToolSpec(
            "ffuf",
            "ffuf",
            ("ffuf",),
            "web",
            "Governed content fuzzing follow-up.",
            kali_install="sudo apt install ffuf",
            ubuntu_install="sudo apt install ffuf",
        ),
        ToolSpec(
            "enum4linux-ng",
            "enum4linux-ng",
            ("enum4linux-ng",),
            "internal",
            "Safer SMB/AD-aware internal enumeration.",
            kali_install="sudo apt install enum4linux-ng",
            ubuntu_install="sudo apt install enum4linux-ng",
            notes="If your Ubuntu release does not package it, use the upstream project install path.",
        ),
        ToolSpec(
            "smbmap",
            "smbmap",
            ("smbmap",),
            "internal",
            "SMB share and access enumeration.",
            kali_install="sudo apt install smbmap",
            ubuntu_install="sudo apt install smbmap",
        ),
        ToolSpec(
            "rpcclient",
            "rpcclient",
            ("rpcclient",),
            "internal",
            "SMB/RPC enumeration for internal workflows.",
            kali_install="sudo apt install samba-common-bin",
            ubuntu_install="sudo apt install samba-common-bin",
        ),
        ToolSpec(
            "enum4linux",
            "enum4linux",
            ("enum4linux",),
            "internal",
            "Legacy SMB enumeration workflows.",
            kali_install="sudo apt install enum4linux",
            ubuntu_install="sudo apt install enum4linux",
        ),
        ToolSpec(
            "ldapsearch",
            "ldapsearch",
            ("ldapsearch",),
            "internal",
            "LDAP and directory enumeration.",
            kali_install="sudo apt install ldap-utils",
            ubuntu_install="sudo apt install ldap-utils",
        ),
        ToolSpec(
            "nbtscan",
            "nbtscan",
            ("nbtscan",),
            "internal",
            "NetBIOS name enumeration.",
            kali_install="sudo apt install nbtscan",
            ubuntu_install="sudo apt install nbtscan",
        ),
        ToolSpec(
            "rpcinfo",
            "rpcinfo",
            ("rpcinfo",),
            "internal",
            "RPC exposure enumeration.",
            kali_install="sudo apt install rpcbind",
            ubuntu_install="sudo apt install rpcbind",
        ),
        ToolSpec(
            "showmount",
            "showmount",
            ("showmount",),
            "internal",
            "NFS export enumeration.",
            kali_install="sudo apt install nfs-common",
            ubuntu_install="sudo apt install nfs-common",
        ),
        ToolSpec(
            "finger",
            "finger",
            ("finger",),
            "legacy",
            "Legacy service enumeration.",
            kali_install="sudo apt install finger",
            ubuntu_install="sudo apt install finger",
        ),
        ToolSpec(
            "dnsmap",
            "dnsmap",
            ("dnsmap",),
            "passive",
            "Legacy DNS brute-force and expansion workflows.",
            kali_install="sudo apt install dnsmap",
            ubuntu_install="Install from the upstream dnsmap project or Kali package sources.",
        ),
        ToolSpec(
            "theHarvester",
            "theHarvester",
            ("theHarvester", "theharvester"),
            "passive",
            "Legacy external recon and passive collection.",
            kali_install="sudo apt install theharvester",
            ubuntu_install="sudo apt install theharvester",
        ),
        ToolSpec(
            "snmpcheck",
            "snmpcheck",
            ("snmpcheck",),
            "internal",
            "Legacy SNMP enumeration.",
            kali_install="sudo apt install snmpcheck",
            ubuntu_install="Install from the upstream snmpcheck project if unavailable in apt.",
        ),
        ToolSpec(
            "samrdump",
            "samrdump",
            ("samrdump",),
            "internal",
            "Legacy Impacket SAMR enumeration.",
            kali_install="sudo apt install impacket-scripts",
            ubuntu_install="python3 -m pip install impacket",
        ),
        ToolSpec(
            "sqlmap",
            "sqlmap",
            ("sqlmap",),
            "web",
            "Legacy SQL injection validation path.",
            kali_install="sudo apt install sqlmap",
            ubuntu_install="sudo apt install sqlmap",
        ),
        ToolSpec(
            "nc",
            "netcat",
            ("nc", "netcat", "ncat"),
            "core",
            "Banner and low-level connectivity probes.",
            kali_install="sudo apt install netcat-openbsd",
            ubuntu_install="sudo apt install netcat-openbsd",
        ),
        ToolSpec(
            "eyewitness",
            "EyeWitness",
            ("eyewitness", "EyeWitness.py", "EyeWitness"),
            "screenshot",
            "Primary screenshot engine when available.",
            kali_install="sudo apt install eyewitness",
            ubuntu_install="Install EyeWitness from the upstream project if unavailable in apt.",
            notes="Legion also has browser fallbacks, but EyeWitness remains a preferred path when present.",
        ),
        ToolSpec(
            "chromium",
            "Chromium / Chrome",
            ("chromium-browser", "chromium", "google-chrome-stable", "google-chrome", "chrome"),
            "screenshot",
            "Browser-based screenshot capture fallback.",
            kali_install="sudo apt install chromium",
            ubuntu_install="sudo apt install chromium-browser || sudo apt install chromium",
        ),
        ToolSpec(
            "firefox",
            "Firefox",
            ("firefox",),
            "screenshot",
            "Browser-based screenshot fallback.",
            kali_install="sudo apt install firefox-esr",
            ubuntu_install="sudo apt install firefox",
        ),
        ToolSpec(
            "geckodriver",
            "geckodriver",
            ("geckodriver",),
            "screenshot",
            "Firefox Selenium driver used by screenshot fallbacks.",
            kali_install="sudo apt install firefox-geckodriver || sudo apt install geckodriver",
            ubuntu_install="sudo apt install firefox-geckodriver || sudo apt install geckodriver",
        ),
        ToolSpec(
            "xvfb-run",
            "xvfb-run",
            ("xvfb-run",),
            "screenshot",
            "Headless display wrapper for EyeWitness/browser capture paths.",
            kali_install="sudo apt install xvfb",
            ubuntu_install="sudo apt install xvfb",
        ),
        ToolSpec(
            "responder",
            "Responder",
            ("responder",),
            "relay",
            "Responder workspace support.",
            configured_setting="tools_path_responder",
            kali_install="sudo apt install responder",
            ubuntu_install="Install from the upstream Responder project or Kali package sources.",
        ),
        ToolSpec(
            "ntlmrelayx",
            "ntlmrelayx",
            ("ntlmrelayx.py", "ntlmrelayx"),
            "relay",
            "NTLM relay workspace support.",
            configured_setting="tools_path_ntlmrelay",
            kali_install="sudo apt install impacket-scripts",
            ubuntu_install="python3 -m pip install impacket",
        ),
        ToolSpec(
            "httpx",
            "httpx",
            ("httpx",),
            "planned",
            "Planned / adjacent ProjectDiscovery HTTP probing support.",
            kali_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            ubuntu_install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            notes="Not yet a first-class launch action in Legion, but worth having available.",
        ),
        ToolSpec(
            "subfinder",
            "subfinder",
            ("subfinder",),
            "planned",
            "Planned passive subdomain discovery support.",
            kali_install="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            ubuntu_install="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            notes="ProjectDiscovery documents the v2 install path and provider-config model.",
        ),
        ToolSpec(
            "uncover",
            "uncover",
            ("uncover",),
            "planned",
            "Planned external exposure discovery support.",
            kali_install="go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest",
            ubuntu_install="go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest",
            notes="Useful when Shodan/Censys style exposure discovery is part of workflow.",
        ),
        ToolSpec(
            "cvemap",
            "vulnx / cvemap",
            ("vulnx", "cvemap"),
            "planned",
            "Planned ProjectDiscovery vulnerability/CPE exploration support.",
            kali_install="go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest",
            ubuntu_install="go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest",
            notes="ProjectDiscovery now recommends vulnx as the successor to cvemap.",
        ),
        ToolSpec(
            "xdg-open",
            "xdg-open",
            ("xdg-open",),
            "desktop",
            "Open artifacts and exported files from the UI.",
            configured_setting="tools_path_texteditor",
            kali_install="sudo apt install xdg-utils",
            ubuntu_install="sudo apt install xdg-utils",
        ),
    ]


_SHELL_BUILTINS = {
    "echo",
    "command",
    "bash",
    "sh",
    "python",
    "python3",
    "sudo",
    "if",
    "then",
    "else",
    "fi",
    "true",
    "false",
}


def _extract_command_v_tools(command_text: str) -> List[str]:
    return list(dict.fromkeys(re.findall(r"(?i)\bcommand\s+-v\s+([A-Za-z0-9_.+-]+)\b", str(command_text or ""))))


def _iter_configured_command_texts(settings: object) -> Iterable[str]:
    for attr_name, command_index in (
        ("hostActions", 2),
        ("portActions", 2),
        ("portTerminalActions", 2),
    ):
        for row in list(getattr(settings, attr_name, []) or []):
            if isinstance(row, (list, tuple)) and len(row) > command_index:
                value = str(row[command_index] or "").strip()
                if value:
                    yield value


def _build_tool_spec_index() -> Dict[str, ToolSpec]:
    specs = _tool_specs()
    alias_map: Dict[str, ToolSpec] = {}
    for spec in specs:
        alias_map[spec.key] = spec
        for command_name in spec.commands:
            alias_map[str(command_name).strip().lower()] = spec
    return alias_map


def _dynamic_specs_from_settings(settings: Optional[object]) -> List[ToolSpec]:
    if settings is None:
        return []
    index = _build_tool_spec_index()
    dynamic: List[ToolSpec] = []
    seen = set()
    for command_text in _iter_configured_command_texts(settings):
        for tool_name in _extract_command_v_tools(command_text):
            key = str(tool_name or "").strip().lower()
            if not key or key in index or key in seen or key in _SHELL_BUILTINS:
                continue
            seen.add(key)
            dynamic.append(
                ToolSpec(
                    key=key,
                    label=tool_name,
                    commands=(tool_name,),
                    category="custom",
                    purpose="Discovered from configured Legion command templates.",
                    notes="No distro-specific install hint has been curated for this tool yet.",
                )
            )
    return dynamic


def list_legion_tool_specs(settings: Optional[object] = None) -> List[ToolSpec]:
    ordered: List[ToolSpec] = []
    seen = set()
    for spec in list(_tool_specs()) + _dynamic_specs_from_settings(settings):
        if spec.key in seen:
            continue
        seen.add(spec.key)
        ordered.append(spec)
    return ordered


def _resolve_configured_path(spec: ToolSpec, settings: Optional[object], env: Dict[str, str]) -> Tuple[str, str]:
    if settings is None or not spec.configured_setting:
        return "", ""
    configured_value = str(getattr(settings, spec.configured_setting, "") or "").strip()
    if not configured_value:
        return "", ""
    expanded = os.path.abspath(os.path.expanduser(configured_value))
    if os.path.isabs(configured_value) or "/" in configured_value:
        if os.path.isfile(expanded):
            return configured_value, expanded
    resolved = shutil.which(configured_value, path=env.get("PATH", ""))
    if resolved:
        return configured_value, os.path.abspath(resolved)
    return configured_value, ""


def _resolve_tool_command(spec: ToolSpec, env: Dict[str, str]) -> Tuple[str, str]:
    for command_name in spec.commands:
        resolved = shutil.which(command_name, path=env.get("PATH", ""))
        if resolved:
            return command_name, os.path.abspath(resolved)
    return "", ""


def audit_legion_tools(
        settings: Optional[object] = None,
        *,
        base_env: Optional[Dict[str, str]] = None,
) -> List[ToolAuditEntry]:
    env = build_tool_execution_env(base_env)
    entries: List[ToolAuditEntry] = []
    for spec in list_legion_tool_specs(settings):
        configured_value, configured_resolved = _resolve_configured_path(spec, settings, env)
        resolved_command = ""
        resolved_path = configured_resolved
        if configured_resolved:
            resolved_command = os.path.basename(configured_resolved)
        else:
            resolved_command, resolved_path = _resolve_tool_command(spec, env)

        status = "installed" if resolved_path else "missing"
        notes = spec.notes
        if configured_value and not configured_resolved:
            status = "configured-missing"
            notes = (
                f"Configured path '{configured_value}' did not resolve."
                + (f" {notes}" if notes else "")
            )

        entries.append(
            ToolAuditEntry(
                key=spec.key,
                label=spec.label,
                category=spec.category,
                purpose=spec.purpose,
                status=status,
                resolved_path=resolved_path,
                resolved_command=resolved_command,
                configured_value=configured_value,
                kali_install=spec.kali_install,
                ubuntu_install=spec.ubuntu_install,
                notes=notes,
                optional=spec.optional,
            )
        )

    category_order = {
        "core": 0,
        "web": 1,
        "internal": 2,
        "screenshot": 3,
        "relay": 4,
        "credentials": 5,
        "passive": 6,
        "desktop": 7,
        "legacy": 8,
        "planned": 9,
        "custom": 10,
    }
    return sorted(entries, key=lambda row: (category_order.get(row.category, 99), row.label.lower()))


def tool_audit_summary(entries: Sequence[ToolAuditEntry]) -> Dict[str, int]:
    installed = sum(1 for entry in entries if entry.status == "installed")
    configured_missing = sum(1 for entry in entries if entry.status == "configured-missing")
    missing = sum(1 for entry in entries if entry.status == "missing")
    required_missing = sum(
        1 for entry in entries
        if not entry.optional and entry.status != "installed"
    )
    return {
        "total": len(entries),
        "installed": installed,
        "configured_missing": configured_missing,
        "missing": missing,
        "required_missing": required_missing,
    }


def format_tool_audit_report(entries: Sequence[ToolAuditEntry]) -> str:
    summary = tool_audit_summary(entries)
    lines = [
        "LEGION tool audit",
        (
            f"Installed: {summary['installed']}/{summary['total']} | "
            f"Missing: {summary['missing']} | "
            f"Configured missing: {summary['configured_missing']} | "
            f"Required missing: {summary['required_missing']}"
        ),
        "",
    ]
    current_category = None
    for entry in entries:
        if entry.category != current_category:
            current_category = entry.category
            lines.append(f"[{current_category}]")
        status = entry.status.upper()
        resolved = entry.resolved_path or entry.configured_value or "-"
        lines.append(f"- {entry.label}: {status} ({resolved})")
        lines.append(f"  Purpose: {entry.purpose}")
        if entry.kali_install:
            lines.append(f"  Kali: {entry.kali_install}")
        if entry.ubuntu_install:
            lines.append(f"  Ubuntu: {entry.ubuntu_install}")
        if entry.notes:
            lines.append(f"  Notes: {entry.notes}")
    return "\n".join(lines).strip() + "\n"
