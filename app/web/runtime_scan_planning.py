from __future__ import annotations

import os
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional

from app.cli_utils import is_wsl, to_windows_path
from app.web.runtime_scan_targets import (
    best_scan_submission_for_subnet,
    compact_targets,
    count_rfc1918_scan_batches,
    iter_rfc1918_scan_batches,
    normalize_rfc_chunk_concurrency,
    normalize_subnet_target,
    normalize_targets,
    record_bool,
    scan_history_targets,
    scan_target_match_score_for_subnet,
    summarize_scan_scope,
)


def apply_engagement_scan_profile(
        runtime_cls,
        scan_options: Dict[str, Any],
        *,
        engagement_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    options = dict(scan_options or {})
    preset = str((engagement_policy or {}).get("preset", "") or "").strip().lower()
    if preset == "internal_quick_recon":
        options["explicit_ports"] = runtime_cls.INTERNAL_QUICK_RECON_TCP_PORTS
        options["top_ports"] = 0
    return options


def build_nmap_scan_plan(
        runtime,
        *,
        targets: List[str],
        discovery: bool,
        staged: bool,
        nmap_path: str,
        nmap_args: str,
        output_prefix: str,
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_path = str(nmap_path or "nmap").strip() or "nmap"
    raw_args = str(nmap_args or "").strip()
    try:
        extra_args = shlex.split(raw_args) if raw_args else []
    except ValueError as exc:
        raise ValueError(f"Invalid nmap arguments: {exc}") from exc

    selected_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
    selected_options = dict(scan_options or {})

    if selected_mode == "rfc1918_discovery":
        rfc_profile = str(selected_options.get("scan_profile", "quick") or "quick").strip().lower()
        default_ports = runtime.RFC1918_COMPREHENSIVE_TCP_PORTS if rfc_profile == "comprehensive" else runtime.INTERNAL_QUICK_RECON_TCP_PORTS
        options = normalize_scan_options(selected_options, {
            "discovery": True,
            "host_discovery_only": True,
            "skip_dns": True,
            "arp_ping": False,
            "force_pn": False,
            "timing": "T3",
            "top_ports": 0,
            "explicit_ports": default_ports,
            "scan_profile": rfc_profile,
            "chunk_concurrency": 1,
            "service_detection": False,
            "default_scripts": False,
            "os_detection": False,
        })
        options["chunk_concurrency"] = normalize_rfc_chunk_concurrency(
            runtime.__class__,
            options.get("chunk_concurrency", 1),
        )
        options["force_pn"] = False
        if bool(options.get("host_discovery_only", False)):
            options["explicit_ports"] = ""
        elif not str(options.get("explicit_ports", "") or "").strip():
            options["explicit_ports"] = default_ports
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="rfc1918_discovery",
            options=options,
            extra_args=extra_args,
        )

    if selected_mode == "easy":
        options = normalize_scan_options(selected_options, {
            "discovery": True,
            "skip_dns": True,
            "force_pn": False,
            "timing": "T3",
            "top_ports": 1000,
            "service_detection": True,
            "default_scripts": True,
            "os_detection": False,
            "aggressive": False,
            "full_ports": False,
            "vuln_scripts": False,
        })
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="easy",
            options=options,
            extra_args=extra_args,
        )

    if selected_mode == "hard":
        options = normalize_scan_options(selected_options, {
            "discovery": False,
            "skip_dns": True,
            "force_pn": False,
            "timing": "T4",
            "top_ports": 1000,
            "service_detection": True,
            "default_scripts": True,
            "os_detection": True,
            "aggressive": False,
            "full_ports": True,
            "vuln_scripts": False,
        })
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="hard",
            options=options,
            extra_args=extra_args,
        )

    if staged:
        stage1_prefix = f"{output_prefix}_stage1"
        stage2_prefix = f"{output_prefix}_stage2"
        stage1_cmd_prefix = nmap_output_prefix_for_command(stage1_prefix, resolved_path)
        stage2_cmd_prefix = nmap_output_prefix_for_command(stage2_prefix, resolved_path)

        stage1_tokens = [resolved_path, "-sn", *targets]
        stage1_tokens = append_nmap_stats_every(stage1_tokens, interval="15s")
        stage1_tokens.extend(["-oA", stage1_cmd_prefix])
        stage2_tokens = [resolved_path, "-sV", "-O"]
        if not bool(discovery):
            stage2_tokens.append("-Pn")
        stage2_tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
        stage2_tokens.extend(targets)
        stage2_tokens.extend(["-oA", stage2_cmd_prefix])

        stages = [
            {
                "tool_name": "nmap-stage1",
                "tab_title": "Nmap Stage 1 Discovery",
                "output_prefix": stage1_prefix,
                "xml_path": f"{stage1_prefix}.xml",
                "command": join_shell_tokens(stage1_tokens),
                "timeout": 1800,
            },
            {
                "tool_name": "nmap-stage2",
                "tab_title": "Nmap Stage 2 Service Scan",
                "output_prefix": stage2_prefix,
                "xml_path": f"{stage2_prefix}.xml",
                "command": join_shell_tokens(stage2_tokens),
                "timeout": 5400,
            },
        ]
        return {"xml_path": f"{stage2_prefix}.xml", "stages": stages}

    output_cmd_prefix = nmap_output_prefix_for_command(output_prefix, resolved_path)
    tokens = [resolved_path]
    if not bool(discovery):
        tokens.append("-Pn")
    tokens.extend(["-T4", "-sV", "-O"])
    tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
    tokens.extend(targets)
    tokens.extend(["-oA", output_cmd_prefix])
    stages = [{
        "tool_name": "nmap-scan",
        "tab_title": "Nmap Scan",
        "output_prefix": output_prefix,
        "xml_path": f"{output_prefix}.xml",
        "command": join_shell_tokens(tokens),
        "timeout": 5400,
    }]
    return {"xml_path": f"{output_prefix}.xml", "stages": stages}


def build_single_scan_plan(
        runtime,
        *,
        targets: List[str],
        nmap_path: str,
        output_prefix: str,
        mode: str,
        options: Dict[str, Any],
        extra_args: List[str],
) -> Dict[str, Any]:
    _ = runtime
    output_cmd_prefix = nmap_output_prefix_for_command(output_prefix, nmap_path)
    tokens = [nmap_path]

    discovery_enabled = bool(options.get("discovery", True))
    host_discovery_only = bool(options.get("host_discovery_only", False))
    skip_dns = bool(options.get("skip_dns", False))
    timing_value = normalize_timing(str(options.get("timing", "T3")))
    service_detection = bool(options.get("service_detection", False))
    default_scripts = bool(options.get("default_scripts", False))
    os_detection = bool(options.get("os_detection", False))
    aggressive = bool(options.get("aggressive", False))
    full_ports = bool(options.get("full_ports", False))
    vuln_scripts = bool(options.get("vuln_scripts", False))
    top_ports = normalize_top_ports(options.get("top_ports", 1000))
    explicit_ports = normalize_explicit_ports(options.get("explicit_ports", ""))
    arp_ping = bool(options.get("arp_ping", False))
    force_pn = bool(options.get("force_pn", False))

    if host_discovery_only:
        tokens.append("-sn")
        if skip_dns:
            tokens.append("-n")
        if arp_ping:
            tokens.append("-PR")
        tokens.append(f"-{timing_value}")
    else:
        if force_pn or not discovery_enabled:
            tokens.append("-Pn")
        if skip_dns:
            tokens.append("-n")
        tokens.append(f"-{timing_value}")
        if full_ports:
            tokens.append("-p-")
        elif explicit_ports:
            tokens.extend(["-p", explicit_ports])
        else:
            tokens.extend(["--top-ports", str(top_ports)])

        if aggressive:
            tokens.append("-A")
        else:
            if service_detection:
                tokens.append("-sV")
            if default_scripts:
                tokens.append("-sC")
            if os_detection:
                tokens.append("-O")

        if vuln_scripts:
            tokens.extend(["--script", "vuln"])

    tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
    tokens.extend(targets)
    tokens.extend(["-oA", output_cmd_prefix])

    tab_title = {
        "rfc1918_discovery": "Nmap RFC1918 Discovery",
        "easy": "Nmap Easy Scan",
        "hard": "Nmap Hard Scan",
    }.get(str(mode), "Nmap Scan")

    return {
        "xml_path": f"{output_prefix}.xml",
        "stages": [{
            "tool_name": f"nmap-{mode}",
            "tab_title": tab_title,
            "output_prefix": output_prefix,
            "xml_path": f"{output_prefix}.xml",
            "command": join_shell_tokens(tokens),
            "timeout": 7200 if mode == "hard" else 5400,
        }],
    }


def normalize_scan_options(options: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(defaults)
    merged.update(dict(options or {}))
    return merged


def normalize_timing(raw: str) -> str:
    value = str(raw or "T3").strip().upper()
    if not value.startswith("T"):
        value = f"T{value}"
    if value not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        return "T3"
    return value


def normalize_top_ports(raw: Any) -> int:
    try:
        value = int(raw)
    except Exception:
        return 1000
    return max(1, min(value, 65535))


def normalize_explicit_ports(raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    cleaned = ",".join(part.strip() for part in value.split(",") if part.strip())
    if not cleaned:
        return ""
    if not re.fullmatch(r"[0-9,\-]+", cleaned):
        return ""
    return cleaned


def contains_nmap_stats_every(args: List[str]) -> bool:
    for token in args:
        value = str(token or "").strip().lower()
        if value == "--stats-every" or value.startswith("--stats-every="):
            return True
    return False


def contains_nmap_verbose(args: List[str]) -> bool:
    for token in args:
        value = str(token or "").strip().lower()
        if value in {"-v", "-vv", "-vvv", "--verbose"}:
            return True
    return False


def append_nmap_stats_every(args: List[str], interval: str = "15s") -> List[str]:
    values = [str(item) for item in list(args or [])]
    if not contains_nmap_stats_every(values):
        values = values + ["--stats-every", str(interval or "15s")]
    if contains_nmap_stats_every(values) and not contains_nmap_verbose(values):
        values = values + ["-vv"]
    return values


def nmap_output_prefix_for_command(output_prefix: str, nmap_path: str) -> str:
    if is_wsl() and str(nmap_path).lower().endswith(".exe"):
        return to_windows_path(output_prefix)
    return output_prefix


def join_shell_tokens(tokens: List[str]) -> str:
    rendered = [str(token) for token in tokens]
    if os.name == "nt":
        return subprocess.list2cmdline(rendered)
    if hasattr(shlex, "join"):
        return shlex.join(rendered)
    return " ".join(shlex.quote(token) for token in rendered)

