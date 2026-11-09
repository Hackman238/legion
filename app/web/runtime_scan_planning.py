from __future__ import annotations

import logging
import os
import shutil
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

log = logging.getLogger(__name__)

OS_DETECTION_DROPPED_MESSAGE = (
    "nmap cannot use raw sockets here (not running as root): OS detection is left out of the scan plan. "
    "Set NMAP_PRIVILEGED=1 if nmap has the capability anyway (setcap, docker --cap-add NET_RAW)."
)


def can_raw_socket(nmap_path: str = "") -> bool:
    """Whether nmap may use raw sockets here.

    OS detection (-O, and -A which includes it) makes an unprivileged nmap quit outright, so plans built
    without privilege leave those flags out and the scan degrades to a connect scan instead of failing.
    Root (or no euid concept, e.g. Windows) counts as privileged, and so does Windows nmap.exe driven from
    WSL: Npcap grants it raw sockets whatever the WSL user's euid is. Capabilities (docker --cap-add NET_RAW
    as a non-root user, setcap on the nmap binary) cannot be seen from the euid, so nmap's own environment
    overrides are honoured: NMAP_PRIVILEGED asserts privilege, NMAP_UNPRIVILEGED denies it.
    """
    if os.environ.get("NMAP_UNPRIVILEGED"):
        return False
    if os.environ.get("NMAP_PRIVILEGED"):
        return True
    if str(nmap_path or "").lower().endswith(".exe") and is_wsl():
        return True
    return not hasattr(os, "geteuid") or os.geteuid() == 0


_os_detection_warned = False


def reset_os_detection_warning() -> None:
    """Let the next dropped OS detection warn again (tests, or after the privilege situation changed)."""
    global _os_detection_warned
    _os_detection_warned = False


def os_detection_allowed(nmap_path: str = "") -> bool:
    """can_raw_socket for a plan that wants OS detection.

    When it is dropped the reason is logged once per process: the host's privilege does not change between
    plans, and a chunked RFC1918 sweep builds one plan per chunk.
    """
    global _os_detection_warned
    if can_raw_socket(nmap_path):
        return True
    if not _os_detection_warned:
        _os_detection_warned = True
        log.warning(OS_DETECTION_DROPPED_MESSAGE)
    return False


def default_nmap_path(runtime) -> str:
    """The configured nmap path when it points at a real file, else plain `nmap` from PATH."""
    try:
        configured = str(getattr(runtime._get_settings(), "tools_path_nmap", "") or "").strip()
    except Exception:
        configured = ""
    if configured and (os.path.isfile(configured) or shutil.which(configured)):
        return configured
    return "nmap"

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
    resolved_path = str(nmap_path or "").strip() or default_nmap_path(runtime)
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
        return build_staged_scan_plan(
            nmap_path=resolved_path,
            targets=list(targets),
            output_prefix=output_prefix,
            discovery=bool(discovery),
            extra_args=extra_args,
            stage_specs=staged_stage_specs(runtime._get_settings()),
        )

    output_cmd_prefix = nmap_output_prefix_for_command(output_prefix, resolved_path)
    tokens = [resolved_path]
    if not bool(discovery):
        tokens.append("-Pn")
    tokens.extend(["-T4", "-sV"])
    if os_detection_allowed(resolved_path):
        tokens.append("-O")
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



STAGE_SETTING_NAMES = tuple(f"tools_nmap_stage{index}_ports" for index in range(1, 7))


def staged_stage_specs(settings) -> List[str]:
    """The raw [StagedNmapSettings] stage values (stage1-ports .. stage6-ports), skipping blanks."""
    specs: List[str] = []
    for name in STAGE_SETTING_NAMES:
        value = str(getattr(settings, name, "") or "").strip().strip('"')
        if value:
            specs.append(value)
    return specs


def parse_stage_spec(value: str) -> Dict[str, Any]:
    """Interpret one stage value.

    Accepted forms: ``PORTS|T:80,443,U:161`` or ``T:80,443`` (a port stage) and ``NSE|vulners`` or
    ``Vulners,CVE`` (a script stage; tokens that are not NSE script names, such as CVE, are dropped).
    """
    text_value = str(value or "").strip().strip('"')
    kind_hint = ""
    if "|" in text_value:
        kind_hint, text_value = [part.strip() for part in text_value.split("|", 1)]
    looks_like_ports = bool(re.fullmatch(r"[TU]?:?[0-9,\-TU:\s]+", text_value)) and any(ch.isdigit() for ch in text_value)
    if kind_hint.upper() == "NSE" or (kind_hint.upper() != "PORTS" and not looks_like_ports):
        scripts = []
        for token in re.split(r"[,\s]+", text_value):
            token = token.strip().lower()
            if token and token != "cve" and re.fullmatch(r"[a-z0-9_.*+-]+", token):
                scripts.append(token)
        return {"kind": "scripts", "scripts": scripts}
    ports = ",".join(part.strip() for part in text_value.split(",") if part.strip())
    return {"kind": "ports", "ports": ports}


def build_staged_scan_plan(
        *,
        nmap_path: str,
        targets: List[str],
        output_prefix: str,
        discovery: bool,
        extra_args: List[str],
        stage_specs: List[str],
) -> Dict[str, Any]:
    """A host-discovery sweep followed by the configured port and script stages; every stage's XML is imported.

    Port stages run service detection (OS detection on the first one); a script stage runs its NSE scripts against
    every port the earlier stages covered, so vulners sees the versions found so far.
    """
    stages: List[Dict[str, Any]] = []
    scanned_port_specs: List[str] = []

    def _stage(name: str, title: str, tokens: List[str], timeout: int) -> Dict[str, Any]:
        prefix = f"{output_prefix}_{name}"
        command_tokens = list(tokens)
        command_tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
        command_tokens.extend(targets)
        command_tokens.extend(["-oA", nmap_output_prefix_for_command(prefix, nmap_path)])
        return {
            "tool_name": f"nmap-{name}",
            "tab_title": title,
            "output_prefix": prefix,
            "xml_path": f"{prefix}.xml",
            "command": join_shell_tokens(command_tokens),
            "timeout": int(timeout),
        }

    if discovery:
        stages.append(_stage("stage0-discovery", "Nmap Host Discovery", [nmap_path, "-sn"], 1800))

    port_stage_index = 0
    for index, raw_spec in enumerate(stage_specs, start=1):
        spec = parse_stage_spec(raw_spec)
        base = [nmap_path]
        if not discovery:
            base.append("-Pn")
        if spec["kind"] == "ports":
            if not spec["ports"]:
                continue
            port_stage_index += 1
            tokens = base + ["-sV"]
            if port_stage_index == 1 and os_detection_allowed(nmap_path):  # only the first port stage wants -O
                tokens.append("-O")
            tokens.extend(["-p", spec["ports"]])
            scanned_port_specs.append(spec["ports"])
            stages.append(_stage(f"stage{index}", f"Nmap Stage {index}: ports {spec['ports'][:40]}", tokens, 5400))
        else:
            if not spec["scripts"]:
                continue
            tokens = base + ["-sV", "--script", ",".join(spec["scripts"])]
            if scanned_port_specs:
                tokens.extend(["-p", ",".join(scanned_port_specs)])
            stages.append(_stage(f"stage{index}", f"Nmap Stage {index}: {', '.join(spec['scripts'])}", tokens, 5400))

    if not stages:  # nothing configured: fall back to one service scan
        fallback = [nmap_path] + ([] if discovery else ["-Pn"]) + ["-sV"]
        if os_detection_allowed(nmap_path):
            fallback.append("-O")
        stages.append(_stage("stage1", "Nmap Service Scan", fallback, 5400))
    return {"xml_path": stages[-1]["xml_path"], "stages": stages, "import_each_stage": True}

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

        privileged = os_detection_allowed(nmap_path) if (aggressive or os_detection) else False
        if aggressive and privileged:
            tokens.append("-A")
        else:
            # Without raw sockets -A and -O make nmap quit; an aggressive request degrades to its
            # unprivileged subset (service detection and default scripts).
            if service_detection or aggressive:
                tokens.append("-sV")
            if default_scripts or aggressive:
                tokens.append("-sC")
            if os_detection and privileged:
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

