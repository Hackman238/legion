from __future__ import annotations

import re
from typing import Any, Optional, Tuple

import psutil

from app.web.runtime_process_progress import (
    build_process_progress_payload,
    coerce_float,
    estimate_remaining_from_percent,
    extract_nmap_progress_from_text,
    extract_nmap_progress_message,
    extract_nuclei_progress_from_text,
    extract_progress_line,
    extract_tshark_passive_progress,
    format_duration_label,
    normalize_progress_source_label,
    parse_duration_seconds,
    process_progress_adapter_for_command,
    update_nmap_process_progress,
    update_process_progress,
)

_TSHARK_DURATION_RE = re.compile(r"\bduration:(\d+)\b", flags=re.IGNORECASE)
_COMMAND_SECRET_PATTERNS = (
    re.compile(
        r"(?P<prefix>\b(?:[A-Z][A-Z0-9_]*API_KEY|[A-Z][A-Z0-9_]*TOKEN|AUTHORIZATION)=)"
        r"(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))"
    ),
    re.compile(
        r"(?P<prefix>\B--api-key\s+)(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<prefix>\B--?(?:access-)?token\s+)(?P<value>(?:'[^']*'|\"[^\"]*\"|[^\s;&|)]+))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+\\/-]+)",
        re.IGNORECASE,
    ),
)


def redact_command_secrets(value: Any) -> str:
    text_value = str(value or "")
    if not text_value:
        return ""

    def _replace(match: re.Match) -> str:
        prefix = str(match.group("prefix") or "")
        secret_value = str(match.group("value") or "")
        stripped = secret_value.strip()
        lowered = stripped.lower()
        if not stripped:
            return match.group(0)
        if "***redacted***" in lowered:
            return match.group(0)
        if stripped.startswith("[") and stripped.endswith("]"):
            return match.group(0)
        return f"{prefix}***redacted***"

    redacted = text_value
    for pattern in _COMMAND_SECRET_PATTERNS:
        redacted = pattern.sub(_replace, redacted)
    return redacted


def is_nmap_command(tool_name: str, command: str) -> bool:
    name = str(tool_name or "").strip().lower()
    if name.startswith("nmap"):
        return True
    command_text = str(command or "").strip().lower()
    return " nmap " in f" {command_text} " or command_text.startswith("nmap ")


def is_nuclei_command(tool_name: str, command: str) -> bool:
    name = str(tool_name or "").strip().lower()
    if name.startswith("nuclei"):
        return True
    command_text = str(command or "").strip().lower()
    return " nuclei " in f" {command_text} " or command_text.startswith("nuclei ")


def is_tshark_passive_capture_command(tool_name: str, command: str) -> bool:
    name = str(tool_name or "").strip().lower()
    if name == "tshark-passive-capture":
        return True
    command_text = str(command or "").strip().lower()
    if not command_text:
        return False
    return (
        (" tshark " in f" {command_text} " or command_text.startswith("tshark "))
        and bool(_TSHARK_DURATION_RE.search(command_text))
    )


def sample_process_tree_activity(proc) -> Optional[Tuple[float, int]]:
    if proc is None or int(getattr(proc, "pid", 0) or 0) <= 0:
        return None
    try:
        root = psutil.Process(int(proc.pid))
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, ValueError):
        return None

    cpu_total = 0.0
    io_total = 0
    seen_pids = set()
    processes = [root]
    try:
        processes.extend(root.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        pass

    for current in processes:
        try:
            pid = int(current.pid)
        except Exception:
            continue
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        try:
            cpu_times = current.cpu_times()
            cpu_total += float(getattr(cpu_times, "user", 0.0) or 0.0)
            cpu_total += float(getattr(cpu_times, "system", 0.0) or 0.0)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
        try:
            io_counters = current.io_counters()
            if io_counters is not None:
                read_chars = getattr(io_counters, "read_chars", None)
                write_chars = getattr(io_counters, "write_chars", None)
                if read_chars is not None or write_chars is not None:
                    io_total += int(read_chars or 0) + int(write_chars or 0)
                else:
                    io_total += int(getattr(io_counters, "read_bytes", 0) or 0)
                    io_total += int(getattr(io_counters, "write_bytes", 0) or 0)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, AttributeError):
            pass
    return round(cpu_total, 4), int(io_total)


def process_tree_activity_changed(
        previous: Optional[Tuple[float, int]],
        current: Optional[Tuple[float, int]],
) -> bool:
    if previous is None or current is None:
        return False
    try:
        prev_cpu, prev_io = previous
        cur_cpu, cur_io = current
    except Exception:
        return False
    return float(cur_cpu) > float(prev_cpu) or int(cur_io) > int(prev_io)
