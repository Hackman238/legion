from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional, Tuple

import psutil

from app.timing import getTimestamp

_NMAP_PROGRESS_PERCENT_RE = re.compile(r"About\s+([0-9]+(?:\.[0-9]+)?)%\s+done", flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_PAREN_RE = re.compile(r"\(([^)]*?)\s+remaining\)", flags=re.IGNORECASE)
_NMAP_PROGRESS_PERCENT_ATTR_RE = re.compile(r'percent=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NMAP_PROGRESS_REMAINING_ATTR_RE = re.compile(r'remaining=["\']([0-9]+(?:\.[0-9]+)?)["\']', flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ELAPSED_RE = re.compile(r"^\[([0-9:]+)\]", flags=re.IGNORECASE)
_TSHARK_DURATION_RE = re.compile(r"\bduration:(\d+)\b", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_REQUESTS_RE = re.compile(
    r"Requests:\s*([0-9]+)\s*/\s*([0-9]+)(?:\s*\(([0-9]+(?:\.[0-9]+)?)%\))?",
    flags=re.IGNORECASE,
)
_NUCLEI_PROGRESS_RPS_RE = re.compile(r"RPS:\s*([0-9]+(?:\.[0-9]+)?)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_MATCHED_RE = re.compile(r"Matched:\s*([0-9]+)", flags=re.IGNORECASE)
_NUCLEI_PROGRESS_ERRORS_RE = re.compile(r"Errors:\s*([0-9]+)", flags=re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
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


def coerce_float(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def format_duration_label(total_seconds: Any) -> str:
    try:
        parsed = int(float(total_seconds))
    except (TypeError, ValueError):
        return ""
    if parsed <= 0:
        return ""
    hours = parsed // 3600
    minutes = (parsed % 3600) // 60
    seconds = parsed % 60
    if hours > 0:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds:02d}s"


def normalize_progress_source_label(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered == "nmap":
        return "Nmap"
    if lowered == "nuclei":
        return "Nuclei"
    if lowered == "tshark":
        return "TShark"
    return raw


def build_process_progress_payload(
        *,
        status: Any = "",
        percent: Any = "",
        estimated_remaining: Any = None,
        elapsed: Any = 0,
        progress_message: Any = "",
        progress_source: Any = "",
        progress_updated_at: Any = "",
) -> Dict[str, Any]:
    percent_numeric = coerce_float(percent)
    percent_display = f"{percent_numeric:.1f}%" if percent_numeric is not None else ""
    eta_seconds = None
    try:
        if estimated_remaining not in ("", None):
            eta_seconds = max(0, int(float(estimated_remaining)))
    except (TypeError, ValueError):
        eta_seconds = None
    elapsed_seconds = None
    try:
        if elapsed not in ("", None):
            elapsed_seconds = max(0, int(float(elapsed)))
    except (TypeError, ValueError):
        elapsed_seconds = None
    message_text = str(progress_message or "").strip()
    source_text = normalize_progress_source_label(progress_source)
    updated_at_text = str(progress_updated_at or "").strip()
    summary_parts = []
    if percent_display:
        summary_parts.append(percent_display)
    eta_label = format_duration_label(eta_seconds)
    if eta_label:
        summary_parts.append(f"ETA {eta_label}")
    if message_text:
        summary_parts.append(message_text)
    elif elapsed_seconds and str(status or "").strip().lower() == "running":
        elapsed_label = format_duration_label(elapsed_seconds)
        if elapsed_label:
            summary_parts.append(f"Elapsed {elapsed_label}")
    return {
        "active": bool(summary_parts or source_text or updated_at_text),
        "summary": " | ".join(summary_parts),
        "percent": f"{percent_numeric:.1f}" if percent_numeric is not None else "",
        "percent_display": percent_display,
        "estimated_remaining": eta_seconds,
        "estimated_remaining_display": eta_label,
        "elapsed": elapsed_seconds,
        "elapsed_display": format_duration_label(elapsed_seconds),
        "message": message_text,
        "source": source_text,
        "updated_at": updated_at_text,
    }


def process_progress_adapter_for_command(runtime_or_cls, tool_name: str, command: str) -> str:
    if runtime_or_cls._is_nmap_command(tool_name, command):
        return "nmap"
    if runtime_or_cls._is_nuclei_command(tool_name, command):
        return "nuclei"
    if runtime_or_cls._is_tshark_passive_capture_command(tool_name, command):
        return "tshark"
    return ""


def estimate_remaining_from_percent(runtime_seconds: float, percent: Optional[float]) -> Optional[int]:
    try:
        elapsed = max(0.0, float(runtime_seconds or 0.0))
    except (TypeError, ValueError):
        elapsed = 0.0
    if elapsed <= 0.0 or percent is None:
        return None
    bounded = max(0.0, min(float(percent), 100.0))
    if bounded <= 0.0 or bounded >= 100.0:
        return None
    fraction = bounded / 100.0
    total = elapsed / fraction
    return max(0, int(total - elapsed))


def extract_progress_line(text: str, predicate) -> str:
    cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
    for raw_line in reversed(cleaned.splitlines()):
        line = str(raw_line or "").strip()
        if line and predicate(line):
            return line[:240]
    return ""


def extract_nmap_progress_message(text: str) -> str:
    return extract_progress_line(
        text,
        lambda line: bool(
            _NMAP_PROGRESS_PERCENT_RE.search(line)
            or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(line)
            or _NMAP_PROGRESS_REMAINING_PAREN_RE.search(line)
            or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(line)
        ),
    )


def extract_nuclei_progress_from_text(
        text: str,
        runtime_seconds: float,
) -> Tuple[Optional[float], Optional[int], str]:
    cleaned = _ANSI_ESCAPE_RE.sub("", str(text or ""))
    if not cleaned:
        return None, None, ""

    for raw_line in reversed(cleaned.splitlines()):
        line = str(raw_line or "").strip()
        if not line or "requests:" not in line.lower():
            continue
        requests_match = _NUCLEI_PROGRESS_REQUESTS_RE.search(line)
        if not requests_match:
            continue
        try:
            completed = int(requests_match.group(1))
            total = int(requests_match.group(2))
        except Exception:
            continue
        percent = None
        percent_group = requests_match.group(3)
        if percent_group not in (None, ""):
            try:
                percent = float(percent_group)
            except Exception:
                percent = None
        if percent is None and total > 0:
            percent = max(0.0, min((float(completed) / float(total)) * 100.0, 100.0))

        elapsed_seconds = runtime_seconds
        elapsed_match = _NUCLEI_PROGRESS_ELAPSED_RE.search(line)
        if elapsed_match:
            parsed_elapsed = parse_duration_seconds(elapsed_match.group(1))
            if parsed_elapsed is not None:
                elapsed_seconds = float(parsed_elapsed)
        remaining = estimate_remaining_from_percent(elapsed_seconds, percent)

        parts = [f"Requests {completed}/{total}"]
        rps_match = _NUCLEI_PROGRESS_RPS_RE.search(line)
        if rps_match:
            parts.append(f"RPS {rps_match.group(1)}")
        matched_match = _NUCLEI_PROGRESS_MATCHED_RE.search(line)
        if matched_match:
            parts.append(f"Matches {matched_match.group(1)}")
        errors_match = _NUCLEI_PROGRESS_ERRORS_RE.search(line)
        if errors_match:
            parts.append(f"Errors {errors_match.group(1)}")
        return percent, remaining, " | ".join(parts)[:240]
    return None, None, ""


def extract_tshark_passive_progress(
        command: str,
        runtime_seconds: float,
) -> Tuple[Optional[float], Optional[int], str]:
    duration_match = _TSHARK_DURATION_RE.search(str(command or ""))
    if not duration_match:
        return None, None, ""
    try:
        total_seconds = max(1, int(duration_match.group(1)))
    except (TypeError, ValueError):
        return None, None, ""
    try:
        elapsed_seconds = max(0.0, float(runtime_seconds or 0.0))
    except (TypeError, ValueError):
        elapsed_seconds = 0.0
    bounded_elapsed = min(elapsed_seconds, float(total_seconds))
    percent = max(0.0, min((bounded_elapsed / float(total_seconds)) * 100.0, 100.0))
    remaining = max(0, int(round(float(total_seconds) - bounded_elapsed)))
    elapsed_label = format_duration_label(int(bounded_elapsed))
    message = f"Elapsed {elapsed_label}" if elapsed_label else ""
    return percent, remaining, message[:240]


def update_process_progress(
        runtime,
        process_repo,
        *,
        process_id: int,
        tool_name: str,
        command: str,
        text_chunk: str,
        runtime_seconds: float,
        state: Dict[str, Any],
):
    adapter = str(state.get("adapter", "") or "").strip().lower()
    if not adapter:
        return

    raw_chunk = str(text_chunk or "")
    percent = None
    remaining = None
    message = ""
    source = adapter
    clear_remaining_on_partial = False

    if adapter == "nmap":
        percent, remaining = extract_nmap_progress_from_text(raw_chunk)
        message = extract_nmap_progress_message(raw_chunk)
        clear_remaining_on_partial = bool(
            (_NMAP_PROGRESS_PERCENT_RE.search(raw_chunk) or _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw_chunk))
            and not (_NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw_chunk) or _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw_chunk))
        )
    elif adapter == "nuclei":
        percent, remaining, message = extract_nuclei_progress_from_text(
            raw_chunk,
            runtime_seconds=runtime_seconds,
        )
    elif adapter == "tshark":
        percent, remaining, message = extract_tshark_passive_progress(
            command,
            runtime_seconds=runtime_seconds,
        )
    else:
        return

    if percent is None and remaining is None and not message:
        return

    changed = False
    percent_value = state.get("percent")
    remaining_value = state.get("remaining")
    message_value = str(state.get("message", "") or "")
    source_value = str(state.get("source", "") or "")

    if percent is not None:
        bounded = max(0.0, min(float(percent), 100.0))
        if percent_value is None or abs(float(percent_value) - bounded) >= 0.1:
            percent_value = bounded
            state["percent"] = bounded
            changed = True

    if remaining is not None:
        bounded_remaining = max(0, int(remaining))
        if remaining_value is None or abs(int(remaining_value) - bounded_remaining) >= 5:
            remaining_value = bounded_remaining
            state["remaining"] = bounded_remaining
            changed = True
    elif clear_remaining_on_partial and remaining_value is not None:
        remaining_value = None
        state["remaining"] = None
        changed = True

    if message and message != message_value:
        message_value = message
        state["message"] = message
        changed = True

    if source != source_value:
        source_value = source
        state["source"] = source
        changed = True

    now = time.monotonic()
    last_update = float(state.get("updated_at", 0.0) or 0.0)
    if not changed and (now - last_update) < 10.0:
        return

    try:
        process_repo.storeProcessProgress(
            str(int(process_id)),
            percent=f"{percent_value:.1f}" if percent_value is not None else None,
            estimated_remaining=remaining_value,
            progress_message=message_value,
            progress_source=source_value,
            progress_updated_at=getTimestamp(True),
        )
        state["updated_at"] = now
        runtime._emit_ui_invalidation("processes", throttle_seconds=5.0)
    except Exception:
        pass


def update_nmap_process_progress(
        runtime,
        process_repo,
        *,
        process_id: int,
        text_chunk: str,
        state: Dict[str, Any],
):
    percent, remaining = extract_nmap_progress_from_text(text_chunk)
    if percent is None and remaining is None:
        return

    changed = False
    percent_value = state.get("percent")
    remaining_value = state.get("remaining")
    if percent is not None:
        bounded = max(0.0, min(float(percent), 100.0))
        if percent_value is None or abs(float(percent_value) - bounded) >= 0.1:
            percent_value = bounded
            state["percent"] = bounded
            changed = True
    if remaining is not None:
        bounded_remaining = max(0, int(remaining))
        if remaining_value is None or int(remaining_value) != bounded_remaining:
            remaining_value = bounded_remaining
            state["remaining"] = bounded_remaining
            changed = True
    elif remaining_value is not None:
        remaining_value = None
        state["remaining"] = None
        changed = True

    now = time.monotonic()
    last_update = float(state.get("updated_at", 0.0) or 0.0)
    if not changed and (now - last_update) < 10.0:
        return

    process_repo.storeProcessProgress(
        str(int(process_id)),
        percent=f"{percent_value:.1f}" if percent_value is not None else None,
        estimated_remaining=remaining_value,
    )
    state["updated_at"] = now
    runtime._emit_ui_invalidation("processes", throttle_seconds=5.0)


def extract_nmap_progress_from_text(text: str) -> Tuple[Optional[float], Optional[int]]:
    raw = str(text or "")
    if not raw:
        return None, None

    percent = None
    remaining_seconds = None

    percent_match = _NMAP_PROGRESS_PERCENT_RE.search(raw)
    if percent_match:
        try:
            percent = float(percent_match.group(1))
        except Exception:
            percent = None

    if percent is None:
        percent_attr_match = _NMAP_PROGRESS_PERCENT_ATTR_RE.search(raw)
        if percent_attr_match:
            try:
                percent = float(percent_attr_match.group(1))
            except Exception:
                percent = None

    remaining_match = _NMAP_PROGRESS_REMAINING_PAREN_RE.search(raw)
    if remaining_match:
        remaining_seconds = parse_duration_seconds(remaining_match.group(1))

    if remaining_seconds is None:
        remaining_attr_match = _NMAP_PROGRESS_REMAINING_ATTR_RE.search(raw)
        if remaining_attr_match:
            try:
                remaining_seconds = int(float(remaining_attr_match.group(1)))
            except Exception:
                remaining_seconds = None

    return percent, remaining_seconds


def parse_duration_seconds(raw: str) -> Optional[int]:
    text_value = str(raw or "").strip()
    if not text_value:
        return None

    if text_value.isdigit():
        return int(text_value)

    parts = text_value.split(":")
    if not all(part.isdigit() for part in parts):
        return None
    if len(parts) == 2:
        minutes, seconds = [int(part) for part in parts]
        return (minutes * 60) + seconds
    if len(parts) == 3:
        hours, minutes, seconds = [int(part) for part in parts]
        return (hours * 3600) + (minutes * 60) + seconds
    return None
