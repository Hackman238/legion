from __future__ import annotations

import re
from typing import Any, List, Set

from app.web import runtime_scheduler_state as web_runtime_scheduler_state


MISSING_NSE_SCRIPT_RE = re.compile(
    r"'([a-z][a-z0-9_.-]+\.nse)'\s+did not match a category, filename, or directory",
    flags=re.IGNORECASE,
)
PYTHON_TOOL_IMPORT_FAILURE_RE = re.compile(
    r"(?:^|\n)\s*(?:modulenotfounderror|importerror):",
    flags=re.IGNORECASE,
)
SCHEDULER_METHOD_PATH_RE = re.compile(
    r"\b(?:get|post|head|options|put|delete|patch)\b[^\n]{0,96}\s/[a-z0-9._~!$&'()*+,;=:@%/\-?]*",
    flags=re.IGNORECASE,
)
SCHEDULER_STATUS_PATH_RE = re.compile(
    r"\b\d{3}\b[^\n]{0,48}\s/[a-z0-9._~!$&'()*+,;=:@%/\-?]*",
    flags=re.IGNORECASE,
)


def truncate_scheduler_text(value: Any, max_chars: int) -> str:
    text_value = str(value or "").replace("\r", " ").replace("\x00", " ")
    text_value = " ".join(text_value.split())
    if len(text_value) <= int(max_chars):
        return text_value
    return text_value[:int(max_chars)].rstrip() + "...[truncated]"


def scheduler_output_lines(value: Any, *, max_line_chars: int = 240, max_lines: int = 320) -> List[str]:
    raw_value = str(value or "").replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
    lines: List[str] = []
    for raw_line in raw_value.split("\n"):
        cleaned = " ".join(str(raw_line or "").split()).strip()
        if not cleaned:
            continue
        if len(cleaned) > int(max_line_chars):
            cleaned = cleaned[:int(max_line_chars)].rstrip() + "...[truncated]"
        lines.append(cleaned)
        if len(lines) >= int(max_lines):
            break
    return lines


def scheduler_line_signal_score(value: Any) -> int:
    line = str(value or "").strip()
    if not line:
        return 0
    lowered = line.lower()
    score = 0
    if web_runtime_scheduler_state.CVE_TOKEN_RE.search(line):
        score += 4
    if web_runtime_scheduler_state.CPE22_TOKEN_RE.search(line) or web_runtime_scheduler_state.CPE23_TOKEN_RE.search(line):
        score += 4
    if "http://" in lowered or "https://" in lowered:
        score += 2
    if SCHEDULER_METHOD_PATH_RE.search(line) or SCHEDULER_STATUS_PATH_RE.search(line):
        score += 3
    for token in (
            "server:",
            "x-powered-by:",
            "location:",
            "allow:",
            "title:",
            "set-cookie:",
            "content-type:",
            "vulnerable",
            "vulnerability",
            "found",
            "interesting",
            "detected",
            "warning",
            "error",
            "exception",
            "traceback",
            "timeout",
            "redirect",
            "wordpress",
            "wp-content",
            "wp-json",
            "jetty",
            "nginx",
            "apache",
            "traccar",
            "pihole",
            "pi-hole",
            "webdav",
            "propfind",
            "tls",
            "ssl",
            "certificate",
            "waf",
            "plugin",
            "theme",
    ):
        if token in lowered:
            score += 1
    return score


def build_scheduler_excerpt(
        value: Any,
        max_chars: int,
        *,
        multiline: bool,
        head_lines: int,
        signal_lines: int,
        tail_lines: int,
        max_line_chars: int,
) -> str:
    lines = scheduler_output_lines(
        value,
        max_line_chars=max_line_chars,
        max_lines=400 if multiline else 260,
    )
    if not lines:
        return ""
    separator = "\n" if multiline else " | "
    joined = separator.join(lines)
    if len(joined) <= int(max_chars):
        return joined

    selected: List[str] = []
    seen: Set[str] = set()

    def _add(line: str) -> None:
        token = str(line or "").strip()
        key = token.lower()
        if not token or key in seen:
            return
        seen.add(key)
        selected.append(token)

    for line in lines[:int(head_lines)]:
        _add(line)

    middle_start = int(head_lines)
    middle_end = len(lines) - int(tail_lines) if int(tail_lines) > 0 else len(lines)
    middle = lines[middle_start:middle_end]
    scored_middle = [
        (scheduler_line_signal_score(line), index, line)
        for index, line in enumerate(middle)
    ]
    scored_middle = [item for item in scored_middle if item[0] > 0]
    scored_middle.sort(key=lambda item: (-item[0], item[1]))
    for _, _, line in scored_middle[:int(signal_lines)]:
        _add(line)

    if len(selected) <= int(head_lines) and middle:
        _add(middle[0])

    if int(tail_lines) > 0:
        for line in lines[-int(tail_lines):]:
            _add(line)

    rendered = separator.join(selected)
    if not rendered:
        rendered = joined

    truncated = len(selected) < len(lines) or len(joined) > int(max_chars)
    marker = "\n...[truncated]" if multiline else " ...[truncated]"
    if truncated and len(rendered) + len(marker) <= int(max_chars):
        return rendered + marker
    if len(rendered) <= int(max_chars):
        return rendered
    budget = max(0, int(max_chars) - len(marker))
    if budget <= 0:
        return marker.strip()
    if multiline and budget >= 80:
        body_budget = max(0, budget - 1)
        head_budget = max(40, body_budget // 2)
        tail_budget = max(20, body_budget - head_budget)
        return (
            rendered[:head_budget].rstrip()
            + marker
            + "\n"
            + rendered[-tail_budget:].lstrip()
        )
    return rendered[:budget].rstrip() + marker


def build_scheduler_prompt_excerpt(value: Any, max_chars: int) -> str:
    return build_scheduler_excerpt(
        value,
        max_chars,
        multiline=False,
        head_lines=2,
        signal_lines=6,
        tail_lines=1,
        max_line_chars=220,
    )


def build_scheduler_analysis_excerpt(value: Any, max_chars: int) -> str:
    return build_scheduler_excerpt(
        value,
        max_chars,
        multiline=True,
        head_lines=3,
        signal_lines=10,
        tail_lines=2,
        max_line_chars=260,
    )


def scheduler_tool_alias_tokens(tool_id: Any) -> Set[str]:
    token = str(tool_id or "").strip().lower()
    if not token:
        return set()
    aliases = {token}
    if token in {"whatweb", "whatweb-http", "whatweb-https"}:
        aliases.update({"whatweb", "whatweb-http", "whatweb-https"})
    elif token.endswith(".nse"):
        aliases.add("nmap")
    return aliases


def extract_unavailable_tool_tokens(text: Any) -> Set[str]:
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized:
        return set()

    found = set()
    patterns = (
        r"(?:^|\n)\s*(?:/bin/sh|bash|zsh|sh|fish):\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*):\s*(?:command not found|not found)(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+command not found(?:\s|$)",
        r"(?:^|\n)\s*([a-z][a-z0-9._+-]*)\s+not found(?:\s|$)",
    )
    for pattern in patterns:
        for match in re.findall(pattern, normalized):
            token = str(match or "").strip().lower()
            if token:
                found.add(token[:48])
    return found


def extract_missing_nse_script_tokens(text: Any) -> Set[str]:
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized:
        return set()
    return {
        str(match or "").strip().lower()[:96]
        for match in MISSING_NSE_SCRIPT_RE.findall(normalized)
        if str(match or "").strip()
    }


def looks_like_local_tool_dependency_failure(text: Any) -> bool:
    normalized = str(text or "").replace("\r", "\n").strip().lower()
    if not normalized or "traceback" not in normalized:
        return False
    return bool(PYTHON_TOOL_IMPORT_FAILURE_RE.search(normalized))


def scheduler_banner_from_evidence(source_id: Any, text_value: Any) -> str:
    source = str(source_id or "").strip().lower()
    if not source:
        return ""

    interesting = (
        source == "banner"
        or source.startswith("banner-")
        or source in {
            "http-title",
            "http-server-header",
            "ssl-cert",
            "ssh-hostkey",
            "smb-os-discovery",
            "fingerprint-strings",
            "smtp-commands",
            "imap-capabilities",
            "pop3-capabilities",
        }
    )
    if not interesting:
        return ""

    cleaned = truncate_scheduler_text(text_value, 280)
    if not cleaned:
        return ""
    if cleaned.lower().startswith("starting nmap"):
        return ""
    return cleaned


def scheduler_service_banner_fallback(*, service_name: str, product: str, version: str, extrainfo: str) -> str:
    parts = []
    product_value = str(product or "").strip()
    version_value = str(version or "").strip()
    extra_value = str(extrainfo or "").strip()
    service_value = str(service_name or "").strip()

    if product_value:
        parts.append(product_value)
    if version_value and version_value.lower() not in product_value.lower():
        parts.append(version_value)
    if extra_value:
        parts.append(extra_value)
    if not parts and service_value:
        parts.append(service_value)

    if not parts:
        return ""
    return truncate_scheduler_text(" ".join(parts), 200)
