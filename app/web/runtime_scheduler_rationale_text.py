from __future__ import annotations

import json
import re
from typing import Any, List


def safe_json_loads(value: Any) -> Any:
    text_value = str(value or "").strip()
    if not text_value:
        return None
    try:
        return json.loads(text_value)
    except Exception:
        return None


def dedupe_text_tokens(values: Any, *, limit: int = 12) -> List[str]:
    seen = set()
    items: List[str] = []
    for item in list(values or []):
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        items.append(token)
        if len(items) >= int(limit):
            break
    return items


def truncate_rationale_text(value: Any, max_chars: int = 180) -> str:
    text_value = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text_value) <= int(max_chars):
        return text_value
    return text_value[:max_chars].rstrip() + "..."


def rationale_list_text(values: Any, *, limit: int = 6) -> str:
    items = dedupe_text_tokens(values, limit=64)
    if not items:
        return ""
    if len(items) <= int(limit):
        return ", ".join(items)
    remaining = len(items) - int(limit)
    return f"{', '.join(items[:int(limit)])} (+{remaining} more)"


def rationale_tag_label(value: Any) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    normalized = token.replace("web_followup", "web followup").replace(":", " / ").replace("_", " ")
    words = [part for part in re.split(r"\s+", normalized) if part]
    if not words:
        return ""
    upper_tokens = {"ai", "http", "https", "rpc", "smb", "tls", "waf", "cve"}
    rendered = []
    for word in words:
        rendered.append(word.upper() if word.lower() in upper_tokens else word.capitalize())
    return " ".join(rendered)


def manual_test_lines(runtime_or_cls, manual_tests: Any, *, limit: int = 2) -> List[str]:
    _ = runtime_or_cls
    lines: List[str] = []
    entries = [item for item in list(manual_tests or []) if isinstance(item, dict)]
    for item in entries[:int(limit)]:
        why = truncate_rationale_text(item.get("why", ""), 120)
        command = truncate_rationale_text(item.get("command", ""), 120)
        if why and command:
            lines.append(f"Manual: {why} | {command}")
        elif command:
            lines.append(f"Manual: {command}")
        elif why:
            lines.append(f"Manual: {why}")
    remaining = len(entries) - min(len(entries), int(limit))
    if remaining > 0:
        lines.append(f"Manual: {remaining} more suggestion(s)")
    return lines


def findings_line(runtime_or_cls, findings: Any) -> str:
    _ = runtime_or_cls
    items = []
    for item in list(findings or [])[:3]:
        if not isinstance(item, dict):
            continue
        title = truncate_rationale_text(item.get("title", ""), 80)
        severity = str(item.get("severity", "") or "").strip()
        if title and severity:
            items.append(f"{title} [{severity}]")
        elif title:
            items.append(title)
    if not items:
        return ""
    return f"Findings: {', '.join(items)}"
