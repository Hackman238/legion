from __future__ import annotations

import re
from typing import Any, Dict, List

from app.web.runtime_scheduler_rationale_text import safe_json_loads


def strip_json_fences(value: Any) -> str:
    text_value = str(value or "").strip()
    if not text_value.startswith("```"):
        return text_value
    lines = text_value.splitlines()
    if lines:
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def extract_prompt_text_from_provider_request(runtime_or_cls, request_body: Any) -> str:
    _ = runtime_or_cls
    payload = safe_json_loads(request_body)
    if not isinstance(payload, dict):
        return ""
    messages = payload.get("messages", [])
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        if str(message.get("role", "") or "").strip().lower() != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks = []
            for item in content:
                if isinstance(item, dict):
                    if str(item.get("type", "") or "").strip().lower() == "text":
                        chunks.append(str(item.get("text", "") or ""))
                elif isinstance(item, str):
                    chunks.append(item)
            return "\n".join(chunk for chunk in chunks if chunk.strip())
    return ""


def extract_scheduler_target_fields_from_prompt(prompt_text: Any) -> Dict[str, str]:
    text_value = str(prompt_text or "")
    payload: Dict[str, str] = {}
    for field_name in ("host_ip", "port", "protocol", "service"):
        match = re.search(rf'"{field_name}"\s*:\s*"([^"]*)"', text_value)
        if match:
            payload[field_name] = str(match.group(1) or "").strip()
    return payload


def extract_provider_response_payload(runtime_or_cls, response_body: Any) -> Dict[str, Any]:
    _ = runtime_or_cls
    payload = safe_json_loads(response_body)
    if isinstance(payload, dict) and any(
            key in payload for key in ("actions", "selected_tool_ids", "promote_tool_ids", "suppress_tool_ids", "next_phase", "focus")
    ):
        return payload

    content_candidates: List[str] = []
    if isinstance(payload, dict):
        for choice in list(payload.get("choices", []) or []):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if isinstance(message, dict):
                content = message.get("content", "")
                if isinstance(content, str) and content.strip():
                    content_candidates.append(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and str(item.get("type", "") or "").strip().lower() == "text":
                            text_value = str(item.get("text", "") or "")
                            if text_value.strip():
                                content_candidates.append(text_value)
            text_value = str(choice.get("text", "") or "")
            if text_value.strip():
                content_candidates.append(text_value)
        for item in list(payload.get("content", []) or []):
            if isinstance(item, dict) and str(item.get("type", "") or "").strip().lower() == "text":
                text_value = str(item.get("text", "") or "")
                if text_value.strip():
                    content_candidates.append(text_value)

    for item in content_candidates:
        parsed = safe_json_loads(strip_json_fences(item))
        if isinstance(parsed, dict):
            return parsed
    return {}
