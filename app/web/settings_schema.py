from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from app.web.http_utils import as_bool


def _split_query_tokens(value: Any) -> List[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


@dataclass(frozen=True)
class LegionConfRequest:
    text_value: str

    @classmethod
    def from_payload(cls, payload: Any) -> "LegionConfRequest":
        source = payload if isinstance(payload, dict) else {}
        text_value = source.get("text", None)
        if not isinstance(text_value, str):
            raise ValueError("Field 'text' is required and must be a string.")
        return cls(text_value=text_value)


@dataclass(frozen=True)
class DisplaySettingsRequest:
    colorful_ascii_background: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "DisplaySettingsRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(colorful_ascii_background=as_bool(source.get("colorful_ascii_background"), False))


@dataclass(frozen=True)
class ToolAuditPlanQuery:
    platform: str
    scope: str
    tool_keys: List[str]

    @classmethod
    def from_args(cls, args: Any) -> "ToolAuditPlanQuery":
        return cls(
            platform=str(args.get("platform", "kali") or "kali"),
            scope=str(args.get("scope", "missing") or "missing"),
            tool_keys=_split_query_tokens(args.get("tool_keys", "")),
        )


@dataclass(frozen=True)
class ToolAuditInstallRequest:
    platform: str
    scope: str
    tool_keys: List[str]

    @classmethod
    def from_payload(cls, payload: Any) -> "ToolAuditInstallRequest":
        source = payload if isinstance(payload, dict) else {}
        tool_keys = source.get("tool_keys", [])
        if tool_keys is None:
            tool_keys = []
        if not isinstance(tool_keys, list):
            raise ValueError("Field 'tool_keys' must be an array when provided.")
        return cls(
            platform=str(source.get("platform", "kali") or "kali"),
            scope=str(source.get("scope", "missing") or "missing"),
            tool_keys=[str(item or "").strip() for item in tool_keys if str(item or "").strip()],
        )
