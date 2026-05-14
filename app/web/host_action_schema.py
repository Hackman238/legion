from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from app.web.http_utils import as_bool, clamp_int


@dataclass(frozen=True)
class WorkspacePortMutationRequest:
    host_id: int
    port: str
    protocol: str
    service: str

    @classmethod
    def from_payload(cls, payload: Any) -> "WorkspacePortMutationRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            host_id=clamp_int(source.get("host_id", 0), 0, 0, 10**9),
            port=str(source.get("port", "") or ""),
            protocol=str(source.get("protocol", "tcp") or "tcp"),
            service=str(source.get("service", "") or ""),
        )


@dataclass(frozen=True)
class HostNoteRequest:
    text_value: str

    @classmethod
    def from_payload(cls, payload: Any) -> "HostNoteRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(text_value=str(source.get("text", "") or ""))


@dataclass(frozen=True)
class HostCategoriesRequest:
    manual_categories: List[Any]
    override_auto: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "HostCategoriesRequest":
        source = payload if isinstance(payload, dict) else {}
        raw_categories = source.get("manual_categories", [])
        if raw_categories is None:
            raw_categories = []
        categories = list(raw_categories) if isinstance(raw_categories, list) else [raw_categories]
        return cls(
            manual_categories=categories,
            override_auto=as_bool(source.get("override_auto", False), default=False),
        )


@dataclass(frozen=True)
class ScriptCreateRequest:
    script_id: str
    port: str
    protocol: str
    output: str

    @classmethod
    def from_payload(cls, payload: Any) -> "ScriptCreateRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            script_id=str(source.get("script_id", "") or "").strip(),
            port=str(source.get("port", "") or "").strip(),
            protocol=str(source.get("protocol", "tcp") or "tcp").strip().lower() or "tcp",
            output=str(source.get("output", "") or ""),
        )


@dataclass(frozen=True)
class ScriptOutputQuery:
    offset: int
    max_chars: int

    @classmethod
    def from_args(cls, args: Any) -> "ScriptOutputQuery":
        return cls(
            offset=clamp_int(args.get("offset", 0), 0, 0, 10**9),
            max_chars=clamp_int(args.get("max_chars", 12000), 12000, 1, 50000),
        )


@dataclass(frozen=True)
class CveCreateRequest:
    name: str
    url: str
    severity: str
    source: str
    product: str
    version: str
    exploit_id: int
    exploit: str
    exploit_url: str

    @classmethod
    def from_payload(cls, payload: Any) -> "CveCreateRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            name=str(source.get("name", "") or "").strip(),
            url=str(source.get("url", "") or ""),
            severity=str(source.get("severity", "") or ""),
            source=str(source.get("source", "") or ""),
            product=str(source.get("product", "") or ""),
            version=str(source.get("version", "") or ""),
            exploit_id=clamp_int(source.get("exploit_id", 0), 0, 0, 10**9),
            exploit=str(source.get("exploit", "") or ""),
            exploit_url=str(source.get("exploit_url", "") or ""),
        )
