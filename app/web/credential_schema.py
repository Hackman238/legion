from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from app.web.http_utils import clamp_int


@dataclass(frozen=True)
class CredentialCaptureConfigRequest:
    updates: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Any) -> "CredentialCaptureConfigRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(updates=dict(source))


@dataclass(frozen=True)
class CredentialCaptureToolRequest:
    tool_id: str

    @classmethod
    def from_payload(cls, payload: Any) -> "CredentialCaptureToolRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(tool_id=str(source.get("tool", "") or "").strip().lower())


@dataclass(frozen=True)
class CredentialCaptureLogQuery:
    tool_id: str

    @classmethod
    def from_args(cls, args: Any) -> "CredentialCaptureLogQuery":
        return cls(tool_id=str(args.get("tool", "") or "").strip().lower())


@dataclass(frozen=True)
class CredentialsQuery:
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "CredentialsQuery":
        return cls(limit=clamp_int(args.get("limit", 5000), 5000, 1, 5000))


@dataclass(frozen=True)
class CredentialsDownloadQuery:
    output_format: str

    @classmethod
    def from_args(cls, args: Any) -> "CredentialsDownloadQuery":
        return cls(output_format=str(args.get("format", "txt") or "txt").strip().lower())
