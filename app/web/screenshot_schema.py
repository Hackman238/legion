from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.web.http_utils import clamp_int


@dataclass(frozen=True)
class ScreenshotRefreshRequest:
    host_id: int
    port: str
    protocol: str

    @classmethod
    def from_payload(cls, payload: Any) -> "ScreenshotRefreshRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            host_id=clamp_int(source.get("host_id", 0), 0, 0, 10**9),
            port=str(source.get("port", "") or ""),
            protocol=str(source.get("protocol", "tcp") or "tcp"),
        )


@dataclass(frozen=True)
class ScreenshotDeleteRequest:
    host_id: int
    artifact_ref: str
    filename: str
    port: str
    protocol: str

    @classmethod
    def from_payload(cls, payload: Any) -> "ScreenshotDeleteRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            host_id=clamp_int(source.get("host_id", 0), 0, 0, 10**9),
            artifact_ref=str(source.get("artifact_ref", "") or ""),
            filename=str(source.get("filename", "") or ""),
            port=str(source.get("port", "") or ""),
            protocol=str(source.get("protocol", "tcp") or "tcp"),
        )
