from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from app.web.http_utils import clamp_int


@dataclass(frozen=True)
class WorkspaceToolsPageQuery:
    service: str
    port: str
    protocol: str
    limit: int
    offset: int

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceToolsPageQuery":
        return cls(
            service=str(args.get("service", "") or "").strip(),
            port=str(args.get("port", "") or "").strip(),
            protocol=str(args.get("protocol", "") or "tcp").strip().lower() or "tcp",
            limit=clamp_int(args.get("limit", 300), 300, 1, 500),
            offset=clamp_int(args.get("offset", 0), 0, 0, 10**9),
        )


@dataclass(frozen=True)
class WorkspaceToolTargetsQuery:
    service: str
    host_id: int
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceToolTargetsQuery":
        return cls(
            service=str(args.get("service", "") or "").strip(),
            host_id=clamp_int(args.get("host_id", 0), 0, 0, 10**9),
            limit=clamp_int(args.get("limit", 300), 300, 1, 5000),
        )


@dataclass(frozen=True)
class ToolRunRequest:
    host_ip: str
    port: str
    protocol: str
    tool_id: str
    parameters: Dict[str, Any]
    timeout: int

    @classmethod
    def from_payload(cls, payload: Any) -> "ToolRunRequest":
        source = payload if isinstance(payload, dict) else {}
        timeout_value = source.get("timeout", 300)
        try:
            timeout = int(timeout_value or 300)
        except (TypeError, ValueError):
            raise ValueError("timeout must be an integer.")
        return cls(
            host_ip=str(source.get("host_ip", "") or "").strip(),
            port=str(source.get("port", "") or "").strip(),
            protocol=str(source.get("protocol", "tcp") or "tcp").strip().lower() or "tcp",
            tool_id=str(source.get("tool_id", "") or "").strip(),
            parameters=dict(source.get("parameters", {}) or {}) if isinstance(source.get("parameters", {}), dict) else {},
            timeout=timeout,
        )
