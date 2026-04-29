from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.web.http_utils import as_bool
from app.web.http_utils import clamp_int


def _multi_value_args(args: Any, *names: str) -> List[str]:
    values: List[str] = []
    for name in names:
        if hasattr(args, "getlist"):
            values.extend(args.getlist(name))
        else:
            value = args.get(name, "") if hasattr(args, "get") else ""
            values.append(value)

    rows: List[str] = []
    seen = set()
    for value in values:
        for token in str(value or "").split(","):
            normalized = token.strip()
            key = normalized.lower()
            if not normalized or key in seen:
                continue
            seen.add(key)
            rows.append(normalized)
    return rows


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


@dataclass(frozen=True)
class WorkspaceHostsQuery:
    host_filter: str
    service_filters: List[str]
    category_filter: str
    limit: Optional[int]

    @property
    def service_filter(self) -> str:
        return ",".join(self.service_filters)

    @property
    def include_down(self) -> bool:
        return self.host_filter == "show_all"

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceHostsQuery":
        host_filter_value = str(args.get("filter", "hide_down") or "").strip().lower()
        if host_filter_value in {"all", "show_all", "show-all"}:
            host_filter = "show_all"
        else:
            host_filter = "hide_down"
        service_filters = _multi_value_args(args, "service", "services")
        category_filter = str(args.get("category", "") or "").strip()
        limit_value = args.get("limit")
        limit: Optional[int]
        if limit_value in {None, ""}:
            limit = None
        else:
            try:
                parsed_limit = int(limit_value)
            except (TypeError, ValueError):
                parsed_limit = 0
            limit = parsed_limit if parsed_limit > 0 else None
        return cls(
            host_filter=host_filter,
            service_filters=service_filters,
            category_filter=category_filter,
            limit=limit,
        )


@dataclass(frozen=True)
class WorkspaceServicesQuery:
    limit: int
    host_id: int
    category: str

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceServicesQuery":
        return cls(
            limit=clamp_int(args.get("limit", 300), 300, 1, 2000),
            host_id=clamp_int(args.get("host_id", 0), 0, 0, 10**9),
            category=str(args.get("category", "") or "").strip(),
        )


@dataclass(frozen=True)
class WorkspaceToolsPageQuery:
    service: str
    limit: int
    offset: int

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceToolsPageQuery":
        return cls(
            service=str(args.get("service", "") or "").strip(),
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
class WorkspaceFindingsQuery:
    host_id: int
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceFindingsQuery":
        return cls(
            host_id=clamp_int(args.get("host_id", 0), 0, 0, 10**9),
            limit=clamp_int(args.get("limit", 1000), 1000, 1, 10000),
        )


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


@dataclass(frozen=True)
class ToolRunRequest:
    host_ip: str
    port: str
    protocol: str
    tool_id: str
    command_override: str
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
            command_override=str(source.get("command_override", "") or ""),
            timeout=timeout,
        )


@dataclass(frozen=True)
class ProcessOutputQuery:
    offset: int
    max_chars: int

    @classmethod
    def from_args(cls, args: Any) -> "ProcessOutputQuery":
        return cls(
            offset=clamp_int(args.get("offset", 0), 0, 0, 10**9),
            max_chars=clamp_int(args.get("max_chars", 12000), 12000, 1, 50000),
        )


@dataclass(frozen=True)
class ProcessRetryRequest:
    timeout: int

    @classmethod
    def from_payload(cls, payload: Any) -> "ProcessRetryRequest":
        source = payload if isinstance(payload, dict) else {}
        timeout_value = source.get("timeout", 300)
        try:
            timeout = int(timeout_value or 300)
        except (TypeError, ValueError):
            raise ValueError("timeout must be an integer.")
        return cls(timeout=timeout)


@dataclass(frozen=True)
class ProcessClearRequest:
    reset_all: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "ProcessClearRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(reset_all=as_bool(source.get("reset_all", False), default=False))
