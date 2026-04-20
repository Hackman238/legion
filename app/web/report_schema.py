from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return int(default)


def _normalized_report_format(value: Any) -> str:
    token = str(value or "json").strip().lower() or "json"
    if token in {"markdown"}:
        return "md"
    if token not in {"json", "md"}:
        return "json"
    return token


@dataclass(frozen=True)
class ReportFormatQuery:
    output_format: str

    @classmethod
    def from_args(cls, args) -> "ReportFormatQuery":
        return cls(output_format=_normalized_report_format(args.get("format", "json")))


@dataclass(frozen=True)
class ReportExportRequest:
    scope: str
    output_format: str
    host_id: int

    @classmethod
    def from_payload(cls, payload: Any) -> "ReportExportRequest":
        source = payload if isinstance(payload, dict) else {}
        scope = str(source.get("scope", "project") or "project").strip().lower() or "project"
        if scope not in {"host", "project"}:
            scope = "project"
        return cls(
            scope=scope,
            output_format=_normalized_report_format(source.get("format", "json")),
            host_id=_parse_int(source.get("host_id", 0), 0),
        )


@dataclass(frozen=True)
class ProjectReportPushRequest:
    overrides: Dict[str, Any]

    @classmethod
    def from_payload(cls, payload: Any) -> "ProjectReportPushRequest":
        source = payload if isinstance(payload, dict) else {}
        overrides = source.get("project_report_delivery")
        if overrides is None and isinstance(source, dict):
            overrides = {
                key: value
                for key, value in source.items()
                if key in {"provider_name", "endpoint", "method", "format", "headers", "timeout_seconds", "mtls"}
            }
        if not isinstance(overrides, dict):
            overrides = {}
        return cls(overrides=overrides)
