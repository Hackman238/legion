from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

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
class WorkspaceFindingsQuery:
    host_id: int
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "WorkspaceFindingsQuery":
        return cls(
            host_id=clamp_int(args.get("host_id", 0), 0, 0, 10**9),
            limit=clamp_int(args.get("limit", 1000), 1000, 1, 10000),
        )

