from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.web.http_utils import as_bool, clamp_int


@dataclass(frozen=True)
class ProjectListQuery:
    limit: int

    @classmethod
    def from_args(cls, args) -> "ProjectListQuery":
        return cls(limit=clamp_int(args.get("limit"), 500, 1, 5000))


@dataclass(frozen=True)
class ProjectPathRequest:
    path: str

    @classmethod
    def from_payload(cls, payload: Any) -> "ProjectPathRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(path=str(source.get("path", "") or "").strip())


@dataclass(frozen=True)
class ProjectSaveRequest:
    path: str
    replace: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "ProjectSaveRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            path=str(source.get("path", "") or "").strip(),
            replace=as_bool(source.get("replace", True), default=True),
        )
