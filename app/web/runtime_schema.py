from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.web.http_utils import clamp_int


@dataclass(frozen=True)
class JobListQuery:
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "JobListQuery":
        return cls(limit=clamp_int(args.get("limit", 100), 100, 1, 500))


@dataclass(frozen=True)
class ProcessListQuery:
    limit: int

    @classmethod
    def from_args(cls, args: Any) -> "ProcessListQuery":
        return cls(limit=clamp_int(args.get("limit", 100), 100, 1, 500))
