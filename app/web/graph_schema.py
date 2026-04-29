from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from app.web.http_utils import as_bool, clamp_int


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return int(default)


def _parse_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return float(default)


def _split_query_tokens(value: Any) -> List[str]:
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value or "").split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def _multi_value_query_tokens(args: Any, *names: str) -> List[str]:
    values: List[Any] = []
    for name in names:
        if hasattr(args, "getlist"):
            values.extend(args.getlist(name))
        elif hasattr(args, "get"):
            values.append(args.get(name, ""))

    rows: List[str] = []
    seen = set()
    for token in _split_query_tokens(values):
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append(token)
    return rows


def _normalized_host_filter(value: Any) -> str:
    token = str(value or "").strip().lower()
    if token in {"all", "show_all", "show-all"}:
        return "show_all"
    return "hide_down"


@dataclass(frozen=True)
class GraphQuery:
    node_types: List[str]
    edge_types: List[str]
    source_kinds: List[str]
    min_confidence: float
    search: str
    include_ai_suggested: bool
    hide_nmap_xml_artifacts: bool
    host_filter: str
    service_filters: List[str]
    category_filter: str
    host_id: int
    limit_nodes: int
    limit_edges: int

    @classmethod
    def from_args(cls, args) -> "GraphQuery":
        include_ai_suggested = not as_bool(args.get("hide_ai_suggested", False), default=False)
        if args.get("include_ai_suggested") is not None:
            include_ai_suggested = as_bool(args.get("include_ai_suggested"), default=True)
        return cls(
            node_types=_split_query_tokens(args.get("node_types", args.get("node_type", ""))),
            edge_types=_split_query_tokens(args.get("edge_types", args.get("edge_type", ""))),
            source_kinds=_split_query_tokens(args.get("source_kinds", args.get("source_kind", ""))),
            min_confidence=_parse_float(args.get("min_confidence", 0.0), 0.0),
            search=str(args.get("q", args.get("search", "")) or ""),
            include_ai_suggested=include_ai_suggested,
            hide_nmap_xml_artifacts=as_bool(args.get("hide_nmap_xml_artifacts", False), default=False),
            host_filter=_normalized_host_filter(args.get("host_filter", args.get("filter", "hide_down"))),
            service_filters=_multi_value_query_tokens(args, "service", "services"),
            category_filter=str(args.get("category", "") or "").strip(),
            host_id=_parse_int(args.get("host_id", 0), 0),
            limit_nodes=clamp_int(args.get("limit_nodes"), 600, 1, 10000),
            limit_edges=clamp_int(args.get("limit_edges"), 1200, 1, 30000),
        )

    def filters(self) -> Dict[str, Any]:
        return {
            "node_types": self.node_types,
            "edge_types": self.edge_types,
            "source_kinds": self.source_kinds,
            "min_confidence": self.min_confidence,
            "search": self.search,
            "include_ai_suggested": self.include_ai_suggested,
            "hide_nmap_xml_artifacts": self.hide_nmap_xml_artifacts,
            "host_filter": self.host_filter,
            "service_filters": self.service_filters,
            "category_filter": self.category_filter,
            "host_id": self.host_id or None,
            "limit_nodes": self.limit_nodes,
            "limit_edges": self.limit_edges,
        }


@dataclass(frozen=True)
class GraphRebuildRequest:
    host_id: int

    @classmethod
    def from_payload(cls, payload: Any) -> "GraphRebuildRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(host_id=_parse_int(source.get("host_id", 0), 0))


@dataclass(frozen=True)
class GraphExportQuery:
    rebuild: bool

    @classmethod
    def from_args(cls, args) -> "GraphExportQuery":
        return cls(rebuild=as_bool(args.get("rebuild", False), default=False))


@dataclass(frozen=True)
class GraphContentQuery:
    max_chars: int
    download: bool

    @classmethod
    def from_args(cls, args) -> "GraphContentQuery":
        return cls(
            max_chars=_parse_int(args.get("max_chars", 12000), 12000),
            download=as_bool(args.get("download", False), default=False),
        )


@dataclass(frozen=True)
class GraphLayoutSaveRequest:
    view_id: str
    name: str
    layout_state: Any
    layout_id: str

    @classmethod
    def from_payload(cls, payload: Any) -> "GraphLayoutSaveRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            view_id=str(source.get("view_id", "") or "").strip(),
            name=str(source.get("name", "") or "").strip(),
            layout_state=source.get("layout", {}),
            layout_id=str(source.get("layout_id", "") or ""),
        )


@dataclass(frozen=True)
class GraphAnnotationQuery:
    target_ref: str
    target_kind: str

    @classmethod
    def from_args(cls, args) -> "GraphAnnotationQuery":
        return cls(
            target_ref=str(args.get("target_ref", "") or ""),
            target_kind=str(args.get("target_kind", "") or ""),
        )


@dataclass(frozen=True)
class GraphAnnotationSaveRequest:
    target_kind: str
    target_ref: str
    body: str
    created_by: str
    source_ref: str
    annotation_id: str

    @classmethod
    def from_payload(cls, payload: Any) -> "GraphAnnotationSaveRequest":
        source = payload if isinstance(payload, dict) else {}
        return cls(
            target_kind=str(source.get("target_kind", "") or "").strip(),
            target_ref=str(source.get("target_ref", "") or "").strip(),
            body=str(source.get("body", "") or "").strip(),
            created_by=str(source.get("created_by", "") or "operator"),
            source_ref=str(source.get("source_ref", "") or ""),
            annotation_id=str(source.get("annotation_id", "") or ""),
        )
