from __future__ import annotations

import mimetypes
import os
from typing import Any, Dict, List, Optional

from app.scheduler.graph import (
    ensure_scheduler_graph_tables,
    export_evidence_graph_graphml,
    export_evidence_graph_json,
    list_graph_annotations,
    list_graph_layout_states,
    query_evidence_graph,
    rebuild_evidence_graph,
    upsert_graph_annotation,
    upsert_graph_layout_state,
)


def _read_text_file_head(path: str, max_chars: int = 12000) -> str:
    normalized_path = str(path or "").strip()
    if not normalized_path or not os.path.isfile(normalized_path):
        return ""
    safe_max_chars = max(0, min(int(max_chars or 12000), 200000))
    if safe_max_chars <= 0:
        return ""
    try:
        read_bytes = max(4096, min(safe_max_chars * 4, 2_000_000))
        with open(normalized_path, "rb") as handle:
            data = handle.read(read_bytes)
        return data.decode("utf-8", errors="replace")[:safe_max_chars]
    except Exception:
        return ""


def _binary_file_signature(path: str, sample_size: int = 8192) -> bool:
    normalized_path = str(path or "").strip()
    if not normalized_path or not os.path.isfile(normalized_path):
        return False
    try:
        with open(normalized_path, "rb") as handle:
            sample = handle.read(max(256, min(int(sample_size or 8192), 65536)))
        if not sample:
            return False
        return b"\x00" in sample
    except Exception:
        return False


def get_evidence_graph(runtime, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        resolved = dict(filters or {})
        return query_evidence_graph(
            project.database,
            node_types=resolved.get("node_types"),
            edge_types=resolved.get("edge_types"),
            source_kinds=resolved.get("source_kinds"),
            min_confidence=float(resolved.get("min_confidence", 0.0) or 0.0),
            search=str(resolved.get("search", "") or ""),
            include_ai_suggested=bool(resolved.get("include_ai_suggested", True)),
            hide_nmap_xml_artifacts=bool(resolved.get("hide_nmap_xml_artifacts", False)),
            hide_down_hosts=str(resolved.get("host_filter", "hide_down") or "").strip().lower() != "show_all",
            host_id=int(resolved.get("host_id", 0) or 0) or None,
            limit_nodes=int(resolved.get("limit_nodes", 600) or 600),
            limit_edges=int(resolved.get("limit_edges", 1200) or 1200),
        )


def get_graph_snapshot_locked(runtime) -> Dict[str, Any]:
    project = runtime._require_active_project()
    ensure_scheduler_graph_tables(project.database)
    return query_evidence_graph(project.database, limit_nodes=5000, limit_edges=10000)


def _graph_inline_evidence_text(runtime, project, node: Dict[str, Any], props: Dict[str, Any], *, max_chars: int = 12000) -> str:
    lines: List[str] = []
    seen = set()

    def _remember(value: Any):
        cleaned = str(value or "").strip()
        if not cleaned:
            return
        lowered = cleaned.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        lines.append(cleaned)

    _remember(props.get("evidence", ""))
    for token in list(props.get("evidence_items", []) or []):
        _remember(token)
    for token in list(node.get("evidence_refs", []) or []):
        cleaned = str(token or "").strip()
        if not cleaned:
            continue
        if cleaned.startswith("process_output:") or cleaned.startswith("/api/screenshots/") or runtime._is_project_artifact_path(project, cleaned):
            continue
        _remember(cleaned)
    inline_text = "\n".join(lines).strip()
    safe_max_chars = max(0, min(int(max_chars or 12000), 200000))
    return inline_text[:safe_max_chars] if safe_max_chars > 0 else ""


def _resolve_graph_content_entry_locked(runtime, project, node: Dict[str, Any], *, max_chars: int = 12000) -> Dict[str, Any]:
    node_id = str(node.get("node_id", "") or "")
    node_type = str(node.get("type", "") or "").strip().lower()
    props = node.get("properties", {}) if isinstance(node.get("properties", {}), dict) else {}
    evidence_refs = [
        str(item or "").strip()
        for item in list(node.get("evidence_refs", []) or [])
        if str(item or "").strip()
    ]
    ref = str(props.get("artifact_ref", "") or props.get("ref", "") or "").strip()
    if not ref:
        for candidate in evidence_refs:
            if candidate.startswith("process_output:") or candidate.startswith("/api/screenshots/") or runtime._is_project_artifact_path(project, candidate):
                ref = candidate
                break
    label = str(node.get("label", "") or os.path.basename(ref) or node_id)
    filename = str(props.get("filename", "") or os.path.basename(ref) or f"{node_type or 'graph-content'}-{node_id}")
    resolved_ref = ref
    if ref.startswith("/api/screenshots/"):
        try:
            resolved_ref = runtime.get_screenshot_file(os.path.basename(ref))
        except Exception:
            resolved_ref = ref
    elif node_type == "screenshot" and filename.lower().endswith(".png") and not runtime._is_project_artifact_path(project, ref):
        try:
            resolved_ref = runtime.get_screenshot_file(filename)
        except Exception:
            resolved_ref = ref
    base = {
        "node_id": node_id,
        "node_type": node_type,
        "label": label,
        "filename": filename,
        "ref": ref,
        "path": "",
        "kind": "unavailable",
        "available": False,
        "preview_text": "",
        "preview_url": "",
        "download_url": "",
        "message": "No preview is available for this graph node.",
    }

    if ref.startswith("process_output:"):
        try:
            process_id = int(ref.split(":", 1)[1])
        except (TypeError, ValueError):
            return base
        payload = runtime.get_process_output(process_id, offset=0, max_chars=max_chars)
        output_text = str(payload.get("output", "") or payload.get("output_chunk", "") or "")
        return {
            **base,
            "kind": "text",
            "available": bool(output_text),
            "preview_text": output_text,
            "filename": filename if filename.endswith(".txt") else f"process-{process_id}-output.txt",
            "download_url": f"/api/graph/content/{node_id}?download=1",
            "message": "" if output_text else "No captured process output is available.",
        }

    if resolved_ref and runtime._is_project_artifact_path(project, resolved_ref):
        mimetype = mimetypes.guess_type(resolved_ref)[0] or "application/octet-stream"
        if node_type == "screenshot" or resolved_ref.lower().endswith(".png"):
            return {
                **base,
                "path": resolved_ref,
                "kind": "image",
                "available": True,
                "preview_url": f"/api/graph/content/{node_id}",
                "download_url": f"/api/graph/content/{node_id}?download=1",
                "message": "",
            }

        if _binary_file_signature(resolved_ref):
            return {
                **base,
                "path": resolved_ref,
                "kind": "binary",
                "available": True,
                "download_url": f"/api/graph/content/{node_id}?download=1",
                "message": f"Binary artifact ({mimetype}) is available for download.",
            }

        preview_text = _read_text_file_head(resolved_ref, max_chars=max_chars)
        return {
            **base,
            "path": resolved_ref,
            "kind": "text",
            "available": bool(preview_text),
            "preview_text": preview_text,
            "download_url": f"/api/graph/content/{node_id}?download=1",
            "message": "" if preview_text else "Artifact file is empty.",
        }

    inline_text = _graph_inline_evidence_text(runtime, project, node, props, max_chars=max_chars)
    if inline_text:
        return {
            **base,
            "kind": "text",
            "available": True,
            "preview_text": inline_text,
            "download_url": f"/api/graph/content/{node_id}?download=1",
            "message": "",
        }

    return base


def get_graph_related_content(runtime, node_id: str, *, max_chars: int = 12000) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        snapshot = get_graph_snapshot_locked(runtime)
        nodes = {
            str(item.get("node_id", "") or ""): item
            for item in list(snapshot.get("nodes", []) or [])
            if isinstance(item, dict) and str(item.get("node_id", "") or "").strip()
        }
        selected_id = str(node_id or "").strip()
        selected_node = nodes.get(selected_id)
        if selected_node is None:
            raise KeyError(f"Unknown graph node id: {node_id}")

        candidate_ids = []
        if str(selected_node.get("type", "") or "").strip().lower() in {"artifact", "screenshot", "evidence_record"}:
            candidate_ids.append(selected_id)
        for edge in list(snapshot.get("edges", []) or []):
            if not isinstance(edge, dict):
                continue
            from_id = str(edge.get("from_node_id", "") or "")
            to_id = str(edge.get("to_node_id", "") or "")
            if selected_id not in {from_id, to_id}:
                continue
            other_id = to_id if from_id == selected_id else from_id
            other_node = nodes.get(other_id)
            other_type = str(other_node.get("type", "") or "").strip().lower() if isinstance(other_node, dict) else ""
            if other_type in {"artifact", "screenshot", "evidence_record"} and other_id not in candidate_ids:
                candidate_ids.append(other_id)

        entries = [
            _resolve_graph_content_entry_locked(runtime, project, nodes[candidate_id], max_chars=max_chars)
            for candidate_id in candidate_ids[:8]
            if candidate_id in nodes
        ]
        return {
            "node_id": selected_id,
            "entry_count": len(entries),
            "entries": entries,
        }


def get_graph_content(runtime, node_id: str, *, download: bool = False, max_chars: int = 12000) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        snapshot = get_graph_snapshot_locked(runtime)
        node = next(
            (
                item for item in list(snapshot.get("nodes", []) or [])
                if isinstance(item, dict) and str(item.get("node_id", "") or "") == str(node_id or "").strip()
            ),
            None,
        )
        if node is None:
            raise KeyError(f"Unknown graph node id: {node_id}")
        entry = _resolve_graph_content_entry_locked(runtime, project, node, max_chars=max_chars)
        ref = str(entry.get("ref", "") or "").strip()
        resolved_path = str(entry.get("path", "") or "").strip()
        if str(entry.get("kind", "") or "") == "text" and (ref.startswith("process_output:") or not resolved_path):
            return {
                "kind": "text",
                "text": str(entry.get("preview_text", "") or ""),
                "filename": str(entry.get("filename", "") or f"{node_id}.txt"),
                "mimetype": "text/plain; charset=utf-8",
                "download": bool(download),
            }
        if (
            str(entry.get("kind", "") or "") in {"image", "binary", "text"}
            and resolved_path
            and runtime._is_project_artifact_path(project, resolved_path)
        ):
            return {
                "kind": str(entry.get("kind", "") or "binary"),
                "path": resolved_path,
                "filename": str(entry.get("filename", "") or os.path.basename(resolved_path) or f"{node_id}.bin"),
                "mimetype": mimetypes.guess_type(resolved_path)[0] or (
                    "text/plain; charset=utf-8" if str(entry.get("kind", "") or "") == "text" else "application/octet-stream"
                ),
                "download": bool(download),
            }
        raise FileNotFoundError(str(entry.get("message", "") or "Graph content is not available."))


def rebuild_evidence_graph_for_runtime(runtime, host_id: Optional[int] = None) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        mutations = rebuild_evidence_graph(project.database, host_id=int(host_id or 0) or None)
        snapshot = query_evidence_graph(project.database, limit_nodes=25, limit_edges=50)
        return {
            "mutations": list(mutations or []),
            "mutation_count": len(list(mutations or [])),
            "nodes": int(snapshot.get("meta", {}).get("total_nodes", 0) or 0),
            "edges": int(snapshot.get("meta", {}).get("total_edges", 0) or 0),
            "host_id": int(host_id or 0) or None,
        }


def export_evidence_graph_json_for_runtime(runtime, *, rebuild: bool = False) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return export_evidence_graph_json(project.database, rebuild=bool(rebuild))


def export_evidence_graph_graphml_for_runtime(runtime, *, rebuild: bool = False) -> str:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return export_evidence_graph_graphml(project.database, rebuild=bool(rebuild))


def get_evidence_graph_layouts(runtime) -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return list_graph_layout_states(project.database)


def save_evidence_graph_layout(
    runtime,
    *,
    view_id: str,
    name: str,
    layout_state: Dict[str, Any],
    layout_id: str = "",
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return upsert_graph_layout_state(
            project.database,
            view_id=str(view_id or ""),
            name=str(name or ""),
            layout_state=layout_state if isinstance(layout_state, dict) else {},
            layout_id=str(layout_id or ""),
        )


def get_evidence_graph_annotations(runtime, *, target_ref: str = "", target_kind: str = "") -> List[Dict[str, Any]]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return list_graph_annotations(
            project.database,
            target_ref=str(target_ref or ""),
            target_kind=str(target_kind or ""),
        )


def save_evidence_graph_annotation(
    runtime,
    *,
    target_kind: str,
    target_ref: str,
    body: str,
    created_by: str = "operator",
    source_ref: str = "",
    annotation_id: str = "",
) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        ensure_scheduler_graph_tables(project.database)
        return upsert_graph_annotation(
            project.database,
            target_kind=str(target_kind or ""),
            target_ref=str(target_ref or ""),
            body=str(body or ""),
            created_by=str(created_by or "operator"),
            source_ref=str(source_ref or ""),
            annotation_id=str(annotation_id or ""),
        )
