from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request, send_file

from app.web.http_utils import json_error, runtime_from_app
from app.web.services.graph_service import GraphService

graph_bp = Blueprint("graph_api", __name__)


def _graph_service() -> GraphService:
    return GraphService(runtime_from_app())


@graph_bp.get("/api/graph")
def evidence_graph():
    service = _graph_service()
    try:
        return jsonify(service.get_graph(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.post("/api/graph/rebuild")
def evidence_graph_rebuild():
    service = _graph_service()
    try:
        return jsonify(service.rebuild(request.get_json(silent=True) or {}))
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/export/json")
def evidence_graph_export_json():
    service = _graph_service()
    try:
        payload = service.export_json(request.args)
        response = current_app.response_class(payload["body"], mimetype=payload["mimetype"])
        response.headers["Content-Disposition"] = f'attachment; filename="{payload["filename"]}"'
        return response
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/export/graphml")
def evidence_graph_export_graphml():
    service = _graph_service()
    try:
        payload = service.export_graphml(request.args)
        response = current_app.response_class(payload["body"], mimetype=payload["mimetype"])
        response.headers["Content-Disposition"] = f'attachment; filename="{payload["filename"]}"'
        return response
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/nodes/<path:node_id>/content")
def evidence_graph_node_content(node_id: str):
    service = _graph_service()
    try:
        return jsonify(service.get_node_content(node_id, request.args))
    except KeyError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/content/<path:node_id>")
def evidence_graph_content(node_id: str):
    service = _graph_service()
    try:
        payload = service.get_content(node_id, request.args)
        if payload.get("path"):
            return send_file(
                str(payload.get("path", "")),
                mimetype=str(payload.get("mimetype", "application/octet-stream") or "application/octet-stream"),
                as_attachment=bool(payload.get("download", False)),
                download_name=str(payload.get("filename", "") or None),
                max_age=0,
            )
        response = current_app.response_class(
            str(payload.get("text", "") or ""),
            mimetype=str(payload.get("mimetype", "text/plain; charset=utf-8") or "text/plain; charset=utf-8"),
        )
        if bool(payload.get("download", False)):
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{str(payload.get("filename", "") or "graph-content.txt")}"'
            )
        return response
    except KeyError as exc:
        return json_error(str(exc), 404)
    except FileNotFoundError as exc:
        return json_error(str(exc), 404)
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/layouts")
def evidence_graph_layouts():
    service = _graph_service()
    try:
        return jsonify(service.list_layouts())
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.post("/api/graph/layouts")
def evidence_graph_save_layout():
    service = _graph_service()
    try:
        return jsonify(service.save_layout(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.get("/api/graph/annotations")
def evidence_graph_annotations():
    service = _graph_service()
    try:
        return jsonify(service.list_annotations(request.args))
    except Exception as exc:
        return json_error(str(exc), 500)


@graph_bp.post("/api/graph/annotations")
def evidence_graph_save_annotation():
    service = _graph_service()
    try:
        return jsonify(service.save_annotation(request.get_json(silent=True) or {}))
    except ValueError as exc:
        return json_error(str(exc), 400)
    except Exception as exc:
        return json_error(str(exc), 500)
