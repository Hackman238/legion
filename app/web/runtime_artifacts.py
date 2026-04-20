from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Tuple

from sqlalchemy import text

from app.scheduler.graph import rebuild_evidence_graph
from app.scheduler.state import build_target_urls, get_target_state, upsert_target_state
from app.screenshot_metadata import screenshot_metadata_path


def path_within(base_path: str, candidate_path: str) -> bool:
    root = os.path.abspath(str(base_path or "").strip())
    target = os.path.abspath(str(candidate_path or "").strip())
    if not root or not target:
        return False
    try:
        return os.path.commonpath([root, target]) == root
    except Exception:
        return False


def is_project_artifact_path(runtime, project, path: str) -> bool:
    candidate = os.path.abspath(str(path or "").strip())
    if not candidate or not os.path.isfile(candidate):
        return False
    roots = [
        getattr(getattr(project, "properties", None), "outputFolder", ""),
        getattr(getattr(project, "properties", None), "runningFolder", ""),
    ]
    return any(path_within(root, candidate) for root in roots if str(root or "").strip())


def collect_command_artifacts(outputfile: str) -> List[str]:
    base_path = str(outputfile or "").strip()
    if not base_path:
        return []
    matches = []
    for path in sorted(set(glob.glob(f"{base_path}*"))):
        if os.path.exists(path):
            matches.append(path)
    return matches


def host_target_item_matches_port(item: Any, port: str, protocol: str) -> bool:
    if not isinstance(item, dict):
        return False
    item_port = str(item.get("port", "") or "").strip()
    item_protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
    return item_port == str(port or "").strip() and item_protocol == str(protocol or "tcp").strip().lower()


def delete_project_artifact_refs(
        runtime,
        project,
        *,
        screenshots: List[Dict[str, Any]],
        artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
    candidate_paths: List[str] = []
    for item in list(screenshots or []):
        if not isinstance(item, dict):
            continue
        item_ref = str(item.get("artifact_ref", "") or item.get("ref", "") or item.get("url", "") or "").strip()
        item_name = os.path.basename(str(item.get("filename", "") or item_ref).strip())
        if item_ref.startswith("/api/screenshots/"):
            api_name = os.path.basename(item_ref)
            if api_name:
                candidate_paths.append(os.path.join(screenshot_dir, api_name))
        elif item_ref and is_project_artifact_path(runtime, project, item_ref):
            candidate_paths.append(item_ref)
        if item_name:
            candidate_paths.append(os.path.join(screenshot_dir, item_name))

    for item in list(artifacts or []):
        if not isinstance(item, dict):
            continue
        item_ref = str(item.get("ref", "") or item.get("artifact_ref", "") or "").strip()
        if item_ref.startswith("/api/screenshots/"):
            api_name = os.path.basename(item_ref)
            if api_name:
                candidate_paths.append(os.path.join(screenshot_dir, api_name))
        elif item_ref and is_project_artifact_path(runtime, project, item_ref):
            candidate_paths.append(item_ref)

    deleted_paths: List[str] = []
    seen_paths = set()
    for path in candidate_paths:
        normalized = os.path.abspath(str(path or "").strip())
        if not normalized or normalized in seen_paths:
            continue
        seen_paths.add(normalized)
        if not os.path.isfile(normalized):
            continue
        if not is_project_artifact_path(runtime, project, normalized):
            continue
        try:
            os.remove(normalized)
            deleted_paths.append(normalized)
        except Exception:
            continue
    return {
        "deleted_files": len(deleted_paths),
        "deleted_paths": deleted_paths,
    }


def prune_target_state_for_port(
        runtime,
        *,
        project,
        host_id: int,
        host_ip: str,
        hostname: str,
        port: str,
        protocol: str,
) -> Dict[str, Any]:
    target_state = get_target_state(project.database, int(host_id or 0)) or {}
    filtered_service_inventory = [
        dict(item) for item in list(target_state.get("service_inventory", []) or [])
        if not host_target_item_matches_port(item, port, protocol)
    ]
    filtered_attempted_actions = [
        dict(item) for item in list(target_state.get("attempted_actions", []) or [])
        if not host_target_item_matches_port(item, port, protocol)
    ]
    filtered_screenshots: List[Dict[str, Any]] = []
    removed_screenshots: List[Dict[str, Any]] = []
    for item in list(target_state.get("screenshots", []) or []):
        if host_target_item_matches_port(item, port, protocol):
            removed_screenshots.append(dict(item))
            continue
        if isinstance(item, dict):
            filtered_screenshots.append(dict(item))
    filtered_artifacts: List[Dict[str, Any]] = []
    removed_artifacts: List[Dict[str, Any]] = []
    for item in list(target_state.get("artifacts", []) or []):
        if host_target_item_matches_port(item, port, protocol):
            removed_artifacts.append(dict(item))
            continue
        if isinstance(item, dict):
            filtered_artifacts.append(dict(item))
    preserved_urls = [
        dict(item) for item in list(target_state.get("urls", []) or [])
        if not host_target_item_matches_port(item, port, protocol)
    ]
    rebuilt_urls = build_target_urls(str(host_ip or ""), str(hostname or ""), filtered_service_inventory)

    updated_state = dict(target_state)
    updated_state["service_inventory"] = filtered_service_inventory
    updated_state["attempted_actions"] = filtered_attempted_actions
    updated_state["screenshots"] = filtered_screenshots
    updated_state["artifacts"] = filtered_artifacts
    updated_state["urls"] = preserved_urls + rebuilt_urls
    upsert_target_state(project.database, int(host_id or 0), updated_state, merge=False)
    return {
        "state": updated_state,
        "removed_screenshots": removed_screenshots,
        "removed_artifacts": removed_artifacts,
    }


def delete_workspace_port(runtime, *, host_id: int, port: str, protocol: str = "tcp") -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    if resolved_host_id <= 0 or not resolved_port:
        raise ValueError("host_id and port are required.")

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        repo_container = project.repositoryContainer
        port_repo = repo_container.portRepository
        service_repo = getattr(repo_container, "serviceRepository", None)
        port_obj = port_repo.getPortByHostIdAndPort(host.id, resolved_port, resolved_protocol)
        if port_obj is None:
            raise KeyError(f"Unknown port {resolved_port}/{resolved_protocol} for host {resolved_host_id}")

        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()
        service_id = str(getattr(port_obj, "serviceId", "") or "").strip()
        service_name = ""
        if service_id and service_repo is not None:
            try:
                service_obj = service_repo.getServiceById(service_id)
            except Exception:
                service_obj = None
            service_name = str(getattr(service_obj, "name", "") or "").strip()

        port_repo.deletePortByHostIdAndPort(host.id, resolved_port, resolved_protocol)

        session = project.database.session()
        try:
            if service_id:
                session.execute(text(
                    "DELETE FROM serviceObj "
                    "WHERE CAST(id AS TEXT) = :service_id "
                    "AND CAST(id AS TEXT) NOT IN ("
                    "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj WHERE COALESCE(serviceId, '') <> ''"
                    ")"
                ), {"service_id": service_id})
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        prune = prune_target_state_for_port(
            runtime,
            project=project,
            host_id=resolved_host_id,
            host_ip=host_ip,
            hostname=hostname,
            port=resolved_port,
            protocol=resolved_protocol,
        )
        deleted_file_info = delete_project_artifact_refs(
            runtime,
            project,
            screenshots=list(prune.get("removed_screenshots", []) or []),
            artifacts=list(prune.get("removed_artifacts", []) or []),
        )
        rebuild_evidence_graph(project.database, host_id=resolved_host_id)
        return {
            "deleted": True,
            "kind": "port",
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "port": resolved_port,
            "protocol": resolved_protocol,
            "service": service_name,
            **deleted_file_info,
        }


def delete_workspace_service(
        runtime,
        *,
        host_id: int,
        port: str,
        protocol: str = "tcp",
        service: str = "",
) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    requested_service = str(service or "").strip().rstrip("?").lower()
    if resolved_host_id <= 0 or not resolved_port:
        raise ValueError("host_id and port are required.")

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()

        session = project.database.session()
        try:
            row = session.execute(text(
                "SELECT p.id, COALESCE(CAST(p.serviceId AS TEXT), ''), COALESCE(s.name, '') "
                "FROM portObj AS p "
                "LEFT JOIN serviceObj AS s ON s.id = p.serviceId "
                "WHERE p.hostId = :host_id "
                "AND COALESCE(p.portId, '') = :port "
                "AND LOWER(COALESCE(p.protocol, 'tcp')) = LOWER(:protocol) "
                "ORDER BY p.id DESC LIMIT 1"
            ), {
                "host_id": str(getattr(host, "id", resolved_host_id) or resolved_host_id),
                "port": resolved_port,
                "protocol": resolved_protocol,
            }).fetchone()
            if not row:
                raise KeyError(f"Unknown port {resolved_port}/{resolved_protocol} for host {resolved_host_id}")

            port_row_id = int(row[0] or 0)
            service_id = str(row[1] or "").strip()
            current_service = str(row[2] or "").strip()
            if not service_id and not current_service:
                raise KeyError(f"No service is associated with {resolved_port}/{resolved_protocol} for host {resolved_host_id}")
            current_service_normalized = current_service.rstrip("?").lower()
            if requested_service and current_service_normalized and requested_service != current_service_normalized:
                raise ValueError(
                    f"Service mismatch for {resolved_port}/{resolved_protocol}: expected {requested_service}, found {current_service_normalized}"
                )

            session.execute(text(
                "UPDATE portObj SET serviceId = NULL WHERE id = :port_row_id"
            ), {"port_row_id": port_row_id})
            if service_id:
                session.execute(text(
                    "DELETE FROM serviceObj "
                    "WHERE CAST(id AS TEXT) = :service_id "
                    "AND CAST(id AS TEXT) NOT IN ("
                    "SELECT DISTINCT CAST(serviceId AS TEXT) FROM portObj WHERE COALESCE(serviceId, '') <> ''"
                    ")"
                ), {"service_id": service_id})
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        prune = prune_target_state_for_port(
            runtime,
            project=project,
            host_id=resolved_host_id,
            host_ip=host_ip,
            hostname=hostname,
            port=resolved_port,
            protocol=resolved_protocol,
        )
        deleted_file_info = delete_project_artifact_refs(
            runtime,
            project,
            screenshots=list(prune.get("removed_screenshots", []) or []),
            artifacts=list(prune.get("removed_artifacts", []) or []),
        )
        rebuild_evidence_graph(project.database, host_id=resolved_host_id)
        return {
            "deleted": True,
            "kind": "service",
            "host_id": resolved_host_id,
            "host_ip": host_ip,
            "hostname": hostname,
            "port": resolved_port,
            "protocol": resolved_protocol,
            "service": current_service,
            **deleted_file_info,
        }


def delete_graph_screenshot(
        runtime,
        *,
        host_id: int,
        artifact_ref: str = "",
        filename: str = "",
        port: str = "",
        protocol: str = "tcp",
) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    if resolved_host_id <= 0:
        raise ValueError("host_id is required.")
    resolved_artifact_ref = str(artifact_ref or "").strip()
    resolved_filename = os.path.basename(str(filename or "").strip())
    resolved_port = str(port or "").strip()
    resolved_protocol = str(protocol or "tcp").strip().lower() or "tcp"
    if not resolved_artifact_ref and not resolved_filename:
        raise ValueError("artifact_ref or filename is required.")

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(resolved_host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        candidate_paths: List[str] = []
        if resolved_filename:
            candidate_paths.append(os.path.join(screenshot_dir, resolved_filename))
        if resolved_artifact_ref:
            if resolved_artifact_ref.startswith("/api/screenshots/"):
                api_filename = os.path.basename(resolved_artifact_ref)
                if api_filename:
                    candidate_paths.append(os.path.join(screenshot_dir, api_filename))
            else:
                candidate_paths.append(resolved_artifact_ref)
        normalized_candidates: List[str] = []
        for path in candidate_paths:
            normalized = os.path.abspath(str(path or "").strip())
            if normalized and normalized not in normalized_candidates:
                normalized_candidates.append(normalized)
                metadata_candidate = screenshot_metadata_path(normalized)
                if metadata_candidate and metadata_candidate not in normalized_candidates:
                    normalized_candidates.append(metadata_candidate)

        deleted_files = 0
        deleted_paths: List[str] = []
        for path in normalized_candidates:
            if not os.path.isfile(path):
                continue
            if not is_project_artifact_path(runtime, project, path):
                continue
            try:
                os.remove(path)
                deleted_files += 1
                deleted_paths.append(path)
            except Exception:
                continue

        target_state = get_target_state(project.database, resolved_host_id) or {}
        filtered_screenshots = []
        for item in list(target_state.get("screenshots", []) or []):
            if not isinstance(item, dict):
                continue
            item_ref = str(item.get("artifact_ref", "") or item.get("ref", "") or item.get("url", "") or "").strip()
            item_name = os.path.basename(str(item.get("filename", "") or item_ref).strip())
            item_port = str(item.get("port", "") or "").strip()
            item_protocol = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
            matches_ref = bool(resolved_artifact_ref and (item_ref == resolved_artifact_ref or os.path.basename(item_ref) == resolved_filename))
            matches_name = bool(resolved_filename and item_name == resolved_filename)
            matches_target = True
            if resolved_port:
                matches_target = item_port == resolved_port
            if matches_target and resolved_protocol:
                matches_target = item_protocol == resolved_protocol
            if (matches_ref or matches_name) and matches_target:
                continue
            filtered_screenshots.append(dict(item))

        filtered_artifacts = []
        for item in list(target_state.get("artifacts", []) or []):
            if not isinstance(item, dict):
                continue
            item_ref = str(item.get("ref", "") or item.get("artifact_ref", "") or "").strip()
            item_kind = str(item.get("kind", "") or "").strip().lower()
            item_name = os.path.basename(item_ref)
            matches_ref = bool(resolved_artifact_ref and (item_ref == resolved_artifact_ref or os.path.basename(item_ref) == resolved_filename))
            matches_name = bool(resolved_filename and item_name == resolved_filename)
            if item_kind == "screenshot" and (matches_ref or matches_name):
                continue
            filtered_artifacts.append(dict(item))

        updated_state = dict(target_state)
        updated_state["screenshots"] = filtered_screenshots
        updated_state["artifacts"] = filtered_artifacts
        upsert_target_state(project.database, resolved_host_id, updated_state, merge=False)
        rebuild_evidence_graph(project.database, host_id=resolved_host_id)

        return {
            "deleted": True,
            "host_id": resolved_host_id,
            "artifact_ref": resolved_artifact_ref,
            "filename": resolved_filename,
            "deleted_files": int(deleted_files),
            "deleted_paths": deleted_paths,
        }


def get_screenshot_file(runtime, filename: str) -> str:
    safe_name = os.path.basename(str(filename or "").strip())
    if safe_name != str(filename or "").strip():
        raise ValueError("Invalid screenshot filename.")
    if not safe_name.lower().endswith(".png"):
        raise ValueError("Only PNG screenshots are supported.")

    with runtime._lock:
        project = runtime._require_active_project()
        screenshot_dir = os.path.join(project.properties.outputFolder, "screenshots")
        path = os.path.join(screenshot_dir, safe_name)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        return path
