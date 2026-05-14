from __future__ import annotations

from typing import Any, Dict

from app.scheduler.state import get_target_state as load_target_state
from app.web.runtime_workspace_identity import resolve_host_os


def get_host_workspace(
        runtime,
        host_id: int,
        *,
        get_target_state_func=None,
        host_detail_script_preview_func=None,
) -> Dict[str, Any]:
    target_state_getter = get_target_state_func or load_target_state
    preview_builder = host_detail_script_preview_func
    if preview_builder is None:
        from app.web.runtime_workspace_read import host_detail_script_preview
        preview_builder = host_detail_script_preview

    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(host_id)
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")

        repo_container = project.repositoryContainer
        port_repo = repo_container.portRepository
        service_repo = repo_container.serviceRepository
        script_repo = repo_container.scriptRepository
        note_repo = repo_container.noteRepository

        note_obj = note_repo.getNoteByHostId(host.id)
        note_text = str(getattr(note_obj, "text", "") or "")

        ports_data = []
        for port in port_repo.getPortsByHostId(host.id):
            service_obj = None
            if getattr(port, "serviceId", None):
                service_obj = service_repo.getServiceById(getattr(port, "serviceId", None))

            scripts = []
            for script in script_repo.getScriptsByPortId(port.id):
                script_id = str(getattr(script, "scriptId", "") or "")
                output = str(getattr(script, "output", "") or "")
                scripts.append({
                    "id": int(getattr(script, "id", 0) or 0),
                    "script_id": script_id,
                    "output": output,
                    "display_output": preview_builder(script_id, output),
                })

            ports_data.append({
                "id": int(getattr(port, "id", 0) or 0),
                "port": str(getattr(port, "portId", "") or ""),
                "protocol": str(getattr(port, "protocol", "") or ""),
                "state": str(getattr(port, "state", "") or ""),
                "service": {
                    "id": int(getattr(service_obj, "id", 0) or 0) if service_obj else 0,
                    "name": str(getattr(service_obj, "name", "") or "") if service_obj else "",
                    "product": str(getattr(service_obj, "product", "") or "") if service_obj else "",
                    "version": str(getattr(service_obj, "version", "") or "") if service_obj else "",
                    "extrainfo": str(getattr(service_obj, "extrainfo", "") or "") if service_obj else "",
                },
                "scripts": scripts,
            })

        cves = runtime._load_cves_for_host(project, int(host.id))
        screenshots = runtime._list_screenshots_for_host(project, str(getattr(host, "ip", "") or ""))
        ai_analysis = runtime._load_host_ai_analysis(project, int(host.id), str(getattr(host, "ip", "") or ""))
        inferred_urls = runtime._infer_host_urls(
            project,
            host_id=int(host.id),
            host_ip=str(getattr(host, "ip", "") or ""),
        )
        service_inventory_payload = [
            {
                "port": str(item.get("port", "") or ""),
                "protocol": str(item.get("protocol", "") or ""),
                "state": str(item.get("state", "") or ""),
                "service": str((item.get("service", {}) or {}).get("name", "") or ""),
                "service_product": str((item.get("service", {}) or {}).get("product", "") or ""),
                "service_version": str((item.get("service", {}) or {}).get("version", "") or ""),
                "service_extrainfo": str((item.get("service", {}) or {}).get("extrainfo", "") or ""),
            }
            for item in ports_data
            if isinstance(item, dict)
        ]
        os_state = resolve_host_os(host, service_inventory=service_inventory_payload)
        runtime._persist_shared_target_state(
            host_id=int(host.id),
            host_ip=str(getattr(host, "ip", "") or ""),
            hostname=str(getattr(host, "hostname", "") or ""),
            hostname_confidence=95.0 if str(getattr(host, "hostname", "") or "").strip() else 0.0,
            os_match=str(os_state.get("os", "") or ""),
            os_confidence=float(os_state.get("os_confidence", 0.0) or 0.0),
            technologies=ai_analysis.get("technologies", []) if isinstance(ai_analysis.get("technologies", []), list) else [],
            findings=ai_analysis.get("findings", []) if isinstance(ai_analysis.get("findings", []), list) else [],
            manual_tests=ai_analysis.get("manual_tests", []) if isinstance(ai_analysis.get("manual_tests", []), list) else [],
            next_phase=str(ai_analysis.get("next_phase", "") or ""),
            provider=str(ai_analysis.get("provider", "") or ""),
            goal_profile=str(ai_analysis.get("goal_profile", "") or ""),
            service_inventory=service_inventory_payload,
            urls=inferred_urls,
            screenshots=screenshots,
        )
        target_state = target_state_getter(project.database, int(host.id)) or {}
        os_state = resolve_host_os(host, service_inventory=service_inventory_payload, target_state=target_state)

        return {
            "host": {
                "id": int(host.id),
                "ip": str(getattr(host, "ip", "") or ""),
                "hostname": str(getattr(host, "hostname", "") or ""),
                "status": str(getattr(host, "status", "") or ""),
                "os": str(os_state.get("os", "") or ""),
                "raw_os": str(os_state.get("raw_os", "") or ""),
                "os_source": str(os_state.get("os_source", "") or ""),
                "os_confidence": float(os_state.get("os_confidence", 0.0) or 0.0),
            },
            "note": note_text,
            "ports": ports_data,
            "cves": cves,
            "screenshots": screenshots,
            "ai_analysis": ai_analysis,
            "target_state": target_state,
        }
