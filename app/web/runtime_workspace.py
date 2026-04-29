from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.scheduler.insights import delete_host_ai_state
from app.scheduler.state import get_target_state, upsert_target_state
from app.scheduler.state import load_observed_service_inventory
from app.web import runtime_workspace_mutation as web_runtime_workspace_mutation
from app.web import runtime_workspace_read as web_runtime_workspace_read


host_is_down = web_runtime_workspace_read.host_is_down
summary = web_runtime_workspace_read.summary
resolve_host = web_runtime_workspace_read.resolve_host
load_cves_for_host = web_runtime_workspace_read.load_cves_for_host
get_workspace_overview = web_runtime_workspace_read.get_workspace_overview
workspace_host_services = web_runtime_workspace_read.workspace_host_services
hostname_for_ip = web_runtime_workspace_read.hostname_for_ip
service_name_for_target = web_runtime_workspace_read.service_name_for_target
resolve_host_device_categories = web_runtime_workspace_read.resolve_host_device_categories
get_workspace_services = web_runtime_workspace_read.get_workspace_services
strip_nmap_preamble = web_runtime_workspace_read.strip_nmap_preamble
host_detail_script_preview = web_runtime_workspace_read.host_detail_script_preview

ensure_workspace_settings_table = web_runtime_workspace_mutation.ensure_workspace_settings_table
get_workspace_setting_locked = web_runtime_workspace_mutation.get_workspace_setting_locked
set_workspace_setting_locked = web_runtime_workspace_mutation.set_workspace_setting_locked
update_host_note = web_runtime_workspace_mutation.update_host_note
delete_host_workspace = web_runtime_workspace_mutation.delete_host_workspace
create_script_entry = web_runtime_workspace_mutation.create_script_entry
delete_script_entry = web_runtime_workspace_mutation.delete_script_entry
get_script_output = web_runtime_workspace_mutation.get_script_output
create_cve_entry = web_runtime_workspace_mutation.create_cve_entry
delete_cve_entry = web_runtime_workspace_mutation.delete_cve_entry


def build_workspace_host_row(runtime, host: Any, port_repo: Any, service_repo: Any, project: Any) -> Dict[str, Any]:
    return web_runtime_workspace_read.build_workspace_host_row(
        runtime,
        host,
        port_repo,
        service_repo,
        project,
        get_target_state_func=get_target_state,
    )


def hosts(runtime, limit: Optional[int] = None, include_down: bool = False) -> List[Dict[str, Any]]:
    return web_runtime_workspace_read.hosts(
        runtime,
        limit=limit,
        include_down=include_down,
        build_workspace_host_row_func=build_workspace_host_row,
    )


def get_workspace_hosts(
        runtime,
        limit: Optional[int] = None,
        include_down: bool = False,
        service: str = "",
        category: str = "",
) -> List[Dict[str, Any]]:
    return web_runtime_workspace_read.get_workspace_hosts(
        runtime,
        limit=limit,
        include_down=include_down,
        service=service,
        category=category,
        build_workspace_host_row_func=build_workspace_host_row,
    )


def get_target_state_view(runtime, host_id: int = 0, limit: int = 500) -> Dict[str, Any]:
    return web_runtime_workspace_read.get_target_state_view(
        runtime,
        host_id=host_id,
        limit=limit,
        get_target_state_func=get_target_state,
    )


def get_findings(
        runtime,
        host_id: int = 0,
        limit_hosts: int = 500,
        limit_findings: int = 1000,
) -> Dict[str, Any]:
    return web_runtime_workspace_read.get_findings(
        runtime,
        host_id=host_id,
        limit_hosts=limit_hosts,
        limit_findings=limit_findings,
        get_target_state_func=get_target_state,
    )


def get_host_workspace(runtime, host_id: int) -> Dict[str, Any]:
    return web_runtime_workspace_read.get_host_workspace(
        runtime,
        host_id,
        get_target_state_func=get_target_state,
    )


def update_host_categories(
        runtime,
        host_id: int,
        *,
        manual_categories: Any = None,
        override_auto: bool = False,
) -> Dict[str, Any]:
    return web_runtime_workspace_mutation.update_host_categories(
        runtime,
        host_id,
        manual_categories=manual_categories,
        override_auto=override_auto,
        upsert_target_state_func=upsert_target_state,
    )
