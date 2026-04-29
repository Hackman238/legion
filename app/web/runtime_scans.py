from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.scheduler.scan_history import (
    ensure_scan_submission_table,
    record_scan_submission as db_record_scan_submission,
    update_scan_submission as db_update_scan_submission,
)
from app.web import runtime_scan_capture as web_runtime_scan_capture
from app.web import runtime_scan_discovery as web_runtime_scan_discovery
from app.web import runtime_scan_nmap as web_runtime_scan_nmap
from app.web import runtime_scan_planning as web_runtime_scan_planning


record_bool = web_runtime_scan_planning.record_bool
normalize_targets = web_runtime_scan_planning.normalize_targets
apply_engagement_scan_profile = web_runtime_scan_planning.apply_engagement_scan_profile
normalize_subnet_target = web_runtime_scan_planning.normalize_subnet_target
count_rfc1918_scan_batches = web_runtime_scan_planning.count_rfc1918_scan_batches
iter_rfc1918_scan_batches = web_runtime_scan_planning.iter_rfc1918_scan_batches
normalize_rfc_chunk_concurrency = web_runtime_scan_planning.normalize_rfc_chunk_concurrency
scan_history_targets = web_runtime_scan_planning.scan_history_targets
scan_target_match_score_for_subnet = web_runtime_scan_planning.scan_target_match_score_for_subnet
best_scan_submission_for_subnet = web_runtime_scan_planning.best_scan_submission_for_subnet
build_nmap_scan_plan = web_runtime_scan_planning.build_nmap_scan_plan
build_single_scan_plan = web_runtime_scan_planning.build_single_scan_plan
normalize_scan_options = web_runtime_scan_planning.normalize_scan_options
normalize_timing = web_runtime_scan_planning.normalize_timing
normalize_top_ports = web_runtime_scan_planning.normalize_top_ports
normalize_explicit_ports = web_runtime_scan_planning.normalize_explicit_ports
contains_nmap_stats_every = web_runtime_scan_planning.contains_nmap_stats_every
contains_nmap_verbose = web_runtime_scan_planning.contains_nmap_verbose
append_nmap_stats_every = web_runtime_scan_planning.append_nmap_stats_every
nmap_output_prefix_for_command = web_runtime_scan_planning.nmap_output_prefix_for_command
join_shell_tokens = web_runtime_scan_planning.join_shell_tokens
compact_targets = web_runtime_scan_planning.compact_targets
summarize_scan_scope = web_runtime_scan_planning.summarize_scan_scope

start_subnet_rescan_job = web_runtime_scan_nmap.start_subnet_rescan_job
start_nmap_xml_import_job = web_runtime_scan_nmap.start_nmap_xml_import_job
start_host_rescan_job = web_runtime_scan_nmap.start_host_rescan_job
start_nmap_scan_job = web_runtime_scan_nmap.start_nmap_scan_job
import_nmap_xml = web_runtime_scan_nmap.import_nmap_xml
run_nmap_scan_and_import = web_runtime_scan_nmap.run_nmap_scan_and_import
run_rfc1918_chunked_scan_and_import = web_runtime_scan_nmap.run_rfc1918_chunked_scan_and_import

start_targets_import_job = web_runtime_scan_discovery.start_targets_import_job
import_targets_from_file = web_runtime_scan_discovery.import_targets_from_file
import_discovered_hosts_into_project = web_runtime_scan_discovery.import_discovered_hosts_into_project
queue_discovered_host_followup_scan = web_runtime_scan_discovery.queue_discovered_host_followup_scan
resolve_host_by_token = web_runtime_scan_discovery.resolve_host_by_token
mark_discovered_host_origin = web_runtime_scan_discovery.mark_discovered_host_origin
start_httpx_bootstrap_job = web_runtime_scan_discovery.start_httpx_bootstrap_job
httpx_bootstrap_command = web_runtime_scan_discovery.httpx_bootstrap_command
materialize_httpx_urls_as_web_targets = web_runtime_scan_discovery.materialize_httpx_urls_as_web_targets
run_httpx_bootstrap = web_runtime_scan_discovery.run_httpx_bootstrap
ingest_discovered_hosts = web_runtime_scan_discovery.ingest_discovered_hosts
run_governed_discovery = web_runtime_scan_discovery.run_governed_discovery

preferred_capture_interface_sort_key = web_runtime_scan_capture.preferred_capture_interface_sort_key
list_capture_interfaces = web_runtime_scan_capture.list_capture_interfaces
get_capture_interface_inventory = web_runtime_scan_capture.get_capture_interface_inventory
connected_ipv4_networks_for_interface = web_runtime_scan_capture.connected_ipv4_networks_for_interface
passive_capture_filter = web_runtime_scan_capture.passive_capture_filter
parse_tshark_field_blob = web_runtime_scan_capture.parse_tshark_field_blob
classify_passive_protocols = web_runtime_scan_capture.classify_passive_protocols
analyze_passive_capture = web_runtime_scan_capture.analyze_passive_capture
start_passive_capture_scan_job = web_runtime_scan_capture.start_passive_capture_scan_job
run_passive_capture_scan = web_runtime_scan_capture.run_passive_capture_scan


def record_scan_submission(
        runtime,
        *,
        submission_kind: str,
        job_id: int,
        targets: Optional[List[str]] = None,
        source_path: str = "",
        discovery: bool = False,
        staged: bool = False,
        run_actions: bool = False,
        nmap_path: str = "",
        nmap_args: str = "",
        scan_mode: str = "",
        scan_options: Optional[Dict[str, Any]] = None,
        target_summary: str = "",
        scope_summary: str = "",
        result_summary: str = "",
) -> Optional[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if project is None:
            return None
        ensure_scan_submission_table(project.database)
        normalized_targets = [str(item or "").strip() for item in list(targets or []) if str(item or "").strip()]
        record = db_record_scan_submission(project.database, {
            "job_id": str(int(job_id or 0) or ""),
            "submission_kind": str(submission_kind or ""),
            "status": "submitted",
            "target_summary": str(target_summary or compact_targets(normalized_targets)),
            "scope_summary": str(scope_summary or summarize_scan_scope(normalized_targets)),
            "targets": normalized_targets,
            "source_path": str(source_path or ""),
            "scan_mode": str(scan_mode or ""),
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": str(nmap_path or ""),
            "nmap_args": str(nmap_args or ""),
            "scan_options": dict(scan_options or {}),
            "result_summary": str(result_summary or ""),
        })
    runtime._emit_ui_invalidation("scan_history")
    return record


def update_scan_submission_status(
        runtime,
        *,
        job_id: int,
        status: str,
        result_summary: str = "",
) -> Optional[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if project is None:
            return None
        ensure_scan_submission_table(project.database)
        record = db_update_scan_submission(
            project.database,
            job_id=int(job_id or 0),
            status=str(status or ""),
            result_summary=str(result_summary or ""),
        )
    runtime._emit_ui_invalidation("scan_history")
    return record
