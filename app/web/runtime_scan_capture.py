from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List

from app.web import runtime_scan_capture_analysis as web_runtime_scan_capture_analysis


preferred_capture_interface_sort_key = web_runtime_scan_capture_analysis.preferred_capture_interface_sort_key
list_capture_interfaces = web_runtime_scan_capture_analysis.list_capture_interfaces
get_capture_interface_inventory = web_runtime_scan_capture_analysis.get_capture_interface_inventory
connected_ipv4_networks_for_interface = web_runtime_scan_capture_analysis.connected_ipv4_networks_for_interface
passive_capture_filter = web_runtime_scan_capture_analysis.passive_capture_filter
parse_tshark_field_blob = web_runtime_scan_capture_analysis.parse_tshark_field_blob
classify_passive_protocols = web_runtime_scan_capture_analysis.classify_passive_protocols
analyze_passive_capture = web_runtime_scan_capture_analysis.analyze_passive_capture


def start_passive_capture_scan_job(
        runtime,
        *,
        interface_name: str,
        duration_minutes: int,
        run_actions: bool = False,
) -> Dict[str, Any]:
    with runtime._lock:
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
    scope = str((engagement_policy or {}).get("scope", "") or "").strip().lower()
    if scope != "internal":
        raise ValueError("Passive capture is available only for internal engagement scopes.")

    available_interfaces = {
        str(item.get("name", "") or "").strip(): item
        for item in runtime.list_capture_interfaces()
    }
    resolved_interface = str(interface_name or "").strip()
    if not resolved_interface:
        raise ValueError("Capture interface is required.")
    if resolved_interface not in available_interfaces:
        raise ValueError(f"Unknown or unavailable capture interface: {resolved_interface}")

    try:
        resolved_duration = int(duration_minutes or 0)
    except (TypeError, ValueError):
        resolved_duration = 0
    allowed_durations = {5, 15, 30, 45, 60, 75, 90, 105, 120}
    if resolved_duration not in allowed_durations:
        raise ValueError("Capture duration must be one of: 5, 15, 30, 45, 60, 75, 90, 105, 120 minutes.")

    payload = {
        "interface_name": resolved_interface,
        "duration_minutes": resolved_duration,
        "run_actions": bool(run_actions),
        "scan_mode": "passive_capture",
    }
    job = runtime._start_job(
        "passive-capture-scan",
        lambda job_id: runtime._run_passive_capture_scan(
            interface_name=resolved_interface,
            duration_minutes=resolved_duration,
            run_actions=bool(run_actions),
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )
    runtime._record_scan_submission(
        submission_kind="passive_capture_scan",
        job_id=int(job.get("id", 0) or 0),
        targets=[],
        discovery=False,
        staged=False,
        run_actions=bool(run_actions),
        nmap_path="",
        nmap_args="",
        scan_mode="passive_capture",
        scan_options={
            "interface_name": resolved_interface,
            "duration_minutes": resolved_duration,
        },
        target_summary=resolved_interface,
        scope_summary=f"interface: {resolved_interface} | duration: {resolved_duration}m",
        result_summary=f"queued passive capture on {resolved_interface} for {resolved_duration}m",
    )
    return job


def run_passive_capture_scan(
        runtime,
        *,
        interface_name: str,
        duration_minutes: int,
        run_actions: bool,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    resolved_interface = str(interface_name or "").strip()
    resolved_duration = int(duration_minutes or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"capturing on {resolved_interface} for {resolved_duration}m",
        )
    with runtime._lock:
        project = runtime._require_active_project()
        running_folder = project.properties.runningFolder
        output_prefix = os.path.join(
            running_folder,
            f"passive-capture-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
        )
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    capture_path = f"{output_prefix}.pcapng"
    analysis_path = f"{output_prefix}.analysis.json"
    capture_seconds = max(300, int(resolved_duration * 60))
    capture_command = runtime._join_shell_tokens([
        "tshark",
        "-i",
        resolved_interface,
        "-n",
        "-q",
        "-a",
        f"duration:{capture_seconds}",
        "-f",
        passive_capture_filter(),
        "-w",
        capture_path,
    ])

    executed, reason, process_id, metadata = runtime._run_command_with_tracking(
        tool_name="tshark-passive-capture",
        tab_title=f"Passive Capture ({resolved_interface})",
        host_ip=resolved_interface,
        port="",
        protocol="",
        command=capture_command,
        outputfile=output_prefix,
        timeout=capture_seconds + 180,
        job_id=resolved_job_id,
        return_metadata=True,
    )
    if not executed:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(reason or "capture failed"),
            )
        raise RuntimeError(str(reason or "Passive capture failed."))

    analysis = runtime._analyze_passive_capture(
        interface_name=resolved_interface,
        capture_path=capture_path,
        analysis_path=analysis_path,
    )
    candidate_networks = list(analysis.get("candidate_networks", []) or [])
    default_scan_options = runtime._apply_engagement_scan_profile({
        "discovery": True,
        "skip_dns": True,
        "timing": "T3",
        "top_ports": 1000,
        "explicit_ports": "",
        "service_detection": True,
        "default_scripts": True,
        "os_detection": False,
        "aggressive": False,
        "full_ports": False,
        "vuln_scripts": False,
        "host_discovery_only": False,
        "arp_ping": False,
    }, engagement_policy=engagement_policy)

    queued_scans: List[Dict[str, Any]] = []
    for subnet in candidate_networks[:16]:
        try:
            job = runtime.start_nmap_scan_job(
                targets=[str(subnet)],
                discovery=True,
                staged=False,
                run_actions=bool(run_actions),
                nmap_path="nmap",
                nmap_args="",
                scan_mode="easy",
                scan_options=dict(default_scan_options),
            )
            queued_scans.append({
                "subnet": str(subnet),
                "job_id": int(job.get("id", 0) or 0),
            })
        except Exception as exc:
            queued_scans.append({
                "subnet": str(subnet),
                "job_id": 0,
                "error": str(exc),
            })

    queued_count = len([item for item in queued_scans if int(item.get("job_id", 0) or 0) > 0])
    result_summary = (
        f"captured {resolved_duration}m on {resolved_interface}; "
        f"queued {queued_count} subnet scan"
        f"{'' if queued_count == 1 else 's'}"
    )
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="completed",
            result_summary=result_summary,
        )
    runtime._emit_ui_invalidation("processes", "jobs", "scan_history", "overview")
    return {
        "interface_name": resolved_interface,
        "duration_minutes": resolved_duration,
        "capture_command": capture_command,
        "capture_path": capture_path,
        "analysis_path": analysis.get("analysis_path", ""),
        "analysis": analysis,
        "queued_scans": queued_scans,
        "run_actions": bool(run_actions),
        "process_id": int(process_id or 0),
        "artifacts": list(metadata.get("artifact_refs", []) or []),
    }
