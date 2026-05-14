from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.screenshot_targets import choose_preferred_command_host


def start_subnet_rescan_job(runtime, subnet: str) -> Dict[str, Any]:
    normalized_subnet = runtime._normalize_subnet_target(subnet)
    with runtime._lock:
        for job in runtime.jobs.list_jobs(limit=200):
            if str(job.get("type", "")).strip() != "nmap-scan":
                continue
            status = str(job.get("status", "") or "").strip().lower()
            if status not in {"queued", "running"}:
                continue
            payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
            try:
                job_targets = runtime._normalize_targets(payload.get("targets", []))
            except Exception:
                job_targets = []
            if normalized_subnet in job_targets:
                existing_copy = dict(job)
                existing_copy["existing"] = True
                return existing_copy
        template = runtime._best_scan_submission_for_subnet(normalized_subnet, runtime.get_scan_history(limit=400))
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    if isinstance(template, dict):
        return runtime.start_nmap_scan_job(
            targets=[normalized_subnet],
            discovery=runtime._record_bool(template.get("discovery"), True),
            staged=runtime._record_bool(template.get("staged"), False),
            run_actions=runtime._record_bool(template.get("run_actions"), False),
            nmap_path=str(template.get("nmap_path", "nmap") or "nmap").strip() or "nmap",
            nmap_args=str(template.get("nmap_args", "") or "").strip(),
            scan_mode=str(template.get("scan_mode", "legacy") or "legacy").strip().lower() or "legacy",
            scan_options=dict(template.get("scan_options", {}) or {}),
        )

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
    return runtime.start_nmap_scan_job(
        targets=[normalized_subnet],
        discovery=True,
        staged=False,
        run_actions=False,
        nmap_path="nmap",
        nmap_args="",
        scan_mode="easy",
        scan_options=default_scan_options,
    )


def start_nmap_xml_import_job(
        runtime,
        path: str,
        run_actions: bool = False,
) -> Dict[str, Any]:
    xml_path = runtime._normalize_existing_file(path)
    job = runtime._start_job(
        "import-nmap-xml",
        lambda job_id: runtime._import_nmap_xml(xml_path, bool(run_actions), job_id=int(job_id or 0)),
        payload={"path": xml_path, "run_actions": bool(run_actions)},
    )
    runtime._record_scan_submission(
        submission_kind="import_nmap_xml",
        job_id=int(job.get("id", 0) or 0),
        source_path=xml_path,
        run_actions=bool(run_actions),
        result_summary=f"queued import from {os.path.basename(xml_path)}",
    )
    return job


def start_host_rescan_job(runtime, host_id: int) -> Dict[str, Any]:
    with runtime._lock:
        host = runtime._resolve_host(int(host_id))
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    scan_target = choose_preferred_command_host(hostname, host_ip, "nmap")
    uses_hostname_target = scan_target != host_ip
    default_scan_options = runtime._apply_engagement_scan_profile({
        "discovery": True,
        "skip_dns": not uses_hostname_target,
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
    return runtime.start_nmap_scan_job(
        targets=[scan_target],
        discovery=True,
        staged=False,
        run_actions=False,
        nmap_path="nmap",
        nmap_args="",
        scan_mode="easy",
        scan_options=default_scan_options,
    )


def start_nmap_scan_job(
        runtime,
        targets,
        discovery: bool = True,
        staged: bool = False,
        run_actions: bool = False,
        nmap_path: str = "nmap",
        nmap_args: str = "",
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_targets = runtime._normalize_targets(targets)
    resolved_nmap_path = str(nmap_path or "nmap").strip() or "nmap"
    resolved_nmap_args = str(nmap_args or "").strip()
    resolved_scan_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
    resolved_scan_options = dict(scan_options or {})
    payload = {
        "targets": normalized_targets,
        "discovery": bool(discovery),
        "staged": bool(staged),
        "run_actions": bool(run_actions),
        "nmap_path": resolved_nmap_path,
        "nmap_args": resolved_nmap_args,
        "scan_mode": resolved_scan_mode,
        "scan_options": resolved_scan_options,
    }
    job = runtime._start_job(
        "nmap-scan",
        lambda job_id: runtime._run_nmap_scan_and_import(
            normalized_targets,
            discovery=bool(discovery),
            staged=bool(staged),
            run_actions=bool(run_actions),
            nmap_path=resolved_nmap_path,
            nmap_args=resolved_nmap_args,
            scan_mode=resolved_scan_mode,
            scan_options=resolved_scan_options,
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )
    runtime._record_scan_submission(
        submission_kind="nmap_scan",
        job_id=int(job.get("id", 0) or 0),
        targets=normalized_targets,
        discovery=bool(discovery),
        staged=bool(staged),
        run_actions=bool(run_actions),
        nmap_path=resolved_nmap_path,
        nmap_args=resolved_nmap_args,
        scan_mode=resolved_scan_mode,
        scan_options=resolved_scan_options,
        result_summary=f"queued nmap for {runtime._compact_targets(normalized_targets)}",
    )
    return job
