from __future__ import annotations

import datetime
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from app.importers.nmap_runner import import_nmap_xml_into_project
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


def import_nmap_xml(
        runtime,
        xml_path: str,
        run_actions: bool = False,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"importing {os.path.basename(str(xml_path or ''))}",
        )
    try:
        with runtime._lock:
            project = runtime._require_active_project()
            import_nmap_xml_into_project(
                project=project,
                xml_path=xml_path,
                output="",
                update_progress_observable=None,
            )

            try:
                runtime.logic.copyNmapXMLToOutputFolder(xml_path)
            except Exception:
                pass

            runtime._ensure_scheduler_table()
            runtime._ensure_scheduler_approval_store()

        scheduler_result = None
        if run_actions:
            scheduler_result = runtime._run_scheduler_actions_web()

        result = {
            "xml_path": xml_path,
            "run_actions": bool(run_actions),
            "scheduler_result": scheduler_result,
        }
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="completed",
                result_summary=f"imported {os.path.basename(str(xml_path or ''))}",
            )
        return result
    except Exception as exc:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(exc),
            )
        raise


def run_nmap_scan_and_import(
        runtime,
        targets: List[str],
        discovery: bool,
        staged: bool,
        run_actions: bool,
        nmap_path: str,
        nmap_args: str,
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"running nmap against {runtime._compact_targets(targets)}",
        )
    with runtime._lock:
        project = runtime._require_active_project()
        running_folder = project.properties.runningFolder
        host_count_before = len(project.repositoryContainer.hostRepository.getAllHostObjs())
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S%f")
        unique_suffix = f"job-{resolved_job_id}" if resolved_job_id > 0 else uuid.uuid4().hex[:12]
        output_prefix = os.path.join(
            running_folder,
            f"web-nmap-{timestamp}-{unique_suffix}",
        )

    try:
        if str(scan_mode or "").strip().lower() == "rfc1918_discovery":
            result = runtime._run_rfc1918_chunked_scan_and_import(
                targets=targets,
                discovery=bool(discovery),
                run_actions=bool(run_actions),
                nmap_path=nmap_path,
                nmap_args=nmap_args,
                scan_options=dict(scan_options or {}),
                job_id=resolved_job_id,
                output_prefix=output_prefix,
                host_count_before=host_count_before,
            )
            runtime._emit_ui_invalidation("overview", "hosts", "services", "graph", "scan_history")
            return result

        scan_plan = runtime._build_nmap_scan_plan(
            targets=targets,
            discovery=bool(discovery),
            staged=bool(staged),
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=output_prefix,
            scan_mode=scan_mode,
            scan_options=dict(scan_options or {}),
        )

        target_label = runtime._compact_targets(targets)
        stage_results: List[Dict[str, Any]] = []
        for stage in scan_plan["stages"]:
            if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
                raise RuntimeError("cancelled")
            executed, reason, process_id = runtime._run_command_with_tracking(
                tool_name=stage["tool_name"],
                tab_title=stage["tab_title"],
                host_ip=target_label,
                port="",
                protocol="",
                command=stage["command"],
                outputfile=stage["output_prefix"],
                timeout=int(stage.get("timeout", 3600)),
                job_id=resolved_job_id,
            )
            stage_results.append({
                "name": stage["tool_name"],
                "command": stage["command"],
                "executed": bool(executed),
                "reason": reason,
                "process_id": int(process_id or 0),
                "output_prefix": stage["output_prefix"],
                "xml_path": stage["xml_path"],
            })
            if not executed:
                raise RuntimeError(
                    f"Nmap stage '{stage['tool_name']}' failed ({reason}). "
                    f"Command: {stage['command']}"
                )

        xml_path = scan_plan["xml_path"]
        if not xml_path or not os.path.isfile(xml_path):
            raise RuntimeError(f"Nmap scan completed but XML output was not found: {xml_path}")

        import_result = runtime._import_nmap_xml(xml_path, run_actions=run_actions)
        with runtime._lock:
            project = runtime._require_active_project()
            host_count_after = len(project.repositoryContainer.hostRepository.getAllHostObjs())
        imported_hosts = max(0, int(host_count_after) - int(host_count_before))
        warnings: List[str] = []
        if imported_hosts == 0:
            if bool(discovery):
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "The target may be dropping discovery probes; try disabling host discovery (-Pn)."
                )
            else:
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "Verify target reachability and scan privileges."
                )

        result = {
            "targets": targets,
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": nmap_path,
            "nmap_args": str(nmap_args or ""),
            "scan_mode": str(scan_mode or "legacy"),
            "scan_options": dict(scan_options or {}),
            "commands": [stage["command"] for stage in scan_plan["stages"]],
            "stages": stage_results,
            "xml_path": xml_path,
            "imported_hosts": imported_hosts,
            "warnings": warnings,
            **import_result,
        }
        if resolved_job_id > 0:
            warning_note = f" ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})" if warnings else ""
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="completed",
                result_summary=f"imported {imported_hosts} host{'s' if imported_hosts != 1 else ''}{warning_note}",
            )
        runtime._emit_ui_invalidation("overview", "hosts", "services", "graph", "scan_history")
        return result
    except Exception as exc:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(exc),
            )
        runtime._emit_ui_invalidation("scan_history")
        raise


def run_rfc1918_chunked_scan_and_import(
        runtime,
        *,
        targets: List[str],
        discovery: bool,
        run_actions: bool,
        nmap_path: str,
        nmap_args: str,
        scan_options: Dict[str, Any],
        job_id: int,
        output_prefix: str,
        host_count_before: int,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    normalized_scan_options = dict(scan_options or {})
    chunk_concurrency = runtime._normalize_rfc_chunk_concurrency(
        normalized_scan_options.get("chunk_concurrency", 1)
    )
    normalized_scan_options["chunk_concurrency"] = chunk_concurrency

    batches = list(runtime._iter_rfc1918_scan_batches(targets))
    total_batches = len(batches)
    if total_batches <= 0:
        raise RuntimeError("RFC1918 discovery requires at least one selected private subnet.")

    completed_batches = 0
    last_xml_path = ""
    active_workers = max(1, min(int(chunk_concurrency), int(total_batches)))
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=(
                f"running RFC1918 sweep across {total_batches} "
                f"batch{'' if total_batches == 1 else 'es'} "
                f"(up to {active_workers} concurrent)"
            ),
        )

    def _run_rfc_batch(batch_index: int, batch_targets: List[str]) -> Dict[str, Any]:
        if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
            raise RuntimeError("cancelled")

        batch_prefix = f"{output_prefix}-chunk-{batch_index:05d}"
        scan_plan = runtime._build_nmap_scan_plan(
            targets=list(batch_targets),
            discovery=bool(discovery),
            staged=False,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=batch_prefix,
            scan_mode="rfc1918_discovery",
            scan_options=dict(normalized_scan_options),
        )
        target_label = runtime._compact_targets(batch_targets)

        for stage in list(scan_plan.get("stages", []) or []):
            stage_tab_title = str(stage.get("tab_title", "Nmap RFC1918 Discovery") or "Nmap RFC1918 Discovery")
            if total_batches > 1:
                stage_tab_title = f"{stage_tab_title} {batch_index}/{total_batches}"
            executed, reason, process_id = runtime._run_command_with_tracking(
                tool_name=str(stage.get("tool_name", "nmap-rfc1918_discovery") or "nmap-rfc1918_discovery"),
                tab_title=stage_tab_title,
                host_ip=target_label,
                port="",
                protocol="",
                command=str(stage.get("command", "") or ""),
                outputfile=str(stage.get("output_prefix", batch_prefix) or batch_prefix),
                timeout=int(stage.get("timeout", 3600) or 3600),
                job_id=resolved_job_id,
            )
            _ = int(process_id or 0)
            if not executed:
                raise RuntimeError(
                    f"Nmap stage '{stage.get('tool_name', 'nmap-rfc1918_discovery')}' failed ({reason}). "
                    f"Command: {stage.get('command', '')}"
                )

        xml_path = str(scan_plan.get("xml_path", "") or "")
        if not xml_path or not os.path.isfile(xml_path):
            raise RuntimeError(f"Nmap chunk completed but XML output was not found: {xml_path}")
        return {
            "batch_index": int(batch_index),
            "batch_targets": list(batch_targets),
            "xml_path": xml_path,
        }

    batch_iter = iter(list(enumerate(batches, start=1)))
    pending: Dict[object, int] = {}

    def _submit_next(pool: ThreadPoolExecutor) -> bool:
        try:
            next_batch_index, next_batch_targets = next(batch_iter)
        except StopIteration:
            return False
        future = pool.submit(_run_rfc_batch, int(next_batch_index), list(next_batch_targets))
        pending[future] = int(next_batch_index)
        return True

    with ThreadPoolExecutor(max_workers=active_workers, thread_name_prefix="legion-rfc1918") as pool:
        for _ in range(active_workers):
            if not _submit_next(pool):
                break

        while pending:
            finished_future = next(as_completed(list(pending.keys())))
            pending.pop(finished_future, None)
            batch_result = finished_future.result()
            xml_path = str(batch_result.get("xml_path", "") or "")
            runtime._import_nmap_xml(xml_path, run_actions=False)
            last_xml_path = xml_path
            completed_batches += 1

            if resolved_job_id > 0:
                runtime._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="running",
                    result_summary=(
                        f"completed RFC1918 sweep batch {completed_batches}/{total_batches} "
                        f"(up to {active_workers} concurrent)"
                    ),
                )
            if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
                raise RuntimeError("cancelled")
            _submit_next(pool)

    scheduler_result = runtime._run_scheduler_actions_web() if run_actions else None
    with runtime._lock:
        project = runtime._require_active_project()
        host_count_after = len(project.repositoryContainer.hostRepository.getAllHostObjs())
    imported_hosts = max(0, int(host_count_after) - int(host_count_before))
    warnings: List[str] = []
    if imported_hosts == 0:
        warnings.append(
            "RFC1918 sweep completed but no hosts were imported. "
            "Verify the selected ranges are reachable from this network segment."
        )
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="completed",
            result_summary=(
                f"completed RFC1918 sweep across {completed_batches}/{total_batches} "
                f"batch{'' if completed_batches == 1 else 'es'} "
                f"(up to {active_workers} concurrent)"
            ),
        )
    return {
        "targets": list(targets or []),
        "discovery": bool(discovery),
        "run_actions": bool(run_actions),
        "nmap_path": nmap_path,
        "nmap_args": str(nmap_args or ""),
        "scan_mode": "rfc1918_discovery",
        "scan_options": dict(normalized_scan_options),
        "xml_path": last_xml_path,
        "chunks_completed": int(completed_batches),
        "chunks_total": int(total_batches),
        "chunk_concurrency": int(active_workers),
        "imported_hosts": imported_hosts,
        "warnings": warnings,
        "scheduler_result": scheduler_result,
    }
