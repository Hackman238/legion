from __future__ import annotations

import datetime
import os
import uuid
from typing import Any, Dict, List, Optional

from app.importers.nmap_runner import import_nmap_xml_into_project
from app.web import runtime_scan_nmap_jobs as web_runtime_scan_nmap_jobs
from app.web import runtime_scan_rfc1918 as web_runtime_scan_rfc1918


start_subnet_rescan_job = web_runtime_scan_nmap_jobs.start_subnet_rescan_job
start_nmap_xml_import_job = web_runtime_scan_nmap_jobs.start_nmap_xml_import_job
start_host_rescan_job = web_runtime_scan_nmap_jobs.start_host_rescan_job
start_nmap_scan_job = web_runtime_scan_nmap_jobs.start_nmap_scan_job
run_rfc1918_chunked_scan_and_import = web_runtime_scan_rfc1918.run_rfc1918_chunked_scan_and_import


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

