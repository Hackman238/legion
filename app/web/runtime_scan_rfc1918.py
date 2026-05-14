from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List


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
