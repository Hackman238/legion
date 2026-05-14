from __future__ import annotations

from typing import Any, Dict, List


def register_job_process(runtime, job_id: int, process_id: int):
    resolved_job_id = int(job_id or 0)
    resolved_process_id = int(process_id or 0)
    if resolved_job_id <= 0 or resolved_process_id <= 0:
        return
    if not hasattr(runtime, "_job_process_ids"):
        runtime._job_process_ids = {}
    if not hasattr(runtime, "_process_job_id"):
        runtime._process_job_id = {}
    with runtime._process_runtime_lock:
        process_ids = runtime._job_process_ids.setdefault(resolved_job_id, set())
        process_ids.add(resolved_process_id)
        runtime._process_job_id[resolved_process_id] = resolved_job_id


def unregister_job_process(runtime, process_id: int):
    resolved_process_id = int(process_id or 0)
    if resolved_process_id <= 0:
        return
    if not hasattr(runtime, "_job_process_ids") or not hasattr(runtime, "_process_job_id"):
        return
    with runtime._process_runtime_lock:
        owner_job_id = runtime._process_job_id.pop(resolved_process_id, None)
        if owner_job_id is None:
            return
        process_ids = runtime._job_process_ids.get(int(owner_job_id))
        if not process_ids:
            return
        process_ids.discard(resolved_process_id)
        if not process_ids:
            runtime._job_process_ids.pop(int(owner_job_id), None)


def job_active_process_ids(runtime, job_id: int) -> List[int]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id <= 0:
        return []
    if not hasattr(runtime, "_job_process_ids"):
        return []
    with runtime._process_runtime_lock:
        process_ids = list(runtime._job_process_ids.get(resolved_job_id, set()))
    return sorted({int(item) for item in process_ids if int(item) > 0})


def list_jobs(runtime, limit: int = 80) -> List[Dict[str, Any]]:
    return runtime.jobs.list_jobs(limit=limit)


def get_job(runtime, job_id: int) -> Dict[str, Any]:
    job = runtime.jobs.get_job(job_id)
    if job is None:
        raise KeyError(f"Unknown job id: {job_id}")
    return job


def stop_job(runtime, job_id: int) -> Dict[str, Any]:
    target_job_id = int(job_id)
    job = runtime.jobs.get_job(target_job_id)
    if job is None:
        raise KeyError(f"Unknown job id: {job_id}")

    status = str(job.get("status", "") or "").strip().lower()
    if status not in {"queued", "running"}:
        return {
            "stopped": False,
            "job": job,
            "killed_process_ids": [],
            "message": "Job is not running or queued.",
        }

    updated = runtime.jobs.cancel_job(target_job_id, reason="stopped by user")
    if updated is None:
        raise KeyError(f"Unknown job id: {job_id}")

    killed_process_ids = []
    for process_id in job_active_process_ids(runtime, target_job_id):
        try:
            runtime.kill_process(int(process_id))
            killed_process_ids.append(int(process_id))
        except Exception:
            continue

    final_job = runtime.jobs.get_job(target_job_id) or updated
    return {
        "stopped": True,
        "job": final_job,
        "killed_process_ids": killed_process_ids,
    }
