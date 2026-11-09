from __future__ import annotations

import contextlib
import threading
from typing import Any, Callable, Dict

from app.scheduler.scan_history import ensure_scan_submission_table, update_scan_submission

# How long a worker thread waits for the request thread to link the job id to the scan-history row.
SUBMISSION_LINK_GRACE_SECONDS = 5.0

_TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}


def start_job_with_scan_submission(
        runtime,
        job_type: str,
        runner_with_job_id: Callable[[int], Any],
        *,
        payload: Dict[str, Any],
        **submission: Any,
) -> Dict[str, Any]:
    """Start a scan-type job whose runner updates its scan-history row.

    The row is recorded before the job starts and linked to the job id right after, so the runner (which looks the
    row up by job id) never finds nothing because the request thread has not inserted it yet. A job manager that
    runs the runner inline cannot be waited for; its terminal status is copied onto the row instead.
    """
    record = runtime._record_scan_submission(job_id=0, **submission) or {}
    submission_id = int(record.get("id", 0) or 0)
    linked = threading.Event()
    starter_thread = threading.get_ident()

    def _run(job_id):
        if threading.get_ident() != starter_thread:
            linked.wait(SUBMISSION_LINK_GRACE_SECONDS)
        return runner_with_job_id(int(job_id or 0))

    try:
        job = runtime._start_job(str(job_type), _run, payload=dict(payload or {}))
    except Exception as exc:
        linked.set()
        _link_submission(runtime, submission_id, job_id=0, status="failed", result_summary=str(exc))
        raise
    try:
        job_status = str(job.get("status", "") or "").strip().lower()
        _link_submission(
            runtime,
            submission_id,
            job_id=int(job.get("id", 0) or 0),
            status=job_status if job_status in _TERMINAL_JOB_STATUSES else None,
            result_summary=str(job.get("error", "") or "") if job_status == "failed" else None,
        )
    finally:
        linked.set()
    return job


def _link_submission(runtime, submission_id: int, *, job_id: int, status=None, result_summary=None) -> None:
    if submission_id <= 0:
        return
    lock = getattr(runtime, "_lock", None) or contextlib.nullcontext()
    with lock:
        project = getattr(getattr(runtime, "logic", None), "activeProject", None)
        if project is None:
            return
        ensure_scan_submission_table(project.database)
        update_scan_submission(
            project.database,
            submission_id=int(submission_id),
            new_job_id=int(job_id or 0),
            status=status,
            result_summary=result_summary,
        )
