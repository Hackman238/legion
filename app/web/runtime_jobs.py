from __future__ import annotations

import datetime
import threading
import time
from typing import Any, Dict, Optional


def emit_ui_invalidation(runtime, *channels: str, throttle_seconds: float = 0.0):
    normalized = sorted({str(item or "").strip() for item in channels if str(item or "").strip()})
    if not normalized:
        return
    key = ",".join(normalized)
    with runtime._ui_event_condition:
        now = time.monotonic()
        if float(throttle_seconds or 0.0) > 0.0:
            last_emitted = float(runtime._ui_last_emit_monotonic.get(key, 0.0) or 0.0)
            if (now - last_emitted) < float(throttle_seconds):
                return
        runtime._ui_last_emit_monotonic[key] = now
        runtime._ui_event_seq += 1
        runtime._ui_events.append({
            "type": "invalidate",
            "seq": int(runtime._ui_event_seq),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "channels": normalized,
        })
        if len(runtime._ui_events) > 256:
            runtime._ui_events = runtime._ui_events[-256:]
        runtime._ui_event_condition.notify_all()


def wait_for_ui_event(runtime, after_seq: int = 0, timeout_seconds: float = 30.0) -> Dict[str, Any]:
    cursor = max(0, int(after_seq or 0))
    timeout_value = max(0.0, float(timeout_seconds or 0.0))
    deadline = time.monotonic() + timeout_value if timeout_value > 0 else None
    with runtime._ui_event_condition:
        while True:
            pending = [item for item in runtime._ui_events if int(item.get("seq", 0) or 0) > cursor]
            if pending:
                channels = sorted({
                    str(channel or "").strip()
                    for item in pending
                    for channel in list(item.get("channels", []) or [])
                    if str(channel or "").strip()
                })
                return {
                    "type": "invalidate",
                    "seq": max(int(item.get("seq", 0) or 0) for item in pending),
                    "channels": channels,
                }
            if deadline is None:
                runtime._ui_event_condition.wait()
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"type": "heartbeat", "seq": cursor, "channels": []}
            runtime._ui_event_condition.wait(remaining)


def _dispose_retired_databases_if_idle(runtime) -> None:
    # Databases replaced by a web Save As while other jobs were running are released once no job runs.
    logic = getattr(runtime, "logic", None)
    if logic is None or not getattr(logic, "hasRetiredDatabases", lambda: False)():
        return
    try:
        jobs = list(runtime.jobs.list_jobs(limit=200) or [])
    except Exception:
        return
    if any(str(job.get("status", "") or "").strip().lower() == "running" for job in jobs):
        return
    logic.disposeRetiredDatabases()


def handle_job_change(runtime, job: Dict[str, Any], event_name: str):
    if str(event_name or "").strip().lower() in {"completed", "failed", "cancelled"}:
        _dispose_retired_databases_if_idle(runtime)
    channels = {"jobs", "overview"}
    job_type = str(job.get("type", "") or "").strip().lower()
    if job_type in {
        "nmap-scan",
        "import-nmap-xml",
        "scheduler-run",
        "scheduler-approval-execute",
        "scheduler-dig-deeper",
        "tool-run",
        "process-retry",
        "credential-capture-session",
    }:
        channels.add("processes")
    if job_type in {"credential-capture-session"}:
        channels.add("credential_capture")
    if job_type in {"nmap-scan", "import-nmap-xml", "project-restore-zip"}:
        channels.update({"scan_history", "hosts", "services", "graph"})
    emit_ui_invalidation(runtime, *sorted(channels))


def start_job(
        runtime,
        job_type: str,
        runner_with_job_id,
        *,
        payload: Optional[Dict[str, Any]] = None,
        queue_front: bool = False,
        exclusive: bool = False,
        on_discard=None,
) -> Dict[str, Any]:
    if not callable(runner_with_job_id):
        raise ValueError("runner_with_job_id must be callable.")

    job_ref = {"id": 0}
    job_id_ready = threading.Event()
    starter_thread = threading.get_ident()

    def _wrapped_runner():
        # A worker can pick the job up before jobs.start() returns; wait until
        # the id has been recorded so the runner never sees job_id=0. Skip the
        # wait when a job manager runs the runner synchronously inside start().
        if threading.get_ident() != starter_thread:
            job_id_ready.wait()
        return runner_with_job_id(int(job_ref.get("id", 0) or 0)) or {}

    start_kwargs = {}
    if callable(on_discard):
        start_kwargs["on_discard"] = on_discard
    try:
        job = runtime.jobs.start(
            str(job_type),
            _wrapped_runner,
            payload=dict(payload or {}),
            queue_front=bool(queue_front),
            exclusive=bool(exclusive),
            **start_kwargs,
        )
        job_ref["id"] = int(job.get("id", 0) or 0)
    finally:
        job_id_ready.set()
    return job


def find_active_job(
        runtime,
        *,
        job_type: str,
        host_id: Optional[int] = None,
        payload_match=None,
) -> Optional[Dict[str, Any]]:
    """First queued/running job of job_type, optionally for host_id and/or whose payload satisfies payload_match."""
    for job in runtime.jobs.list_jobs(limit=200):
        if str(job.get("type", "")).strip() != str(job_type or "").strip():
            continue
        status = str(job.get("status", "")).strip().lower()
        if status not in {"queued", "running"}:
            continue
        payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
        if payload_match is not None and not payload_match(payload):
            continue
        if host_id is None:
            return job
        try:
            payload_host_id = int(payload.get("host_id", 0) or 0)
        except (TypeError, ValueError):
            payload_host_id = 0
        if payload_host_id == int(host_id):
            return job
    return None
