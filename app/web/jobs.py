import datetime
import itertools
import threading
from typing import Any, Callable, Dict, List, Optional


class WebJobManager:
    def __init__(self, max_jobs: int = 200, worker_count: int = 1):
        self.max_jobs = max(20, int(max_jobs))
        self.worker_count = max(1, int(worker_count))
        self._lock = threading.Lock()
        self._queue_cv = threading.Condition(self._lock)
        self._counter = itertools.count(1)
        self._jobs: List[Dict[str, Any]] = []
        self._jobs_by_id: Dict[int, Dict[str, Any]] = {}
        self._pending_job_ids: List[int] = []
        self._runners: Dict[int, Callable[[], Dict[str, Any]]] = {}
        self._workers: List[threading.Thread] = []
        self._running_job_count = 0
        self._running_exclusive_job_id = 0

        self.ensure_worker_count(self.worker_count)

    def start(
            self,
            job_type: str,
            runner: Callable[[], Dict[str, Any]],
            payload: Optional[Dict[str, Any]] = None,
            queue_front: bool = False,
            exclusive: bool = False,
    ):
        job_id = next(self._counter)
        now = self._utc_now()
        job = {
            "id": job_id,
            "type": str(job_type),
            "status": "queued",
            "exclusive": bool(exclusive),
            "cancel_requested": False,
            "cancel_reason": "",
            "created_at": now,
            "started_at": "",
            "finished_at": "",
            "payload": payload or {},
            "result": {},
            "error": "",
        }
        with self._queue_cv:
            self._jobs.append(job)
            self._jobs_by_id[job_id] = job
            self._runners[job_id] = runner
            if queue_front:
                self._pending_job_ids.insert(0, job_id)
            else:
                self._pending_job_ids.append(job_id)
            self._trim_locked()
            self._queue_cv.notify_all()
        return self._copy_job(job)

    def list_jobs(self, limit: int = 80) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), self.max_jobs))
        with self._lock:
            selected = list(reversed(self._jobs[-limit:]))
            return [self._copy_job(item) for item in selected]

    def ensure_worker_count(self, worker_count: int) -> Dict[str, Any]:
        requested = max(1, int(worker_count))
        with self._queue_cv:
            before = len(self._workers)
            current = before
            if requested > current:
                for worker_index in range(current + 1, requested + 1):
                    self._spawn_worker(worker_index)
                current = len(self._workers)

            # Shrinking workers is not supported in-place because workers are daemon loops.
            effective = current
            self.worker_count = effective
            self._queue_cv.notify_all()
            return {
                "requested": int(requested),
                "effective": int(effective),
                "increased": requested > before,
                "decrease_deferred": requested < effective,
            }

    def ensure_max_jobs(self, max_jobs: int) -> Dict[str, Any]:
        requested = max(20, int(max_jobs))
        with self._queue_cv:
            before = int(self.max_jobs)
            self.max_jobs = requested
            self._trim_locked()
            self._queue_cv.notify_all()
            return {
                "requested": int(requested),
                "effective": int(self.max_jobs),
                "changed": int(before) != int(self.max_jobs),
            }

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs_by_id.get(int(job_id))
            if job is None:
                return None
            return self._copy_job(job)

    def cancel_job(self, job_id: int, reason: str = "cancelled by user") -> Optional[Dict[str, Any]]:
        target_id = int(job_id)
        cancel_reason = str(reason or "cancelled by user")
        with self._queue_cv:
            job = self._jobs_by_id.get(target_id)
            if job is None:
                return None

            status = str(job.get("status", "") or "").strip().lower()
            if status in {"completed", "failed", "cancelled"}:
                return self._copy_job(job)

            job["cancel_requested"] = True
            job["cancel_reason"] = cancel_reason

            if status == "queued":
                if target_id in self._pending_job_ids:
                    self._pending_job_ids.remove(target_id)
                if target_id in self._runners:
                    del self._runners[target_id]
                job["status"] = "cancelled"
                job["error"] = cancel_reason
                job["finished_at"] = self._utc_now()
                self._trim_locked()

            self._queue_cv.notify_all()
            return self._copy_job(job)

    def is_cancel_requested(self, job_id: int) -> bool:
        target_id = int(job_id)
        with self._lock:
            job = self._jobs_by_id.get(target_id)
            if not job:
                return False
            return bool(job.get("cancel_requested", False))

    def _worker_loop(self):
        while True:
            with self._queue_cv:
                selected = None
                while selected is None:
                    selected = self._dequeue_next_runnable_locked()
                    if selected is not None:
                        break
                    self._queue_cv.wait()

                job_id, runner = selected
                job = self._jobs_by_id.get(job_id)
                if not job:
                    continue

            try:
                result = runner() or {}
                with self._lock:
                    job = self._jobs_by_id.get(job_id)
                    if not job:
                        continue
                    if bool(job.get("cancel_requested", False)):
                        job["status"] = "cancelled"
                        if not str(job.get("error", "") or "").strip():
                            job["error"] = str(job.get("cancel_reason", "") or "cancelled by user")
                    else:
                        job["status"] = "completed"
                    job["result"] = result
            except Exception as exc:
                with self._lock:
                    job = self._jobs_by_id.get(job_id)
                    if not job:
                        continue
                    if bool(job.get("cancel_requested", False)):
                        job["status"] = "cancelled"
                        cancel_reason = str(job.get("cancel_reason", "") or "").strip()
                        job["error"] = cancel_reason or f"cancelled ({exc})"
                    else:
                        job["status"] = "failed"
                        job["error"] = str(exc)
            finally:
                with self._queue_cv:
                    job = self._jobs_by_id.get(job_id)
                    if job:
                        job["finished_at"] = self._utc_now()
                    self._running_job_count = max(0, int(self._running_job_count) - 1)
                    if int(self._running_exclusive_job_id or 0) == int(job_id):
                        self._running_exclusive_job_id = 0
                    self._trim_locked()
                    self._queue_cv.notify_all()

    def _dequeue_next_runnable_locked(self):
        while self._pending_job_ids:
            job_id = int(self._pending_job_ids[0])
            job = self._jobs_by_id.get(job_id)
            runner = self._runners.get(job_id)

            if not job or runner is None:
                self._pending_job_ids.pop(0)
                if job_id in self._runners:
                    del self._runners[job_id]
                continue

            status = str(job.get("status", "") or "").strip().lower()
            if status != "queued":
                self._pending_job_ids.pop(0)
                if job_id in self._runners:
                    del self._runners[job_id]
                continue

            if self._running_exclusive_job_id:
                return None

            if bool(job.get("exclusive", False)):
                if int(self._running_job_count) > 0:
                    return None
                self._pending_job_ids.pop(0)
                self._runners.pop(job_id, None)
                self._running_job_count += 1
                self._running_exclusive_job_id = int(job_id)
                job["status"] = "running"
                job["started_at"] = self._utc_now()
                return int(job_id), runner

            self._pending_job_ids.pop(0)
            self._runners.pop(job_id, None)
            self._running_job_count += 1
            job["status"] = "running"
            job["started_at"] = self._utc_now()
            return int(job_id), runner

        return None

    def _spawn_worker(self, worker_index: int):
        thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name=f"legion-web-job-{int(worker_index)}",
        )
        thread.start()
        self._workers.append(thread)

    def _trim_locked(self):
        while len(self._jobs) > self.max_jobs:
            drop_index = None
            for idx, candidate in enumerate(self._jobs):
                status = str(candidate.get("status", "") or "").strip().lower()
                if status in {"queued", "running"}:
                    continue
                drop_index = idx
                break

            if drop_index is None:
                break

            dropped = self._jobs.pop(drop_index)
            dropped_id = dropped.get("id")
            if dropped_id in self._jobs_by_id:
                del self._jobs_by_id[dropped_id]
            if dropped_id in self._runners:
                del self._runners[dropped_id]
            if dropped_id in self._pending_job_ids:
                self._pending_job_ids.remove(dropped_id)

    @staticmethod
    def _copy_job(job: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": job.get("id"),
            "type": job.get("type", ""),
            "status": job.get("status", ""),
            "exclusive": bool(job.get("exclusive", False)),
            "cancel_requested": bool(job.get("cancel_requested", False)),
            "cancel_reason": job.get("cancel_reason", ""),
            "created_at": job.get("created_at", ""),
            "started_at": job.get("started_at", ""),
            "finished_at": job.get("finished_at", ""),
            "payload": dict(job.get("payload", {})),
            "result": dict(job.get("result", {})),
            "error": job.get("error", ""),
        }

    @staticmethod
    def _utc_now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
