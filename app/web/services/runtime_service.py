from __future__ import annotations

from typing import Any, Dict

from app.web.runtime_schema import JobListQuery, ProcessListQuery


class RuntimeService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_snapshot(self) -> Dict[str, Any]:
        return self.runtime.get_snapshot()

    def list_jobs(self, args) -> Dict[str, Any]:
        query = JobListQuery.from_args(args)
        return {"jobs": self.runtime.list_jobs(limit=query.limit)}

    def list_processes(self, args) -> Dict[str, Any]:
        query = ProcessListQuery.from_args(args)
        return {"processes": self.runtime.get_workspace_processes(limit=query.limit)}

    def get_job(self, job_id: int) -> Dict[str, Any]:
        return self.runtime.get_job(int(job_id))

    def stop_job(self, job_id: int) -> Dict[str, Any]:
        return self.runtime.stop_job(int(job_id))
