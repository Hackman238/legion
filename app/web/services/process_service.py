from __future__ import annotations

from typing import Any, Dict

from app.web.process_schema import ProcessClearRequest, ProcessOutputQuery, ProcessRetryRequest


class ProcessService:
    def __init__(self, runtime):
        self.runtime = runtime

    def kill_process(self, process_id: int) -> Dict[str, Any]:
        return self.runtime.kill_process(int(process_id))

    def retry_process(self, process_id: int, payload: Any) -> Dict[str, Any]:
        request = ProcessRetryRequest.from_payload(payload)
        job = self.runtime.start_process_retry_job(process_id=int(process_id), timeout=request.timeout)
        return {"status": "accepted", "job": job}

    def close_process(self, process_id: int) -> Dict[str, Any]:
        return self.runtime.close_process(int(process_id))

    def clear_processes(self, payload: Any) -> Dict[str, Any]:
        request = ProcessClearRequest.from_payload(payload)
        return self.runtime.clear_processes(reset_all=request.reset_all)

    def get_process_output(self, process_id: int, args) -> Dict[str, Any]:
        query = ProcessOutputQuery.from_args(args)
        return self.runtime.get_process_output(int(process_id), offset=query.offset, max_chars=query.max_chars)
