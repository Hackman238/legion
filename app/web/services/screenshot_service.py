from __future__ import annotations

from typing import Any, Dict

from app.web.screenshot_schema import ScreenshotDeleteRequest, ScreenshotRefreshRequest


class ScreenshotService:
    def __init__(self, runtime):
        self.runtime = runtime

    def get_screenshot_file(self, filename: str) -> str:
        return self.runtime.get_screenshot_file(filename)

    def refresh_host_screenshots(self, host_id: int) -> Dict[str, Any]:
        job = self.runtime.start_host_screenshot_refresh_job(int(host_id))
        return {"status": "accepted", "job": job}

    def refresh_graph_screenshot(self, payload: Any) -> Dict[str, Any]:
        request = ScreenshotRefreshRequest.from_payload(payload)
        job = self.runtime.start_graph_screenshot_refresh_job(
            request.host_id,
            request.port,
            request.protocol,
        )
        return {"status": "accepted", "job": job}

    def delete_graph_screenshot(self, payload: Any) -> Dict[str, Any]:
        request = ScreenshotDeleteRequest.from_payload(payload)
        return self.runtime.delete_graph_screenshot(
            host_id=request.host_id,
            artifact_ref=request.artifact_ref,
            filename=request.filename,
            port=request.port,
            protocol=request.protocol,
        )
