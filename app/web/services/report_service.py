from __future__ import annotations

import datetime
import json
import re
from typing import Any, Callable, Dict, Tuple

from app.web.report_schema import ProjectReportPushRequest, ReportExportRequest, ReportFormatQuery


def _safe_filename_token(value: str, fallback: str = "host") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        return str(fallback)
    return token[:96]


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")


class ReportService:
    def __init__(self, runtime):
        self.runtime = runtime

    def _build_download_payload(
        self,
        report: Dict[str, Any],
        *,
        output_format: str,
        filename_prefix: str,
        filename_token: str,
        markdown_renderer: Callable[[Dict[str, Any]], str],
    ) -> Dict[str, Any]:
        timestamp = _timestamp()
        if output_format == "md":
            return {
                "body": markdown_renderer(report),
                "mimetype": "text/markdown; charset=utf-8",
                "filename": f"{filename_prefix}-{filename_token}-{timestamp}.md",
            }
        return {
            "body": json.dumps(report, indent=2, default=str),
            "mimetype": "application/json",
            "filename": f"{filename_prefix}-{filename_token}-{timestamp}.json",
        }

    def export_host_ai_report(self, host_id: int, args) -> Dict[str, Any]:
        query = ReportFormatQuery.from_args(args)
        report = self.runtime.get_host_ai_report(host_id)
        host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
        host_token = _safe_filename_token(
            str(host.get("hostname", "")).strip() or str(host.get("ip", "")).strip() or f"host-{host_id}",
            fallback=f"host-{host_id}",
        )
        return self._build_download_payload(
            report,
            output_format=query.output_format,
            filename_prefix="legion-host-ai-report",
            filename_token=host_token,
            markdown_renderer=self.runtime.render_host_ai_report_markdown,
        )

    def export_host_report(self, host_id: int, args) -> Dict[str, Any]:
        query = ReportFormatQuery.from_args(args)
        report = self.runtime.get_host_report(host_id)
        host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
        host_token = _safe_filename_token(
            str(host.get("hostname", "")).strip() or str(host.get("ip", "")).strip() or f"host-{host_id}",
            fallback=f"host-{host_id}",
        )
        return self._build_download_payload(
            report,
            output_format=query.output_format,
            filename_prefix="legion-host-report",
            filename_token=host_token,
            markdown_renderer=self.runtime.render_host_report_markdown,
        )

    def build_host_ai_reports_zip(self) -> Tuple[str, str]:
        return self.runtime.build_host_ai_reports_zip()

    def export_project_ai_report(self, args) -> Dict[str, Any]:
        query = ReportFormatQuery.from_args(args)
        report = self.runtime.get_project_ai_report()
        project = report.get("project", {}) if isinstance(report.get("project", {}), dict) else {}
        project_token = _safe_filename_token(
            str(project.get("name", "")).strip() or "project",
            fallback="project",
        )
        return self._build_download_payload(
            report,
            output_format=query.output_format,
            filename_prefix="legion-project-ai-report",
            filename_token=project_token,
            markdown_renderer=self.runtime.render_project_ai_report_markdown,
        )

    def export_project_report(self, args) -> Dict[str, Any]:
        query = ReportFormatQuery.from_args(args)
        report = self.runtime.get_project_report()
        project = report.get("project", {}) if isinstance(report.get("project", {}), dict) else {}
        project_token = _safe_filename_token(
            str(project.get("name", "")).strip() or "project",
            fallback="project",
        )
        return self._build_download_payload(
            report,
            output_format=query.output_format,
            filename_prefix="legion-project-report",
            filename_token=project_token,
            markdown_renderer=self.runtime.render_project_report_markdown,
        )

    def push_project_ai_report(self, payload: Any) -> Tuple[Dict[str, Any], int]:
        request = ProjectReportPushRequest.from_payload(payload)
        result = self.runtime.push_project_ai_report(overrides=request.overrides)
        status_code = 200 if bool(result.get("ok", False)) else 400
        status_value = "ok" if bool(result.get("ok", False)) else "error"
        return {"status": status_value, **result}, status_code

    def push_project_report(self, payload: Any) -> Tuple[Dict[str, Any], int]:
        request = ProjectReportPushRequest.from_payload(payload)
        result = self.runtime.push_project_report(overrides=request.overrides)
        status_code = 200 if bool(result.get("ok", False)) else 400
        status_value = "ok" if bool(result.get("ok", False)) else "error"
        return {"status": status_value, **result}, status_code

    def export_report(self, payload: Any) -> Dict[str, Any]:
        request = ReportExportRequest.from_payload(payload)
        if request.scope == "host":
            if request.host_id <= 0:
                raise ValueError("host_id is required when scope=host")
            if hasattr(self.runtime, "get_host_report"):
                report = self.runtime.get_host_report(request.host_id)
                markdown_renderer = self.runtime.render_host_report_markdown
            else:
                report = self.runtime.get_host_ai_report(request.host_id)
                markdown_renderer = self.runtime.render_host_ai_report_markdown
            if request.output_format == "md":
                return {
                    "scope": "host",
                    "format": "md",
                    "host_id": request.host_id,
                    "body": markdown_renderer(report),
                }
            return {
                "scope": "host",
                "format": "json",
                "host_id": request.host_id,
                "report": report,
            }

        if hasattr(self.runtime, "get_project_report"):
            report = self.runtime.get_project_report()
            markdown_renderer = self.runtime.render_project_report_markdown
        else:
            report = self.runtime.get_project_ai_report()
            markdown_renderer = self.runtime.render_project_ai_report_markdown
        if request.output_format == "md":
            return {
                "scope": "project",
                "format": "md",
                "body": markdown_renderer(report),
            }
        return {
            "scope": "project",
            "format": "json",
            "report": report,
        }
