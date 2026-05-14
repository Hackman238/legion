from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from app.scheduler.reporting import (
    build_host_report,
    build_project_report,
    render_host_report_markdown as render_scheduler_host_report_markdown,
    render_project_report_markdown as render_scheduler_project_report_markdown,
)
from app.web.runtime_ai_reports import (
    build_host_ai_reports_zip,
    get_host_ai_report,
    get_project_ai_report,
    render_host_ai_report_markdown,
    render_project_ai_report_markdown,
)


def get_host_report(runtime, host_id: int) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        host = runtime._resolve_host(int(host_id))
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
        host_row = {
            "id": int(getattr(host, "id", 0) or 0),
            "ip": str(getattr(host, "ip", "") or ""),
            "hostname": str(getattr(host, "hostname", "") or ""),
            "status": str(getattr(host, "status", "") or ""),
            "os": str(getattr(host, "osMatch", "") or ""),
        }
        project_meta = dict(runtime._project_metadata())
    return build_host_report(
        project.database,
        host_row=host_row,
        engagement_policy=engagement_policy,
        project_metadata=project_meta,
    )


def render_host_report_markdown(report: Dict[str, Any]) -> str:
    return render_scheduler_host_report_markdown(report)


def get_project_report(runtime) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        project_meta = dict(runtime._project_metadata())
        summary = dict(runtime._summary())
        host_rows = list(runtime._hosts(limit=5000))
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
    return build_project_report(
        project.database,
        project_metadata=project_meta,
        engagement_policy=engagement_policy,
        summary=summary,
        host_inventory=host_rows,
    )


def render_project_report_markdown(report: Dict[str, Any]) -> str:
    return render_scheduler_project_report_markdown(report)


def push_project_report_common(
    runtime,
    *,
    report: Dict[str, Any],
    markdown_renderer,
    overrides: Optional[Dict[str, Any]] = None,
    report_label: str = "project report",
) -> Dict[str, Any]:
    with runtime._lock:
        config = runtime.scheduler_config.load()
        base_delivery = runtime._project_report_delivery_config(config)

    merged_delivery = dict(base_delivery)
    merged_delivery["headers"] = dict(base_delivery.get("headers", {}))
    merged_delivery["mtls"] = dict(base_delivery.get("mtls", {}))
    if isinstance(overrides, dict):
        for key, value in overrides.items():
            if key == "headers" and isinstance(value, dict):
                merged_delivery["headers"] = {
                    str(k or "").strip(): str(v or "")
                    for k, v in value.items()
                    if str(k or "").strip()
                }
            elif key == "mtls" and isinstance(value, dict):
                next_mtls = dict(merged_delivery.get("mtls", {}))
                next_mtls.update(value)
                merged_delivery["mtls"] = next_mtls
            else:
                merged_delivery[key] = value
    delivery = runtime._project_report_delivery_config({"project_report_delivery": merged_delivery})

    endpoint = str(delivery.get("endpoint", "") or "").strip()
    if not endpoint:
        raise ValueError("Project report delivery endpoint is required.")

    report_format = str(delivery.get("format", "json") or "json").strip().lower()
    if report_format == "md":
        body = markdown_renderer(report)
        content_type = "text/markdown; charset=utf-8"
    else:
        report_format = "json"
        body = json.dumps(report, indent=2, default=str)
        content_type = "application/json"

    headers = runtime._normalize_project_report_headers(delivery.get("headers", {}))
    has_content_type = any(str(name).strip().lower() == "content-type" for name in headers.keys())
    if not has_content_type:
        headers["Content-Type"] = content_type

    timeout_seconds = int(delivery.get("timeout_seconds", 30) or 30)
    timeout_seconds = max(5, min(timeout_seconds, 300))

    mtls = delivery.get("mtls", {}) if isinstance(delivery.get("mtls", {}), dict) else {}
    cert_value = None
    verify_value: Any = True
    if bool(mtls.get("enabled", False)):
        cert_path = str(mtls.get("client_cert_path", "") or "").strip()
        key_path = str(mtls.get("client_key_path", "") or "").strip()
        ca_path = str(mtls.get("ca_cert_path", "") or "").strip()

        if not cert_path:
            raise ValueError("mTLS is enabled but client cert path is empty.")
        if not os.path.isfile(cert_path):
            raise ValueError(f"mTLS client cert not found: {cert_path}")
        if key_path and not os.path.isfile(key_path):
            raise ValueError(f"mTLS client key not found: {key_path}")
        if ca_path and not os.path.isfile(ca_path):
            raise ValueError(f"mTLS CA cert not found: {ca_path}")

        cert_value = (cert_path, key_path) if key_path else cert_path
        if ca_path:
            verify_value = ca_path

    method = str(delivery.get("method", "POST") or "POST").strip().upper()
    if method not in {"POST", "PUT", "PATCH"}:
        method = "POST"

    from app.web.runtime import _get_requests_module

    try:
        requests_module = _get_requests_module()
        response = requests_module.request(
            method=method,
            url=endpoint,
            headers=headers,
            data=body.encode("utf-8"),
            timeout=timeout_seconds,
            cert=cert_value,
            verify=verify_value,
        )
        response_text = str(getattr(response, "text", "") or "")
        excerpt = response_text[:4000].rstrip()
        ok = 200 <= int(response.status_code) < 300
        return {
            "ok": bool(ok),
            "provider_name": str(delivery.get("provider_name", "") or ""),
            "endpoint": endpoint,
            "method": method,
            "format": report_format,
            "report_label": str(report_label or "project report"),
            "status_code": int(response.status_code),
            "response_body_excerpt": excerpt,
        }
    except Exception as exc:
        return {
            "ok": False,
            "provider_name": str(delivery.get("provider_name", "") or ""),
            "endpoint": endpoint,
            "method": method,
            "format": report_format,
            "report_label": str(report_label or "project report"),
            "error": str(exc),
        }


def push_project_ai_report(runtime, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    report = get_project_ai_report(runtime)
    return push_project_report_common(
        runtime,
        report=report,
        markdown_renderer=render_project_ai_report_markdown,
        overrides=overrides,
        report_label="project ai report",
    )


def push_project_report(runtime, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    report = get_project_report(runtime)
    return push_project_report_common(
        runtime,
        report=report,
        markdown_renderer=render_project_report_markdown,
        overrides=overrides,
        report_label="project report",
    )
