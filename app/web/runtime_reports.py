from __future__ import annotations

import datetime
import json
import os
import re
import tempfile
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from app.scheduler.reporting import (
    build_host_report,
    build_project_report,
    render_host_report_markdown as render_scheduler_host_report_markdown,
    render_project_report_markdown as render_scheduler_project_report_markdown,
)


def _safe_report_token(value: Any, fallback: str = "host") -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-._")
    if not token:
        token = str(fallback or "host")
    return token[:96]


def get_host_ai_report(runtime, host_id: int) -> Dict[str, Any]:
    details = runtime.get_host_workspace(int(host_id))
    host = details.get("host", {}) if isinstance(details.get("host", {}), dict) else {}
    ports = details.get("ports", []) if isinstance(details.get("ports", []), list) else []
    cves = details.get("cves", []) if isinstance(details.get("cves", []), list) else []
    screenshots = details.get("screenshots", []) if isinstance(details.get("screenshots", []), list) else []
    ai_analysis = details.get("ai_analysis", {}) if isinstance(details.get("ai_analysis", {}), dict) else {}
    target_state = details.get("target_state", {}) if isinstance(details.get("target_state", {}), dict) else {}

    port_rows = []
    for item in ports:
        if not isinstance(item, dict):
            continue
        service = item.get("service", {}) if isinstance(item.get("service", {}), dict) else {}
        scripts = item.get("scripts", []) if isinstance(item.get("scripts", []), list) else []
        script_rows = []
        banner = ""
        for script in scripts:
            if not isinstance(script, dict):
                continue
            script_id = str(script.get("script_id", "")).strip()
            output_excerpt = runtime._truncate_scheduler_text(script.get("output", ""), 280)
            script_rows.append({
                "script_id": script_id,
                "output_excerpt": output_excerpt,
            })
            if not banner:
                candidate = runtime._scheduler_banner_from_evidence(script_id, output_excerpt)
                if candidate:
                    banner = candidate
        if not banner:
            banner = runtime._scheduler_service_banner_fallback(
                service_name=str(service.get("name", "") or ""),
                product=str(service.get("product", "") or ""),
                version=str(service.get("version", "") or ""),
                extrainfo=str(service.get("extrainfo", "") or ""),
            )

        port_rows.append({
            "port": str(item.get("port", "") or ""),
            "protocol": str(item.get("protocol", "") or ""),
            "state": str(item.get("state", "") or ""),
            "service": str(service.get("name", "") or ""),
            "service_product": str(service.get("product", "") or ""),
            "service_version": str(service.get("version", "") or ""),
            "service_extrainfo": str(service.get("extrainfo", "") or ""),
            "banner": banner,
            "scripts": script_rows,
        })

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "report_version": 1,
        "host": {
            "id": int(host.get("id", 0) or 0),
            "ip": str(host.get("ip", "") or ""),
            "hostname": str(host.get("hostname", "") or ""),
            "status": str(host.get("status", "") or ""),
            "os": str(host.get("os", "") or ""),
        },
        "note": str(details.get("note", "") or ""),
        "ports": port_rows,
        "cves": cves,
        "screenshots": screenshots,
        "ai_analysis": ai_analysis,
        "target_state": target_state,
    }


def render_host_ai_report_markdown(report: Dict[str, Any]) -> str:
    payload = report if isinstance(report, dict) else {}
    host = payload.get("host", {}) if isinstance(payload.get("host", {}), dict) else {}
    ai = payload.get("ai_analysis", {}) if isinstance(payload.get("ai_analysis", {}), dict) else {}
    host_updates = ai.get("host_updates", {}) if isinstance(ai.get("host_updates", {}), dict) else {}
    technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
    findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
    manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
    ports = payload.get("ports", []) if isinstance(payload.get("ports", []), list) else []
    cves = payload.get("cves", []) if isinstance(payload.get("cves", []), list) else []

    lines = [
        "# Legion Host AI Report",
        "",
        f"- Generated: {payload.get('generated_at', '')}",
        f"- Host ID: {host.get('id', '')}",
        f"- Host IP: {host.get('ip', '')}",
        f"- Hostname: {host.get('hostname', '')}",
        f"- Status: {host.get('status', '')}",
        f"- OS: {host.get('os', '')}",
        "",
        "## AI Analysis",
        "",
        f"- Provider: {ai.get('provider', '')}",
        f"- Goal Profile: {ai.get('goal_profile', '')}",
        f"- Updated: {ai.get('updated_at', '')}",
        f"- Next Phase: {ai.get('next_phase', '')}",
        f"- Hostname Suggestion: {host_updates.get('hostname', '')} ({host_updates.get('hostname_confidence', 0)}%)",
        f"- OS Suggestion: {host_updates.get('os', '')} ({host_updates.get('os_confidence', 0)}%)",
        "",
        "## Technologies",
        "",
    ]

    if technologies:
        for item in technologies:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('name', '')} {item.get('version', '')} | CPE: {item.get('cpe', '')} | Evidence: {item.get('evidence', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Findings", ""])
    if findings:
        for item in findings:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- [{item.get('severity', 'info')}] {item.get('title', '')} | CVE: {item.get('cve', '')} | CVSS: {item.get('cvss', '')} | Evidence: {item.get('evidence', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Manual Tests", ""])
    if manual_tests:
        for item in manual_tests:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- Why: {item.get('why', '')} | Command: `{item.get('command', '')}` | Scope: {item.get('scope_note', '')}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Open Services", ""])
    if ports:
        for item in ports:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('port', '')}/{item.get('protocol', '')} {item.get('service', '')} {item.get('service_product', '')} {item.get('service_version', '')}".strip()
            )
    else:
        lines.append("- none")

    lines.extend(["", "## CVEs", ""])
    if cves:
        for item in cves:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('name', '')} | Severity: {item.get('severity', '')} | Product: {item.get('product', '')}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines).strip() + "\n"


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


def build_host_ai_reports_zip(runtime) -> Tuple[str, str]:
    with runtime._lock:
        project = runtime._require_active_project()
        host_repo = project.repositoryContainer.hostRepository
        hosts = host_repo.getAllHostObjs()

    if not hosts:
        raise ValueError("No hosts available in workspace to export AI reports.")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    bundle_name = f"legion-host-ai-reports-{timestamp}.zip"
    root_name = f"legion-host-ai-reports-{timestamp}"
    tmp = tempfile.NamedTemporaryFile(prefix="legion-host-ai-reports-", suffix=".zip", delete=False)
    bundle_path = tmp.name
    tmp.close()

    manifest = {
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "report_version": 1,
        "host_count": len(hosts),
        "hosts": [],
    }

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for host in hosts:
            host_id = int(getattr(host, "id", 0) or 0)
            host_ip = str(getattr(host, "ip", "") or "")
            host_name = str(getattr(host, "hostname", "") or "")
            if host_id <= 0:
                continue

            report = get_host_ai_report(runtime, host_id)
            report_host = report.get("host", {}) if isinstance(report.get("host", {}), dict) else {}
            host_token = _safe_report_token(
                str(report_host.get("hostname", "")).strip()
                or str(report_host.get("ip", "")).strip()
                or f"host-{host_id}",
                fallback=f"host-{host_id}",
            )
            safe_stem = f"{host_token}-{host_id}"
            json_member = f"{root_name}/hosts/{safe_stem}.json"
            md_member = f"{root_name}/hosts/{safe_stem}.md"
            archive.writestr(json_member, json.dumps(report, indent=2, default=str))
            archive.writestr(md_member, render_host_ai_report_markdown(report))

            manifest["hosts"].append({
                "host_id": host_id,
                "ip": host_ip,
                "hostname": host_name,
                "json": f"hosts/{safe_stem}.json",
                "markdown": f"hosts/{safe_stem}.md",
            })

        archive.writestr(
            f"{root_name}/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True),
        )

    return bundle_path, bundle_name


def get_project_ai_report(runtime) -> Dict[str, Any]:
    with runtime._lock:
        runtime._require_active_project()
        project_meta = dict(runtime._project_metadata())
        summary = dict(runtime._summary())
        host_rows = list(runtime._hosts(limit=5000))

    host_reports: List[Dict[str, Any]] = []
    for row in host_rows:
        host_id = int(row.get("id", 0) or 0)
        if host_id <= 0:
            continue
        try:
            host_reports.append(get_host_ai_report(runtime, host_id))
        except Exception:
            continue

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "report_version": 1,
        "project": project_meta,
        "summary": summary,
        "host_count": len(host_reports),
        "hosts": host_reports,
    }


def render_project_ai_report_markdown(report: Dict[str, Any]) -> str:
    payload = report if isinstance(report, dict) else {}
    project = payload.get("project", {}) if isinstance(payload.get("project", {}), dict) else {}
    summary = payload.get("summary", {}) if isinstance(payload.get("summary", {}), dict) else {}
    hosts = payload.get("hosts", []) if isinstance(payload.get("hosts", []), list) else []

    lines = [
        "# Legion Project AI Report",
        "",
        f"- Generated: {payload.get('generated_at', '')}",
        f"- Report Version: {payload.get('report_version', '')}",
        f"- Project: {project.get('name', '')}",
        f"- Temporary: {bool(project.get('is_temporary', False))}",
        f"- Output Folder: {project.get('output_folder', '')}",
        f"- Running Folder: {project.get('running_folder', '')}",
        "",
        "## Summary",
        "",
        f"- Hosts: {summary.get('hosts', 0)}",
        f"- Open Ports: {summary.get('open_ports', 0)}",
        f"- Services: {summary.get('services', 0)}",
        f"- CVEs: {summary.get('cves', 0)}",
        f"- Running Jobs: {summary.get('running_processes', 0)}",
        f"- Finished Jobs: {summary.get('finished_processes', 0)}",
        "",
        "## Hosts",
        "",
    ]

    if not hosts:
        lines.append("- none")
        return "\n".join(lines).strip() + "\n"

    for item in hosts:
        if not isinstance(item, dict):
            continue
        host = item.get("host", {}) if isinstance(item.get("host", {}), dict) else {}
        ai = item.get("ai_analysis", {}) if isinstance(item.get("ai_analysis", {}), dict) else {}
        technologies = ai.get("technologies", []) if isinstance(ai.get("technologies", []), list) else []
        findings = ai.get("findings", []) if isinstance(ai.get("findings", []), list) else []
        manual_tests = ai.get("manual_tests", []) if isinstance(ai.get("manual_tests", []), list) else []
        ports = item.get("ports", []) if isinstance(item.get("ports", []), list) else []
        cves = item.get("cves", []) if isinstance(item.get("cves", []), list) else []
        host_ip = str(host.get("ip", "") or "")
        host_name = str(host.get("hostname", "") or "")
        host_heading = host_ip
        if host_name:
            host_heading = f"{host_ip} ({host_name})".strip()
        lines.extend([
            f"### {host_heading}",
            "",
            f"- Host ID: {host.get('id', '')}",
            f"- Status: {host.get('status', '')}",
            f"- OS: {host.get('os', '')}",
            f"- Open Services: {len(ports)}",
            f"- CVEs: {len(cves)}",
            f"- Provider: {ai.get('provider', '')}",
            f"- Goal Profile: {ai.get('goal_profile', '')}",
            f"- Updated: {ai.get('updated_at', '')}",
            f"- Next Phase: {ai.get('next_phase', '')}",
            "",
            "#### Technologies",
        ])
        if technologies:
            for tech in technologies:
                if not isinstance(tech, dict):
                    continue
                lines.append(
                    f"- {tech.get('name', '')} {tech.get('version', '')} | CPE: {tech.get('cpe', '')} | Evidence: {tech.get('evidence', '')}"
                )
        else:
            lines.append("- none")
        lines.extend(["", "#### Findings"])
        if findings:
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                lines.append(
                    f"- [{finding.get('severity', 'info')}] {finding.get('title', '')} | CVE: {finding.get('cve', '')} | CVSS: {finding.get('cvss', '')}"
                )
        else:
            lines.append("- none")
        lines.extend(["", "#### Manual Tests"])
        if manual_tests:
            for test in manual_tests:
                if not isinstance(test, dict):
                    continue
                lines.append(
                    f"- Why: {test.get('why', '')} | Command: `{test.get('command', '')}` | Scope: {test.get('scope_note', '')}"
                )
        else:
            lines.append("- none")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


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
