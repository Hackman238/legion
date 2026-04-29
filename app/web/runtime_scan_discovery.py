from __future__ import annotations

import os
import re
import shlex
from types import SimpleNamespace
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from app.cli_utils import import_targets, import_targets_from_textfile
from app.scheduler.graph import rebuild_evidence_graph
from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.state import build_attempted_action_entry
from app.timing import getTimestamp
from db.entities.port import portObj
from db.entities.service import serviceObj


def start_targets_import_job(runtime, path: str) -> Dict[str, Any]:
    file_path = runtime._normalize_existing_file(path)
    return runtime._start_job(
        "import-targets",
        lambda _job_id: runtime._import_targets_from_file(file_path),
        payload={"path": file_path},
    )


def import_targets_from_file(runtime, file_path: str) -> Dict[str, Any]:
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        host_repo = project.repositoryContainer.hostRepository
        try:
            added = import_targets_from_textfile(session, host_repo, file_path)
        finally:
            session.close()
        return {
            "path": file_path,
            "added": int(added or 0),
        }


def import_discovered_hosts_into_project(runtime, discovered_hosts: List[str]) -> List[str]:
    targets = [str(item or "").strip() for item in list(discovered_hosts or []) if str(item or "").strip()]
    if not targets:
        return []
    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        host_repo = project.repositoryContainer.hostRepository
        try:
            added = import_targets(session, host_repo, targets)
        finally:
            session.close()
    return list(added or [])


def queue_discovered_host_followup_scan(runtime, targets: List[str]) -> Dict[str, Any]:
    target_list = [str(item or "").strip() for item in list(targets or []) if str(item or "").strip()]
    if not target_list:
        return {}
    scan_options = {
        "discovery": True,
        "skip_dns": False,
        "timing": "T3",
        "top_ports": 100,
        "service_detection": True,
        "default_scripts": True,
        "os_detection": False,
        "aggressive": False,
        "full_ports": False,
        "vuln_scripts": False,
        "host_discovery_only": False,
        "arp_ping": False,
    }
    return runtime.start_nmap_scan_job(
        targets=target_list,
        discovery=True,
        staged=False,
        run_actions=False,
        nmap_path="nmap",
        nmap_args="",
        scan_mode="easy",
        scan_options=scan_options,
    )


def resolve_host_by_token(runtime, host_token: str):
    token = str(host_token or "").strip()
    if not token:
        return None
    with runtime._lock:
        project = runtime._require_active_project()
        host_repo = project.repositoryContainer.hostRepository
        host = host_repo.getHostByIP(token)
        if host is None:
            host = host_repo.getHostByHostname(token)
        return host


def mark_discovered_host_origin(runtime, host_tokens: List[str], *, source_tool_id: str = ""):
    normalized_source = str(source_tool_id or "").strip().lower()
    if not normalized_source:
        return
    decision = SimpleNamespace(
        tool_id=normalized_source,
        label=normalized_source,
        action_id=normalized_source,
        family_id="",
        mode="deterministic",
        approval_state="approved",
        coverage_gap="",
        pack_ids=[],
    )
    command_template = {
        "subfinder": "subfinder -d [IP] -o [OUTPUT].jsonl",
        "grayhatwarfare": "python3 -m app.grayhatwarfare_probe --domain [ROOT_DOMAIN] --output [OUTPUT].json",
        "shodan-enrichment": "python3 -m app.shodan_probe --target [IP] --output [OUTPUT].json",
        "dnsmap": "dnsmap [IP]",
    }.get(normalized_source, normalized_source)
    command_signature = runtime._command_signature_for_target(command_template, "tcp")
    attempted_at = getTimestamp(True)
    for host_token in list(host_tokens or []):
        host = resolve_host_by_token(runtime, str(host_token or "").strip())
        if host is None:
            continue
        host_id = int(getattr(host, "id", 0) or 0)
        if host_id <= 0:
            continue
        host_ip = str(getattr(host, "ip", "") or host_token or "").strip()
        hostname = str(getattr(host, "hostname", "") or host_ip).strip()
        runtime._persist_shared_target_state(
            host_id=host_id,
            host_ip=host_ip,
            hostname=hostname,
            protocol="tcp",
            scheduler_mode="deterministic",
            attempted_action=build_attempted_action_entry(
                decision=decision,
                status="executed",
                reason=f"discovered via {normalized_source}",
                attempted_at=attempted_at,
                port="",
                protocol="tcp",
                service="",
                command_signature=command_signature,
            ),
            raw={
                "discovered_via": normalized_source,
            },
        )


def start_httpx_bootstrap_job(runtime, targets: List[str]) -> Dict[str, Any]:
    normalized_targets = [
        str(item or "").strip()
        for item in list(targets or [])
        if str(item or "").strip()
    ]
    if not normalized_targets:
        return {}
    return runtime._start_job(
        "httpx-bootstrap",
        lambda job_id: runtime._run_httpx_bootstrap(normalized_targets, job_id=int(job_id or 0)),
        payload={
            "targets": list(normalized_targets),
            "target_count": len(normalized_targets),
        },
    )


def httpx_bootstrap_command(targets_file: str, output_prefix: str) -> str:
    quoted_targets = shlex.quote(str(targets_file or ""))
    quoted_output = shlex.quote(f"{str(output_prefix or '')}.jsonl")
    return (
        "(command -v httpx >/dev/null 2>&1 && "
        f"httpx -silent -json -title -tech-detect -web-server -status-code -content-type "
        f"-l {quoted_targets} -o {quoted_output}) || echo httpx not found"
    )


def materialize_httpx_urls_as_web_targets(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        hostname: str,
        host_token: str,
        observed_payload: Dict[str, Any],
) -> Dict[str, Any]:
    resolved_host_id = int(host_id or 0)
    if resolved_host_id <= 0:
        return {"targets": []}

    candidate_hosts = {
        str(token or "").strip().lower()
        for token in [host_token, host_ip, hostname]
        if str(token or "").strip()
    }
    candidate_targets: Dict[Tuple[str, str], Dict[str, str]] = {}
    for item in list((observed_payload or {}).get("urls", []) or []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "") or "").strip()
        if not url:
            continue
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        scheme = str(parsed.scheme or "").strip().lower()
        if scheme not in {"http", "https"}:
            continue
        parsed_host = str(parsed.hostname or "").strip().lower()
        if candidate_hosts and parsed_host and parsed_host not in candidate_hosts:
            continue
        port_value = int(parsed.port or (443 if scheme == "https" else 80))
        service_name = "https" if scheme == "https" else "http"
        key = (str(port_value), "tcp")
        candidate_targets[key] = {
            "port": str(port_value),
            "protocol": "tcp",
            "service": service_name,
            "url": url,
        }

    if not candidate_targets:
        return {"targets": []}

    with runtime._lock:
        project = runtime._require_active_project()
        session = project.database.session()
        try:
            for item in list(candidate_targets.values()):
                port_value = str(item.get("port", "") or "").strip()
                protocol_value = str(item.get("protocol", "tcp") or "tcp").strip().lower() or "tcp"
                service_name = str(item.get("service", "") or "").strip() or "http"
                port_row = session.query(portObj).filter_by(
                    hostId=str(resolved_host_id),
                    portId=port_value,
                    protocol=protocol_value,
                ).first()
                service_row = None
                if port_row is not None and str(getattr(port_row, "serviceId", "") or "").strip():
                    service_row = session.query(serviceObj).filter_by(id=getattr(port_row, "serviceId", None)).first()
                if service_row is None:
                    service_row = serviceObj(service_name, resolved_host_id)
                    session.add(service_row)
                    session.flush()
                else:
                    current_name = str(getattr(service_row, "name", "") or "").strip().lower()
                    if not current_name or current_name in {"http", "https", "ssl", "http-alt", "https-alt", "soap", "http-proxy"}:
                        service_row.name = service_name
                        session.add(service_row)
                if port_row is None:
                    port_row = portObj(port_value, protocol_value, "open", resolved_host_id, service_row.id)
                    session.add(port_row)
                else:
                    port_row.state = "open"
                    port_row.serviceId = service_row.id
                    session.add(port_row)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        rebuild_evidence_graph(project.database, host_id=resolved_host_id)

    return {"targets": list(candidate_targets.values())}


def run_httpx_bootstrap(runtime, targets: List[str], *, job_id: int = 0) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    normalized_targets = [
        str(item or "").strip()
        for item in list(targets or [])
        if str(item or "").strip()
    ]
    if not normalized_targets:
        return {"targets": [], "results": [], "materialized_hosts": [], "scheduler_followup": {}}

    with runtime._lock:
        project = runtime._require_active_project()
        running_folder = project.properties.runningFolder

    results: List[Dict[str, Any]] = []
    materialized_host_ids: Set[int] = set()
    for host_token in normalized_targets:
        if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
            raise RuntimeError("cancelled")

        safe_token = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(host_token or "").strip())[:96] or "target"
        output_prefix = os.path.join(running_folder, f"{getTimestamp()}-httpx-bootstrap-{safe_token}")
        targets_file = f"{output_prefix}-targets.txt"
        with open(targets_file, "w", encoding="utf-8") as handle:
            handle.write(f"https://{host_token}\n")
            handle.write(f"http://{host_token}\n")

        command = httpx_bootstrap_command(targets_file, output_prefix)
        executed, reason, process_id, metadata = runtime._run_command_with_tracking(
            tool_name="httpx-bootstrap",
            tab_title="httpx bootstrap",
            host_ip=str(host_token),
            port="",
            protocol="tcp",
            command=command,
            outputfile=output_prefix,
            timeout=900,
            job_id=resolved_job_id,
            return_metadata=True,
        )
        artifact_refs = list((metadata or {}).get("artifact_refs", []) or [])
        output_text = ""
        if int(process_id or 0) > 0:
            try:
                process_output = runtime.get_process_output(int(process_id), offset=0, max_chars=200000)
                output_text = str(process_output.get("output", "") or "")
            except Exception:
                output_text = ""

        observed_payload = extract_tool_observations(
            "httpx",
            output_text,
            protocol="tcp",
            artifact_refs=artifact_refs,
            host_ip=str(host_token),
            hostname=str(host_token),
        )
        host = resolve_host_by_token(runtime, str(host_token))
        host_id = int(getattr(host, "id", 0) or 0)
        host_ip = str(getattr(host, "ip", "") or host_token).strip()
        hostname = str(getattr(host, "hostname", "") or host_ip).strip()

        materialized = materialize_httpx_urls_as_web_targets(
            runtime,
            host_id=host_id,
            host_ip=host_ip,
            hostname=hostname,
            host_token=str(host_token),
            observed_payload=observed_payload,
        )
        materialized_targets = list(materialized.get("targets", []) or [])
        if materialized_targets:
            materialized_host_ids.add(int(host_id))

        if host_id > 0:
            decision = SimpleNamespace(
                tool_id="httpx",
                label="Run httpx",
                action_id="httpx",
                family_id="",
                mode="deterministic",
                approval_state="approved",
                coverage_gap="",
                pack_ids=[],
            )
            command_signature = runtime._command_signature_for_target(command, "tcp")
            if materialized_targets:
                for item in materialized_targets:
                    runtime._persist_shared_target_state(
                        host_id=host_id,
                        host_ip=host_ip,
                        hostname=hostname,
                        port=str(item.get("port", "") or ""),
                        protocol=str(item.get("protocol", "tcp") or "tcp"),
                        service_name=str(item.get("service", "") or ""),
                        scheduler_mode="deterministic",
                        attempted_action=build_attempted_action_entry(
                            decision=decision,
                            status="executed" if executed else "failed",
                            reason=reason,
                            attempted_at=getTimestamp(True),
                            port=str(item.get("port", "") or ""),
                            protocol=str(item.get("protocol", "tcp") or "tcp"),
                            service=str(item.get("service", "") or ""),
                            command_signature=command_signature,
                            artifact_refs=artifact_refs,
                        ),
                        artifact_refs=artifact_refs,
                        technologies=list(observed_payload.get("technologies", []) or []) or None,
                        findings=list(observed_payload.get("findings", []) or []) or None,
                        urls=list(observed_payload.get("urls", []) or []) or None,
                        raw={
                            "httpx_bootstrap": True,
                            "bootstrap_source": "subfinder",
                        },
                    )
            elif observed_payload:
                runtime._persist_shared_target_state(
                    host_id=host_id,
                    host_ip=host_ip,
                    hostname=hostname,
                    protocol="tcp",
                    scheduler_mode="deterministic",
                    artifact_refs=artifact_refs,
                    technologies=list(observed_payload.get("technologies", []) or []) or None,
                    findings=list(observed_payload.get("findings", []) or []) or None,
                    urls=list(observed_payload.get("urls", []) or []) or None,
                    raw={
                        "httpx_bootstrap": True,
                        "bootstrap_source": "subfinder",
                    },
                )

        results.append({
            "host": str(host_token),
            "executed": bool(executed),
            "reason": str(reason or ""),
            "process_id": int(process_id or 0),
            "artifact_refs": artifact_refs,
            "materialized_targets": materialized_targets,
        })

    scheduler_followup = {}
    if materialized_host_ids:
        scheduler_followup = runtime._run_scheduler_actions_web(
            host_ids=set(materialized_host_ids),
            dig_deeper=False,
            job_id=resolved_job_id,
        )
    return {
        "targets": list(normalized_targets),
        "results": results,
        "materialized_hosts": sorted(materialized_host_ids),
        "scheduler_followup": scheduler_followup,
    }


def ingest_discovered_hosts(runtime, discovered_hosts: List[str], *, source_tool_id: str = "") -> Dict[str, Any]:
    observed = [str(item or "").strip() for item in list(discovered_hosts or []) if str(item or "").strip()]
    if not observed:
        return {"added_hosts": [], "followup_job": {}, "followup_error": "", "bootstrap_job": {}, "bootstrap_error": ""}
    added_hosts = import_discovered_hosts_into_project(runtime, observed)
    mark_discovered_host_origin(runtime, added_hosts, source_tool_id=source_tool_id)
    followup_job: Dict[str, Any] = {}
    followup_error = ""
    bootstrap_job: Dict[str, Any] = {}
    bootstrap_error = ""
    normalized_source = str(source_tool_id or "").strip().lower()
    if normalized_source == "subfinder" and added_hosts:
        try:
            followup_job = queue_discovered_host_followup_scan(runtime, added_hosts)
        except Exception as exc:
            followup_error = str(exc)
        try:
            bootstrap_job = runtime.start_httpx_bootstrap_job(added_hosts)
        except Exception as exc:
            bootstrap_error = str(exc)
    elif normalized_source in {"grayhatwarfare", "shodan-enrichment"} and added_hosts:
        try:
            bootstrap_job = runtime.start_httpx_bootstrap_job(added_hosts)
        except Exception as exc:
            bootstrap_error = str(exc)
    return {
        "added_hosts": added_hosts,
        "followup_job": followup_job,
        "followup_error": followup_error,
        "bootstrap_job": bootstrap_job,
        "bootstrap_error": bootstrap_error,
    }


def run_governed_discovery(
        runtime,
        target: str,
        *,
        run_actions: bool = False,
) -> Dict[str, Any]:
    normalized_targets = runtime._normalize_targets([target])
    if not normalized_targets:
        raise ValueError("Discovery target is required.")

    runtime.create_new_temporary_project()
    scan_result = runtime._run_nmap_scan_and_import(
        normalized_targets,
        discovery=True,
        staged=False,
        run_actions=bool(run_actions),
        nmap_path="nmap",
        nmap_args="",
        scan_mode="legacy",
        scan_options={},
    )
    project = runtime.get_project_details()
    hosts = runtime.get_workspace_hosts(include_down=True)
    services = runtime.get_workspace_services(limit=300)
    response = {
        "target": str(normalized_targets[0] or ""),
        "run_actions": bool(run_actions),
        "project": project,
        "scan": scan_result,
        "results": hosts,
        "services": services,
    }
    if run_actions:
        response["approvals"] = runtime.get_scheduler_approvals(limit=100, status="pending")
        response["decisions"] = runtime.get_scheduler_decisions(limit=100)
    return response
