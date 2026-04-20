from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import psutil
from app.cli_utils import import_targets, import_targets_from_textfile, is_wsl, to_windows_path
from app.importers.nmap_runner import import_nmap_xml_into_project
from app.scheduler.graph import rebuild_evidence_graph
from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.scan_history import (
    ensure_scan_submission_table,
    record_scan_submission as db_record_scan_submission,
    update_scan_submission as db_update_scan_submission,
)
from app.scheduler.state import build_attempted_action_entry
from app.screenshot_targets import choose_preferred_command_host
from app.timing import getTimestamp
from app.tooling import build_tool_execution_env
from db.entities.port import portObj
from db.entities.service import serviceObj


def record_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text_value = str(value or "").strip().lower()
    if text_value in {"1", "true", "yes", "on"}:
        return True
    if text_value in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def normalize_subnet_target(subnet: str) -> str:
    token = str(subnet or "").strip()
    if not token:
        raise ValueError("Subnet is required.")
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {token}") from exc


def count_rfc1918_scan_batches(runtime_cls, targets: List[str]) -> int:
    chunk_prefix = max(1, min(int(runtime_cls.RFC1918_SWEEP_CHUNK_PREFIX), 32))
    batch_size = max(1, int(runtime_cls.RFC1918_SWEEP_BATCH_SIZE))
    chunk_count = 0
    for raw_target in list(targets or []):
        token = str(raw_target or "").strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            chunk_count += 1
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
            chunk_count += 1
            continue
        if int(network.prefixlen) >= int(chunk_prefix):
            chunk_count += 1
        else:
            chunk_count += 1 << int(chunk_prefix - int(network.prefixlen))
    if chunk_count <= 0:
        return 0
    return max(1, int((chunk_count + batch_size - 1) / batch_size))


def iter_rfc1918_scan_batches(runtime_cls, targets: List[str]):
    chunk_prefix = max(1, min(int(runtime_cls.RFC1918_SWEEP_CHUNK_PREFIX), 32))
    batch_size = max(1, int(runtime_cls.RFC1918_SWEEP_BATCH_SIZE))
    batch: List[str] = []
    for raw_target in list(targets or []):
        token = str(raw_target or "").strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            batch.append(token)
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
            batch.append(str(network))
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
            continue
        subnet_iterable = (
            [str(network)]
            if int(network.prefixlen) >= int(chunk_prefix)
            else (str(item) for item in network.subnets(new_prefix=chunk_prefix))
        )
        for subnet in subnet_iterable:
            batch.append(str(subnet))
            if len(batch) >= batch_size:
                yield list(batch)
                batch = []
    if batch:
        yield list(batch)


def normalize_rfc_chunk_concurrency(runtime_cls, raw: Any) -> int:
    try:
        value = int(raw)
    except Exception:
        return 1
    return max(1, min(value, int(runtime_cls.RFC1918_SWEEP_MAX_CONCURRENCY)))


def scan_history_targets(record: Dict[str, Any]) -> List[str]:
    if isinstance(record.get("targets"), list):
        values = [str(item or "").strip() for item in list(record.get("targets", [])) if str(item or "").strip()]
        if values:
            return values
    raw_targets = str(record.get("targets_json", "") or "").strip()
    if raw_targets:
        try:
            parsed = json.loads(raw_targets)
        except Exception:
            parsed = []
        if isinstance(parsed, list):
            values = [str(item or "").strip() for item in parsed if str(item or "").strip()]
            if values:
                return values
    fallback: List[str] = []
    for source in (record.get("scope_summary", ""), record.get("target_summary", "")):
        for token in re.findall(r"[A-Za-z0-9./:-]+", str(source or "")):
            cleaned = str(token or "").strip(",:")
            if cleaned and cleaned not in fallback:
                fallback.append(cleaned)
    return fallback


def scan_target_match_score_for_subnet(target: Any, subnet: str) -> int:
    token = str(target or "").strip().strip(",")
    if not token:
        return -1
    subnet_network = ipaddress.ip_network(str(subnet), strict=False)
    try:
        target_ip = ipaddress.ip_address(token)
        return 50 if target_ip in subnet_network else -1
    except ValueError:
        pass
    try:
        target_network = ipaddress.ip_network(token, strict=False)
        if target_network == subnet_network:
            return 100
        if subnet_network.subnet_of(target_network):
            return 90
        if target_network.subnet_of(subnet_network):
            return 80
        if target_network.overlaps(subnet_network):
            return 70
        return -1
    except ValueError:
        pass
    return -1


def best_scan_submission_for_subnet(runtime_cls, subnet: str, records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    _ = runtime_cls
    best_record: Optional[Dict[str, Any]] = None
    best_score = -1
    for record in list(records or []):
        if str(record.get("submission_kind", "") or "").strip() != "nmap_scan":
            continue
        score = -1
        for target in scan_history_targets(record):
            score = max(score, scan_target_match_score_for_subnet(target, subnet))
        if score > best_score:
            best_record = record
            best_score = score
    return best_record if best_score >= 0 else None


def start_subnet_rescan_job(runtime, subnet: str) -> Dict[str, Any]:
    normalized_subnet = runtime._normalize_subnet_target(subnet)
    with runtime._lock:
        for job in runtime.jobs.list_jobs(limit=200):
            if str(job.get("type", "")).strip() != "nmap-scan":
                continue
            status = str(job.get("status", "") or "").strip().lower()
            if status not in {"queued", "running"}:
                continue
            payload = job.get("payload", {}) if isinstance(job.get("payload", {}), dict) else {}
            try:
                job_targets = runtime._normalize_targets(payload.get("targets", []))
            except Exception:
                job_targets = []
            if normalized_subnet in job_targets:
                existing_copy = dict(job)
                existing_copy["existing"] = True
                return existing_copy
        template = runtime._best_scan_submission_for_subnet(normalized_subnet, runtime.get_scan_history(limit=400))
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    if isinstance(template, dict):
        return runtime.start_nmap_scan_job(
            targets=[normalized_subnet],
            discovery=runtime._record_bool(template.get("discovery"), True),
            staged=runtime._record_bool(template.get("staged"), False),
            run_actions=runtime._record_bool(template.get("run_actions"), False),
            nmap_path=str(template.get("nmap_path", "nmap") or "nmap").strip() or "nmap",
            nmap_args=str(template.get("nmap_args", "") or "").strip(),
            scan_mode=str(template.get("scan_mode", "legacy") or "legacy").strip().lower() or "legacy",
            scan_options=dict(template.get("scan_options", {}) or {}),
        )

    default_scan_options = runtime._apply_engagement_scan_profile({
        "discovery": True,
        "skip_dns": True,
        "timing": "T3",
        "top_ports": 1000,
        "explicit_ports": "",
        "service_detection": True,
        "default_scripts": True,
        "os_detection": False,
        "aggressive": False,
        "full_ports": False,
        "vuln_scripts": False,
        "host_discovery_only": False,
        "arp_ping": False,
    }, engagement_policy=engagement_policy)
    return runtime.start_nmap_scan_job(
        targets=[normalized_subnet],
        discovery=True,
        staged=False,
        run_actions=False,
        nmap_path="nmap",
        nmap_args="",
        scan_mode="easy",
        scan_options=default_scan_options,
    )


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


def preferred_capture_interface_sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
    name = str(item.get("name", "") or "").strip().lower()
    preferred_prefixes = ("eth", "en", "eno", "ens", "enp", "wl", "wlan")
    depreferred_prefixes = ("docker", "br-", "veth", "virbr", "vmnet", "zt", "tailscale", "tun", "tap")
    if name.startswith(depreferred_prefixes):
        return 2, name
    if name.startswith(preferred_prefixes):
        return 0, name
    return 1, name


def list_capture_interfaces(runtime) -> List[Dict[str, Any]]:
    stats = psutil.net_if_stats() if hasattr(psutil, "net_if_stats") else {}
    addrs = psutil.net_if_addrs() if hasattr(psutil, "net_if_addrs") else {}
    rows: List[Dict[str, Any]] = []
    for name, entries in dict(addrs or {}).items():
        token = str(name or "").strip()
        if not token or token == "lo":
            continue
        stat = (stats or {}).get(token)
        if stat is not None and not bool(getattr(stat, "isup", True)):
            continue
        ipv4_addresses: List[str] = []
        ipv4_networks: List[str] = []
        seen_networks: Set[str] = set()
        for entry in list(entries or []):
            if int(getattr(entry, "family", 0) or 0) != int(socket.AF_INET):
                continue
            address = str(getattr(entry, "address", "") or "").strip()
            netmask = str(getattr(entry, "netmask", "") or "").strip()
            if not address:
                continue
            try:
                iface = ipaddress.ip_interface(f"{address}/{netmask or '32'}")
            except ValueError:
                continue
            if iface.ip.is_loopback:
                continue
            ipv4_addresses.append(str(iface.ip))
            network_text = str(iface.network)
            if network_text and network_text not in seen_networks:
                seen_networks.add(network_text)
                ipv4_networks.append(network_text)
        if not ipv4_addresses:
            continue
        rows.append({
            "name": token,
            "label": f"{token} ({', '.join(ipv4_addresses[:2])})",
            "ipv4_addresses": ipv4_addresses,
            "ipv4_networks": ipv4_networks,
        })
    rows.sort(key=preferred_capture_interface_sort_key)
    return rows


def get_capture_interface_inventory(runtime) -> Dict[str, Any]:
    rows = list_capture_interfaces(runtime)
    default_name = str(rows[0].get("name", "") or "") if rows else ""
    return {
        "interfaces": rows,
        "default_interface": default_name,
    }


def connected_ipv4_networks_for_interface(runtime, interface_name: str) -> List[ipaddress.IPv4Network]:
    token = str(interface_name or "").strip()
    if not token:
        return []
    rows = runtime.list_capture_interfaces()
    for item in rows:
        if str(item.get("name", "") or "").strip() != token:
            continue
        networks: List[ipaddress.IPv4Network] = []
        for raw in list(item.get("ipv4_networks", []) or []):
            try:
                networks.append(ipaddress.ip_network(str(raw), strict=False))
            except ValueError:
                continue
        return networks
    return []


def start_nmap_xml_import_job(
        runtime,
        path: str,
        run_actions: bool = False,
) -> Dict[str, Any]:
    xml_path = runtime._normalize_existing_file(path)
    job = runtime._start_job(
        "import-nmap-xml",
        lambda job_id: runtime._import_nmap_xml(xml_path, bool(run_actions), job_id=int(job_id or 0)),
        payload={"path": xml_path, "run_actions": bool(run_actions)},
    )
    runtime._record_scan_submission(
        submission_kind="import_nmap_xml",
        job_id=int(job.get("id", 0) or 0),
        source_path=xml_path,
        run_actions=bool(run_actions),
        result_summary=f"queued import from {os.path.basename(xml_path)}",
    )
    return job


def start_host_rescan_job(runtime, host_id: int) -> Dict[str, Any]:
    with runtime._lock:
        host = runtime._resolve_host(int(host_id))
        if host is None:
            raise KeyError(f"Unknown host id: {host_id}")
        host_ip = str(getattr(host, "ip", "") or "").strip()
        hostname = str(getattr(host, "hostname", "") or "").strip()
        if not host_ip:
            raise ValueError(f"Host {host_id} does not have a valid IP.")
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    scan_target = choose_preferred_command_host(hostname, host_ip, "nmap")
    uses_hostname_target = scan_target != host_ip
    default_scan_options = runtime._apply_engagement_scan_profile({
        "discovery": True,
        "skip_dns": not uses_hostname_target,
        "timing": "T3",
        "top_ports": 1000,
        "explicit_ports": "",
        "service_detection": True,
        "default_scripts": True,
        "os_detection": False,
        "aggressive": False,
        "full_ports": False,
        "vuln_scripts": False,
        "host_discovery_only": False,
        "arp_ping": False,
    }, engagement_policy=engagement_policy)
    return runtime.start_nmap_scan_job(
        targets=[scan_target],
        discovery=True,
        staged=False,
        run_actions=False,
        nmap_path="nmap",
        nmap_args="",
        scan_mode="easy",
        scan_options=default_scan_options,
    )


def passive_capture_filter() -> str:
    return (
        "arp or broadcast or multicast or "
        "udp port 67 or udp port 68 or udp port 137 or udp port 138 or "
        "udp port 5353 or udp port 5355 or udp port 1900"
    )


def parse_tshark_field_blob(value: str) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip() for item in re.split(r"[,;]", text) if item.strip()]


def classify_passive_protocols(protocol_blob: str, udp_ports: List[str], query_name: str) -> Set[str]:
    labels: Set[str] = set()
    text = str(protocol_blob or "").strip().lower()
    query = str(query_name or "").strip().lower()
    port_tokens = {str(item or "").strip() for item in list(udp_ports or []) if str(item or "").strip()}
    if "arp" in text:
        labels.add("arp")
    if "mdns" in text or "udp:5353" in text or "5353" in port_tokens or query.endswith(".local"):
        labels.update({"mdns", "bonjour"})
    if "llmnr" in text or "5355" in port_tokens:
        labels.add("llmnr")
    if "nbns" in text or "netbios" in text or "137" in port_tokens or "138" in port_tokens:
        labels.add("netbios")
    if "ssdp" in text or "1900" in port_tokens:
        labels.add("ssdp")
    if "dhcp" in text or "bootp" in text or "67" in port_tokens or "68" in port_tokens:
        labels.add("dhcp")
    if "igmp" in text:
        labels.add("multicast")
    return labels


def analyze_passive_capture(
        runtime,
        *,
        interface_name: str,
        capture_path: str,
        analysis_path: str,
) -> Dict[str, Any]:
    if not os.path.isfile(str(capture_path or "")):
        return {
            "candidate_networks": [],
            "observed_private_hosts": [],
            "signals": [],
            "analysis_path": "",
            "record_count": 0,
        }

    connected_networks = runtime._connected_ipv4_networks_for_interface(interface_name)
    local_ips: Set[ipaddress.IPv4Address] = set()
    for network in connected_networks:
        try:
            interface_addr = network.network_address + 1
        except Exception:
            continue
        local_ips.add(interface_addr)
    for item in runtime.list_capture_interfaces():
        if str(item.get("name", "") or "").strip() != str(interface_name or "").strip():
            continue
        for raw_ip in list(item.get("ipv4_addresses", []) or []):
            try:
                local_ips.add(ipaddress.ip_address(str(raw_ip)))
            except ValueError:
                continue

    fields = [
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "udp.srcport",
        "udp.dstport",
        "dns.qry.name",
    ]
    cmd = ["tshark", "-r", str(capture_path), "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "header=n", "-E", "separator=\t", "-E", "occurrence=f"])
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=build_tool_execution_env(),
        check=False,
    )
    if int(result.returncode or 0) != 0:
        return {
            "candidate_networks": [],
            "observed_private_hosts": [],
            "signals": [],
            "analysis_path": "",
            "record_count": 0,
            "error": str(result.stderr or result.stdout or "").strip(),
        }

    observed_private_hosts: Set[str] = set()
    candidate_networks: Set[str] = set()
    protocol_counts: Dict[str, int] = defaultdict(int)
    record_count = 0

    for line in str(result.stdout or "").splitlines():
        columns = line.split("\t")
        while len(columns) < len(fields):
            columns.append("")
        protocol_blob, ip_src, ip_dst, arp_src, arp_dst, udp_src, udp_dst, query_name = columns[:len(fields)]
        ip_values = []
        for value in (ip_src, ip_dst, arp_src, arp_dst):
            ip_values.extend(parse_tshark_field_blob(value))
        parsed_ips: List[ipaddress.IPv4Address] = []
        for raw_ip in ip_values:
            try:
                ip_value = ipaddress.ip_address(str(raw_ip))
            except ValueError:
                continue
            if not isinstance(ip_value, ipaddress.IPv4Address):
                continue
            if not ip_value.is_private or ip_value.is_loopback or ip_value.is_link_local or ip_value.is_multicast:
                continue
            if ip_value in local_ips:
                continue
            parsed_ips.append(ip_value)
            observed_private_hosts.add(str(ip_value))
        if not parsed_ips and not str(protocol_blob or "").strip():
            continue
        record_count += 1

        protocols = classify_passive_protocols(
            protocol_blob,
            parse_tshark_field_blob(udp_src) + parse_tshark_field_blob(udp_dst),
            query_name,
        )
        for label in protocols:
            protocol_counts[label] += 1

        for ip_value in parsed_ips:
            matching_network = next((item for item in connected_networks if ip_value in item), None)
            if matching_network is None:
                inferred = ipaddress.ip_network(f"{ip_value}/24", strict=False)
            elif int(matching_network.prefixlen) >= 24:
                inferred = matching_network
            else:
                inferred = ipaddress.ip_network(f"{ip_value}/24", strict=False)
            if inferred.prefixlen <= 32:
                candidate_networks.add(str(inferred))

    summary = {
        "candidate_networks": sorted(candidate_networks),
        "observed_private_hosts": sorted(observed_private_hosts),
        "signals": [
            {"name": key, "count": int(protocol_counts[key])}
            for key in sorted(protocol_counts.keys())
        ],
        "analysis_path": str(analysis_path or ""),
        "record_count": int(record_count),
    }
    if analysis_path:
        try:
            with open(analysis_path, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, indent=2, sort_keys=True)
        except Exception:
            pass
    return summary


def start_passive_capture_scan_job(
        runtime,
        *,
        interface_name: str,
        duration_minutes: int,
        run_actions: bool = False,
) -> Dict[str, Any]:
    with runtime._lock:
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)
    scope = str((engagement_policy or {}).get("scope", "") or "").strip().lower()
    if scope != "internal":
        raise ValueError("Passive capture is available only for internal engagement scopes.")

    available_interfaces = {
        str(item.get("name", "") or "").strip(): item
        for item in runtime.list_capture_interfaces()
    }
    resolved_interface = str(interface_name or "").strip()
    if not resolved_interface:
        raise ValueError("Capture interface is required.")
    if resolved_interface not in available_interfaces:
        raise ValueError(f"Unknown or unavailable capture interface: {resolved_interface}")

    try:
        resolved_duration = int(duration_minutes or 0)
    except (TypeError, ValueError):
        resolved_duration = 0
    allowed_durations = {5, 15, 30, 45, 60, 75, 90, 105, 120}
    if resolved_duration not in allowed_durations:
        raise ValueError("Capture duration must be one of: 5, 15, 30, 45, 60, 75, 90, 105, 120 minutes.")

    payload = {
        "interface_name": resolved_interface,
        "duration_minutes": resolved_duration,
        "run_actions": bool(run_actions),
        "scan_mode": "passive_capture",
    }
    job = runtime._start_job(
        "passive-capture-scan",
        lambda job_id: runtime._run_passive_capture_scan(
            interface_name=resolved_interface,
            duration_minutes=resolved_duration,
            run_actions=bool(run_actions),
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )
    runtime._record_scan_submission(
        submission_kind="passive_capture_scan",
        job_id=int(job.get("id", 0) or 0),
        targets=[],
        discovery=False,
        staged=False,
        run_actions=bool(run_actions),
        nmap_path="",
        nmap_args="",
        scan_mode="passive_capture",
        scan_options={
            "interface_name": resolved_interface,
            "duration_minutes": resolved_duration,
        },
        target_summary=resolved_interface,
        scope_summary=f"interface: {resolved_interface} | duration: {resolved_duration}m",
        result_summary=f"queued passive capture on {resolved_interface} for {resolved_duration}m",
    )
    return job


def run_passive_capture_scan(
        runtime,
        *,
        interface_name: str,
        duration_minutes: int,
        run_actions: bool,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    resolved_interface = str(interface_name or "").strip()
    resolved_duration = int(duration_minutes or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"capturing on {resolved_interface} for {resolved_duration}m",
        )
    with runtime._lock:
        project = runtime._require_active_project()
        running_folder = project.properties.runningFolder
        output_prefix = os.path.join(
            running_folder,
            f"passive-capture-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
        )
        engagement_policy = runtime._load_engagement_policy_locked(persist_if_missing=True)

    capture_path = f"{output_prefix}.pcapng"
    analysis_path = f"{output_prefix}.analysis.json"
    capture_seconds = max(300, int(resolved_duration * 60))
    capture_command = runtime._join_shell_tokens([
        "tshark",
        "-i",
        resolved_interface,
        "-n",
        "-q",
        "-a",
        f"duration:{capture_seconds}",
        "-f",
        passive_capture_filter(),
        "-w",
        capture_path,
    ])

    executed, reason, process_id, metadata = runtime._run_command_with_tracking(
        tool_name="tshark-passive-capture",
        tab_title=f"Passive Capture ({resolved_interface})",
        host_ip=resolved_interface,
        port="",
        protocol="",
        command=capture_command,
        outputfile=output_prefix,
        timeout=capture_seconds + 180,
        job_id=resolved_job_id,
        return_metadata=True,
    )
    if not executed:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(reason or "capture failed"),
            )
        raise RuntimeError(str(reason or "Passive capture failed."))

    analysis = runtime._analyze_passive_capture(
        interface_name=resolved_interface,
        capture_path=capture_path,
        analysis_path=analysis_path,
    )
    candidate_networks = list(analysis.get("candidate_networks", []) or [])
    default_scan_options = runtime._apply_engagement_scan_profile({
        "discovery": True,
        "skip_dns": True,
        "timing": "T3",
        "top_ports": 1000,
        "explicit_ports": "",
        "service_detection": True,
        "default_scripts": True,
        "os_detection": False,
        "aggressive": False,
        "full_ports": False,
        "vuln_scripts": False,
        "host_discovery_only": False,
        "arp_ping": False,
    }, engagement_policy=engagement_policy)

    queued_scans: List[Dict[str, Any]] = []
    for subnet in candidate_networks[:16]:
        try:
            job = runtime.start_nmap_scan_job(
                targets=[str(subnet)],
                discovery=True,
                staged=False,
                run_actions=bool(run_actions),
                nmap_path="nmap",
                nmap_args="",
                scan_mode="easy",
                scan_options=dict(default_scan_options),
            )
            queued_scans.append({
                "subnet": str(subnet),
                "job_id": int(job.get("id", 0) or 0),
            })
        except Exception as exc:
            queued_scans.append({
                "subnet": str(subnet),
                "job_id": 0,
                "error": str(exc),
            })

    result_summary = (
        f"captured {resolved_duration}m on {resolved_interface}; "
        f"queued {len([item for item in queued_scans if int(item.get('job_id', 0) or 0) > 0])} subnet scan"
        f"{'' if len([item for item in queued_scans if int(item.get('job_id', 0) or 0) > 0]) == 1 else 's'}"
    )
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="completed",
            result_summary=result_summary,
        )
    runtime._emit_ui_invalidation("processes", "jobs", "scan_history", "overview")
    return {
        "interface_name": resolved_interface,
        "duration_minutes": resolved_duration,
        "capture_command": capture_command,
        "capture_path": capture_path,
        "analysis_path": analysis.get("analysis_path", ""),
        "analysis": analysis,
        "queued_scans": queued_scans,
        "run_actions": bool(run_actions),
        "process_id": int(process_id or 0),
        "artifacts": list(metadata.get("artifact_refs", []) or []),
    }


def start_nmap_scan_job(
        runtime,
        targets,
        discovery: bool = True,
        staged: bool = False,
        run_actions: bool = False,
        nmap_path: str = "nmap",
        nmap_args: str = "",
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_targets = runtime._normalize_targets(targets)
    resolved_nmap_path = str(nmap_path or "nmap").strip() or "nmap"
    resolved_nmap_args = str(nmap_args or "").strip()
    resolved_scan_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
    resolved_scan_options = dict(scan_options or {})
    payload = {
        "targets": normalized_targets,
        "discovery": bool(discovery),
        "staged": bool(staged),
        "run_actions": bool(run_actions),
        "nmap_path": resolved_nmap_path,
        "nmap_args": resolved_nmap_args,
        "scan_mode": resolved_scan_mode,
        "scan_options": resolved_scan_options,
    }
    job = runtime._start_job(
        "nmap-scan",
        lambda job_id: runtime._run_nmap_scan_and_import(
            normalized_targets,
            discovery=bool(discovery),
            staged=bool(staged),
            run_actions=bool(run_actions),
            nmap_path=resolved_nmap_path,
            nmap_args=resolved_nmap_args,
            scan_mode=resolved_scan_mode,
            scan_options=resolved_scan_options,
            job_id=int(job_id or 0),
        ),
        payload=payload,
    )
    runtime._record_scan_submission(
        submission_kind="nmap_scan",
        job_id=int(job.get("id", 0) or 0),
        targets=normalized_targets,
        discovery=bool(discovery),
        staged=bool(staged),
        run_actions=bool(run_actions),
        nmap_path=resolved_nmap_path,
        nmap_args=resolved_nmap_args,
        scan_mode=resolved_scan_mode,
        scan_options=resolved_scan_options,
        result_summary=f"queued nmap for {runtime._compact_targets(normalized_targets)}",
    )
    return job


def import_nmap_xml(
        runtime,
        xml_path: str,
        run_actions: bool = False,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"importing {os.path.basename(str(xml_path or ''))}",
        )
    try:
        with runtime._lock:
            project = runtime._require_active_project()
            import_nmap_xml_into_project(
                project=project,
                xml_path=xml_path,
                output="",
                update_progress_observable=None,
            )

            try:
                runtime.logic.copyNmapXMLToOutputFolder(xml_path)
            except Exception:
                pass

            runtime._ensure_scheduler_table()
            runtime._ensure_scheduler_approval_store()

        scheduler_result = None
        if run_actions:
            scheduler_result = runtime._run_scheduler_actions_web()

        result = {
            "xml_path": xml_path,
            "run_actions": bool(run_actions),
            "scheduler_result": scheduler_result,
        }
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="completed",
                result_summary=f"imported {os.path.basename(str(xml_path or ''))}",
            )
        return result
    except Exception as exc:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(exc),
            )
        raise


def run_nmap_scan_and_import(
        runtime,
        targets: List[str],
        discovery: bool,
        staged: bool,
        run_actions: bool,
        nmap_path: str,
        nmap_args: str,
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
        job_id: int = 0,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=f"running nmap against {runtime._compact_targets(targets)}",
        )
    with runtime._lock:
        project = runtime._require_active_project()
        running_folder = project.properties.runningFolder
        host_count_before = len(project.repositoryContainer.hostRepository.getAllHostObjs())
        output_prefix = os.path.join(
            running_folder,
            f"web-nmap-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
        )

    try:
        if str(scan_mode or "").strip().lower() == "rfc1918_discovery":
            result = runtime._run_rfc1918_chunked_scan_and_import(
                targets=targets,
                discovery=bool(discovery),
                run_actions=bool(run_actions),
                nmap_path=nmap_path,
                nmap_args=nmap_args,
                scan_options=dict(scan_options or {}),
                job_id=resolved_job_id,
                output_prefix=output_prefix,
                host_count_before=host_count_before,
            )
            runtime._emit_ui_invalidation("overview", "hosts", "services", "graph", "scan_history")
            return result

        scan_plan = runtime._build_nmap_scan_plan(
            targets=targets,
            discovery=bool(discovery),
            staged=bool(staged),
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=output_prefix,
            scan_mode=scan_mode,
            scan_options=dict(scan_options or {}),
        )

        target_label = runtime._compact_targets(targets)
        stage_results: List[Dict[str, Any]] = []
        for stage in scan_plan["stages"]:
            if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
                raise RuntimeError("cancelled")
            executed, reason, process_id = runtime._run_command_with_tracking(
                tool_name=stage["tool_name"],
                tab_title=stage["tab_title"],
                host_ip=target_label,
                port="",
                protocol="",
                command=stage["command"],
                outputfile=stage["output_prefix"],
                timeout=int(stage.get("timeout", 3600)),
                job_id=resolved_job_id,
            )
            stage_results.append({
                "name": stage["tool_name"],
                "command": stage["command"],
                "executed": bool(executed),
                "reason": reason,
                "process_id": int(process_id or 0),
                "output_prefix": stage["output_prefix"],
                "xml_path": stage["xml_path"],
            })
            if not executed:
                raise RuntimeError(
                    f"Nmap stage '{stage['tool_name']}' failed ({reason}). "
                    f"Command: {stage['command']}"
                )

        xml_path = scan_plan["xml_path"]
        if not xml_path or not os.path.isfile(xml_path):
            raise RuntimeError(f"Nmap scan completed but XML output was not found: {xml_path}")

        import_result = runtime._import_nmap_xml(xml_path, run_actions=run_actions)
        with runtime._lock:
            project = runtime._require_active_project()
            host_count_after = len(project.repositoryContainer.hostRepository.getAllHostObjs())
        imported_hosts = max(0, int(host_count_after) - int(host_count_before))
        warnings: List[str] = []
        if imported_hosts == 0:
            if bool(discovery):
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "The target may be dropping discovery probes; try disabling host discovery (-Pn)."
                )
            else:
                warnings.append(
                    "Nmap completed but no hosts were imported. "
                    "Verify target reachability and scan privileges."
                )

        result = {
            "targets": targets,
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": nmap_path,
            "nmap_args": str(nmap_args or ""),
            "scan_mode": str(scan_mode or "legacy"),
            "scan_options": dict(scan_options or {}),
            "commands": [stage["command"] for stage in scan_plan["stages"]],
            "stages": stage_results,
            "xml_path": xml_path,
            "imported_hosts": imported_hosts,
            "warnings": warnings,
            **import_result,
        }
        if resolved_job_id > 0:
            warning_note = f" ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})" if warnings else ""
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="completed",
                result_summary=f"imported {imported_hosts} host{'s' if imported_hosts != 1 else ''}{warning_note}",
            )
        runtime._emit_ui_invalidation("overview", "hosts", "services", "graph", "scan_history")
        return result
    except Exception as exc:
        if resolved_job_id > 0:
            runtime._update_scan_submission_status(
                job_id=resolved_job_id,
                status="failed",
                result_summary=str(exc),
            )
        runtime._emit_ui_invalidation("scan_history")
        raise


def run_rfc1918_chunked_scan_and_import(
        runtime,
        *,
        targets: List[str],
        discovery: bool,
        run_actions: bool,
        nmap_path: str,
        nmap_args: str,
        scan_options: Dict[str, Any],
        job_id: int,
        output_prefix: str,
        host_count_before: int,
) -> Dict[str, Any]:
    resolved_job_id = int(job_id or 0)
    normalized_scan_options = dict(scan_options or {})
    chunk_concurrency = runtime._normalize_rfc_chunk_concurrency(
        normalized_scan_options.get("chunk_concurrency", 1)
    )
    normalized_scan_options["chunk_concurrency"] = chunk_concurrency

    batches = list(runtime._iter_rfc1918_scan_batches(targets))
    total_batches = len(batches)
    if total_batches <= 0:
        raise RuntimeError("RFC1918 discovery requires at least one selected private subnet.")

    completed_batches = 0
    last_xml_path = ""
    active_workers = max(1, min(int(chunk_concurrency), int(total_batches)))
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="running",
            result_summary=(
                f"running RFC1918 sweep across {total_batches} "
                f"batch{'' if total_batches == 1 else 'es'} "
                f"(up to {active_workers} concurrent)"
            ),
        )

    def _run_rfc_batch(batch_index: int, batch_targets: List[str]) -> Dict[str, Any]:
        if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
            raise RuntimeError("cancelled")

        batch_prefix = f"{output_prefix}-chunk-{batch_index:05d}"
        scan_plan = runtime._build_nmap_scan_plan(
            targets=list(batch_targets),
            discovery=bool(discovery),
            staged=False,
            nmap_path=nmap_path,
            nmap_args=nmap_args,
            output_prefix=batch_prefix,
            scan_mode="rfc1918_discovery",
            scan_options=dict(normalized_scan_options),
        )
        target_label = runtime._compact_targets(batch_targets)

        for stage in list(scan_plan.get("stages", []) or []):
            stage_tab_title = str(stage.get("tab_title", "Nmap RFC1918 Discovery") or "Nmap RFC1918 Discovery")
            if total_batches > 1:
                stage_tab_title = f"{stage_tab_title} {batch_index}/{total_batches}"
            executed, reason, process_id = runtime._run_command_with_tracking(
                tool_name=str(stage.get("tool_name", "nmap-rfc1918_discovery") or "nmap-rfc1918_discovery"),
                tab_title=stage_tab_title,
                host_ip=target_label,
                port="",
                protocol="",
                command=str(stage.get("command", "") or ""),
                outputfile=str(stage.get("output_prefix", batch_prefix) or batch_prefix),
                timeout=int(stage.get("timeout", 3600) or 3600),
                job_id=resolved_job_id,
            )
            _ = int(process_id or 0)
            if not executed:
                raise RuntimeError(
                    f"Nmap stage '{stage.get('tool_name', 'nmap-rfc1918_discovery')}' failed ({reason}). "
                    f"Command: {stage.get('command', '')}"
                )

        xml_path = str(scan_plan.get("xml_path", "") or "")
        if not xml_path or not os.path.isfile(xml_path):
            raise RuntimeError(f"Nmap chunk completed but XML output was not found: {xml_path}")
        return {
            "batch_index": int(batch_index),
            "batch_targets": list(batch_targets),
            "xml_path": xml_path,
        }

    batch_iter = iter(list(enumerate(batches, start=1)))
    pending: Dict[Any, int] = {}

    def _submit_next(pool: ThreadPoolExecutor) -> bool:
        try:
            next_batch_index, next_batch_targets = next(batch_iter)
        except StopIteration:
            return False
        future = pool.submit(_run_rfc_batch, int(next_batch_index), list(next_batch_targets))
        pending[future] = int(next_batch_index)
        return True

    with ThreadPoolExecutor(max_workers=active_workers, thread_name_prefix="legion-rfc1918") as pool:
        for _ in range(active_workers):
            if not _submit_next(pool):
                break

        while pending:
            finished_future = next(as_completed(list(pending.keys())))
            pending.pop(finished_future, None)
            batch_result = finished_future.result()
            xml_path = str(batch_result.get("xml_path", "") or "")
            runtime._import_nmap_xml(xml_path, run_actions=False)
            last_xml_path = xml_path
            completed_batches += 1

            if resolved_job_id > 0:
                runtime._update_scan_submission_status(
                    job_id=resolved_job_id,
                    status="running",
                    result_summary=(
                        f"completed RFC1918 sweep batch {completed_batches}/{total_batches} "
                        f"(up to {active_workers} concurrent)"
                    ),
                )
            if resolved_job_id > 0 and runtime.jobs.is_cancel_requested(resolved_job_id):
                raise RuntimeError("cancelled")
            _submit_next(pool)

    scheduler_result = runtime._run_scheduler_actions_web() if run_actions else None
    with runtime._lock:
        project = runtime._require_active_project()
        host_count_after = len(project.repositoryContainer.hostRepository.getAllHostObjs())
    imported_hosts = max(0, int(host_count_after) - int(host_count_before))
    warnings: List[str] = []
    if imported_hosts == 0:
        warnings.append(
            "RFC1918 sweep completed but no hosts were imported. "
            "Verify the selected ranges are reachable from this network segment."
        )
    if resolved_job_id > 0:
        runtime._update_scan_submission_status(
            job_id=resolved_job_id,
            status="completed",
            result_summary=(
                f"completed RFC1918 sweep across {completed_batches}/{total_batches} "
                f"batch{'' if completed_batches == 1 else 'es'} "
                f"(up to {active_workers} concurrent)"
            ),
        )
    return {
        "targets": list(targets or []),
        "discovery": bool(discovery),
        "run_actions": bool(run_actions),
        "nmap_path": nmap_path,
        "nmap_args": str(nmap_args or ""),
        "scan_mode": "rfc1918_discovery",
        "scan_options": dict(normalized_scan_options),
        "xml_path": last_xml_path,
        "chunks_completed": int(completed_batches),
        "chunks_total": int(total_batches),
        "chunk_concurrency": int(active_workers),
        "imported_hosts": imported_hosts,
        "warnings": warnings,
        "scheduler_result": scheduler_result,
    }


def build_nmap_scan_plan(
        runtime,
        *,
        targets: List[str],
        discovery: bool,
        staged: bool,
        nmap_path: str,
        nmap_args: str,
        output_prefix: str,
        scan_mode: str = "legacy",
        scan_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_path = str(nmap_path or "nmap").strip() or "nmap"
    raw_args = str(nmap_args or "").strip()
    try:
        extra_args = shlex.split(raw_args) if raw_args else []
    except ValueError as exc:
        raise ValueError(f"Invalid nmap arguments: {exc}") from exc

    selected_mode = str(scan_mode or "legacy").strip().lower() or "legacy"
    selected_options = dict(scan_options or {})

    if selected_mode == "rfc1918_discovery":
        rfc_profile = str(selected_options.get("scan_profile", "quick") or "quick").strip().lower()
        default_ports = runtime.RFC1918_COMPREHENSIVE_TCP_PORTS if rfc_profile == "comprehensive" else runtime.INTERNAL_QUICK_RECON_TCP_PORTS
        options = normalize_scan_options(selected_options, {
            "discovery": True,
            "host_discovery_only": True,
            "skip_dns": True,
            "arp_ping": False,
            "force_pn": False,
            "timing": "T3",
            "top_ports": 0,
            "explicit_ports": default_ports,
            "scan_profile": rfc_profile,
            "chunk_concurrency": 1,
            "service_detection": False,
            "default_scripts": False,
            "os_detection": False,
        })
        options["chunk_concurrency"] = runtime._normalize_rfc_chunk_concurrency(
            options.get("chunk_concurrency", 1)
        )
        options["force_pn"] = False
        if bool(options.get("host_discovery_only", False)):
            options["explicit_ports"] = ""
        elif not str(options.get("explicit_ports", "") or "").strip():
            options["explicit_ports"] = default_ports
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="rfc1918_discovery",
            options=options,
            extra_args=extra_args,
        )

    if selected_mode == "easy":
        options = normalize_scan_options(selected_options, {
            "discovery": True,
            "skip_dns": True,
            "force_pn": False,
            "timing": "T3",
            "top_ports": 1000,
            "service_detection": True,
            "default_scripts": True,
            "os_detection": False,
            "aggressive": False,
            "full_ports": False,
            "vuln_scripts": False,
        })
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="easy",
            options=options,
            extra_args=extra_args,
        )

    if selected_mode == "hard":
        options = normalize_scan_options(selected_options, {
            "discovery": False,
            "skip_dns": True,
            "force_pn": False,
            "timing": "T4",
            "top_ports": 1000,
            "service_detection": True,
            "default_scripts": True,
            "os_detection": True,
            "aggressive": False,
            "full_ports": True,
            "vuln_scripts": False,
        })
        return build_single_scan_plan(
            runtime,
            targets=targets,
            nmap_path=resolved_path,
            output_prefix=output_prefix,
            mode="hard",
            options=options,
            extra_args=extra_args,
        )

    if staged:
        stage1_prefix = f"{output_prefix}_stage1"
        stage2_prefix = f"{output_prefix}_stage2"
        stage1_cmd_prefix = nmap_output_prefix_for_command(stage1_prefix, resolved_path)
        stage2_cmd_prefix = nmap_output_prefix_for_command(stage2_prefix, resolved_path)

        stage1_tokens = [resolved_path, "-sn", *targets]
        stage1_tokens = append_nmap_stats_every(stage1_tokens, interval="15s")
        stage1_tokens.extend(["-oA", stage1_cmd_prefix])
        stage2_tokens = [resolved_path, "-sV", "-O"]
        if not bool(discovery):
            stage2_tokens.append("-Pn")
        stage2_tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
        stage2_tokens.extend(targets)
        stage2_tokens.extend(["-oA", stage2_cmd_prefix])

        stages = [
            {
                "tool_name": "nmap-stage1",
                "tab_title": "Nmap Stage 1 Discovery",
                "output_prefix": stage1_prefix,
                "xml_path": f"{stage1_prefix}.xml",
                "command": join_shell_tokens(stage1_tokens),
                "timeout": 1800,
            },
            {
                "tool_name": "nmap-stage2",
                "tab_title": "Nmap Stage 2 Service Scan",
                "output_prefix": stage2_prefix,
                "xml_path": f"{stage2_prefix}.xml",
                "command": join_shell_tokens(stage2_tokens),
                "timeout": 5400,
            },
        ]
        return {"xml_path": f"{stage2_prefix}.xml", "stages": stages}

    output_cmd_prefix = nmap_output_prefix_for_command(output_prefix, resolved_path)
    tokens = [resolved_path]
    if not bool(discovery):
        tokens.append("-Pn")
    tokens.extend(["-T4", "-sV", "-O"])
    tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
    tokens.extend(targets)
    tokens.extend(["-oA", output_cmd_prefix])
    stages = [{
        "tool_name": "nmap-scan",
        "tab_title": "Nmap Scan",
        "output_prefix": output_prefix,
        "xml_path": f"{output_prefix}.xml",
        "command": join_shell_tokens(tokens),
        "timeout": 5400,
    }]
    return {"xml_path": f"{output_prefix}.xml", "stages": stages}


def build_single_scan_plan(
        runtime,
        *,
        targets: List[str],
        nmap_path: str,
        output_prefix: str,
        mode: str,
        options: Dict[str, Any],
        extra_args: List[str],
) -> Dict[str, Any]:
    output_cmd_prefix = nmap_output_prefix_for_command(output_prefix, nmap_path)
    tokens = [nmap_path]

    discovery_enabled = bool(options.get("discovery", True))
    host_discovery_only = bool(options.get("host_discovery_only", False))
    skip_dns = bool(options.get("skip_dns", False))
    timing_value = normalize_timing(str(options.get("timing", "T3")))
    service_detection = bool(options.get("service_detection", False))
    default_scripts = bool(options.get("default_scripts", False))
    os_detection = bool(options.get("os_detection", False))
    aggressive = bool(options.get("aggressive", False))
    full_ports = bool(options.get("full_ports", False))
    vuln_scripts = bool(options.get("vuln_scripts", False))
    top_ports = normalize_top_ports(options.get("top_ports", 1000))
    explicit_ports = normalize_explicit_ports(options.get("explicit_ports", ""))
    arp_ping = bool(options.get("arp_ping", False))
    force_pn = bool(options.get("force_pn", False))

    if host_discovery_only:
        tokens.append("-sn")
        if skip_dns:
            tokens.append("-n")
        if arp_ping:
            tokens.append("-PR")
        tokens.append(f"-{timing_value}")
    else:
        if force_pn or not discovery_enabled:
            tokens.append("-Pn")
        if skip_dns:
            tokens.append("-n")
        tokens.append(f"-{timing_value}")
        if full_ports:
            tokens.append("-p-")
        elif explicit_ports:
            tokens.extend(["-p", explicit_ports])
        else:
            tokens.extend(["--top-ports", str(top_ports)])

        if aggressive:
            tokens.append("-A")
        else:
            if service_detection:
                tokens.append("-sV")
            if default_scripts:
                tokens.append("-sC")
            if os_detection:
                tokens.append("-O")

        if vuln_scripts:
            tokens.extend(["--script", "vuln"])

    tokens.extend(append_nmap_stats_every(extra_args, interval="15s"))
    tokens.extend(targets)
    tokens.extend(["-oA", output_cmd_prefix])

    tab_title = {
        "rfc1918_discovery": "Nmap RFC1918 Discovery",
        "easy": "Nmap Easy Scan",
        "hard": "Nmap Hard Scan",
    }.get(str(mode), "Nmap Scan")

    return {
        "xml_path": f"{output_prefix}.xml",
        "stages": [{
            "tool_name": f"nmap-{mode}",
            "tab_title": tab_title,
            "output_prefix": output_prefix,
            "xml_path": f"{output_prefix}.xml",
            "command": join_shell_tokens(tokens),
            "timeout": 7200 if mode == "hard" else 5400,
        }],
    }


def normalize_scan_options(options: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(defaults)
    merged.update(dict(options or {}))
    return merged


def normalize_timing(raw: str) -> str:
    value = str(raw or "T3").strip().upper()
    if not value.startswith("T"):
        value = f"T{value}"
    if value not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        return "T3"
    return value


def normalize_top_ports(raw: Any) -> int:
    try:
        value = int(raw)
    except Exception:
        return 1000
    return max(1, min(value, 65535))


def normalize_explicit_ports(raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    cleaned = ",".join(part.strip() for part in value.split(",") if part.strip())
    if not cleaned:
        return ""
    if not re.fullmatch(r"[0-9,\-]+", cleaned):
        return ""
    return cleaned


def contains_nmap_stats_every(args: List[str]) -> bool:
    for token in args:
        value = str(token or "").strip().lower()
        if value == "--stats-every" or value.startswith("--stats-every="):
            return True
    return False


def contains_nmap_verbose(args: List[str]) -> bool:
    for token in args:
        value = str(token or "").strip().lower()
        if value in {"-v", "-vv", "-vvv", "--verbose"}:
            return True
    return False


def append_nmap_stats_every(args: List[str], interval: str = "15s") -> List[str]:
    values = [str(item) for item in list(args or [])]
    if not contains_nmap_stats_every(values):
        values = values + ["--stats-every", str(interval or "15s")]
    if contains_nmap_stats_every(values) and not contains_nmap_verbose(values):
        values = values + ["-vv"]
    return values


def nmap_output_prefix_for_command(output_prefix: str, nmap_path: str) -> str:
    if is_wsl() and str(nmap_path).lower().endswith(".exe"):
        return to_windows_path(output_prefix)
    return output_prefix


def join_shell_tokens(tokens: List[str]) -> str:
    rendered = [str(token) for token in tokens]
    if os.name == "nt":
        return subprocess.list2cmdline(rendered)
    if hasattr(shlex, "join"):
        return shlex.join(rendered)
    return " ".join(shlex.quote(token) for token in rendered)


def compact_targets(targets: List[str]) -> str:
    if not targets:
        return ""
    if len(targets) <= 3:
        return ",".join(str(item) for item in targets)
    return ",".join(str(item) for item in targets[:3]) + ",..."


def summarize_scan_scope(targets: List[str]) -> str:
    subnets: List[str] = []
    hosts: List[str] = []
    ranges: List[str] = []
    domains: List[str] = []
    for item in list(targets or []):
        token = str(item or "").strip()
        if not token:
            continue
        if "/" in token:
            try:
                subnet = str(ipaddress.ip_network(token, strict=False))
            except ValueError:
                subnet = ""
            if subnet and subnet not in subnets:
                subnets.append(subnet)
                continue
        if "-" in token and token not in ranges:
            ranges.append(token)
            continue
        try:
            host_value = str(ipaddress.ip_address(token))
        except ValueError:
            host_value = ""
        if host_value:
            if host_value not in hosts:
                hosts.append(host_value)
            continue
        if token not in domains:
            domains.append(token)

    parts: List[str] = []
    if subnets:
        parts.append(f"subnets: {', '.join(subnets[:4])}" + (" ..." if len(subnets) > 4 else ""))
    if ranges:
        parts.append(f"ranges: {', '.join(ranges[:3])}" + (" ..." if len(ranges) > 3 else ""))
    if hosts:
        host_summary = ", ".join(hosts[:4])
        if len(hosts) > 4:
            host_summary = f"{host_summary} ... ({len(hosts)} hosts)"
        parts.append(f"hosts: {host_summary}")
    if domains:
        parts.append(f"domains: {', '.join(domains[:4])}" + (" ..." if len(domains) > 4 else ""))
    return " | ".join(parts[:4])


def record_scan_submission(
        runtime,
        *,
        submission_kind: str,
        job_id: int,
        targets: Optional[List[str]] = None,
        source_path: str = "",
        discovery: bool = False,
        staged: bool = False,
        run_actions: bool = False,
        nmap_path: str = "",
        nmap_args: str = "",
        scan_mode: str = "",
        scan_options: Optional[Dict[str, Any]] = None,
        target_summary: str = "",
        scope_summary: str = "",
        result_summary: str = "",
) -> Optional[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if project is None:
            return None
        ensure_scan_submission_table(project.database)
        normalized_targets = [str(item or "").strip() for item in list(targets or []) if str(item or "").strip()]
        record = db_record_scan_submission(project.database, {
            "job_id": str(int(job_id or 0) or ""),
            "submission_kind": str(submission_kind or ""),
            "status": "submitted",
            "target_summary": str(target_summary or compact_targets(normalized_targets)),
            "scope_summary": str(scope_summary or summarize_scan_scope(normalized_targets)),
            "targets": normalized_targets,
            "source_path": str(source_path or ""),
            "scan_mode": str(scan_mode or ""),
            "discovery": bool(discovery),
            "staged": bool(staged),
            "run_actions": bool(run_actions),
            "nmap_path": str(nmap_path or ""),
            "nmap_args": str(nmap_args or ""),
            "scan_options": dict(scan_options or {}),
            "result_summary": str(result_summary or ""),
        })
    runtime._emit_ui_invalidation("scan_history")
    return record


def update_scan_submission_status(
        runtime,
        *,
        job_id: int,
        status: str,
        result_summary: str = "",
) -> Optional[Dict[str, Any]]:
    with runtime._lock:
        project = getattr(runtime.logic, "activeProject", None)
        if project is None:
            return None
        ensure_scan_submission_table(project.database)
        record = db_update_scan_submission(
            project.database,
            job_id=int(job_id or 0),
            status=str(status or ""),
            result_summary=str(result_summary or ""),
        )
    runtime._emit_ui_invalidation("scan_history")
    return record
