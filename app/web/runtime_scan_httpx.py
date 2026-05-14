from __future__ import annotations

import os
import re
import shlex
from types import SimpleNamespace
from typing import Any, Dict, List, Set

from app.scheduler.observation_parsers import extract_tool_observations
from app.scheduler.state import build_attempted_action_entry
from app.timing import getTimestamp


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
        host = runtime._resolve_host_by_token(str(host_token))
        host_id = int(getattr(host, "id", 0) or 0)
        host_ip = str(getattr(host, "ip", "") or host_token).strip()
        hostname = str(getattr(host, "hostname", "") or host_ip).strip()

        materialized = runtime._materialize_httpx_urls_as_web_targets(
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
            _persist_httpx_observations(
                runtime,
                host_id=host_id,
                host_ip=host_ip,
                hostname=hostname,
                command=command,
                executed=executed,
                reason=reason,
                artifact_refs=artifact_refs,
                observed_payload=observed_payload,
                materialized_targets=materialized_targets,
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


def _persist_httpx_observations(
        runtime,
        *,
        host_id: int,
        host_ip: str,
        hostname: str,
        command: str,
        executed: bool,
        reason: str,
        artifact_refs: List[str],
        observed_payload: Dict[str, Any],
        materialized_targets: List[Dict[str, Any]],
) -> None:
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
