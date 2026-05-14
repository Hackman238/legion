from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.scheduler.models import ExecutionRecord
from app.scheduler.planner import ScheduledAction
from app.scheduler.runners import (
    RunnerExecutionRequest,
    RunnerExecutionResult,
    execute_runner_request,
    normalize_runner_settings,
)
from app.settings import AppSettings
from app.timing import getTimestamp


def execute_scheduler_decision(
        runtime,
        decision: ScheduledAction,
        *,
        host_ip: str,
        port: str,
        protocol: str,
        service_name: str,
        command_template: str,
        timeout: int,
        job_id: int = 0,
        capture_metadata: bool = False,
        approval_id: int = 0,
        runner_preference: str = "",
        runner_settings: Optional[Dict[str, Any]] = None,
) -> Any:
    normalized_runner_settings = normalize_runner_settings(runner_settings or {})
    project = runtime._require_active_project()
    input_error = AppSettings._scheduler_target_input_error(
        str(decision.tool_id or ""),
        str(command_template or ""),
        port=str(port or ""),
    )
    if not isinstance(input_error, str):
        input_error = ""
    if input_error:
        if not capture_metadata:
            return False, input_error, 0
        fallback_timestamp = getTimestamp(True)
        execution_record = ExecutionRecord.from_plan_step(
            decision,
            started_at=fallback_timestamp,
            finished_at=fallback_timestamp,
            exit_status=input_error,
            runner_type="local",
            approval_id=str(approval_id or ""),
        )
        return {
            "executed": False,
            "reason": input_error,
            "process_id": 0,
            "execution_record": execution_record,
        }
    request = RunnerExecutionRequest(
        decision=decision,
        tool_id=str(decision.tool_id or ""),
        command_template=str(command_template or ""),
        host_ip=str(host_ip or ""),
        hostname=str(runtime._hostname_for_ip(host_ip) or ""),
        port=str(port or ""),
        protocol=str(protocol or "tcp"),
        service_name=str(service_name or ""),
        timeout=int(timeout or 300),
        job_id=int(job_id or 0),
        approval_id=int(approval_id or 0),
        declared_runner_type=str(getattr(getattr(decision, "action", None), "runner_type", "local") or "local"),
    )

    def _build_command(request_payload):
        return runtime._build_command(
            str(request_payload.command_template or ""),
            str(request_payload.host_ip or ""),
            str(request_payload.port or ""),
            str(request_payload.protocol or "tcp"),
            str(request_payload.tool_id or ""),
            str(getattr(request_payload, "service_name", "") or ""),
        )

    def _execute_local_command(*, request, rendered_command, outputfile, runner_type):
        tab_title = f"{request.tool_id} ({request.port}/{request.protocol})"
        command_result = runtime._run_command_with_tracking(
            tool_name=request.tool_id,
            tab_title=tab_title,
            host_ip=request.host_ip,
            port=request.port,
            protocol=request.protocol,
            command=rendered_command,
            outputfile=outputfile,
            timeout=int(request.timeout or 300),
            job_id=int(request.job_id or 0),
            return_metadata=True,
        )
        executed, reason, process_id, metadata = command_result
        return RunnerExecutionResult(
            executed=bool(executed),
            reason=str(reason or ""),
            runner_type=str(runner_type or "local"),
            process_id=int(process_id or 0),
            started_at=str(metadata.get("started_at", "") or ""),
            finished_at=str(metadata.get("finished_at", "") or ""),
            stdout_ref=str(metadata.get("stdout_ref", "") or ""),
            stderr_ref=str(metadata.get("stderr_ref", "") or ""),
            artifact_refs=list(metadata.get("artifact_refs", []) or []),
        )

    def _execute_browser_action(*, request, browser_settings, runner_type):
        started_at = getTimestamp(True)
        executed, reason, artifact_refs = runtime._take_screenshot(
            str(request.host_ip or ""),
            str(request.port or ""),
            service_name=str(request.service_name or ""),
            return_artifacts=True,
            browser_settings=browser_settings,
        )
        return RunnerExecutionResult(
            executed=bool(executed),
            reason=str(reason or ""),
            runner_type=str(runner_type or "browser"),
            started_at=started_at,
            finished_at=getTimestamp(True),
            artifact_refs=list(artifact_refs or []),
        )

    allow_optional_runners = True
    scheduler_config = getattr(runtime, "scheduler_config", None)
    if scheduler_config is not None and hasattr(scheduler_config, "is_feature_enabled"):
        allow_optional_runners = bool(scheduler_config.is_feature_enabled("optional_runners"))

    runner_result = execute_runner_request(
        request,
        runner_preference=str(runner_preference or ""),
        runner_settings=normalized_runner_settings,
        allow_optional_runners=allow_optional_runners,
        build_command=_build_command,
        execute_local_command=_execute_local_command,
        execute_browser_action=_execute_browser_action,
        mount_paths=[
            getattr(project.properties, "runningFolder", ""),
            getattr(project.properties, "outputFolder", ""),
            os.getcwd(),
        ],
        workdir=os.getcwd(),
    )
    if not capture_metadata:
        return bool(runner_result.executed), str(runner_result.reason or ""), int(runner_result.process_id or 0)

    fallback_timestamp = getTimestamp(True)
    execution_record = ExecutionRecord.from_plan_step(
        decision,
        started_at=str(runner_result.started_at or fallback_timestamp),
        finished_at=str(runner_result.finished_at or fallback_timestamp),
        exit_status=str(runner_result.reason or ""),
        runner_type=str(runner_result.runner_type or "local"),
        stdout_ref=str(runner_result.stdout_ref or ""),
        stderr_ref=str(runner_result.stderr_ref or ""),
        artifact_refs=list(runner_result.artifact_refs or []),
        approval_id=str(approval_id or ""),
    )
    return {
        "executed": bool(runner_result.executed),
        "reason": str(runner_result.reason or ""),
        "process_id": int(runner_result.process_id or 0),
        "execution_record": execution_record,
    }
