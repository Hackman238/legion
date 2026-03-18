#!/usr/bin/env python

"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""

import glob
import ntpath
import os
import re
import shutil
import subprocess
import sys

from app.Project import Project
from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.logging.legionLog import getAppLogger
from app.screenshot_targets import apply_preferred_target_placeholders, choose_preferred_screenshot_host
from app.tools.ToolCoordinator import ToolCoordinator
from app.shell.Shell import Shell
from app.tools.nmap.NmapPaths import getNmapOutputFolder

log = getAppLogger()

class Logic:
    def __init__(self, shell: Shell, projectManager, toolCoordinator: ToolCoordinator):
        self.projectManager = projectManager
        self.activeProject: Project = None
        self.toolCoordinator = toolCoordinator
        self.shell = shell

    def run_scripted_actions(self):
        """
        Run scripted actions/automated attacks for all hosts/ports in the active project (headless/CLI mode).
        Screenshots are also taken using EyeWitness, just as in the GUI.
        """
        from app.settings import AppSettings, Settings
        from app.scheduler.approvals import ensure_scheduler_approval_table, queue_pending_approval
        from app.scheduler.audit import log_scheduler_decision
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.execution import ensure_scheduler_execution_table, store_execution_record
        from app.scheduler.models import ExecutionRecord
        from app.scheduler.orchestrator import SchedulerDecisionDisposition, SchedulerOrchestrator
        from app.scheduler.observation_parsers import extract_tool_observations
        from app.scheduler.state import (
            build_attempted_action_entry,
            build_target_urls,
            ensure_scheduler_target_state_table,
            load_observed_service_inventory,
            upsert_target_state,
        )
        from app.scheduler.policy import (
            ensure_scheduler_engagement_policy_table,
        )
        from app.scheduler.runners import (
            RunnerExecutionRequest,
            RunnerExecutionResult,
            execute_runner_request,
            normalize_runner_settings,
        )
        from app.timing import getTimestamp
        from app.tooling import build_tool_execution_env
        from app.httputil.isHttps import isHttps

        print("[*] Running scripted actions/automated attacks (headless mode)...")
        settingsFile = AppSettings()
        settings = Settings(settingsFile)
        repo_container = self.activeProject.repositoryContainer
        scheduler_config = SchedulerConfigManager()
        runner_settings = normalize_runner_settings(scheduler_config.load().get("runners", {}))
        scheduler_orchestrator = SchedulerOrchestrator(scheduler_config)
        engagement_policy = None
        database = getattr(self.activeProject, "database", None)
        if database is not None:
            try:
                engagement_policy = scheduler_orchestrator.load_project_engagement_policy(
                    database,
                    persist_if_missing=True,
                    updated_at=getTimestamp(True),
                )
            except Exception:
                engagement_policy = None

        def record(decision, host_ip, host_port, host_protocol, host_service, approved, executed, reason, approval_id=""):
            database = getattr(self.activeProject, "database", None)
            if database is None:
                return
            log_scheduler_decision(database, {
                "timestamp": getTimestamp(True),
                "host_ip": str(host_ip),
                "port": str(host_port),
                "protocol": str(host_protocol),
                "service": str(host_service),
                "scheduler_mode": str(decision.mode),
                "goal_profile": str(decision.goal_profile),
                "engagement_preset": str(decision.engagement_preset),
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "risk_tags": ",".join(decision.risk_tags),
                "requires_approval": "True" if decision.requires_approval else "False",
                "policy_decision": str(decision.policy_decision),
                "policy_reason": str(decision.policy_reason),
                "risk_summary": str(decision.risk_summary),
                "safer_alternative": str(decision.safer_alternative),
                "family_policy_state": str(decision.family_policy_state),
                "approved": "True" if approved else "False",
                "executed": "True" if executed else "False",
                "reason": str(reason),
                "rationale": str(decision.rationale),
                "approval_id": str(approval_id or ""),
            })

        def record_execution(
                decision,
                host_ip,
                host_port,
                host_protocol,
                host_service,
                *,
                started_at,
                finished_at,
                exit_status,
                runner_type="",
                artifact_refs=None,
                approval_id="",
                stdout_ref="",
                stderr_ref="",
        ):
            database = getattr(self.activeProject, "database", None)
            if database is None:
                return
            try:
                ensure_scheduler_execution_table(database)
                execution_record = ExecutionRecord.from_plan_step(
                    decision,
                    started_at=str(started_at or ""),
                    finished_at=str(finished_at or ""),
                    exit_status=str(exit_status or ""),
                    runner_type=str(runner_type or ""),
                    stdout_ref=str(stdout_ref or ""),
                    stderr_ref=str(stderr_ref or ""),
                    artifact_refs=list(artifact_refs or []),
                    approval_id=str(approval_id or ""),
                )
                store_execution_record(
                    database,
                    execution_record,
                    step=decision,
                    host_ip=str(host_ip),
                    port=str(host_port),
                    protocol=str(host_protocol),
                    service=str(host_service),
                )
            except Exception:
                return

        def remember_target_state(
                decision,
                host_id,
                host_ip,
                host_port,
                host_protocol,
                host_service,
                *,
                status,
                reason,
                artifact_refs=None,
                observations=None,
        ):
            database = getattr(self.activeProject, "database", None)
            if database is None or int(host_id or 0) <= 0:
                return
            try:
                ensure_scheduler_target_state_table(database)
                service_inventory = load_observed_service_inventory(database, int(host_id or 0))
                urls = build_target_urls(str(host_ip or ""), "", service_inventory)
                upsert_target_state(database, int(host_id or 0), {
                    "host_ip": str(host_ip or ""),
                    "updated_at": getTimestamp(True),
                    "last_mode": str(decision.mode),
                    "goal_profile": str(decision.goal_profile),
                    "engagement_preset": str(decision.engagement_preset),
                    "last_port": str(host_port or ""),
                    "last_protocol": str(host_protocol or "tcp"),
                    "last_service": str(host_service or ""),
                    "service_inventory": service_inventory,
                    "urls": urls,
                    "attempted_actions": [
                        build_attempted_action_entry(
                            decision=decision,
                            status=str(status or ""),
                            reason=str(reason or ""),
                            attempted_at=getTimestamp(True),
                            port=str(host_port or ""),
                            protocol=str(host_protocol or "tcp"),
                            service=str(host_service or ""),
                            family_id=str(getattr(decision, "family_id", "") or ""),
                            command_signature=scheduler_orchestrator.planner._command_signature(
                                str(host_protocol or "tcp"),
                                str(getattr(decision, "command_template", "") or ""),
                            ),
                            artifact_refs=list(artifact_refs or []),
                        )
                    ],
                    "artifacts": [
                        {
                            "ref": str(ref or ""),
                            "kind": "screenshot" if str(ref or "").lower().endswith(".png") else "artifact",
                            "tool_id": str(decision.tool_id),
                            "port": str(host_port or ""),
                            "protocol": str(host_protocol or "tcp"),
                            "source_kind": "observed",
                            "observed": True,
                        }
                        for ref in list(artifact_refs or [])
                        if str(ref or "").strip()
                    ],
                    "screenshots": [
                        {
                            "artifact_ref": str(ref or ""),
                            "filename": os.path.basename(str(ref or "")),
                            "port": str(host_port or ""),
                            "protocol": str(host_protocol or "tcp"),
                            "source_kind": "observed",
                            "observed": True,
                        }
                        for ref in list(artifact_refs or [])
                        if str(ref or "").strip().lower().endswith(".png")
                    ],
                }, merge=True)
                if isinstance(observations, dict):
                    observation_updates = {}
                    if isinstance(observations.get("technologies", []), list) and observations.get("technologies", []):
                        observation_updates["technologies"] = list(observations.get("technologies", []) or [])
                    if isinstance(observations.get("findings", []), list) and observations.get("findings", []):
                        observation_updates["findings"] = list(observations.get("findings", []) or [])
                    if isinstance(observations.get("urls", []), list) and observations.get("urls", []):
                        observation_updates["urls"] = list(observations.get("urls", []) or []) + list(urls or [])
                    if observation_updates:
                        upsert_target_state(database, int(host_id or 0), observation_updates, merge=True)
            except Exception:
                return

        def queue_approval(decision, host_ip, host_port, host_protocol, host_service, command_template):
            database = getattr(self.activeProject, "database", None)
            if database is None:
                return 0
            ensure_scheduler_approval_table(database)
            return int(queue_pending_approval(database, {
                "status": "pending",
                "host_ip": str(host_ip),
                "port": str(host_port),
                "protocol": str(host_protocol),
                "service": str(host_service),
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_template": str(command_template or ""),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "risk_tags": ",".join(decision.risk_tags),
                "scheduler_mode": str(decision.mode),
                "goal_profile": str(decision.goal_profile),
                "engagement_preset": str(decision.engagement_preset),
                "rationale": str(decision.rationale),
                "policy_decision": str(decision.policy_decision),
                "policy_reason": str(decision.policy_reason),
                "risk_summary": str(decision.risk_summary),
                "safer_alternative": str(decision.safer_alternative),
                "family_policy_state": str(decision.family_policy_state),
                "evidence_refs": ",".join(str(item) for item in list(decision.linked_evidence_refs or []) if str(item).strip()),
                "decision_reason": "pending approval",
                "execution_job_id": "",
            }) or 0)

        def execute_batch(tasks, _max_concurrency):
            results = []
            project_paths = [
                getattr(self.activeProject.properties, "runningFolder", ""),
                getattr(self.activeProject.properties, "outputFolder", ""),
                os.getcwd(),
            ]

            def build_command(request):
                command_template = str(request.command_template or "")
                normalized_tool = str(request.tool_id or "").strip().lower()
                if normalized_tool == "banner":
                    command_template = AppSettings._ensure_banner_command(command_template)
                if normalized_tool == "nuclei-web":
                    command_template = AppSettings._ensure_nuclei_auto_scan(command_template)
                elif "nuclei" in normalized_tool or "nuclei" in str(command_template).lower():
                    command_template = AppSettings._ensure_nuclei_command(command_template, automatic_scan=False)
                if str(request.tool_id or "").strip().lower() == "web-content-discovery":
                    command_template = AppSettings._ensure_web_content_discovery_command(command_template)
                if "wapiti" in str(command_template).lower():
                    scheme = "https" if "https-wapiti" in normalized_tool else "http"
                    command_template = AppSettings._ensure_wapiti_command(command_template, scheme=scheme)
                command_template = AppSettings._canonicalize_web_target_placeholders(command_template)
                if "nmap" in str(command_template).lower():
                    command_template = AppSettings._ensure_nmap_stats_every(command_template)
                running_folder = self.activeProject.properties.runningFolder
                outputfile = os.path.join(
                    running_folder,
                    f"{getTimestamp()}-{request.tool_id}-{request.host_ip}-{request.port}",
                )
                outputfile = os.path.normpath(outputfile).replace("\\", "/")
                command, target_host = apply_preferred_target_placeholders(
                    command_template,
                    hostname=str(request.hostname or ""),
                    ip=str(request.host_ip),
                    port=str(request.port),
                    output=outputfile,
                    service_name=str(request.service_name or ""),
                )
                command = AppSettings._collapse_redundant_fallbacks(command)
                command = AppSettings._ensure_nmap_hostname_target_support(command, target_host)
                return command, outputfile

            def execute_local_command(*, request, rendered_command, outputfile, runner_type):
                started_at = getTimestamp(True)
                print(
                    f"[+] Running tool '{request.tool_id}' for "
                    f"{request.host_ip}:{request.port}/{request.protocol} via {runner_type}: {rendered_command}"
                )
                try:
                    result = subprocess.run(
                        rendered_command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=int(request.timeout or 300),
                        env=build_tool_execution_env(),
                    )
                    combined_output = "\n".join(
                        part for part in [
                            str(getattr(result, "stdout", "") or ""),
                            str(getattr(result, "stderr", "") or ""),
                        ]
                        if str(part or "").strip()
                    )
                    artifact_refs = [
                        path for path in sorted(set(glob.glob(f"{outputfile}*")))
                        if os.path.exists(path)
                    ]
                    observations = extract_tool_observations(
                        str(request.tool_id or ""),
                        combined_output,
                        port=str(request.port or ""),
                        protocol=str(request.protocol or "tcp"),
                        service=str(request.service_name or ""),
                        artifact_refs=artifact_refs,
                        host_ip=str(request.host_ip or ""),
                        hostname=str(request.hostname or ""),
                    )
                    print(f"[{request.tool_id} STDOUT]\n{result.stdout}")
                    if result.stderr:
                        print(f"[{request.tool_id} STDERR]\n{result.stderr}")
                    return RunnerExecutionResult(
                        executed=True,
                        reason=(
                            "completed"
                            if int(getattr(result, "returncode", 0) or 0) == 0 else
                            f"completed (exit {int(getattr(result, 'returncode', 0) or 0)})"
                        ),
                        runner_type=str(runner_type or "local"),
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                        artifact_refs=artifact_refs,
                        metadata={"observations": observations},
                    )
                except Exception as exc:
                    print(f"[!] Error running tool '{request.tool_id}' for {request.host_ip}:{request.port}: {exc}")
                    artifact_refs = [
                        path for path in sorted(set(glob.glob(f"{outputfile}*")))
                        if os.path.exists(path)
                    ]
                    return RunnerExecutionResult(
                        executed=False,
                        reason=f"error: {exc}",
                        runner_type=str(runner_type or "local"),
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                        artifact_refs=artifact_refs,
                    )

            def execute_browser_action(*, request, browser_settings, runner_type):
                started_at = getTimestamp(True)
                target_host = choose_preferred_screenshot_host(str(request.hostname or ""), str(request.host_ip or ""))
                url = f"{target_host}:{request.port}"
                if isHttps(target_host, request.port):
                    url = f"https://{url}"
                else:
                    url = f"http://{url}"
                try:
                    print(f"[+] Taking screenshot of {url} using EyeWitness...")
                    screenshots_dir = os.path.join(self.activeProject.properties.outputFolder, "screenshots")
                    os.makedirs(screenshots_dir, exist_ok=True)
                    capture = run_eyewitness_capture(
                        url=url,
                        output_parent_dir=screenshots_dir,
                        delay=int(browser_settings.get("delay", 5) or 5),
                        use_xvfb=bool(browser_settings.get("use_xvfb", True)),
                        timeout=int(browser_settings.get("timeout", 180) or 180),
                    )
                    if not capture.get("ok"):
                        reason = str(capture.get("reason", "") or "")
                        if reason == "eyewitness missing":
                            print("[!] EyeWitness executable was not found on this system.")
                            exit_status = "skipped: eyewitness missing"
                        else:
                            detail = summarize_eyewitness_failure(capture.get("attempts", []))
                            if detail:
                                print(f"[!] EyeWitness did not produce a screenshot: {detail}")
                            else:
                                print("[!] EyeWitness did not produce a screenshot PNG.")
                            exit_status = "skipped: screenshot png missing"
                        return RunnerExecutionResult(
                            executed=False,
                            reason=exit_status,
                            runner_type=str(runner_type or "browser"),
                            started_at=started_at,
                            finished_at=getTimestamp(True),
                        )

                    src_path = str(capture.get("screenshot_path", "") or "")
                    if not src_path or not os.path.isfile(src_path):
                        print("[!] EyeWitness reported success but screenshot file is missing.")
                        return RunnerExecutionResult(
                            executed=False,
                            reason="skipped: screenshot output missing",
                            runner_type=str(runner_type or "browser"),
                            started_at=started_at,
                            finished_at=getTimestamp(True),
                        )

                    deterministic_name = f"{request.host_ip}-{request.port}-screenshot.png"
                    deterministic_path = os.path.join(screenshots_dir, deterministic_name)
                    shutil.copy2(src_path, deterministic_path)
                    print(f"[screenshooter] Copied screenshot to {deterministic_path}")
                    exit_status = (
                        f"completed (eyewitness exited {capture.get('returncode')})"
                        if int(capture.get("returncode", 0) or 0) != 0 else
                        "completed"
                    )
                    return RunnerExecutionResult(
                        executed=True,
                        reason=exit_status,
                        runner_type=str(runner_type or "browser"),
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                        artifact_refs=[deterministic_path],
                    )
                except Exception as exc:
                    print(f"[!] Error taking screenshot for {request.host_ip}:{request.port}: {exc}")
                    return RunnerExecutionResult(
                        executed=False,
                        reason=f"error: {exc}",
                        runner_type=str(runner_type or "browser"),
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                    )

            for task in list(tasks or []):
                decision = task.decision
                request = RunnerExecutionRequest(
                    decision=decision,
                    tool_id=str(task.tool_id or ""),
                    command_template=str(task.command_template or ""),
                    host_ip=str(task.host_ip or ""),
                    hostname=str(task.hostname or ""),
                    port=str(task.port or ""),
                    protocol=str(task.protocol or "tcp"),
                    service_name=str(task.service_name or ""),
                    timeout=int(task.timeout or 300),
                    job_id=int(task.job_id or 0),
                    approval_id=int(task.approval_id or 0),
                    declared_runner_type=str(getattr(getattr(decision, "action", None), "runner_type", "local") or "local"),
                )
                runner_result = execute_runner_request(
                    request,
                    runner_preference=str(task.runner_preference or ""),
                    runner_settings=runner_settings,
                    allow_optional_runners=scheduler_config.is_feature_enabled("optional_runners"),
                    build_command=build_command,
                    execute_local_command=execute_local_command,
                    execute_browser_action=execute_browser_action,
                    mount_paths=project_paths,
                    workdir=os.getcwd(),
                )
                execution_record = ExecutionRecord.from_plan_step(
                    decision,
                    started_at=str(runner_result.started_at or getTimestamp(True)),
                    finished_at=str(runner_result.finished_at or getTimestamp(True)),
                    exit_status=str(runner_result.reason or ""),
                    runner_type=str(runner_result.runner_type or "local"),
                    stdout_ref=str(runner_result.stdout_ref or ""),
                    stderr_ref=str(runner_result.stderr_ref or ""),
                    artifact_refs=list(runner_result.artifact_refs or []),
                    approval_id=str(task.approval_id or ""),
                )
                results.append({
                    "decision": decision,
                    "tool_id": str(task.tool_id or ""),
                    "executed": bool(runner_result.executed),
                    "reason": str(runner_result.reason or ""),
                    "process_id": int(runner_result.process_id or 0),
                    "execution_record": execution_record,
                    "approval_id": int(task.approval_id or 0),
                    "metadata": dict(getattr(runner_result, "metadata", {}) or {}),
                })
            return results

        targets = scheduler_orchestrator.collect_project_targets(
            self.activeProject,
            allowed_states={"open"},
        )
        options = scheduler_orchestrator.build_run_options(
            scheduler_config.load(),
            enable_feedback=False,
            max_actions_per_round=0,
        )

        scheduler_orchestrator.run_targets(
            settings=settings,
            targets=targets,
            engagement_policy=engagement_policy,
            options=options,
            handle_blocked=lambda *, target, decision, command_template: (
                print(
                    f"[!] Skipping {decision.tool_id} for {target.host_ip}:{target.port}/{target.protocol} "
                    f"because policy blocked it: {decision.policy_reason or 'blocked by policy'}."
                ) or remember_target_state(
                    decision,
                    target.host_id,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    status="blocked",
                    reason=decision.policy_reason or "blocked by policy",
                ) or record(
                    decision,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    approved=False,
                    executed=False,
                    reason=decision.policy_reason or "blocked by policy",
                ) or SchedulerDecisionDisposition(
                    action="skipped",
                    reason=decision.policy_reason or "blocked by policy",
                )
            ),
            handle_approval=lambda *, target, decision, command_template: (
                (lambda approval_id: (
                    print(
                        f"[!] Queued approval #{approval_id} for {decision.tool_id} on "
                        f"{target.host_ip}:{target.port}/{target.protocol}."
                    ),
                    remember_target_state(
                        decision,
                        target.host_id,
                        target.host_ip,
                        target.port,
                        target.protocol,
                        target.service_name,
                        status="approval_queued",
                        reason=f"pending approval #{approval_id}",
                    ),
                    record(
                        decision,
                        target.host_ip,
                        target.port,
                        target.protocol,
                        target.service_name,
                        approved=False,
                        executed=False,
                        reason=f"pending approval #{approval_id}",
                        approval_id=approval_id,
                    ),
                    SchedulerDecisionDisposition(
                        action="queued",
                        reason=f"pending approval #{approval_id}",
                        approval_id=approval_id,
                    ),
                )[-1])(queue_approval(
                    decision,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    command_template,
                ))
            ),
            execute_batch=execute_batch,
            on_execution_result=lambda *, target, decision, result: (
                record(
                    decision,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    approved=True,
                    executed=bool(result.get("executed", False)),
                    reason=str(result.get("reason", "") or ""),
                    approval_id=str(result.get("approval_id", "") or ""),
                ),
                record_execution(
                    decision,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    started_at=str(getattr(result.get("execution_record"), "started_at", "") or ""),
                    finished_at=str(getattr(result.get("execution_record"), "finished_at", "") or ""),
                    exit_status=str(getattr(result.get("execution_record"), "exit_status", "") or result.get("reason", "")),
                    runner_type=str(getattr(result.get("execution_record"), "runner_type", "") or ""),
                    artifact_refs=list(getattr(result.get("execution_record"), "artifact_refs", []) or []),
                    approval_id=str(result.get("approval_id", "") or ""),
                ),
                remember_target_state(
                    decision,
                    target.host_id,
                    target.host_ip,
                    target.port,
                    target.protocol,
                    target.service_name,
                    status="executed" if bool(result.get("executed", False)) else "failed",
                    reason=str(result.get("reason", "") or ""),
                    artifact_refs=list(getattr(result.get("execution_record"), "artifact_refs", []) or []),
                    observations=(result.get("metadata", {}) if isinstance(result.get("metadata", {}), dict) else {}).get("observations"),
                ),
            ),
        )

    def createFolderForTool(self, tool):
        if 'nmap' in tool:
            tool = 'nmap'
        path = self.activeProject.properties.runningFolder + '/' + re.sub("[^0-9a-zA-Z]", "", str(tool))
        if not os.path.exists(path):
            os.makedirs(path)

    # this flag is matched to the conf file setting, so that we know if we need
    # to delete the found usernames/passwords wordlists on exit
    def setStoreWordlistsOnExit(self, flag=True):
        self.storeWordlists = flag

    def copyNmapXMLToOutputFolder(self, file):
        outputFolder = self.activeProject.properties.outputFolder
        try:
            path = getNmapOutputFolder(outputFolder)
            ntpath.basename(str(file))
            if not os.path.exists(path):
                os.makedirs(path)

            shutil.copy(str(file), path)  # will overwrite if file already exists
        except:
            log.info('Something went wrong copying the imported XML to the project folder.')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    def createNewTemporaryProject(self) -> None:
        self.activeProject = self.projectManager.createNewProject(projectType="legion", isTemp=True)

    def openExistingProject(self, filename, projectType="legion") -> None:
        self.activeProject = self.projectManager.openExistingProject(projectName=filename, projectType=projectType)

    def saveProjectAs(self, filename, replace=0, projectType='legion') -> bool:
        project = self.projectManager.saveProjectAs(self.activeProject, filename, replace, projectType)
        if project:
            self.activeProject = project
            return True
        return False
