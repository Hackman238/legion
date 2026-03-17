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
from app.screenshot_targets import apply_preferred_target_placeholders, choose_preferred_host
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
        from app.scheduler.policy import (
            ensure_scheduler_engagement_policy_table,
        )
        from app.timing import getTimestamp
        from app.httputil.isHttps import isHttps

        print("[*] Running scripted actions/automated attacks (headless mode)...")
        settingsFile = AppSettings()
        settings = Settings(settingsFile)
        repo_container = self.activeProject.repositoryContainer
        scheduler_config = SchedulerConfigManager()
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
            for task in list(tasks or []):
                decision = task.decision
                ip = str(task.host_ip or "")
                hostname = str(task.hostname or "")
                port_num = str(task.port or "")
                protocol = str(task.protocol or "tcp")
                service_name = str(task.service_name or "")

                if decision.tool_id == "screenshooter":
                    started_at = getTimestamp(True)
                    try:
                        target_host = choose_preferred_host(hostname, ip)
                        url = f"{target_host}:{port_num}"
                        if isHttps(target_host, port_num):
                            url = f"https://{url}"
                        else:
                            url = f"http://{url}"
                        print(f"[+] Taking screenshot of {url} using EyeWitness...")
                        screenshots_dir = os.path.join(self.activeProject.properties.outputFolder, "screenshots")
                        os.makedirs(screenshots_dir, exist_ok=True)
                        capture = run_eyewitness_capture(
                            url=url,
                            output_parent_dir=screenshots_dir,
                            delay=5,
                            use_xvfb=True,
                            timeout=180,
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
                            execution_record = ExecutionRecord.from_plan_step(
                                decision,
                                started_at=started_at,
                                finished_at=getTimestamp(True),
                                exit_status=exit_status,
                                approval_id=str(task.approval_id or ""),
                            )
                            results.append({
                                "decision": decision,
                                "tool_id": str(task.tool_id or ""),
                                "executed": False,
                                "reason": exit_status,
                                "process_id": 0,
                                "execution_record": execution_record,
                                "approval_id": int(task.approval_id or 0),
                            })
                            continue

                        src_path = str(capture.get("screenshot_path", "") or "")
                        if not src_path or not os.path.isfile(src_path):
                            print("[!] EyeWitness reported success but screenshot file is missing.")
                            exit_status = "skipped: screenshot output missing"
                            execution_record = ExecutionRecord.from_plan_step(
                                decision,
                                started_at=started_at,
                                finished_at=getTimestamp(True),
                                exit_status=exit_status,
                                approval_id=str(task.approval_id or ""),
                            )
                            results.append({
                                "decision": decision,
                                "tool_id": str(task.tool_id or ""),
                                "executed": False,
                                "reason": exit_status,
                                "process_id": 0,
                                "execution_record": execution_record,
                                "approval_id": int(task.approval_id or 0),
                            })
                            continue

                        deterministic_name = f"{ip}-{port_num}-screenshot.png"
                        deterministic_path = os.path.join(screenshots_dir, deterministic_name)
                        shutil.copy2(src_path, deterministic_path)
                        print(f"[screenshooter] Copied screenshot to {deterministic_path}")
                        exit_status = (
                            f"completed (eyewitness exited {capture.get('returncode')})"
                            if int(capture.get("returncode", 0) or 0) != 0 else
                            "completed"
                        )
                        execution_record = ExecutionRecord.from_plan_step(
                            decision,
                            started_at=started_at,
                            finished_at=getTimestamp(True),
                            exit_status=exit_status,
                            artifact_refs=[deterministic_path],
                            approval_id=str(task.approval_id or ""),
                        )
                        results.append({
                            "decision": decision,
                            "tool_id": str(task.tool_id or ""),
                            "executed": True,
                            "reason": "completed",
                            "process_id": 0,
                            "execution_record": execution_record,
                            "approval_id": int(task.approval_id or 0),
                        })
                    except Exception as exc:
                        print(f"[!] Error taking screenshot for {ip}:{port_num}: {exc}")
                        execution_record = ExecutionRecord.from_plan_step(
                            decision,
                            started_at=started_at,
                            finished_at=getTimestamp(True),
                            exit_status=f"error: {exc}",
                            approval_id=str(task.approval_id or ""),
                        )
                        results.append({
                            "decision": decision,
                            "tool_id": str(task.tool_id or ""),
                            "executed": False,
                            "reason": f"error: {exc}",
                            "process_id": 0,
                            "execution_record": execution_record,
                            "approval_id": int(task.approval_id or 0),
                        })
                    continue

                command_template = str(task.command_template or "")
                if str(decision.tool_id).strip().lower() == "nuclei-web":
                    command_template = AppSettings._ensure_nuclei_auto_scan(command_template)
                if str(decision.tool_id).strip().lower() == "web-content-discovery":
                    command_template = AppSettings._ensure_web_content_discovery_command(command_template)
                runningFolder = self.activeProject.properties.runningFolder
                outputfile = os.path.join(runningFolder, f"{getTimestamp()}-{decision.tool_id}-{ip}-{port_num}")
                outputfile = os.path.normpath(outputfile).replace("\\", "/")
                command, _target_host = apply_preferred_target_placeholders(
                    command_template,
                    hostname=str(hostname or ""),
                    ip=str(ip),
                    port=port_num,
                    output=outputfile,
                )
                print(f"[+] Running tool '{decision.tool_id}' for {ip}:{port_num}/{protocol}: {command}")
                started_at = getTimestamp(True)
                try:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=int(task.timeout or 300),
                    )
                    print(f"[{decision.tool_id} STDOUT]\n{result.stdout}")
                    if result.stderr:
                        print(f"[{decision.tool_id} STDERR]\n{result.stderr}")
                    artifact_refs = [
                        path for path in sorted(set(glob.glob(f"{outputfile}*")))
                        if os.path.exists(path)
                    ]
                    execution_record = ExecutionRecord.from_plan_step(
                        decision,
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                        exit_status=(
                            "completed"
                            if int(getattr(result, "returncode", 0) or 0) == 0 else
                            f"completed (exit {int(getattr(result, 'returncode', 0) or 0)})"
                        ),
                        artifact_refs=artifact_refs,
                        approval_id=str(task.approval_id or ""),
                    )
                    results.append({
                        "decision": decision,
                        "tool_id": str(task.tool_id or ""),
                        "executed": True,
                        "reason": "completed",
                        "process_id": 0,
                        "execution_record": execution_record,
                        "approval_id": int(task.approval_id or 0),
                    })
                except Exception as exc:
                    print(f"[!] Error running tool '{decision.tool_id}' for {ip}:{port_num}: {exc}")
                    artifact_refs = [
                        path for path in sorted(set(glob.glob(f"{outputfile}*")))
                        if os.path.exists(path)
                    ]
                    execution_record = ExecutionRecord.from_plan_step(
                        decision,
                        started_at=started_at,
                        finished_at=getTimestamp(True),
                        exit_status=f"error: {exc}",
                        artifact_refs=artifact_refs,
                        approval_id=str(task.approval_id or ""),
                    )
                    results.append({
                        "decision": decision,
                        "tool_id": str(task.tool_id or ""),
                        "executed": False,
                        "reason": f"error: {exc}",
                        "process_id": 0,
                        "execution_record": execution_record,
                        "approval_id": int(task.approval_id or 0),
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
                    artifact_refs=list(getattr(result.get("execution_record"), "artifact_refs", []) or []),
                    approval_id=str(result.get("approval_id", "") or ""),
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
