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

import ntpath
import shutil

from app.Project import Project
from app.eyewitness import run_eyewitness_capture, summarize_eyewitness_failure
from app.tools.ToolCoordinator import ToolCoordinator
from app.shell.Shell import Shell
from app.tools.nmap.NmapPaths import getNmapOutputFolder
from ui.ancillaryDialog import *

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
        import subprocess
        import os
        import shutil
        from app.settings import AppSettings, Settings
        from app.scheduler.audit import log_scheduler_decision
        from app.scheduler.config import SchedulerConfigManager
        from app.scheduler.planner import SchedulerPlanner
        from app.timing import getTimestamp
        from app.httputil.isHttps import isHttps

        print("[*] Running scripted actions/automated attacks (headless mode)...")
        settingsFile = AppSettings()
        settings = Settings(settingsFile)
        repo_container = self.activeProject.repositoryContainer
        service_repo = getattr(repo_container, "serviceRepository", None)
        scheduler_config = SchedulerConfigManager()
        scheduler_planner = SchedulerPlanner(scheduler_config)

        def record(decision, host_ip, host_port, host_protocol, host_service, approved, executed, reason):
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
                "tool_id": str(decision.tool_id),
                "label": str(decision.label),
                "command_family_id": str(decision.family_id),
                "danger_categories": ",".join(decision.danger_categories),
                "requires_approval": "True" if decision.requires_approval else "False",
                "approved": "True" if approved else "False",
                "executed": "True" if executed else "False",
                "reason": str(reason),
                "rationale": str(decision.rationale),
            })

        # For each host
        hosts = repo_container.hostRepository.getAllHostObjs()
        for host in hosts:
            ip = getattr(host, "ip", None)
            # hostname = getattr(host, "hostname", None)
            if not ip:
                continue
            # For each port
            try:
                ports = repo_container.portRepository.getPortsByHostId(host.id)
            except Exception:
                ports = []
            for port in ports:
                port_num = str(getattr(port, "portId", "") or "")
                if not port_num:
                    continue
                protocol = str(getattr(port, "protocol", "tcp") or "tcp").lower()
                state = getattr(port, "state", "")
                if state != "open":
                    continue
                service_name = ""
                service_id = getattr(port, "serviceId", None)
                if service_repo and service_id:
                    try:
                        service_obj = service_repo.getServiceById(service_id)
                        service_name = getattr(service_obj, "name", "") if service_obj else ""
                    except Exception:
                        service_name = ""
                if service_name.endswith("?"):
                    service_name = service_name[:-1]
                decisions = scheduler_planner.plan_actions(service_name, protocol, settings)
                for decision in decisions:
                    if decision.requires_approval:
                        print(
                            f"[!] Skipping {decision.tool_id} for {ip}:{port_num}/{protocol} "
                            f"because approval is required for family {decision.family_id}."
                        )
                        record(decision, ip, port_num, protocol, service_name, approved=False, executed=False,
                               reason="blocked: approval required in headless mode")
                        continue

                    if decision.tool_id == "screenshooter":
                        try:
                            url = f"{ip}:{port_num}"
                            if isHttps(ip, port_num):
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
                                    record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                                           reason="skipped: eyewitness missing")
                                    continue
                                detail = summarize_eyewitness_failure(capture.get("attempts", []))
                                if detail:
                                    print(f"[!] EyeWitness did not produce a screenshot: {detail}")
                                else:
                                    print("[!] EyeWitness did not produce a screenshot PNG.")
                                record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                                       reason="skipped: screenshot png missing")
                                continue

                            command = capture.get("command", [])
                            resolved_eyewitness = str(capture.get("executable", "") or "")
                            if command:
                                print(f"[screenshooter CMD] {' '.join(command)}")
                            stdout = str(capture.get("stdout", "") or "")
                            stderr = str(capture.get("stderr", "") or "")
                            if stdout:
                                print(f"[screenshooter STDOUT]\n{stdout}")
                            if stderr:
                                print(f"[screenshooter STDERR]\n{stderr}")

                            src_path = str(capture.get("screenshot_path", "") or "")
                            if not src_path or not os.path.isfile(src_path):
                                print("[!] EyeWitness reported success but screenshot file is missing.")
                                record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                                       reason="skipped: screenshot output missing")
                                continue

                            deterministic_name = f"{ip}-{port_num}-screenshot.png"
                            deterministic_path = os.path.join(screenshots_dir, deterministic_name)
                            shutil.copy2(src_path, deterministic_path)
                            print(f"[screenshooter] Copied screenshot to {deterministic_path}")
                            if int(capture.get("returncode", 0) or 0) != 0:
                                print(
                                    f"[!] EyeWitness command exited non-zero ({capture.get('returncode')}) "
                                    f"from {resolved_eyewitness}"
                                )
                            record(decision, ip, port_num, protocol, service_name, approved=True, executed=True,
                                   reason="completed")
                        except Exception as e:
                            print(f"[!] Error taking screenshot for {ip}:{port_num}: {e}")
                            record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                                   reason=f"error: {e}")
                        continue

                    matched_action = None
                    for action in settings.portActions:
                        if decision.tool_id == action[1]:
                            matched_action = action
                            break
                    if not matched_action:
                        record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                               reason="skipped: no matching action")
                        continue

                    command_template = decision.command_template or str(matched_action[2])
                    if str(decision.tool_id).strip().lower() == "nuclei-web":
                        command_template = AppSettings._ensure_nuclei_auto_scan(command_template)
                    if str(decision.tool_id).strip().lower() == "web-content-discovery":
                        command_template = AppSettings._ensure_web_content_discovery_command(command_template)
                    command = command_template.replace("[IP]", ip).replace("[PORT]", port_num)
                    runningFolder = self.activeProject.properties.runningFolder
                    outputfile = os.path.join(runningFolder, f"{getTimestamp()}-{decision.tool_id}-{ip}-{port_num}")
                    outputfile = os.path.normpath(outputfile).replace("\\", "/")
                    command = command.replace("[OUTPUT]", outputfile)
                    print(f"[+] Running tool '{decision.tool_id}' for {ip}:{port_num}/{protocol}: {command}")
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=300,
                        )
                        print(f"[{decision.tool_id} STDOUT]\n{result.stdout}")
                        if result.stderr:
                            print(f"[{decision.tool_id} STDERR]\n{result.stderr}")
                        record(decision, ip, port_num, protocol, service_name, approved=True, executed=True,
                               reason="completed")
                    except Exception as e:
                        print(f"[!] Error running tool '{decision.tool_id}' for {ip}:{port_num}: {e}")
                        record(decision, ip, port_num, protocol, service_name, approved=True, executed=False,
                               reason=f"error: {e}")

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
