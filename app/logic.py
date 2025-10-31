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
        import tempfile
        import shutil
        from app.settings import AppSettings, Settings
        from app.timing import getTimestamp
        from app.httputil.isHttps import isHttps

        print("[*] Running scripted actions/automated attacks (headless mode)...")
        settingsFile = AppSettings()
        settings = Settings(settingsFile)
        repo_container = self.activeProject.repositoryContainer

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
                port_num = str(getattr(port, "port", ""))
                protocol = getattr(port, "protocol", "tcp")
                state = getattr(port, "state", "")
                if state != "open":
                    continue
                # For each automated attack/tool
                for tool in settings.automatedAttacks:
                    tool_name = tool[0]
                    services = tool[1].split(",")
                    tool_protocol = tool[2] if len(tool) > 2 else "tcp"
                    # Check if this tool applies to this service/protocol
                    service = getattr(port, "service", None)
                    service_name = getattr(service, "name", "") if service else ""
                    if (service_name in services or "*" in services or not services[0]) and protocol == tool_protocol:
                        if tool_name == "screenshooter":
                            # Take screenshot using EyeWitness
                            try:
                                # Build URL
                                url = f"{ip}:{port_num}"
                                if isHttps(ip, port_num):
                                    url = f"https://{url}"
                                else:
                                    url = f"http://{url}"
                                print(f"[+] Taking screenshot of {url} using EyeWitness...")
                                # Determine EyeWitness path
                                eyewitness_path = (
                                    "/usr/bin/eyewitness"
                                    if shutil.which("eyewitness")
                                    else "/usr/local/bin/eyewitness"
                                )
                                if not os.path.isfile(eyewitness_path):
                                    print(f"[!] EyeWitness not found at {eyewitness_path}. Please install it.")
                                    continue
                                screenshots_dir = os.path.join(
                                    self.activeProject.properties.outputFolder, "screenshots"
                                )
                                os.makedirs(screenshots_dir, exist_ok=True)
                                tmpOutputfolder = tempfile.mkdtemp(dir=screenshots_dir)
                                command = (
                                    f"{eyewitness_path} --single {url} --no-prompt --web --delay 5 -d {tmpOutputfolder}"
                                )
                                print(f"[screenshooter CMD] {command}")
                                p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=180)
                                print(f"[screenshooter STDOUT]\n{p.stdout}")
                                if p.stderr:
                                    print(f"[screenshooter STDERR]\n{p.stderr}")
                                screens_dir = os.path.join(tmpOutputfolder, 'screens')
                                if not os.path.isdir(screens_dir):
                                    print(f"[!] EyeWitness did not create expected directory: {screens_dir}")
                                    continue
                                files = [f for f in os.listdir(screens_dir) if f.lower().endswith('.png')]
                                if not files:
                                    print(f"[!] No screenshot PNG found in {screens_dir}. EyeWitness may have failed.")
                                    continue
                                fileName = files[0]
                                deterministic_name = f"{ip}-{port_num}-screenshot.png"
                                deterministic_path = os.path.join(screenshots_dir, deterministic_name)
                                src_path = os.path.join(screens_dir, fileName)
                                shutil.copy2(src_path, deterministic_path)
                                print(f"[screenshooter] Copied screenshot to {deterministic_path}")
                            except Exception as e:
                                print(f"[!] Error taking screenshot for {ip}:{port_num}: {e}")
                        else:
                            # Find the corresponding portAction for this tool
                            for a in settings.portActions:
                                if tool_name == a[1]:
                                    # Build command
                                    command = str(a[2])
                                    command = command.replace("[IP]", ip).replace("[PORT]", port_num)
                                    # Output file
                                    runningFolder = self.activeProject.properties.runningFolder
                                    outputfile = os.path.join(
                                        runningFolder,
                                        f"{getTimestamp()}-{tool_name}-{ip}-{port_num}"
                                    )
                                    outputfile = os.path.normpath(outputfile).replace("\\", "/")
                                    command = command.replace("[OUTPUT]", outputfile)
                                    print(f"[+] Running tool '{tool_name}' for {ip}:{port_num}/{protocol}: {command}")
                                    try:
                                        result = subprocess.run(
                                            command,
                                            shell=True,
                                            capture_output=True,
                                            text=True,
                                            timeout=300,
                                        )
                                        print(f"[{tool_name} STDOUT]\n{result.stdout}")
                                        if result.stderr:
                                            print(f"[{tool_name} STDERR]\n{result.stderr}")
                                    except Exception as e:
                                        print(f"[!] Error running tool '{tool_name}' for {ip}:{port_num}: {e}")
                                    break

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
