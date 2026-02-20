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
import shutil

from app.ApplicationInfo import getConsoleLogo
from app.ProjectManager import ProjectManager
from app.logging.legionLog import getStartupLogger, getDbLogger, getAppLogger
from app.paths import ensure_legion_home, get_legion_backup_dir, get_legion_conf_path
from app.shell.DefaultShell import DefaultShell
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory
from app.tools.ToolCoordinator import ToolCoordinator
from app.logic import Logic
import os
import sys
import subprocess

startupLog = getStartupLogger()

def doPathSetup():
    import os
    ensure_legion_home()
    backup_dir = get_legion_backup_dir()
    conf_path = get_legion_conf_path()
    if not os.path.isdir(backup_dir):
        os.makedirs(backup_dir, exist_ok=True)

    if not os.path.exists(conf_path):
        shutil.copy('./legion.conf', conf_path)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Start Legion")
    parser.add_argument("--mcp-server", action="store_true", help="Start MCP server for AI integration")
    parser.add_argument("--headless", action="store_true", help="Run Legion in headless (CLI) mode")
    parser.add_argument("--web", action="store_true", help="Run Legion with the local Flask web interface")
    parser.add_argument("--web-port", type=int, default=5000, help="Local web interface port (localhost only)")
    parser.add_argument("--input-file", type=str, help="Text file with targets (hostnames, subnets, IPs, etc.)")
    parser.add_argument("--discovery", action="store_true", help="Enable host discovery (default: enabled)")
    parser.add_argument("--staged-scan", action="store_true", help="Enable staged scan")
    parser.add_argument("--output-file", type=str, help="Output file (.legion or .json)")
    parser.add_argument(
        "--run-actions",
        action="store_true",
        help="Run scripted actions/automated attacks after scan/import"
    )
    args = parser.parse_args()

    if args.mcp_server:
        # Start MCP server as a subprocess (separate stdio)
        mcp_proc = subprocess.Popen(
            [sys.executable, "app/mcpServer.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

    from colorama import init
    from termcolor import cprint
    init(strip=not sys.stdout.isatty())
    cprint(getConsoleLogo())

    doPathSetup()

    if args.web:
        from app.web import create_app
        from app.web.bootstrap import create_default_logic
        from app.web.runtime import WebRuntime

        startupLog.info("Starting Legion web interface on http://127.0.0.1:%s", args.web_port)
        logic = create_default_logic()
        runtime = WebRuntime(logic)
        web_app = create_app(runtime)
        web_app.run(host="127.0.0.1", port=args.web_port, debug=False, use_reloader=False)
        sys.exit(0)

    if args.headless:
        # --- HEADLESS CLI MODE ---
        from app.cli_utils import import_targets_from_textfile, run_nmap_scan
        from app.importers.NmapImporter import NmapImporter
        import time

        shell = DefaultShell()
        dbLog = getDbLogger()
        appLogger = getAppLogger()
        repositoryFactory = RepositoryFactory(dbLog)
        projectManager = ProjectManager(shell, repositoryFactory, appLogger)
        nmapExporter = DefaultNmapExporter(shell, appLogger)
        toolCoordinator = ToolCoordinator(shell, nmapExporter)
        logic = Logic(shell, projectManager, toolCoordinator)
        startupLog.info("Creating temporary project for headless mode...")
        logic.createNewTemporaryProject()

        # Import targets from input file
        if not args.input_file or not os.path.isfile(args.input_file):
            print("Error: --input-file is required and must exist in headless mode.", file=sys.stderr)
            sys.exit(1)
        session = logic.activeProject.database.session()
        hostRepository = logic.activeProject.repositoryContainer.hostRepository
        import_targets_from_textfile(session, hostRepository, args.input_file)

        # Run nmap scan if requested
        nmap_xml = None
        if args.staged_scan or args.discovery:
            # Build targets string for nmap (space-separated)
            targets = []
            with open(args.input_file, "r") as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        targets.append(t)
            targets_str = " ".join(targets)
            output_prefix = os.path.join(logic.activeProject.properties.runningFolder, f"cli-nmap-{int(time.time())}")
            nmap_xml = run_nmap_scan(
                targets_str,
                output_prefix,
                discovery=args.discovery,
                staged=args.staged_scan
            )
            # Import nmap XML results into the project
            nmapImporter = NmapImporter(None, hostRepository)
            nmapImporter.setDB(logic.activeProject.database)
            nmapImporter.setHostRepository(hostRepository)
            nmapImporter.setFilename(nmap_xml)
            nmapImporter.setOutput("")
            nmapImporter.run()

        # Run scripted actions/automated attacks if requested
        if args.run_actions:
            # Placeholder: will call logic.run_scripted_actions() after implementation
            print("Running scripted actions/automated attacks (CLI)...")
            logic.run_scripted_actions()

        # Export results
        if args.output_file:
            if args.output_file.endswith(".json"):
                # Export directly from the current activeProject (no temp .legion file)
                import json
                import base64
                hostRepository = logic.activeProject.repositoryContainer.hostRepository
                hosts = hostRepository.getAllHostObjs()
                hosts_data = []
                for host in hosts:
                    host_dict = host.__dict__.copy()
                    host_dict.pop('_sa_instance_state', None)
                    # Ports/services for this host
                    try:
                        ports = logic.activeProject.repositoryContainer.portRepository.getPortsByHostId(host.id)
                    except Exception:
                        ports = []
                    ports_data = []
                    for port in ports:
                        port_dict = port.__dict__.copy()
                        port_dict.pop('_sa_instance_state', None)
                        # Service for this port
                        try:
                            service = (
                                logic.activeProject.repositoryContainer.serviceRepository.getServiceById(port.serviceId)
                                if hasattr(port, 'serviceId') and port.serviceId
                                else None
                            )
                        except Exception:
                            service = None
                        if service:
                            service_dict = service.__dict__.copy()
                            service_dict.pop('_sa_instance_state', None)
                            port_dict['service'] = service_dict
                        # Scripts for this port
                        try:
                            scripts = (
                                logic.activeProject.repositoryContainer.scriptRepository.getScriptsByPortId(port.id)
                                if hasattr(logic.activeProject.repositoryContainer, 'scriptRepository')
                                else []
                            )
                        except Exception:
                            scripts = []
                        scripts_data = []
                        for script in scripts:
                            script_dict = script.__dict__.copy()
                            script_dict.pop('_sa_instance_state', None)
                            scripts_data.append(script_dict)
                        port_dict['scripts'] = scripts_data
                        ports_data.append(port_dict)
                    host_dict['ports'] = ports_data
                    # Notes for this host
                    try:
                        note = logic.activeProject.repositoryContainer.noteRepository.getNoteByHostId(host.id)
                        host_dict['note'] = note.text if note else ""
                    except Exception:
                        host_dict['note'] = ""
                    # CVEs for this host
                    try:
                        cves = logic.activeProject.repositoryContainer.cveRepository.getCVEsByHostIP(host.ip)
                    except Exception:
                        cves = []
                    cves_data = []
                    for cve in cves:
                        cve_dict = cve.__dict__.copy()
                        cve_dict.pop('_sa_instance_state', None)
                        cves_data.append(cve_dict)
                    host_dict['cves'] = cves_data
                    hosts_data.append(host_dict)
                # Gather screenshots
                screenshots_dir = os.path.join(logic.activeProject.properties.outputFolder, "screenshots")
                screenshots_data = {}
                if os.path.isdir(screenshots_dir):
                    for fname in os.listdir(screenshots_dir):
                        if fname.lower().endswith(".png"):
                            fpath = os.path.join(screenshots_dir, fname)
                            try:
                                with open(fpath, "rb") as f:
                                    b64 = base64.b64encode(f.read()).decode("utf-8")
                                screenshots_data[fname] = b64
                            except Exception as e:
                                screenshots_data[fname] = f"ERROR: {e}"
                export = {
                    "hosts": hosts_data,
                    "screenshots": screenshots_data
                }
                with open(args.output_file, "w", encoding="utf-8") as f:
                    json.dump(export, f, indent=2)
                print(f"Exported results as JSON to {args.output_file}")
            elif args.output_file.endswith(".legion"):
                # Save project as .legion file
                projectManager.saveProjectAs(logic.activeProject, args.output_file, replace=1, projectType="legion")
                print(f"Exported project as .legion to {args.output_file}")
            else:
                print("Error: --output-file must end with .json or .legion", file=sys.stderr)
                sys.exit(1)
        else:
            print("No --output-file specified, skipping export.")

        print("Headless Legion run complete.")
        sys.exit(0)

    # --- GUI MODE ---
    from ui.eventfilter import MyEventFilter
    from ui.ViewState import ViewState
    from ui.gui import *
    from ui.gui import Ui_MainWindow
    import qasync
    import asyncio

    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    MainWindow = QtWidgets.QMainWindow()
    Screen = QGuiApplication.primaryScreen()
    app.setWindowIcon(QIcon('./images/icons/Legion-N_128x128.svg'))
    app.setStyleSheet("* { font-family: \"monospace\"; font-size: 10pt; }")

    from ui.view import *
    from controller.controller import *

    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)

    # Platform-independent privilege check
    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            startupLog.error("Legion must run as root for raw socket access. Please start legion using sudo.")
            notice = QMessageBox()
            notice.setIcon(QMessageBox.Icon.Critical)
            notice.setText("Legion must run as root for raw socket access. Please start legion using sudo.")
            notice.exec()
            exit(1)
    elif os.name == "nt":
        # On Windows, warn but do not exit
        startupLog.warning("Legion may require Administrator privileges for some features on Windows.")
        notice = QMessageBox()
        notice.setIcon(QMessageBox.Icon.Warning)
        notice.setText("Legion may require Administrator privileges for some features on Windows.")
        notice.exec()


    shell = DefaultShell()
    dbLog = getDbLogger()
    appLogger = getAppLogger()
    repositoryFactory = RepositoryFactory(dbLog)
    projectManager = ProjectManager(shell, repositoryFactory, appLogger)
    nmapExporter = DefaultNmapExporter(shell, appLogger)
    toolCoordinator = ToolCoordinator(shell, nmapExporter)
    logic = Logic(shell, projectManager, toolCoordinator)

    startupLog.info("Creating temporary project at application start...")
    logic.createNewTemporaryProject()

    viewState = ViewState()
    view = View(viewState, ui, MainWindow, shell, app, loop)  # View prep (gui)
    controller = Controller(view, logic)  # Controller prep (communication between model and view)

    myFilter = MyEventFilter(view, MainWindow)  # to capture events
    app.installEventFilter(myFilter)

    # Center the application in screen
    screenCenter = Screen.availableGeometry().center()
    MainWindow.move(screenCenter - MainWindow.rect().center())

    import signal

    def graceful_shutdown(*args):
        startupLog.info("Graceful shutdown initiated.")
        try:
            # Attempt to stop QThreads (e.g., Screenshooter)
            if hasattr(controller, "screenshooter") and controller.screenshooter.isRunning():
                controller.screenshooter.quit()
                controller.screenshooter.wait(3000)
        except Exception as e:
            startupLog.error(f"Error during QThread shutdown: {e}")
        try:
            loop.stop()
        except Exception:
            pass
        try:
            app.quit()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    startupLog.info("Legion started successfully.")
    try:
        sys.exit(loop.run_forever())
    except KeyboardInterrupt:
        graceful_shutdown()
