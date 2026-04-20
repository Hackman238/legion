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
import os
import re
import shutil
import subprocess
import sys
import logging
from typing import Optional

MIN_SUPPORTED_PYTHON = (3, 12)

# Python 3.12's logging task-name capture uses asyncio.current_task().
# In this environment that segfaults after sqlalchemy/greenlet imports,
# so disable it before importing Legion modules.
if hasattr(logging, "logAsyncioTasks"):
    logging.logAsyncioTasks = False


def _coerce_python_version_tuple(version_info=None):
    info = version_info if version_info is not None else sys.version_info
    major = getattr(info, "major", None)
    minor = getattr(info, "minor", None)
    micro = getattr(info, "micro", None)
    if major is None:
        try:
            major = int(info[0])
        except Exception:
            major = 0
    if minor is None:
        try:
            minor = int(info[1])
        except Exception:
            minor = 0
    if micro is None:
        try:
            micro = int(info[2])
        except Exception:
            micro = 0
    return int(major), int(minor), int(micro)


def is_supported_python_runtime(version_info=None):
    major, minor, _micro = _coerce_python_version_tuple(version_info)
    return (major, minor) >= tuple(MIN_SUPPORTED_PYTHON)


def is_virtualenv_runtime(prefix=None, base_prefix=None, real_prefix=None):
    resolved_prefix = str(prefix if prefix is not None else getattr(sys, "prefix", ""))
    resolved_base_prefix = str(base_prefix if base_prefix is not None else getattr(sys, "base_prefix", resolved_prefix))
    resolved_real_prefix = str(real_prefix if real_prefix is not None else getattr(sys, "real_prefix", ""))
    return bool(resolved_real_prefix) or resolved_prefix != resolved_base_prefix


def format_python_runtime_error(version_info=None, executable=None, prefix=None, base_prefix=None, real_prefix=None):
    major, minor, micro = _coerce_python_version_tuple(version_info)
    resolved_executable = str(executable if executable is not None else getattr(sys, "executable", "python")).strip() or "python"
    runtime_scope = "virtualenv" if is_virtualenv_runtime(prefix=prefix, base_prefix=base_prefix, real_prefix=real_prefix) else "system interpreter"
    required_version = ".".join(str(part) for part in MIN_SUPPORTED_PYTHON)
    current_version = f"{major}.{minor}.{micro}"
    return (
        f"Legion requires Python {required_version}+.\n"
        f"Current interpreter: {resolved_executable} ({current_version}, {runtime_scope}).\n"
        "Recreate or activate a compatible environment first, for example:\n"
        "  python3.12 -m venv .venv\n"
        "  source .venv/bin/activate\n"
        "  python legion.py --web"
    )


def ensure_supported_python_runtime(version_info=None, executable=None, prefix=None, base_prefix=None, real_prefix=None, stderr=None):
    if is_supported_python_runtime(version_info):
        return
    stream = stderr if stderr is not None else sys.stderr
    print(
        format_python_runtime_error(
            version_info=version_info,
            executable=executable,
            prefix=prefix,
            base_prefix=base_prefix,
            real_prefix=real_prefix,
        ),
        file=stream,
    )
    raise SystemExit(1)


def _distribution_version(distribution_name: str) -> str:
    try:
        from importlib import metadata as importlib_metadata
    except Exception:
        return ""
    try:
        return str(importlib_metadata.version(str(distribution_name or "").strip()))
    except Exception:
        return ""


def _module_origin(module_name: str) -> str:
    try:
        import importlib.util
        spec = importlib.util.find_spec(str(module_name or "").strip())
    except Exception:
        return ""
    if spec is None:
        return ""
    return str(getattr(spec, "origin", "") or "")


def _coerce_distribution_version_tuple(version_text: str):
    parts = [int(item) for item in re.findall(r"\d+", str(version_text or ""))]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def has_known_flask_werkzeug_mismatch(flask_version: str = "", werkzeug_version: str = "") -> bool:
    if not str(flask_version or "").strip() or not str(werkzeug_version or "").strip():
        return False
    return _coerce_distribution_version_tuple(flask_version) < (2, 3, 0) and _coerce_distribution_version_tuple(werkzeug_version) >= (3, 0, 0)


def _find_local_venv_python() -> str:
    for rel_path in ("venv/bin/python", ".venv/bin/python"):
        abs_path = os.path.abspath(rel_path)
        if os.path.isfile(abs_path) and os.access(abs_path, os.X_OK):
            return abs_path
    return ""


def format_web_dependency_environment_error(
        *,
        executable: Optional[str] = None,
        flask_version: str = "",
        flask_origin: str = "",
        werkzeug_version: str = "",
        werkzeug_origin: str = "",
) -> str:
    resolved_executable = str(executable if executable is not None else getattr(sys, "executable", "python")).strip() or "python"
    local_venv_python = _find_local_venv_python()
    lines = [
        "Legion detected an incompatible Flask/Werkzeug environment for web mode.",
        f"Interpreter: {resolved_executable}",
        f"Flask: {str(flask_version or 'unknown').strip() or 'unknown'} from {str(flask_origin or 'not found').strip() or 'not found'}",
        f"Werkzeug: {str(werkzeug_version or 'unknown').strip() or 'unknown'} from {str(werkzeug_origin or 'not found').strip() or 'not found'}",
        "This usually means the system interpreter is mixing distro packages with pip-installed packages instead of using Legion's virtualenv.",
    ]
    if local_venv_python:
        lines.extend([
            "Use Legion's local virtualenv instead:",
            f"  {local_venv_python} legion.py --web",
            "or:",
            f"  source {os.path.dirname(local_venv_python)}/activate",
            "  python legion.py --web",
        ])
    else:
        lines.extend([
            "Create a clean Python 3.12 virtualenv and reinstall requirements:",
            "  python3.12 -m venv venv",
            "  source venv/bin/activate",
            "  python -m pip install --upgrade pip",
            "  python -m pip install -r requirements.txt",
            "  python legion.py --web",
        ])
    return "\n".join(lines)


def ensure_web_dependency_compatibility(
        *,
        executable: Optional[str] = None,
        flask_version: Optional[str] = None,
        flask_origin: Optional[str] = None,
        werkzeug_version: Optional[str] = None,
        werkzeug_origin: Optional[str] = None,
        stderr=None,
):
    resolved_flask_version = str(flask_version) if flask_version is not None else _distribution_version("Flask")
    resolved_werkzeug_version = str(werkzeug_version) if werkzeug_version is not None else _distribution_version("Werkzeug")
    resolved_flask_origin = str(flask_origin) if flask_origin is not None else _module_origin("flask")
    resolved_werkzeug_origin = str(werkzeug_origin) if werkzeug_origin is not None else _module_origin("werkzeug")
    if not has_known_flask_werkzeug_mismatch(resolved_flask_version, resolved_werkzeug_version):
        return
    stream = stderr if stderr is not None else sys.stderr
    print(
        format_web_dependency_environment_error(
            executable=executable,
            flask_version=resolved_flask_version,
            flask_origin=resolved_flask_origin,
            werkzeug_version=resolved_werkzeug_version,
            werkzeug_origin=resolved_werkzeug_origin,
        ),
        file=stream,
    )
    raise SystemExit(1)

startupLog = None

def doPathSetup():
    from app.paths import ensure_legion_home, get_legion_backup_dir, get_legion_conf_path

    ensure_legion_home()
    backup_dir = get_legion_backup_dir()
    conf_path = get_legion_conf_path()
    if not os.path.isdir(backup_dir):
        os.makedirs(backup_dir, exist_ok=True)

    if not os.path.exists(conf_path):
        shutil.copy('./legion.conf', conf_path)


def build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(description="Start Legion")
    audit_group = parser.add_mutually_exclusive_group()
    parser.add_argument("--mcp-server", action="store_true", help="Start MCP server for AI integration")
    parser.add_argument("--headless", action="store_true", help="Run Legion in headless (CLI) mode")
    parser.add_argument("--web", action="store_true", help="Run Legion with the local Flask web interface")
    audit_group.add_argument("--tool-audit", action="store_true", help="Print a tool availability audit and exit")
    audit_group.add_argument(
        "--tool-install-plan",
        choices=("kali", "ubuntu"),
        help="Print the generated install script for missing tools on the selected platform and exit",
    )
    audit_group.add_argument(
        "--tool-install",
        choices=("kali", "ubuntu"),
        help="Run the generated install plan for missing tools on the selected platform and exit",
    )
    parser.add_argument("--web-port", type=int, default=5000, help="Local web interface port")
    parser.add_argument(
        "--web-bind-all",
        action="store_true",
        help="When used with --web, bind the web interface to 0.0.0.0 instead of 127.0.0.1",
    )
    parser.add_argument(
        "--web-transparent-ui",
        action="store_true",
        help="When used with --web, enable transparent UI effects",
    )
    parser.add_argument(
        "--web-opaque-ui",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--input-file", type=str, help="Text file with targets (hostnames, subnets, IPs, etc.)")
    parser.add_argument("--discovery", action="store_true", help="Enable host discovery (default: enabled)")
    parser.add_argument("--staged-scan", action="store_true", help="Enable staged scan")
    parser.add_argument("--output-file", type=str, help="Output file (.legion or .json)")
    parser.add_argument(
        "--run-actions",
        action="store_true",
        help="Run scripted actions/automated attacks after scan/import"
    )
    return parser


def resolve_web_bind_host(args) -> str:
    if bool(getattr(args, "web_bind_all", False)):
        return "0.0.0.0"
    return "127.0.0.1"


def describe_web_bind_host(host: str) -> str:
    host_value = str(host or "").strip()
    if host_value == "0.0.0.0":
        return "All interfaces"
    return "Localhost only"


def resolve_web_opaque_ui(args) -> bool:
    if bool(getattr(args, "web_transparent_ui", False)):
        return False
    return True

if __name__ == "__main__":
    ensure_supported_python_runtime()
    parser = build_arg_parser()
    args = parser.parse_args()

    from app.ApplicationInfo import getConsoleLogo
    from app.ProjectManager import ProjectManager
    from app.logging.legionLog import getStartupLogger, getDbLogger, getAppLogger
    from app.shell.DefaultShell import DefaultShell
    from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
    from db.RepositoryFactory import RepositoryFactory
    from app.tools.ToolCoordinator import ToolCoordinator
    from app.logic import Logic

    startupLog = getStartupLogger()

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

    if args.tool_audit:
        from app.settings import AppSettings, Settings
        from app.tooling import audit_legion_tools, format_tool_audit_report

        settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        print(format_tool_audit_report(entries), end="")
        sys.exit(0)

    if args.tool_install_plan or args.tool_install:
        from app.settings import AppSettings, Settings
        from app.tooling import (
            audit_legion_tools,
            build_tool_install_plan,
            execute_tool_install_plan,
        )

        settings = Settings(AppSettings())
        entries = audit_legion_tools(settings)
        selected_platform = str(args.tool_install_plan or args.tool_install or "kali")
        plan = build_tool_install_plan(entries, platform=selected_platform)

        if args.tool_install_plan:
            print(str(plan.get("script", "") or ""), end="")
            sys.exit(0)

        commands = list(plan.get("commands", []) or [])
        manual = list(plan.get("manual", []) or [])
        if commands:
            print(
                f"LEGION tool install plan for {selected_platform}: "
                f"{len(commands)} command{'s' if len(commands) != 1 else ''}"
                + (f", {len(manual)} manual follow-up item{'s' if len(manual) != 1 else ''}" if manual else ""),
                file=sys.stderr,
            )
            for item in commands:
                print(f"  -> {item.get('command', '')}", file=sys.stderr)
        else:
            print(f"No installable missing tools matched the selected scope for {selected_platform}.", file=sys.stderr)
            if manual:
                for item in manual:
                    print(f"  manual: {item.get('label', 'tool')} -> {item.get('hint', '')}", file=sys.stderr)
            sys.exit(0)

        try:
            result = execute_tool_install_plan(plan)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)

        print(str(result.get("message", "Tool installation finished.")), file=sys.stderr)
        sys.exit(0)

    if args.web:
        ensure_web_dependency_compatibility()
        from app.web import create_app
        from app.web.bootstrap import create_default_logic
        from app.web.runtime import WebRuntime

        web_bind_host = resolve_web_bind_host(args)
        startupLog.info("Starting Legion web interface on http://%s:%s", web_bind_host, args.web_port)
        logic = create_default_logic()
        runtime = WebRuntime(logic)
        web_app = create_app(runtime)
        web_app.config["LEGION_WEB_BIND_HOST"] = web_bind_host
        web_app.config["LEGION_WEB_BIND_LABEL"] = describe_web_bind_host(web_bind_host)
        web_app.config["LEGION_UI_OPAQUE"] = resolve_web_opaque_ui(args)
        web_app.run(host=web_bind_host, port=args.web_port, debug=False, use_reloader=False)
        sys.exit(0)

    if args.headless:
        # --- HEADLESS CLI MODE ---
        from app.cli_utils import import_targets_from_textfile, run_nmap_scan
        from app.importers.nmap_runner import import_nmap_xml_into_project
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
            import_nmap_xml_into_project(
                project=logic.activeProject,
                xml_path=nmap_xml,
                output="",
                update_progress_observable=None,
                host_repository=hostRepository,
            )

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
