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

"""

import signal  # for file operations, to kill processes, for regex, for subprocesses
import subprocess
import tempfile
import os
from PyQt6.QtCore import QTimer, QElapsedTimer, QVariant

from app.ApplicationInfo import applicationInfo
from app.Screenshooter import Screenshooter
from app.actions.updateProgress.UpdateProgressObservable import UpdateProgressObservable
from app.importers.NmapImporter import NmapImporter
from app.importers.PythonImporter import PythonImporter
from app.tools.nmap.NmapPaths import getNmapRunningFolder
from app.auxiliary import unixPath2Win, winPath2Unix, getPid, formatCommandQProcess, isWsl
from ui.observers.QtUpdateProgressObserver import QtUpdateProgressObserver
import os

try:
    import queue
except Exception:
    log.exception("Failed to import queue module")
    import Queue as queue
from app.logic import *
from app.settings import *
from db.entities.port import portObj

log = getAppLogger()

def normalize_path(path):
    """Normalize a path to use forward slashes, regardless of input."""
    return os.path.normpath(path).replace("\\", "/")

class Controller:

    # initialisations that will happen once - when the program is launched
    @timing
    def __init__(self, view, logic):
        self.logic = logic
        self.view = view
        self.view.setController(self)
        self.view.startOnce()
        self.view.startConnections()

        self.loadSettings()  # creation of context menu actions from settings file and set up of various settings
        updateProgressObservable = UpdateProgressObservable()

        self.initNmapImporter(updateProgressObservable)
        self.initPythonImporter()
        self.initScreenshooter()
        self.initBrowserOpener()
        self.start()                                                    # initialisations (globals, etc)
        self.initTimers()
        self.processTimers = {}
        self.processMeasurements = {}

    # initialisations that will happen everytime we create/open a project - can happen several times in the
    # program's lifetime
    def start(self, title='*untitled'):
        self.processes = []                    # to store all the processes we run (nmaps, niktos, etc)
        self.fastProcessQueue = queue.Queue()  # to manage fast processes (banner, snmpenum, etc)
        self.fastProcessesRunning = 0          # counts the number of fast processes currently running
        self.slowProcessesRunning = 0          # counts the number of slow processes currently running
        activeProject = self.logic.activeProject
        self.nmapImporter.setDB(activeProject.database)  # tell nmap importer which db to use
        self.nmapImporter.setHostRepository(activeProject.repositoryContainer.hostRepository)
        self.pythonImporter.setDB(activeProject.database)
        self.updateOutputFolder()                                       # tell screenshooter where the output folder is
        self.view.start(title)

    def initNmapImporter(self, updateProgressObservable: UpdateProgressObservable):
        self.nmapImporter = NmapImporter(updateProgressObservable,
                                         self.logic.activeProject.repositoryContainer.hostRepository)
        self.nmapImporter.done.connect(self.importFinished)
        self.nmapImporter.done.connect(self.view.updateInterface)
        self.nmapImporter.done.connect(self.view.updateToolsTableView)
        self.nmapImporter.done.connect(self.view.updateProcessesTableView)
        self.nmapImporter.schedule.connect(self.scheduler)              # run automated attacks
        self.nmapImporter.log.connect(self.view.ui.LogOutputTextView.append)
        # Connect progressUpdated signal to view's progress bar update slot
        self.nmapImporter.progressUpdated.connect(self.view.updateImportProgress)

    def initPythonImporter(self):
        self.pythonImporter = PythonImporter()
        self.pythonImporter.done.connect(self.importFinished)
        self.pythonImporter.done.connect(self.view.updateInterface)
        self.pythonImporter.done.connect(self.view.updateToolsTableView)
        self.pythonImporter.done.connect(self.view.updateProcessesTableView)
        self.pythonImporter.schedule.connect(self.scheduler)              # run automated attacks
        self.pythonImporter.log.connect(self.view.ui.LogOutputTextView.append)

    def initScreenshooter(self):
        # screenshot taker object (different thread)
        self.screenshooter = Screenshooter(self.settings.general_screenshooter_timeout)
        self.screenshooter.done.connect(self.screenshotFinished)
        self.screenshooter.log.connect(self.view.ui.LogOutputTextView.append)

    def initBrowserOpener(self):
        self.browser = BrowserOpener()                                  # browser opener object (different thread)
        self.browser.log.connect(self.view.ui.LogOutputTextView.append)

    # these timers are used to prevent from updating the UI several times within a short time period -
    # which freezes the UI
    def initTimers(self):
        self.updateUITimer = QTimer()
        self.updateUITimer.setSingleShot(True)

        self.updateUI2Timer = QTimer()
        self.updateUI2Timer.setSingleShot(True)

        self.processTableUiUpdateTimer = QTimer()
        self.processTableUiUpdateTimer.timeout.connect(self.view.updateProcessesTableView)
        self.processTableUiUpdateTimer.start(500) # Faster than this doesn't make anything smoother

    # this function fetches all the settings from the conf file. Among other things it populates the actions lists
    # that will be used in the context menus.
    def loadSettings(self):
        self.settingsFile = AppSettings()
        # load settings from conf file (create conf file first if necessary)
        self.settings = Settings(self.settingsFile)
        # save the original state so that we can know if something has changed when we exit LEGION
        self.originalSettings = Settings(self.settingsFile)
        self.logic.projectManager.setStoreWordListsOnExit(self.logic.activeProject,
            self.settings.brute_store_cleartext_passwords_on_exit == 'True')
        self.view.settingsWidget.setSettings(Settings(self.settingsFile))

    # call this function when clicking 'apply' in the settings menu (after validation)
    def applySettings(self, newSettings):
        self.settings = newSettings

    def cancelSettings(self):  # called when the user presses cancel in the Settings dialog
        # resets the dialog's settings to the current application settings to forget any changes made by the user
        self.view.settingsWidget.setSettings(self.settings)

    @timing
    def saveSettings(self, saveBackup = True):
        if not self.settings == self.originalSettings:
            log.info('Settings have been changed.')
            self.settingsFile.backupAndSave(self.settings, saveBackup)
        else:
            log.info('Settings have NOT been changed.')

    def getSettings(self):
        return self.settings

    #################### AUXILIARY ####################

    def getCWD(self):
        return self.logic.activeProject.properties.workingDirectory

    def getProjectName(self):
        return self.logic.activeProject.properties.projectName

    def getRunningFolder(self):
        return self.logic.activeProject.properties.runningFolder

    def getOutputFolder(self):
        return self.logic.activeProject.properties.outputFolder

    def getUserlistPath(self):
        return self.logic.activeProject.properties.usernamesWordList.filename

    def getPasslistPath(self):
        return self.logic.activeProject.properties.passwordWordList.filename

    def updateOutputFolder(self):
        self.screenshooter.updateOutputFolder(
            self.logic.activeProject.properties.outputFolder + '/screenshots')  # update screenshot folder

    def copyNmapXMLToOutputFolder(self, filename):
        self.logic.copyNmapXMLToOutputFolder(filename)

    def isTempProject(self):
        return self.logic.activeProject.properties.isTemporary

    def getDB(self):
        return self.logic.activeProject.database

    def getRunningProcesses(self):
        return self.processes

    def getHostActions(self):
        return self.settings.hostActions

    def getPortActions(self):
        return self.settings.portActions

    def getPortTerminalActions(self):
        return self.settings.portTerminalActions

    #################### ACTIONS ####################

    def createNewProject(self):
        self.view.closeProject()  # removes temp folder (if any)
        self.logic.createNewTemporaryProject()
        self.start()  # initialisations (globals, etc)

    def openExistingProject(self, filename, projectType='legion'):
        self.view.closeProject()
        self.logic.openExistingProject(filename, projectType)
        # initialisations (globals, signals, etc)
        self.start(os.path.basename(self.logic.activeProject.properties.projectName))
        self.view.restoreToolTabs() # restores the tool tabs for each host
        self.view.hostTableClick() # click on first host to restore his host tool tabs
        try:
            repo_container = getattr(self.logic.activeProject, "repositoryContainer", None)
            if repo_container and hasattr(repo_container, "processRepository"):
                repo_container.processRepository.resetDisplayStatusForOpenProcesses()
                self.view.refreshToolsTableModel()
                self.view.viewState.lazy_update_tools = True
        except Exception:
            log.exception("Failed to reset process display status when opening project")

    def saveProject(self, lastHostIdClicked, notes):
        if not lastHostIdClicked == '':
            self.logic.activeProject.repositoryContainer.noteRepository.storeNotes(lastHostIdClicked, notes)

    def saveProjectAs(self, filename, replace=0):
        success = self.logic.saveProjectAs(filename, replace)
        if success:
            self.nmapImporter.setDB(self.logic.activeProject.database) # tell nmap importer which db to use
        return success

    def closeProject(self):
        self.saveSettings() # backup and save config file, if necessary
        self.screenshooter.terminate()
        self.initScreenshooter()
        self.view.updateProcessesTableView() # clear process table
        self.logic.projectManager.closeProject(self.logic.activeProject)

    def copyToClipboard(self, data):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(data) # Assuming item.text() contains the IP or hostname

    @timing
    def addHosts(self, targetHosts, runHostDiscovery, runStagedNmap, nmapSpeed, scanMode,
                 nmapOptions=None, enableIPv6=False):
        if targetHosts == '':
            log.info('No hosts entered..')
            return

        if nmapOptions is None:
            nmapOptions = []
        else:
            nmapOptions = [opt for opt in nmapOptions if opt]

        # Normalize whitespace
        nmapOptions = [opt.strip() for opt in nmapOptions if opt.strip()]

        incompatible_prefixes = ('-f', '--randomize-hosts', '--data-length')
        if enableIPv6:
            filtered_options = []
            removed = []
            for opt in nmapOptions:
                lower = opt.lower()
                if lower.startswith(incompatible_prefixes):
                    removed.append(opt)
                    continue
                filtered_options.append(opt)
            if removed:
                log.info(f"Removing IPv6-incompatible nmap options: {', '.join(removed)}")
            nmapOptions = filtered_options

        import os
        runningFolder = normalize_path(self.logic.activeProject.properties.runningFolder)
        # Use the session directory for temp files
        session_path = getattr(self.logic.activeProject, "sessionFile", None)
        if session_path:
            session_dir = normalize_path(os.path.dirname(session_path))
        else:
            session_dir = runningFolder
        # Use the tool output directory directly, not a subdirectory
        tool_output_dir = session_dir
        ipv6_flag = enableIPv6

        if scanMode == 'Easy':
            if runStagedNmap:
                self.runStagedNmap(targetHosts, discovery=runHostDiscovery, enable_ipv6=ipv6_flag)
            elif runHostDiscovery:
                outputfile = normalize_path(os.path.join(tool_output_dir, f"{getTimestamp()}-host-discover"))
                easy_mode_flags = ['-f', '--data-length 5', '--randomize-hosts', '--max-retries 2']
                if ipv6_flag:
                    removed_easy = [flag for flag in easy_mode_flags if flag.startswith('-f') or flag.startswith('--randomize-hosts') or flag.startswith('--data-length')]
                    if removed_easy:
                        log.info(f"Removing IPv6-incompatible easy-mode options: {', '.join(removed_easy)}")
                    easy_mode_flags = [flag for flag in easy_mode_flags if flag not in removed_easy]

                command_tokens = ["nmap"]
                if ipv6_flag:
                    command_tokens.append("-6")
                command_tokens.extend(nmapOptions)
                command_tokens.extend(easy_mode_flags)
                command_tokens.extend([
                    "-sV", "-O", "--version-light", f"-T{str(nmapSpeed)}",
                    targetHosts, "--stats-every", "10s", "-oA", outputfile
                ])
                command = ' '.join(token for token in command_tokens if token)
                self.runCommand('nmap', 'nmap (discovery)', targetHosts, '', '', command, getTimestamp(True),
                                outputfile, self.view.createNewTabForHost(str(targetHosts), 'nmap (discovery)', True),
                                enable_ipv6=ipv6_flag)
            else:
                outputfile = normalize_path(os.path.join(tool_output_dir, f"{getTimestamp()}-nmap-list"))
                command_tokens = ["nmap"]
                if ipv6_flag:
                    command_tokens.append("-6")
                command_tokens.extend(nmapOptions)
                command_tokens.extend([
                    "-sL", f"-T{str(nmapSpeed)}", targetHosts, "--stats-every", "10s", "-oA", outputfile
                ])
                command = ' '.join(token for token in command_tokens if token)
                self.runCommand('nmap', 'nmap (list)', targetHosts, '', '', command, getTimestamp(True),
                                outputfile,
                                self.view.createNewTabForHost(str(targetHosts), 'nmap (list)', True),
                                enable_ipv6=ipv6_flag)
        elif scanMode == 'Hard':
            outputfile = normalize_path(os.path.join(tool_output_dir, f"{getTimestamp()}-nmap-custom"))
            options_tokens = list(nmapOptions)
            if not any('randomize' in opt.lower() for opt in options_tokens):
                options_tokens.append(f"-T{str(nmapSpeed)}")
            if ipv6_flag and not any(opt.strip().startswith('-6') for opt in options_tokens):
                options_tokens.insert(0, '-6')
            options_tokens = [opt for opt in options_tokens if opt]
            options_str = ' '.join(options_tokens).strip()
            command_tokens = ["nmap"]
            command_tokens.extend(options_tokens)
            command_tokens.extend([targetHosts, "--stats-every", "10s", "-oA", outputfile])
            command = ' '.join(token for token in command_tokens if token)
            display_label = options_str
            self.runCommand('nmap', 'nmap (custom ' + display_label + ')', targetHosts, '', '', command,
                            getTimestamp(True), outputfile,
                            self.view.createNewTabForHost(
                                str(targetHosts), 'nmap (custom ' + display_label + ')', True),
                            enable_ipv6=ipv6_flag)

    #################### CONTEXT MENUS ####################

    # showAll exists because in some cases we only want to show host tools excluding portscans and 'mark as checked'
    @timing
    def getContextMenuForHost(self, isChecked, showAll=True):
        menu = QMenu()
        self.nmapSubMenu = QMenu('Portscan')
        actions = []

        for a in self.settings.hostActions:
            if "nmap" in a[1] or "unicornscan" in a[1]:
                actions.append(self.nmapSubMenu.addAction(a[0]))
            else:
                actions.append(menu.addAction(a[0]))

        if showAll:
            actions.append(self.nmapSubMenu.addAction("Run nmap (staged)"))

            menu.addMenu(self.nmapSubMenu)
            menu.addSeparator()

            if isChecked == 'True':
                menu.addAction('Mark as unchecked')
            else:
                menu.addAction('Mark as checked')
            menu.addAction('Rescan')
            menu.addAction('Purge Results')
            menu.addAction('Delete')

        return menu, actions

    @timing
    def handleHostAction(self, ip, hostid, actions, action):
        repositoryContainer = self.logic.activeProject.repositoryContainer

        runningFolder = self.logic.activeProject.properties.runningFolder
        # Use the session directory for temp files
        session_path = getattr(self.logic.activeProject, "sessionFile", None)
        if session_path:
            session_dir = os.path.dirname(session_path)
        else:
            session_dir = runningFolder
        # Use the tool output directory directly, not a subdirectory
        tool_output_dir = session_dir

        if action.text() == 'Mark as checked' or action.text() == 'Mark as unchecked':
            repositoryContainer.hostRepository.toggleHostCheckStatus(ip)
            self.view.updateInterface()
            return

        if action.text() == 'Run nmap (staged)':
            # Do not purge previous portscan data; preserve previously discovered ports/services.
            log.info('Running nmap (staged) scan for ' + str(ip))
            self.runStagedNmap(ip, False)
            return

        if action.text() == 'Rescan':
            log.info(f'Rescanning host {str(ip)}')
            self.runStagedNmap(ip, False)
            return

        if action.text() == 'Purge Results':
            log.info(f'Purging previous portscan data for host {str(ip)}')
            if repositoryContainer.portRepository.getPortsByIPAndProtocol(ip, 'tcp'):
                repositoryContainer.portRepository.deleteAllPortsAndScriptsByHostId(hostid, 'tcp')
            if repositoryContainer.portRepository.getPortsByIPAndProtocol(ip, 'udp'):
                repositoryContainer.portRepository.deleteAllPortsAndScriptsByHostId(hostid, 'udp')
            self.view.updateInterface()
            return

        if action.text() == 'Delete':
            log.info('Purging previous portscan data for host {0}'.format(str(ip)))
            if repositoryContainer.portRepository.getPortsByIPAndProtocol(ip, 'tcp'):
                repositoryContainer.portRepository.deleteAllPortsAndScriptsByHostId(hostid, 'tcp')
            if repositoryContainer.portRepository.getPortsByIPAndProtocol(ip, 'udp'):
                repositoryContainer.portRepository.deleteAllPortsAndScriptsByHostId(hostid, 'udp')
            self.logic.activeProject.repositoryContainer.hostRepository.deleteHost(ip)
            self.view.updateInterface()
            return

        for i in range(0,len(actions)):
            if action == actions[i]:
                name = self.settings.hostActions[i][1]
                invisibleTab = False
                # to make sure different nmap scans appear under the same tool name
                if 'nmap' in name:
                    name = 'nmap'
                    invisibleTab = True
                elif 'python-script' in name:
                    invisibleTab = True
                
                outputfile = normalize_path(os.path.join(
                    tool_output_dir,
                    f"{getTimestamp()}-{re.sub('[^0-9a-zA-Z]', '', str(self.settings.hostActions[i][1]))}-{ip}"
                ))
                command = str(self.settings.hostActions[i][2])
                command = command.replace('[IP]', ip).replace('[OUTPUT]', outputfile)
                command = f"{command} -oA {outputfile}"

                tabTitle = self.settings.hostActions[i][1]
                self.runCommand(name, tabTitle, ip, '', '', command, getTimestamp(True), outputfile,
                                self.view.createNewTabForHost(ip, tabTitle, invisibleTab))
                break

    @timing
    def getContextMenuForServiceName(self, serviceName='*', menu=None):
        if menu == None:  # if no menu was given, create a new one
            menu = QMenu()

        if serviceName == '*' or serviceName in self.settings.general_web_services.split(","):
            menu.addAction("Open in browser")
            menu.addAction("Take screenshot")

        actions = []
        for a in self.settings.portActions:
            # if the service name exists in the portActions list show the command in the context menu
            if serviceName is None or serviceName == '*' or serviceName in a[3].split(",") or a[3] == '':
                # in actions list write the service and line number that corresponds to it in portActions
                actions.append([self.settings.portActions.index(a), menu.addAction(a[0])])

        # if the user pressed SHIFT+Right-click show full menu
        modifiers = QtWidgets.QApplication.keyboardModifiers()
        if modifiers == QtCore.Qt.KeyboardModifier.ShiftModifier:
            shiftPressed = True
        else:
            shiftPressed = False

        return menu, actions, shiftPressed

    @timing
    def handleServiceNameAction(self, targets, actions, action, restoring=True):

        if action.text() == 'Take screenshot':
            for ip in targets:
                url = ip[0] + ':' + ip[1]
                self.screenshooter.addToQueue(ip[0], ip[1], url)
            self.screenshooter.start()
            return

        elif action.text() == 'Open in browser':
            for ip in targets:
                url = ip[0]+':'+ip[1]
                self.browser.addToQueue(url)
            self.browser.start()
            return

        for i in range(0,len(actions)):
            if action == actions[i][1]:
                srvc_num = actions[i][0]
                for ip in targets:
                    tool = self.settings.portActions[srvc_num][1]
                    tabTitle = self.settings.portActions[srvc_num][1]+" ("+ip[1]+"/"+ip[2]+")"
                    import os
                    # Use the same tool_output_dir logic as runStagedNmap for manual tool runs
                    runningFolder = normalize_path(self.logic.activeProject.properties.runningFolder)
                    session_path = getattr(self.logic.activeProject, "sessionFile", None)
                    if session_path:
                        tool_output_dir = normalize_path(os.path.dirname(session_path))
                    else:
                        tool_output_dir = runningFolder
                    outputfile = normalize_path(os.path.join(
                        tool_output_dir,
                        f"{getTimestamp()}-{tool}-{ip[0]}-{ip[1]}"
                    ))

                    command = str(self.settings.portActions[srvc_num][2])
                    # Insert normalized outputfile into command
                    command = command.replace('[IP]', ip[0]).replace('[PORT]', ip[1]).replace('[OUTPUT]', outputfile)
                    if 'nmap' in command:
                        command = f"{command} -oA {outputfile}"

                    if 'nmap' in command and ip[2] == 'udp':
                        command = command.replace("-sV", "-sVU")

                    if 'nmap' in tabTitle:                              # we don't want to show nmap tabs
                        restoring = True
                    elif 'python-script' in tabTitle:                              # we don't want to show nmap tabs
                        restoring = True

                    self.runCommand(tool, tabTitle, ip[0], ip[1], ip[2], command, getTimestamp(True), outputfile,
                                    self.view.createNewTabForHost(ip[0], tabTitle, restoring))
                break

    @timing
    def getContextMenuForPort(self, serviceName='*'):

        menu = QMenu()

        modifiers = QtWidgets.QApplication.keyboardModifiers()  # if the user pressed SHIFT+Right-click show full menu
        if modifiers == QtCore.Qt.KeyboardModifier.ShiftModifier:
            serviceName='*'

        terminalActions = []  # custom terminal actions from settings file
        # if wildcard or the command is valid for this specific service or if the command is valid for all services
        for a in self.settings.portTerminalActions:
            if serviceName is None or serviceName == '*' or serviceName in a[3].split(",") or a[3] == '':
                terminalActions.append([self.settings.portTerminalActions.index(a), menu.addAction(a[0])])

        menu.addSeparator()
        menu.addAction("Send to Brute")
        # Add Take screenshot action for all ports
        menu.addAction("Take screenshot")
        menu.addSeparator()  # dummy is there because we don't need the third return value
        menu, actions, dummy = self.getContextMenuForServiceName(serviceName, menu)
        menu.addSeparator()
        menu.addAction("Run custom command")
        # Add Delete Port action
        # deletePortAction = menu.addAction("Delete Port")  # Unused variable removed

        return menu, actions, terminalActions

    @timing
    def handlePortAction(self, targets, *args):
        actions = args[0]
        terminalActions = args[1]
        action = args[2]
        restoring = args[3]

        if action.text() == 'Delete Port':
            # targets: list of [ip, port, protocol, serviceName]
            repo_container = self.logic.activeProject.repositoryContainer
            host_repo = repo_container.hostRepository
            port_repo = repo_container.portRepository
            for t in targets:
                ip, port, protocol, _ = t
                host = host_repo.getHostByIP(ip)
                if host:
                    # Attempt to delete the port by host id, port, and protocol
                    if hasattr(port_repo, "deletePortByHostIdAndPort"):
                        port_repo.deletePortByHostIdAndPort(host.id, port, protocol)
                    else:
                        # Fallback: try to find and delete the port manually
                        session = self.logic.activeProject.database.session()
                        port_obj = session.query(portObj).filter_by(
                            hostId=host.id, port=port, protocol=protocol
                        ).first()
                        if port_obj:
                            session.delete(port_obj)
                            session.commit()
            self.view.updateInterface()
            return

        if action.text() == 'Send to Brute':
            for ip in targets:
                # ip[0] is the IP, ip[1] is the port number and ip[3] is the service name
                self.view.createNewBruteTab(ip[0], ip[1], ip[3])
            return

        if action.text() == 'Take screenshot':
            for ip in targets:
                url = f"{ip[0]}:{ip[1]}"
                self.screenshooter.addToQueue(ip[0], ip[1], url)
            self.screenshooter.start()
            return

        if action.text() == 'Run custom command':
            log.info('custom command')
            return

        terminal = self.settings.general_default_terminal               # handle terminal actions
        for i in range(0,len(terminalActions)):
            if action == terminalActions[i][1]:
                srvc_num = terminalActions[i][0]
                for ip in targets:
                    command = str(self.settings.portTerminalActions[srvc_num][2])
                    command = command.replace('[IP]', ip[0]).replace('[PORT]', ip[1])
                    if "[term]" in command:
                        command = command.replace("[term]", "")
                        subprocess.Popen(terminal + " -e './scripts/exec-in-shell " + command + "'", shell=True)
                    else:
                        subprocess.Popen("bash -c \"" + command + "; exec bash\"", shell=True)
                return

        self.handleServiceNameAction(targets, actions, action, restoring)

    def getContextMenuForProcess(self):
        menu = QMenu()
        menu.addAction("Kill")
        menu.addAction("Clear")
        return menu

    # selectedProcesses is a list of tuples (pid, status, procId)
    def handleProcessAction(self, selectedProcesses, action):
        if action.text() == 'Kill':
            if self.view.killProcessConfirmation():
                for p in selectedProcesses:
                    if p[1] != "Running":
                        if p[1] == "Waiting":
                            if str(self.logic.activeProject.repositoryContainer.processRepository.getStatusByProcessId(
                                    p[2])) == 'Running':
                                self.killProcess(self.view.ProcessesTableModel.getProcessPidForId(p[2]), p[2])
                            self.logic.activeProject.repositoryContainer.processRepository.storeProcessCancelStatus(
                                str(p[2]))
                        else:
                            log.info("This process has already been terminated. Skipping.")
                    else:
                        self.killProcess(p[0], p[2])
                self.view.updateProcessesTableView()
            return

        if action.text() == 'Clear':  # hide all the processes that are not running
            self.logic.activeProject.repositoryContainer.processRepository.toggleProcessDisplayStatus()
            self.view.updateProcessesTableView()

    #################### LEFT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def isHostInDB(self, host):
        return self.logic.activeProject.repositoryContainer.hostRepository.exists(host)

    def getHostsFromDB(self, filters):
        return self.logic.activeProject.repositoryContainer.hostRepository.getHosts(filters)

    def getServiceNamesFromDB(self, filters):
        return self.logic.activeProject.repositoryContainer.serviceRepository.getServiceNames(filters)

    def getProcessStatusForDBId(self, dbId):
        return self.logic.activeProject.repositoryContainer.processRepository.getStatusByProcessId(dbId)

    def getPidForProcess(self, dbId):
        return self.logic.activeProject.repositoryContainer.processRepository.getPIDByProcessId(dbId)

    def storeCloseTabStatusInDB(self, pid):
        return self.logic.activeProject.repositoryContainer.processRepository.storeCloseStatus(pid)

    def getServiceNameForHostAndPort(self, hostIP, port):
        return self.logic.activeProject.repositoryContainer.serviceRepository.getServiceNamesByHostIPAndPort(hostIP,
                                                                                                             port)

    #################### RIGHT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def getPortsAndServicesForHostFromDB(self, hostIP, filters):
        return self.logic.activeProject.repositoryContainer.portRepository.getPortsAndServicesByHostIP(hostIP, filters)

    def getHostsAndPortsForServiceFromDB(self, serviceName, filters):
        return self.logic.activeProject.repositoryContainer.hostRepository.getHostsAndPortsByServiceName(serviceName,
                                                                                                         filters)

    def getHostInformation(self, hostIP):
        return self.logic.activeProject.repositoryContainer.hostRepository.getHostInformation(hostIP)

    def getPortStatesForHost(self, hostid):
        return self.logic.activeProject.repositoryContainer.portRepository.getPortStatesByHostId(hostid)

    def getScriptsFromDB(self, hostIP):
        return self.logic.activeProject.repositoryContainer.scriptRepository.getScriptsByHostIP(hostIP)

    def getCvesFromDB(self, hostIP):
        return self.logic.activeProject.repositoryContainer.cveRepository.getCVEsByHostIP(hostIP)

    def getScriptOutputFromDB(self, scriptDBId):
        return self.logic.activeProject.repositoryContainer.scriptRepository.getScriptOutputById(scriptDBId)

    def getNoteFromDB(self, hostid):
        return self.logic.activeProject.repositoryContainer.noteRepository.getNoteByHostId(hostid)

    def getHostsForTool(self, toolName, closed='False'):
        return self.logic.activeProject.repositoryContainer.processRepository.getHostsByToolName(toolName, closed)

    def exportAsJson(self, filename):
        import json
        import base64

        try:
            # Gather all hosts
            hosts = self.logic.activeProject.repositoryContainer.hostRepository.getAllHostObjs()
        except Exception as e:
            log.error(f"Failed to fetch hosts from DB: {e}")
            hosts = []

        hosts_data = []
        for host in hosts:
            try:
                host_dict = host.__dict__.copy()
                host_dict.pop('_sa_instance_state', None)
                # Ports/services for this host
                try:
                    ports = self.logic.activeProject.repositoryContainer.portRepository.getPortsByHostId(host.id)
                except Exception as e:
                    log.error(f"Failed to fetch ports for host {host.id}: {e}")
                    ports = []
                ports_data = []
                for port in ports:
                    try:
                        port_dict = port.__dict__.copy()
                        port_dict.pop('_sa_instance_state', None)
                        # Service for this port
                        try:
                            service_repo = self.logic.activeProject.repositoryContainer.serviceRepository
                            service = service_repo.getServiceById(port.serviceId) \
                                if hasattr(port, 'serviceId') and port.serviceId else None
                        except Exception as e:
                            log.error(f"Failed to fetch service for port {port.id}: {e}")
                            service = None
                        if service:
                            service_dict = service.__dict__.copy()
                            service_dict.pop('_sa_instance_state', None)
                            port_dict['service'] = service_dict
                        # Scripts for this port
                        try:
                            script_repo = self.logic.activeProject.repositoryContainer.scriptRepository
                            scripts = script_repo.getScriptsByPortId(port.id) \
                                if hasattr(self.logic.activeProject.repositoryContainer, 'scriptRepository') else []
                        except Exception as e:
                            log.error(f"Failed to fetch scripts for port {port.id}: {e}")
                            scripts = []
                        scripts_data = []
                        for script in scripts:
                            try:
                                script_dict = script.__dict__.copy()
                                script_dict.pop('_sa_instance_state', None)
                                scripts_data.append(script_dict)
                            except Exception as e:
                                log.error(f"Failed to process script for port {port.id}: {e}")
                        port_dict['scripts'] = scripts_data
                        ports_data.append(port_dict)
                    except Exception as e:
                        log.error(f"Failed to process port for host {host.id}: {e}")
                host_dict['ports'] = ports_data
                # Notes for this host
                try:
                    note = self.logic.activeProject.repositoryContainer.noteRepository.getNoteByHostId(host.id)
                    host_dict['note'] = note.text if note else ""
                except Exception as e:
                    log.error(f"Failed to fetch note for host {host.id}: {e}")
                    host_dict['note'] = ""
                # CVEs for this host
                try:
                    cves = self.logic.activeProject.repositoryContainer.cveRepository.getCVEsByHostIP(host.ip)
                except Exception as e:
                    log.error(f"Failed to fetch CVEs for host {host.ip}: {e}")
                    cves = []
                cves_data = []
                for cve in cves:
                    try:
                        if hasattr(cve, "__dict__"):
                            cve_dict = cve.__dict__.copy()
                            cve_dict.pop('_sa_instance_state', None)
                        else:
                            # Likely a Row object, convert to dict
                            cve_dict = dict(cve)
                        cves_data.append(cve_dict)
                    except Exception as e:
                        log.error(f"Failed to process CVE for host {host.ip}: {e}")
                host_dict['cves'] = cves_data
                hosts_data.append(host_dict)
            except Exception as e:
                log.error(f"Failed to process host {getattr(host, 'id', '?')}: {e}")

        # Gather screenshots
        screenshots_dir = os.path.join(self.logic.activeProject.properties.outputFolder, "screenshots")
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
                        log.error(f"Failed to read screenshot {fname}: {e}")
                        screenshots_data[fname] = f"ERROR: {e}"

        # Attach screenshots to ports if available
        for host in hosts_data:
            ip = host.get("ip")
            for port in host.get("ports", []):
                port_num = str(port.get("port"))
                screenshot_fname = f"{ip}-{port_num}-screenshot.png"
                if screenshot_fname in screenshots_data:
                    port["screenshot"] = screenshots_data[screenshot_fname]

        # Compose final export
        export = {
            "hosts": hosts_data,
            "screenshots": screenshots_data
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export, f, indent=2)
            log.info(f"Exported results as JSON to {filename}")
        except Exception as e:
            log.error(f"Failed to export JSON: {e}")

    #################### BOTTOM PANEL INTERFACE UPDATE FUNCTIONS ####################

    def getProcessesFromDB(self, filters, showProcesses='noNmap', sort='desc', ncol='id'):
        return self.logic.activeProject.repositoryContainer.processRepository.getProcesses(filters, showProcesses, sort,
                                                                                           ncol)

    def getProcessesForRestore(self):
        return self.logic.activeProject.repositoryContainer.processRepository.getProcessesForRestore()

    #################### PROCESSES ####################

    def checkProcessQueue(self):
        # New: User-configurable max concurrent scans (not just fast processes)
        max_concurrent_scans = getattr(self.settings, "general_max_concurrent_scans", 3)
        try:
            max_concurrent_scans = int(max_concurrent_scans)
        except Exception:
            max_concurrent_scans = 3

        log.debug(f'Queue maximum concurrent scans: {str(max_concurrent_scans)}')
        log.debug(f'Queue maximum concurrent processes: {str(self.settings.general_max_fast_processes)}')
        log.debug(f'Queue processes running: {str(self.fastProcessesRunning)}')
        log.debug(f'Queue processes waiting: {str(self.fastProcessQueue.qsize())}')

        # Count running nmap (or other scan) processes
        running_scans = sum(1 for p in self.processes if hasattr(p, "name") and "nmap" in str(p.name).lower())

        if not self.fastProcessQueue.empty():
            self.processTableUiUpdateTimer.start(1000)
            # Allow up to max_concurrent_scans nmap (or other scan) processes, and up to max_fast_processes for others
            while (self.fastProcessesRunning < int(self.settings.general_max_fast_processes) and
                   (running_scans < max_concurrent_scans or self.fastProcessQueue.empty())):
                if self.fastProcessQueue.empty():
                    break
                next_proc = self.fastProcessQueue.get()
                # If this is a scan, check scan concurrency
                is_scan = hasattr(next_proc, "name") and "nmap" in str(next_proc.name).lower()
                if is_scan and running_scans >= max_concurrent_scans:
                    # Put back and break
                    self.fastProcessQueue.put(next_proc)
                    break
                if not self.logic.activeProject.repositoryContainer.processRepository.isCancelledProcess(
                        str(next_proc.id)):
                    log.info('Running: ' + str(next_proc.command))
                    next_proc.display.clear()
                    self.processes.append(next_proc)
                    self.fastProcessesRunning += 1
                    if is_scan:
                        running_scans += 1
                    # Add Timeout
                    next_proc.waitForFinished(10)
                    formattedCommand = formatCommandQProcess(next_proc.command)
                    log.debug(f'Up next: {formattedCommand[0]}, {formattedCommand[1]}')
                    next_proc.start(formattedCommand[0], formattedCommand[1])
                    self.logic.activeProject.repositoryContainer.processRepository.storeProcessRunningStatus(
                        next_proc.id, getPid(next_proc))
                elif not self.fastProcessQueue.empty():
                    log.debug('Process was canceled, checking queue again..')
                    continue
        else:
            log.info("Halting process panel update timer as all processes are finished.")
            self.processTableUiUpdateTimer.stop()

    def cancelProcess(self, dbId):
        log.info('Canceling process: ' + str(dbId))
        self.logic.activeProject.repositoryContainer.processRepository.storeProcessCancelStatus(
            str(dbId))  # mark it as cancelled
        self.updateUITimer.stop()
        self.updateUITimer.start(1500)                                  # update the interface soon

    def killProcess(self, pid, dbId):
        log.info('Killing process: ' + str(pid))
        self.logic.activeProject.repositoryContainer.processRepository.storeProcessKillStatus(str(dbId))
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            log.info('This process has already been terminated.')
        except:
            log.info("Unexpected error:", sys.exc_info()[0])

    def killRunningProcesses(self):
        log.info('Killing running processes!')
        for p in self.processes:
            p.finished.disconnect()                 # experimental
            self.killProcess(int(getPid(p)), p.id)

    # this function creates a new process, runs the command and takes care of displaying the ouput. returns the PID
    # the last 3 parameters are only used when the command is a staged nmap
    def runCommand(self, *args, discovery=True, stage=0, stop=False, enable_ipv6=False):
        def handleProcStop(*vargs):
            updateElapsed.stop()
            self.processTimers[qProcess.id] = None
            procTime = timer.elapsed() / 1000
            qProcess.elapsed = procTime
            self.logic.activeProject.repositoryContainer.processRepository.storeProcessRunningElapsedTime(qProcess.id,
                                                                                                          procTime)

        def handleProcUpdate(*vargs):
            procTime = timer.elapsed() / 1000
            self.processMeasurements[getPid(qProcess)] = procTime

        name = args[0]
        tabTitle = args[1]
        hostIp = args[2]
        port = args[3]
        protocol = args[4]
        command = args[5]
        startTime = args[6]
        outputfile = args[7]
        textbox = args[8]
        timer = QElapsedTimer()
        updateElapsed = QTimer()

        if 'python-script' in name:
            log.info(f'Running python script {name}')
            # Determine which script to run and the argument
            import subprocess
            import shlex
            script_path = None
            arg = None
            output = ""
            if "macvendors" in name.lower():
                script_path = "scripts/python/macvendors.py"
                # Try to get MAC address from hostIp or port (hostIp is used for IP, but we need MAC)
                # Fallback: use hostIp as MAC if it looks like a MAC, else skip
                mac = hostIp if hostIp and ":" in hostIp else ""
                if not mac and hasattr(self, "view"):
                    # Try to get MAC from selected host in the UI
                    try:
                        selected_row = self.view.ui.HostsTableView.selectionModel().selectedRows()[0].row()
                        mac = self.view.HostsTableModel.getMacForRow(selected_row)
                    except Exception:
                        mac = ""
                arg = mac
            elif "shodan" in name.lower():
                script_path = "scripts/python/pyShodan.py"
                arg = hostIp
            if script_path and arg:
                try:
                    cmd = f"python3 {shlex.quote(script_path)} {shlex.quote(str(arg))}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    output = result.stdout + ("\n" + result.stderr if result.stderr else "")
                except Exception as e:
                    log.exception(f"Error running script: {script_path} with arg: {arg}")
                    output = f"Error running script: {e}"
            else:
                output = "No valid script or argument found."
            # Display output in the tab
            if textbox:
                textbox.setPlainText(output)
            return 0

        self.logic.createFolderForTool(name)
        qProcess = MyQProcess(name, tabTitle, hostIp, port, protocol, command, startTime, outputfile, textbox)
        qProcess.started.connect(timer.start)
        qProcess.finished.connect(handleProcStop)
        updateElapsed.timeout.connect(handleProcUpdate)

        processRepository = self.logic.activeProject.repositoryContainer.processRepository
        textbox.setProperty('dbId', str(processRepository.storeProcess(qProcess)))
        updateElapsed.start(1000)
        self.processTimers[qProcess.id] = updateElapsed
        self.processMeasurements[getPid(qProcess)] = 0

        log.info('Queuing: ' + str(command))
        self.fastProcessQueue.put(qProcess)

        self.checkProcessQueue()

        # update the processes table
        self.updateUITimer.stop()
        # while the process is running, when there's output to read, display it in the GUI
        self.updateUITimer.start(900)

        qProcess.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
        qProcess.readyReadStandardOutput.connect(lambda: qProcess.display.appendPlainText(
            str(qProcess.readAllStandardOutput().data().decode('ISO-8859-1'))))

        qProcess.sigHydra.connect(self.handleHydraFindings)
        qProcess.finished.connect(lambda: self.processFinished(qProcess))
        qProcess.errorOccurred.connect(lambda: self.processCrashed(qProcess))
        log.info(f"runCommand called for stage {str(stage)}")

        if stage > 0 and stage < 6:  # if this is a staged nmap, launch the next stage
            log.info(f"runCommand connected for stage {str(stage)}")
            nextStage = stage + 1
            qProcess.finished.connect(
                lambda host=str(hostIp), discovery_flag=discovery, next_stage=nextStage,
                       enable_ipv6_flag=enable_ipv6, process_id=qProcess.id:
                self.runStagedNmap(
                    host,
                    discovery=discovery_flag,
                    stage=next_stage,
                    stop=processRepository.isKilledProcess(str(process_id)),
                    enable_ipv6=enable_ipv6_flag
                )
            )

        return getPid(qProcess)  # return the pid so that we can kill the process if needed

    def runPython(self):
        textbox = self.view.createNewConsole("python")
        name = 'python'
        tabTitle = name
        hostIp = '127.0.0.1'
        port = '22'
        protocol = 'tcp'
        command = 'python3 --version'
        startTime = getTimestamp(True)
        outputfile = tempfile.NamedTemporaryFile(delete=False).name
        qProcess = MyQProcess(name, tabTitle, hostIp, port, protocol, command, startTime, outputfile, textbox)

        processRepository = self.logic.activeProject.repositoryContainer.processRepository
        textbox.setProperty('dbId', str(processRepository.storeProcess(qProcess)))

        log.info('Queuing: ' + str(command))
        self.fastProcessQueue.put(qProcess)

        self.checkProcessQueue()

        qProcess.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
        qProcess.readyReadStandardOutput.connect(lambda: qProcess.display.appendPlainText(
            str(qProcess.readAllStandardOutput().data().decode('ISO-8859-1'))))

        qProcess.sigHydra.connect(self.handleHydraFindings)
        qProcess.finished.connect(lambda: self.processFinished(qProcess))
        qProcess.error.connect(lambda: self.processCrashed(qProcess))

        return getPid(qProcess)

    # recursive function used to run nmap in different stages for quick results
    def runStagedNmap(self, targetHosts, discovery=True, stage=1, stop=False, enable_ipv6=False):
        import os
        log.info(f"runStagedNmap called for stage {str(stage)}")
        runningFolder = self.logic.activeProject.properties.runningFolder
        # Use the session directory for temp files
        session_path = getattr(self.logic.activeProject, "sessionFile", None)
        if session_path:
            session_dir = os.path.dirname(session_path)
        else:
            session_dir = runningFolder
        # Use the tool output directory directly, not a subdirectory
        tool_output_dir = session_dir
        if not stop:
            textbox = self.view.createNewTabForHost(str(targetHosts), 'nmap (stage ' + str(stage) + ')', True)
            outputfile = os.path.join(tool_output_dir, f"{getTimestamp()}-nmapstage{str(stage)}")

            if stage == 1:
                stageData = self.settings.tools_nmap_stage1_ports
            elif stage == 2:
                stageData = self.settings.tools_nmap_stage2_ports
            elif stage == 3:
                stageData = self.settings.tools_nmap_stage3_ports
            elif stage == 4:
                stageData = self.settings.tools_nmap_stage4_ports
            elif stage == 5:
                stageData = self.settings.tools_nmap_stage5_ports
            elif stage == 6:
                stageData = self.settings.tools_nmap_stage6_ports
            stageDataSplit = str(stageData).split('|')
            stageOp = stageDataSplit[0]
            stageOpValues = stageDataSplit[1]
            log.debug(f"Stage {str(stage)} stageOp {str(stageOp)}")
            log.debug(f"Stage {str(stage)} stageOpValues {str(stageOpValues)}")

            if stageOp == "" or stageOp == "NOOP" or stageOp == "SKIP":
                log.debug(f"Skipping stage {str(stage)} as stageOp is {str(stageOp)}")
                return

            if discovery:                                           # is it with/without host discovery?
                command = "nmap "
                if enable_ipv6:
                    command += "-6 "
                command += "-T4 -sV -sSU -O "
            else:
                command = "nmap "
                if enable_ipv6:
                    command += "-6 "
                command += "-Pn -sSU "

            if stageOp == 'PORTS':
                command += '-p ' + stageOpValues + ' -vvvv ' + targetHosts + ' -oA ' + outputfile
            elif stageOp == 'NSE':
                command = 'nmap '
                if enable_ipv6:
                    command += '-6 '
                command += '-sV --script=' + stageOpValues + ' -vvvv ' + targetHosts + ' --stats-every 10s -oA ' + outputfile

            log.debug(f"Stage {str(stage)} command: {str(command)}")

            self.runCommand('nmap', 'nmap (stage ' + str(stage) + ')', str(targetHosts), '', '', command,
                            getTimestamp(True), outputfile, textbox, discovery=discovery, stage=stage, stop=stop,
                            enable_ipv6=enable_ipv6)

    def importFinished(self):
        # if nmap import was the first action, we need to hide the overlay (note: we shouldn't need to do this
        # every time. this can be improved)
        self.view.displayAddHostsOverlay(False)
        # Ensure DB session is refreshed so new hosts are visible
        try:
            if hasattr(self.logic.activeProject, "database") and hasattr(self.logic.activeProject.database, "session"):
                session = self.logic.activeProject.database.session()
                session.expire_all()
        except Exception:
            log.exception(f"Failed to refresh DB session after import: error")
        # Ensure UI update is queued on main thread
        from PyQt6 import QtCore
        QtCore.QMetaObject.invokeMethod(self.view, "updateInterface", QtCore.Qt.ConnectionType.QueuedConnection)

    def screenshotFinished(self, ip, port, filename):
        log.info("---------------Screenshoot done. Args %s, %s, %s" % (str(ip), str(port), str(filename)))
        outputFolder = self.logic.activeProject.properties.outputFolder
        dbId = self.logic.activeProject.repositoryContainer.processRepository.storeScreenshot(str(ip), str(port),
                                                                                              str(filename))
        imageviewer = self.view.createNewTabForHost(ip, 'screenshot (' + port + '/tcp)', True, '',
                                                    str(outputFolder) + '/screenshots/' + str(filename))
        imageviewer.setProperty('dbId', QVariant(str(dbId)))
        # to make sure the screenshot tab appears when it is launched from the host services tab
        self.view.switchTabClick()
        #self.updateUITimer.stop()  # update the processes table
        #self.updateUITimer.start(900)

    def processCrashed(self, proc):
        processRepository = self.logic.activeProject.repositoryContainer.processRepository
        processRepository.storeProcessCrashStatus(str(proc.id))
        log.info(f'Process {proc.id} Crashed!')
        qProcessOutput = "\n\t" + str(proc.display.toPlainText()).replace('\n', '').replace("b'", "")
        # self.view.closeHostToolTab(self, index))
        self.view.findFinishedServiceTab(str(processRepository.getPIDByProcessId(str(proc.id))))
        log.info(f'Process {proc.id} Output: {qProcessOutput}')
        log.info(f'Process {proc.id} Crash Output: {proc.errorString()}')
        # --- User notification for scan crash ---
        from PyQt6.QtWidgets import QMessageBox
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Scan Crashed")
        msg.setText(
            f"Scan process '{proc.name}' crashed!\n\nCommand: {proc.command}\n\nError: {proc.errorString()}\n\n"
            "Check the log for more details."
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    # this function handles everything after a process ends
    # def processFinished(self, qProcess, crashed=False):
    def processFinished(self, qProcess):
        processRepository = self.logic.activeProject.repositoryContainer.processRepository
        try:
            if not processRepository.isKilledProcess(str(qProcess.id)):
                log.debug(
                    f'Process: {str(qProcess.id)}\n'
                    f'Command: {str(qProcess.command)}\n'
                    f'outputfile: {str(qProcess.outputfile)}'
                )
                if not qProcess.outputfile == '':
                    outputfile = winPath2Unix(qProcess.outputfile)
                    try:
                        self.logic.toolCoordinator.saveToolOutput(
                            self.logic.activeProject.properties.outputFolder, outputfile
                        )
                    except Exception:
                        log.exception(f"Error saving tool output: {outputfile}")
                    if 'nmap' in qProcess.command:
                        if qProcess.exitCode() == 0:
                            log.debug(f"qProcess.outputfile {str(outputfile)}")
                            log.debug(
                                f"self.logic.activeProject.properties.runningFolder "
                                f"{str(self.logic.activeProject.properties.runningFolder)}"
                            )
                            log.debug(
                                f"self.logic.activeProject.properties.outputFolder "
                                f"{str(self.logic.activeProject.properties.outputFolder)}"
                            )
                            newoutputfile = outputfile.replace(
                                self.logic.activeProject.properties.runningFolder,
                                self.logic.activeProject.properties.outputFolder
                            )
                            try:
                                self.nmapImporter.setFilename(str(newoutputfile) + '.xml')
                                self.nmapImporter.setOutput(str(qProcess.display.toPlainText()))
                                self.nmapImporter.start()
                            except Exception:
                                log.exception(f"Error starting nmapImporter for {newoutputfile}")
                    elif 'PythonScript' in qProcess.command:
                        pythonScript = str(qProcess.command).split(' ')[2]
                        print(f'PythonImporter running for script: {pythonScript}')
                        if qProcess.exitCode() == 0:
                            try:
                                self.pythonImporter.setOutput(str(qProcess.display.toPlainText()))
                                self.pythonImporter.setHostIp(str(qProcess.hostIp))
                                self.pythonImporter.setPythonScript(pythonScript)
                                self.pythonImporter.start()
                            except Exception:
                                log.exception(f"Error starting pythonImporter for {pythonScript}")
                log.info(f"Process {qProcess.id} is done!")

            try:
                processRepository.storeProcessOutput(str(qProcess.id), qProcess.display.toPlainText())
            except Exception:
                log.exception(f"Error storing process output for {qProcess.id}")

            try:
                self.view.refreshToolsTableModel()
                self.view.viewState.lazy_update_tools = True
            except Exception:
                log.exception("Failed to refresh tools table after process completion")

            if 'hydra' in qProcess.name:
                try:
                    self.view.findFinishedBruteTab(
                        str(processRepository.getPIDByProcessId(str(qProcess.id)))
                    )
                except Exception:
                    log.exception(f"Error updating brute tab for process {qProcess.id}")

            try:
                self.fastProcessesRunning -= 1
                self.checkProcessQueue()
                self.processes.remove(qProcess)
                self.updateUITimer.stop()
                self.updateUITimer.start(1000)
            except Exception:
                log.exception("Process Finished Cleanup Exception")
        except Exception:
            log.exception("Process Finished Exception")
            raise

    # when hydra finds valid credentials we need to save them and change the brute tab title to red
    def handleHydraFindings(self, bWidget, userlist, passlist):
        self.view.blinkBruteTab(bWidget)
        for username in userlist:
            self.logic.activeProject.properties.usernamesWordList.add(username)
        for password in passlist:
            self.logic.activeProject.properties.passwordWordList.add(password)

    # this function parses nmap's output looking for open ports to run automated attacks on
    def scheduler(self, parser, isNmapImport):
        try:
            if isNmapImport and self.settings.general_enable_scheduler_on_import == 'False':
                return
            if self.settings.general_enable_scheduler == 'True':
                log.info('Scheduler started!')

                for h in parser.getAllHosts():
                    try:
                        for p in h.all_ports():
                            try:
                                if p.state == 'open':
                                    s = p.getService()
                                    if not (s is None):
                                        self.runToolsFor(s.name, h.hostname, h.ip, p.portId, p.protocol)
                            except Exception as port_exc:
                                log.error(f"Scheduler error for port {getattr(p, 'portId', '?')}: {port_exc}")
                    except Exception as host_exc:
                        log.error(f"Scheduler error for host {getattr(h, 'ip', '?')}: {host_exc}")

                log.info('-----------------------------------------------')
            log.info('Scheduler ended!')
        except Exception as sched_exc:
            log.error(f"Scheduler encountered a fatal error: {sched_exc}")
            from PyQt6.QtWidgets import QMessageBox
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Scheduler Error")
            msg.setText(
                "An error occurred during scheduling of automated attacks.\n\n"
                f"Error: {sched_exc}\n\nCheck the log for more details."
            )
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()

    def findDuplicateTab(self, tabWidget, tabName):
        for i in range(tabWidget.count()):
            log.debug(f"Tab text for {str(i)}: {str(tabWidget.tabText(i))}")
            if tabWidget.tabText(i) == tabName:
                return True
        return False

    def runToolsFor(self, service, hostname, ip, port, protocol='tcp'):
        log.info('Running tools for: ' + service + ' on ' + ip + ':' + port)

        # Import here to avoid circular import issues
        import os

        if service.endswith("?"):  # when nmap is not sure it will append a ?, so we need to remove it
            service=service[:-1]

        # Get repositories for deduplication checks
        repo_container = self.logic.activeProject.repositoryContainer
        script_repo = getattr(repo_container, "scriptRepository", None)
        port_repo = getattr(repo_container, "portRepository", None)
        host_repo = getattr(repo_container, "hostRepository", None)

        for tool in self.settings.automatedAttacks:
            if service in tool[1].split(",") and protocol==tool[2]:
                if tool[0] == "screenshooter":
                    if hostname:
                        url = hostname+':'+port
                    else:
                        url = ip+':'+port
                    # Check if screenshot already exists using deterministic filename
                    screenshots_dir = os.path.join(self.logic.activeProject.properties.outputFolder, "screenshots")
                    deterministic_screenshot = f"{ip}-{port}-screenshot.png"
                    screenshot_exists = False
                    if os.path.isdir(screenshots_dir):
                        if deterministic_screenshot in os.listdir(screenshots_dir):
                            screenshot_exists = True
                    if screenshot_exists:
                        log.info(f"Skipping screenshot for {ip}:{port} (already exists)")
                    else:
                        log.info("Screenshooter of URL: %s" % str(url))
                        self.screenshooter.addToQueue(ip, port, url)
                        self.screenshooter.start()

                else:
                    for a in self.settings.portActions:
                        if tool[0] == a[1]:
                            tabTitle = a[1] + " (" + port + "/" + protocol + ")"
                            # Deduplication: check if script already ran for this host/port/tool
                            skip_script = False
                            if script_repo and port_repo and host_repo:
                                # Find host and port objects
                                db_host = host_repo.getHostByIP(ip)
                                db_port = None
                                if db_host:
                                    db_port = port_repo.getPortByHostIdAndPort(db_host.id, port, protocol)
                                if db_host and db_port:
                                    # l1ScriptObj: scriptId, portId, hostId
                                    existing_scripts = script_repo.getScriptsByPortId(db_port.id)
                                    for s in existing_scripts:
                                        if hasattr(s, "scriptId") and s.scriptId == a[1]:
                                            skip_script = True
                                            break
                            if skip_script:
                                log.info(f"Skipping script {a[1]} for {ip}:{port}/{protocol} (already exists)")
                                break
                            # Cheese
                            outputfile = os.path.join(
                                self.logic.activeProject.properties.runningFolder,
                                f"{getTimestamp()}-{a[1]}-{ip}-{port}"
                            )
                            outputfile = os.path.normpath(outputfile).replace("\\", "/")
                            command = str(a[2])
                            command = command.replace('[IP]', ip).replace('[PORT]', port)\
                                .replace('[OUTPUT]', outputfile)
                            log.debug(f"Running tool command: {str(command)}")

                            if self.findDuplicateTab(self.view.ui.ServicesTabWidget, tabTitle):
                                log.debug("Duplicate tab name. Tool might have already run.")
                                break
                            tab = self.view.ui.HostsTabWidget.tabText(self.view.ui.HostsTabWidget.currentIndex())
                            self.runCommand(tool[0], tabTitle, ip, port, protocol, command,
                                            getTimestamp(True),
                                            outputfile,
                                            self.view.createNewTabForHost(ip, tabTitle, not (tab == 'Hosts')))
                            break

    def addPortToHost(self, host_ip, port_data):
        """
        Manually add a port to an existing host.
        :param host_ip: IP address of the host (string)
        :param port_data: dict with keys 'port', 'state', 'protocol'
        """
        repo_container = self.logic.activeProject.repositoryContainer
        # Find host by IP using getHosts and filter
        filters = self.view.viewState.filters
        hosts = repo_container.hostRepository.getHosts(filters)
        host = None
        for h in hosts:
            if hasattr(h, "ip") and h.ip == host_ip:
                host = h
                break
        if not host:
            log.error(f"Host with IP {host_ip} not found.")
            return

        # Create and add the port
        try:
            port_id = str(port_data.get('port', '')).strip()
            protocol = port_data.get('protocol', '').strip()
            state = port_data.get('state', '').strip()
            host_id = host.id
            new_port = portObj(port_id, protocol, state, host_id)
            session = self.logic.activeProject.database.session()
            session.add(new_port)
            session.commit()
            log.info(f"Added port {port_id}/{protocol} ({state}) to host {host_ip}")
            self.view.updateInterface()
        except Exception as e:
            log.error(f"Failed to add port to host {host_ip}: {e}")
