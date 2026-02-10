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

import ntpath  # for file operations, to kill processes and for regex
import os
import shutil
from collections import OrderedDict
from collections.abc import Mapping

from app.ApplicationInfo import applicationInfo, getVersion
from app.timing import getTimestamp
from ui.ViewState import ViewState
from ui.dialogs import *
from ui.settingsDialog import *
from ui.configDialog import *
from ui.helpDialog import *
from ui.addHostDialog import *
from ui.AddPortDialog import AddPortDialog
from ui.ancillaryDialog import *
from ui.models.hostmodels import *
from ui.models.servicemodels import *
from ui.models.scriptmodels import *
from ui.models.cvemodels import *
from ui.models.processmodels import *
from ui.models.ostables import OsSummaryTableModel, OsHostsTableModel
from ui.models.credentialmodels import CredentialCaptureModel
from app.auxiliary import *
from six import u as unicode
import pandas as pd
from PyQt6.QtWidgets import QAbstractItemView
from PyQt6.QtCore import Qt

log = getAppLogger()

# this class handles everything gui-related
class View(QtCore.QObject):
    tick = QtCore.pyqtSignal(int, name="changed")                       # signal used to update the progress bar
    
    def __init__(self, viewState: ViewState, ui, ui_mainwindow, shell: Shell, app, loop):
        QtCore.QObject.__init__(self)
        self.ui = ui
        self.ui_mainwindow = ui_mainwindow  # TODO: retrieve window dimensions/location from settings
        self.app = app
        self.loop = loop
        # Guard against double-exit/double-close (Qt can emit multiple close signals during shutdown).
        self._app_exit_in_progress = False
        self._close_project_in_progress = False

        self.bottomWindowSize = 100
        self.leftPanelSize = 300

        self.ui.splitter_2.setSizes([250, self.bottomWindowSize])  # set better default size for bottom panel
        self.qss = None
        self.processesTableViewSort = 'desc'
        self.processesTableViewSortColumn = 'status'
        self.toolsTableViewSort = 'desc'
        self.toolsTableViewSortColumn = 'id'
        self.shell = shell
        self.viewState = viewState
        self._os_selection_model = None
        self.processStatusFilter = None
        self.responderWidgets = {}

    # the view needs access to controller methods to link gui actions with real actions
    def setController(self, controller):
        self.controller = controller

    def startOnce(self):
        # the number of fixed host tabs (services, scripts, information, notes)
        self.fixedTabsCount = self.ui.ServicesTabWidget.count()
        self.hostInfoWidget = HostInformationWidget(self.ui.InformationTab)
        self.filterdialog = FiltersDialog(self.ui.centralwidget)
        # Remove ProgressWidget dialog, use status bar progress instead
        self.importProgressBar = QtWidgets.QProgressBar()
        self.importProgressBar.setMinimum(0)
        self.importProgressBar.setMaximum(100)
        self.importProgressBar.setValue(0)
        self.importProgressBar.setVisible(False)
        self.cancelImportButton = QtWidgets.QPushButton("Cancel Import")
        self.cancelImportButton.setVisible(False)
        self.cancelImportButton.clicked.connect(self.cancelImportNmap)
        self.ui.statusbar.addPermanentWidget(self.importProgressBar)
        self.ui.statusbar.addPermanentWidget(self.cancelImportButton)
        self.importInProgress = False  # Track import state
        # Connect NmapImporter progressUpdated signal to UI slot
        if hasattr(self, "controller") and hasattr(self.controller, "nmapImporter"):
            self.controller.nmapImporter.progressUpdated.connect(self.updateImportProgress)
            self.controller.nmapImporter.done.connect(self.importFinished)
        self.adddialog = AddHostsDialog(self.ui.centralwidget)
        self.settingsWidget = AddSettingsDialog(self.shell, self.ui.centralwidget)
        self.helpDialog = HelpDialog(applicationInfo["name"], applicationInfo["author"], applicationInfo["copyright"],
                                     applicationInfo["links"], applicationInfo["emails"], applicationInfo["version"],
                                     applicationInfo["build"], applicationInfo["update"], applicationInfo["license"],
                                     applicationInfo["desc"], applicationInfo["smallIcon"], applicationInfo["bigIcon"],
                                     qss = self.qss, parent = self.ui.centralwidget)
        self.configDialog = ConfigDialog(controller = self.controller, qss = self.qss, parent = self.ui.centralwidget)

        self.ui.HostsTableView.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.ui.ServiceNamesTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.CvesTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.ToolsTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.ScriptsTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.ToolHostsTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.OsListTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.OsHostsTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ui.ResponderResultsTableView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.connectOsHostsClick()
        status_combo = self.ui.ProcessStatusFilterComboBox
        status_combo.setItemData(0, None)
        status_combo.setItemData(1, ["Waiting", "Running"])
        status_combo.setItemData(2, ["Finished"])
        status_combo.setItemData(3, ["Crashed", "Cancelled", "Killed", "Failed"])
        status_combo.setItemData(4, ["Waiting"])
        status_combo.setCurrentIndex(0)
        self.processStatusFilter = status_combo.currentData()

    # initialisations (globals, etc)
    def start(self, title='*untitled'):
        self.viewState = ViewState()
        self.ui.keywordTextInput.setText('')                            # clear keyword filter

        self.ProcessesTableModel = None  # fixes bug when sorting processes for the first time
        self.ToolsTableModel = None
        self.OsListTableModel = None
        self.OsHostsTableModel = None
        self.setupProcessesTableView()
        self.setupToolsTableView()
        self.setupOsTabViews()

        self.setMainWindowTitle(title)
        self.ui.statusbar.showMessage('Starting up..', msecs=1000)

        self.initTables()                                               # initialise all tables

        self.updateInterface()
        self.restoreToolTabWidget(True)                  # True means we want to show the original textedit
        self.updateScriptsOutputView('')                                # update the script output panel (right)
        self.updateToolHostsTableView('')
        self.ui.MainTabWidget.setCurrentIndex(0)                        # display scan tab by default
        self.ui.HostsTabWidget.setCurrentIndex(0)                       # display Hosts tab by default
        self.ui.ServicesTabWidget.setCurrentIndex(0)                    # display Services tab by default
        self.ui.BottomTabWidget.setCurrentIndex(0)                      # display Log tab by default
        self.ui.BruteTabWidget.setTabsClosable(True)                    # sets all tabs as closable in bruteforcer
        self.ui.ResponderTabWidget.setTabsClosable(True)

        self.ui.ServicesTabWidget.setTabsClosable(True)  # hide the close button (cross) from the fixed tabs

        self.ui.ServicesTabWidget.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(1, QTabBar.ButtonPosition.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(2, QTabBar.ButtonPosition.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(3, QTabBar.ButtonPosition.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(4, QTabBar.ButtonPosition.RightSide, None)

        self.resetBruteTabs()  # clear brute tabs (if any) and create default brute tab
        self.resetResponderTabs()
        self.displayToolPanel(False)
        self.displayScreenshots(False)
        # displays an overlay over the hosttableview saying 'click here to add host(s) to scope'
        self.displayAddHostsOverlay(True)
        self._initToolTabContextMenu()
        self.updateResponderResultsTable()

    def startConnections(self):  # signal initialisations (signals/slots, actions, etc)
        ### MENU ACTIONS ###
        self.connectCreateNewProject()
        self.connectOpenExistingProject()
        self.connectSaveProject()
        self.connectSaveProjectAs()
        self.connectAddHosts()
        self.connectImportNmap()
        self.connectExportJson()
        #self.connectSettings()
        self.connectHelp()
        self.connectConfig()
        self.connectAppExit()
        ### TABLE ACTIONS ###
        self.connectAddHostsOverlayClick()
        self.connectHostTableClick()
        self.connectServiceNamesTableClick()
        self.connectToolsTableClick()
        self.connectScriptTableClick()
        self.connectToolHostsClick()
        self.connectAdvancedFilterClick()
        self.connectAddHostClick()
        self.connectSwitchTabClick()                                    # to detect changing tabs (on left panel)
        self.connectSwitchMainTabClick()                                # to detect changing top level tabs
        self.connectTableDoubleClick()   # for double clicking on host (it redirects to the host view)
        self.connectProcessTableHeaderResize()
        ### CONTEXT MENUS ###
        self.connectHostsTableContextMenu()
        self.connectServiceNamesTableContextMenu()
        self.connectServicesTableContextMenu()
        self.connectToolHostsTableContextMenu()
        self.connectProcessesTableContextMenu()
        self.connectScreenshotContextMenu()
        self.connectOsListClick()
        ### OTHER ###
        self.ui.NotesTextEdit.textChanged.connect(self.setDirty)
        self.ui.FilterApplyButton.clicked.connect(self.updateFilterKeywords)
        self.ui.ServicesTabWidget.tabCloseRequested.connect(self.closeHostToolTab)
        self.ui.BruteTabWidget.tabCloseRequested.connect(self.closeBruteTab)
        self.ui.ResponderTabWidget.tabCloseRequested.connect(self.closeResponderTab)
        self.ui.keywordTextInput.returnPressed.connect(self.ui.FilterApplyButton.click)
        self.filterdialog.applyButton.clicked.connect(self.updateFilter)
        self.ui.ProcessStatusFilterComboBox.currentIndexChanged.connect(self.onProcessStatusFilterChanged)
        #self.settingsWidget.applyButton.clicked.connect(self.applySettings)
        #self.settingsWidget.cmdCancelButton.clicked.connect(self.cancelSettings)
        #self.settingsWidget.applyButton.clicked.connect(self.controller.applySettings(self.settingsWidget.settings))
        #self.tick.connect(self.importProgressWidget.setProgress, QtCore.Qt.ConnectionType.QueuedConnection)

    #################### AUXILIARY ####################

    def initTables(self):  # this function prepares the default settings for each table
        # hosts table (left)
        headers = ["Id", "OS", "Accuracy", "Host", "IPv4", "IPv6", "Mac", "Status", "Hostname", "Vendor", "Uptime",
                   "Lastboot", "Distance", "CheckedHost", "Country Code", "State", "City", "Latitude", "Longitude",
                   "Count", "Closed"]
        setTableProperties(self.ui.HostsTableView, len(headers), [0, 2, 4, 5, 6, 7, 8, 9, 10 , 11, 12, 13, 14, 15, 16,
                                                                  17, 18, 19, 20, 21, 22, 23, 24])
        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 120)
        ##
        self.HostsTableModel = HostsTableModel(self.controller.getHostsFromDB(self.viewState.filters), headers)
        # Set the model of the HostsTableView to the HostsTableModel
        self.ui.HostsTableView.setModel(self.HostsTableModel)
        # Resize the OS column
        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 120)
        # Sort the model by the Host column in descending order
        self.HostsTableModel.sort(3, Qt.SortOrder.DescendingOrder)
        # Connect the clicked signal of the HostsTableView to the hostTableClick() method
        self.ui.HostsTableView.clicked.connect(self.hostTableClick)
        self.ui.HostsTableView.doubleClicked.connect(self.hostTableDoubleClick)

        ##

        # service names table (left)
        headers = ["Name"]
        setTableProperties(self.ui.ServiceNamesTableView, len(headers))

        # cves table (right)
        headers = ["CVE Id", "Severity", "Product", "Version", "CVE URL", "Source", "ExploitDb ID", "ExploitDb",
                   "ExploitDb URL"]
        setTableProperties(self.ui.CvesTableView, len(headers))
        self.ui.CvesTableView.setSortingEnabled(True)

        # tools table (left)
        headers = ["Progress", "Display", "Pid", "Tool", "Tool", "Host", "Port", "Protocol", "Command", "Start time",
                   "OutputFile", "Output", "Status"]
        setTableProperties(self.ui.ToolsTableView, len(headers),
                           [i for i in range(len(headers)) if i != 5])

        # service table (right)
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId", "ServiceId", "Name", "Product", "Version",
                   "Extrainfo", "Fingerprint"]
        setTableProperties(self.ui.ServicesTableView, len(headers), [0, 1, 5, 6, 8, 10, 11])

        # ports by service (right)
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId", "ServiceId", "Name", "Product", "Version",
                   "Extrainfo", "Fingerprint"]
        setTableProperties(self.ui.ServicesTableView, len(headers), [2, 5, 6, 8, 10, 11])
        self.ui.ServicesTableView.horizontalHeader().resizeSection(0, 130)       # resize IP

        # scripts table (right)
        headers = ["Id", "Script", "Port", "Protocol"]
        setTableProperties(self.ui.ScriptsTableView, len(headers), [0, 3])

        # tool hosts table (right)
        headers = ["Progress", "Display", "Pid", "Name", "Action", "Target", "Port", "Protocol", "Command",
                   "Start time", "OutputFile", "Output", "Status"]
        setTableProperties(self.ui.ToolHostsTableView, len(headers), [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12])
        self.ui.ToolHostsTableView.horizontalHeader().resizeSection(5,150)      # default width for Host column

        # os list table (left)
        headers = ["OS", "Hosts"]
        setTableProperties(self.ui.OsListTableView, len(headers))
        self.ui.OsListTableView.setSortingEnabled(False)

        # os hosts table (right)
        headers = ["IP", "Hostname", "OS", "Status"]
        setTableProperties(self.ui.OsHostsTableView, len(headers))

        # process table
        headers = ["Progress", "Display", "Run time", "Percent Complete", "Pid", "Name", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
        setTableProperties(self.ui.ProcessesTableView, len(headers), [1, 3, 4, 5, 8, 9, 10, 13, 14, 16])
        self.ui.ProcessesTableView.setSortingEnabled(True)

        headers = ["Captured", "Tool", "Source", "Username", "Hash", "Details"]
        setTableProperties(self.ui.ResponderResultsTableView, len(headers))
        self.ui.ResponderResultsTableView.setSortingEnabled(True)
        self.credentialModel = CredentialCaptureModel([])
        self.ui.ResponderResultsTableView.setModel(self.credentialModel)

    def setMainWindowTitle(self, title):
        self.ui_mainwindow.setWindowTitle(str(title))

    def yesNoDialog(self, message, title):
        dialog = QtWidgets.QMessageBox.question(self.ui.centralwidget, title, message,
                                                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                                                QtWidgets.QMessageBox.StandardButton.No)
        return dialog
        
    def setDirty(self, status=True):   # this function is called for example when the user edits notes
        self.viewState.dirty = status
        title = ''
        
        if self.viewState.dirty:
            title = '*'
        if self.controller.isTempProject():
            title += 'untitled'
        else:
            title += ntpath.basename(str(self.controller.getProjectName()))
        
        self.setMainWindowTitle(applicationInfo["name"] + ' ' + getVersion() + ' - ' + title + ' - ' +
                                self.controller.getCWD())
        
    #################### ACTIONS ####################

    def connectProcessTableHeaderResize(self):
        self.ui.ProcessesTableView.horizontalHeader().sectionResized.connect(self.saveProcessHeaderWidth)

    def saveProcessHeaderWidth(self, index, oldSize, newSize):
        columnWidths = self.controller.getSettings().gui_process_tab_column_widths.split(',')
        # Ensure columnWidths has enough entries
        while len(columnWidths) <= index:
            columnWidths.append(str(newSize))
        # Validate current value
        try:
            current_width = int(columnWidths[index])
        except (ValueError, TypeError):
            current_width = newSize
        difference = abs(current_width - newSize)
        if difference >= 5:
            columnWidths[index] = str(newSize)
            self.controller.settings.gui_process_tab_column_widths = ','.join(columnWidths)
            self.controller.applySettings(self.controller.settings)

    def dealWithRunningProcesses(self, exiting=False):
        if len(self.controller.getRunningProcesses()) > 0:
            message = "There are still processes running. If you continue, every process will be terminated. " + \
                      "Are you sure you want to continue?"
            reply = self.yesNoDialog(message, 'Confirm')
                    
            if not reply == QtWidgets.QMessageBox.StandardButton.Yes:
                return False
            self.controller.killRunningProcesses()
        
        elif exiting:
            return self.confirmExit()
        
        return True

    # returns True if we can proceed with: creating/opening a project or exiting
    def dealWithCurrentProject(self, exiting=False):
        if self.viewState.dirty:   # if there are unsaved changes, show save dialog first
            if not self.saveOrDiscard():                                # if the user canceled, stop
                return False
        
        return self.dealWithRunningProcesses(exiting)                   # deal with running processes

    def confirmExit(self):
        message = "Are you sure to exit the program?"
        reply = self.yesNoDialog(message, 'Confirm')
        return (reply == QtWidgets.QMessageBox.StandardButton.Yes)

    def killProcessConfirmation(self):
        message = "Are you sure you want to kill the selected processes?"
        reply = self.yesNoDialog(message, 'Confirm')
        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            return True
        return False

    def connectCreateNewProject(self):
        self.ui.actionNew.triggered.connect(self.createNewProject)

    def createNewProject(self):
        if self.dealWithCurrentProject():
            log.info('Creating new project..')
            self.controller.createNewProject()

    def connectOpenExistingProject(self):
        self.ui.actionOpen.triggered.connect(self.openExistingProject)

    def openExistingProject(self):
        if self.dealWithCurrentProject():
            filename = QtWidgets.QFileDialog.getOpenFileName(
                self.ui.centralwidget, 'Open project', self.controller.getCWD(),
                filter='Legion session (*.legion);; Sparta session (*.sprt)')[0]
        
            if not filename == '':                                      # check for permissions
                if not os.access(filename, os.R_OK) or not os.access(filename, os.W_OK):
                    log.info('Insufficient permissions to open this file.')
                    QtWidgets.QMessageBox.warning(self.ui.centralwidget, 'Warning',
                                                          "You don't have the necessary permissions on this file.",
                                                          "Ok")
                    return

                if '.legion' in str(filename):
                    projectType = 'legion'
                elif '.sprt' in str(filename):
                    projectType = 'sparta'
                                
                if not self.controller.openExistingProject(filename, projectType):
                    return
                self.viewState.firstSave = False  # overwrite this variable because we are opening an existing file
                # do not show the overlay because the hosttableview is already populated
                self.displayAddHostsOverlay(False)
            else:
                log.info('No file chosen..')

    def connectSaveProject(self):
        self.ui.actionSave.triggered.connect(self.saveProject)
    
    def saveProject(self):
        self.ui.statusbar.showMessage('Saving..')
        if self.viewState.firstSave:
            self.saveProjectAs()
        else:
            log.info('Saving project..')
            self.controller.saveProject(self.viewState.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

            self.setDirty(False)
            self.ui.statusbar.showMessage('Saved!', msecs=1000)
            log.info('Saved!')

    def connectSaveProjectAs(self):
        self.ui.actionSaveAs.triggered.connect(self.saveProjectAs)

    def saveProjectAs(self):
        self.ui.statusbar.showMessage('Saving..')
        log.info('Saving project..')

        self.controller.saveProject(self.viewState.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

        filename = QtWidgets.QFileDialog.getSaveFileName(self.ui.centralwidget, 'Save project as',
                                                         self.controller.getCWD(), filter='Legion session (*.legion)',
                                                         options=QtWidgets.QFileDialog.Option.DontConfirmOverwrite)[0]
            
        while not filename =='':
            if not os.access(ntpath.dirname(str(filename)), os.R_OK) or not os.access(
                    ntpath.dirname(str(filename)), os.W_OK):
                log.info('Insufficient permissions on this folder.')
                reply = QtWidgets.QMessageBox.warning(self.ui.centralwidget, 'Warning',
                                                      "You don't have the necessary permissions on this folder.")
                
            else:
                if self.controller.saveProjectAs(filename):
                    break
                    
                if not str(filename).endswith('.legion'):
                    filename = str(filename) + '.legion'
                msgBox = QtWidgets.QMessageBox()
                reply = msgBox.question(self.ui.centralwidget, 'Confirm',
                                        "A file named \""+ntpath.basename(str(filename))+"\" already exists.  " +
                                        "Do you want to replace it?",
                                        QtWidgets.QMessageBox.StandardButton.Abort | QtWidgets.QMessageBox.StandardButton.Save)
            
                if reply == QtWidgets.QMessageBox.StandardButton.Save:
                    self.controller.saveProjectAs(filename, 1)          # replace
                    break

            filename = QtWidgets.QFileDialog.getSaveFileName(self.ui.centralwidget, 'Save project as', '.',
                                                             filter='Legion session (*.legion)',
                                                             options=QtWidgets.QFileDialog.Option.DontConfirmOverwrite)[0]

        if not filename == '':
            self.setDirty(False)
            self.viewState.firstSave = False
            self.ui.statusbar.showMessage('Saved!', msecs=1000)
            self.controller.updateOutputFolder()
            log.info('Saved!')
        else:
            log.info('No file chosen..')

    def saveOrDiscard(self):
        reply = QtWidgets.QMessageBox.question(
            self.ui.centralwidget, 'Confirm', "The project has been modified. Do you want to save your changes?",
            QtWidgets.QMessageBox.StandardButton.Save | QtWidgets.QMessageBox.StandardButton.Discard | QtWidgets.QMessageBox.StandardButton.Cancel,
            QtWidgets.QMessageBox.StandardButton.Save)
        
        if reply == QtWidgets.QMessageBox.StandardButton.Save:
            self.saveProject()
            return True
        elif reply == QtWidgets.QMessageBox.StandardButton.Discard:
            return True
        else:
            return False                                                # the user cancelled
            
    def closeProject(self):
        if self._close_project_in_progress:
            return
        self._close_project_in_progress = True
        self.ui.statusbar.showMessage('Closing project..', msecs=1000)
        # Wait for NmapImporter thread to finish before cleanup
        try:
            if hasattr(self.controller, "nmapImporter") and self.controller.nmapImporter.isRunning():
                log.info("Waiting for NmapImporter thread to finish before closing project...")
                self.controller.nmapImporter.wait()
        except Exception as e:
            log.info(f"Error waiting for NmapImporter: {e}")
        try:
            self.controller.closeProject()
        finally:
            # Always tear down UI state even if controller cleanup hits an edge-case.
            self.removeToolTabs()                                           # to make them disappear from the UI
            self.resetResponderTabs()
            self._close_project_in_progress = False

    def clearProcessesTableView(self):
        """
        Clear the processes table without querying the database.
        This is important during shutdown, after the temp DB file may have been removed.
        """
        try:
            if getattr(self, "ProcessesTableModel", None) is None:
                return
            self.ProcessesTableModel.setDataList([])
            self._configureProcessesColumns()
            self.ui.ProcessesTableView.repaint()
            self.ui.ProcessesTableView.update()
            self.updateProcessesIcon()
        except Exception:
            log.exception("Failed to clear processes table view")
                
    def connectAddHosts(self):
        self.ui.actionAddHosts.triggered.connect(self.connectAddHostsDialog)
        
    def connectAddHostsDialog(self):
        self.adddialog.cmdAddButton.setDefault(True)
        self.adddialog.txtHostList.setFocus(Qt.FocusReason.OtherFocusReason)
        self.adddialog.validationLabel.hide()
        self.adddialog.spacer.changeSize(15, 15)
        self.adddialog.show()
        self.adddialog.cmdAddButton.clicked.connect(self.callAddHosts)
        self.adddialog.cmdCancelButton.clicked.connect(self.adddialog.close)
        
    def callAddHosts(self):
        hostListStr = str(self.adddialog.txtHostList.toPlainText()).replace(';',' ')
        nmapOptions = []
        scanMode = 'Unset'

        if validateNmapInput(hostListStr):
            self.adddialog.close()
            hostList = []
            splitTypes = [';', ' ', '\n']

            for splitType in splitTypes:
                hostListStr = hostListStr.replace(splitType, ';')

            hostList = hostListStr.split(';')
            hostList = [hostEntry for hostEntry in hostList if len(hostEntry) > 0]

            hostAddOptionControls = [self.adddialog.rdoScanOptTcpConnect, self.adddialog.rdoScanOptObfuscated,
                                     self.adddialog.rdoScanOptTcpSyn, self.adddialog.rdoScanOptFin,
                                     self.adddialog.rdoScanOptNull,
                                     self.adddialog.rdoScanOptXmas, self.adddialog.rdoScanOptPingTcp,
                                     self.adddialog.rdoScanOptPingUdp, self.adddialog.rdoScanOptPingDisable,
                                     self.adddialog.rdoScanOptPingRegular, self.adddialog.rdoScanOptPingSyn,
                                     self.adddialog.rdoScanOptPingAck, self.adddialog.rdoScanOptPingTimeStamp,
                                     self.adddialog.rdoScanOptPingNetmask, self.adddialog.chkScanOptFragmentation]
            nmapOptions = []

            if self.adddialog.rdoModeOptEasy.isChecked():
                scanMode = 'Easy'
            else:
                scanMode = 'Hard'
                for hostAddOptionControl in hostAddOptionControls:
                    if hostAddOptionControl.isChecked():
                       nmapOptionValue = str(hostAddOptionControl.toolTip())
                       nmapOptionValueSplit = nmapOptionValue.split('[')
                       if len(nmapOptionValueSplit) > 1:
                           nmapOptionValue = nmapOptionValueSplit[1].replace(']','')
                           nmapOptions.append(nmapOptionValue)
                nmapOptions.append(str(self.adddialog.txtCustomOptList.text()))
            # Hostname resolution option
            # Remove any existing -n or -R from nmapOptions to avoid conflicts
            nmapOptions = [opt for opt in nmapOptions if opt.strip() not in ['-n', '-R']]
            if self.adddialog.chkResolveHostnames.isChecked():
                nmapOptions.append('-R')
            else:
                nmapOptions.append('-n')

            for hostListEntry in hostList:
                self.controller.addHosts(targetHosts=hostListEntry,
                                         runHostDiscovery=self.adddialog.chkDiscovery.isChecked(),
                                         runStagedNmap=self.adddialog.chkNmapStaging.isChecked(),
                                         nmapSpeed=self.adddialog.sldScanTimingSlider.value(),
                                         scanMode=scanMode,
                                         nmapOptions=nmapOptions,
                                         enableIPv6=self.adddialog.chkEnableIPv6.isChecked(),
                                         easyStealth=self.adddialog.chkEasyStealth.isChecked(),
                                         includeUDP=self.adddialog.chkEasyIncludeUdp.isChecked())
            self.adddialog.cmdAddButton.clicked.disconnect()   # disconnect all the signals from that button
        else:
            self.adddialog.spacer.changeSize(0,0)
            self.adddialog.validationLabel.show()
            self.adddialog.cmdAddButton.clicked.disconnect()  # disconnect all the signals from that button
            self.adddialog.cmdAddButton.clicked.connect(self.callAddHosts)

    ###
    
    def connectImportNmap(self):
        self.ui.actionImportNmap.triggered.connect(self.importNmap)

    def importNmap(self):
        self.ui.statusbar.showMessage('Importing nmap xml..', msecs=1000)
        filename = QtWidgets.QFileDialog.getOpenFileName(self.ui.centralwidget, 'Choose nmap file',
                                                         self.controller.getCWD(), filter='XML file (*.xml)')[0]
        log.info('Importing nmap xml from {0}...'.format(str(filename)))
        if not filename == '':
            if not os.access(filename, os.R_OK):                        # check for read permissions on the xml file
                log.info('Insufficient permissions to read this file.')
                QtWidgets.QMessageBox.warning(self.ui.centralwidget, 'Warning',
                                                      "You don't have the necessary permissions to read this file.",
                                                      "Ok")
                return

            self.controller.nmapImporter.setFilename(str(filename))
            self.importProgressBar.setValue(0)
            log.debug(f"importNmap: setVisible(True) called, importProgressBar id={id(self.importProgressBar)}, \
                       parent={self.importProgressBar.parent()}")
            self.importProgressBar.setVisible(True)
            self.cancelImportButton.setVisible(True)
            self.importInProgress = True
            self.controller.nmapImporter.start()
            self.controller.copyNmapXMLToOutputFolder(str(filename))
        else:
            log.info('No file chosen..')

    def cancelImportNmap(self):
        try:
            if hasattr(self.controller, "nmapImporter"):
                log.info("Canceling Nmap import at user request.")
                self.controller.nmapImporter.cancel()
        except Exception as e:
            log.info(f"Error canceling Nmap import: {e}")

    def updateImportProgress(self, progress, title):
        # If import is not in progress, always hide the bar and cancel button, and force UI update
        if not getattr(self, "importInProgress", True):
            self.importProgressBar.setVisible(False)
            self.cancelImportButton.setVisible(False)
            self.importProgressBar.repaint()
            if hasattr(self, "ui") and hasattr(self.ui, "statusbar"):
                self.ui.statusbar.repaint()
            return
        # If "Processing ports..." just reached 100%, show "Finishing up..." and hide cancel button
        if title.lower().startswith("processing ports") and progress >= 100:
            self.importProgressBar.setValue(100)
            self.importProgressBar.setFormat("Finishing up... (100%)")
            self.cancelImportButton.setVisible(False)
            return
        self.importProgressBar.setValue(int(progress))
        self.importProgressBar.setFormat(f"{title} ({int(progress)}%)")
        if "almost done" in title.lower():
            log.debug(f"updateImportProgress: 'Almost done...' progressBar id={id(self.importProgressBar)}, \
                      parent={self.importProgressBar.parent()}, format={self.importProgressBar.format()}, \
                        visible={self.importProgressBar.isVisible()}")
        # Hide the cancel button if we're finishing up, but keep the progress bar visible until import is truly done
        if title.lower().startswith("finishing up") and progress >= 100:
            self.cancelImportButton.setVisible(False)
        # Only hide the progress bar when the import is truly finished, not just when any stage hits 100%
        # The progress bar will be hidden by a separate signal/slot when the import is done.

    def importFinished(self):
        import traceback
        log.debug("importFinished called - hiding progress bar and cancel button")
        log.debug(f"importFinished: importProgressBar id={id(self.importProgressBar)}, \
                  parent={self.importProgressBar.parent()}")
        log.debug("".join(traceback.format_stack()))
        self.importInProgress = False
        self.importProgressBar.setVisible(False)
        log.debug(f"importFinished: setVisible(False) called, visible={self.importProgressBar.isVisible()}")
        self.cancelImportButton.setVisible(False)
        log.debug(f"importFinished: cancelImportButton setVisible(False), \
                  visible={self.cancelImportButton.isVisible()}")
        self.importProgressBar.repaint()
        if hasattr(self, "ui") and hasattr(self.ui, "statusbar"):
            self.ui.statusbar.repaint()
        # Delayed hide as failsafe
        from PyQt6.QtCore import QTimer
        def delayed_hide():
            log.debug("Delayed hide of progress bar and cancel button")
            log.debug(f"delayed_hide: importProgressBar id={id(self.importProgressBar)}, \
                      parent={self.importProgressBar.parent()}")
            log.debug("".join(traceback.format_stack()))
            self.importProgressBar.setVisible(False)
            log.debug(f"delayed_hide: setVisible(False) called, visible={self.importProgressBar.isVisible()}")
            self.cancelImportButton.setVisible(False)
            log.debug(f"delayed_hide: cancelImportButton setVisible(False), \
                      visible={self.cancelImportButton.isVisible()}")
            self.importProgressBar.repaint()
            if hasattr(self, "ui") and hasattr(self.ui, "statusbar"):
                self.ui.statusbar.repaint()
        QTimer.singleShot(2000, delayed_hide)
    def connectSettings(self):
        self.ui.actionSettings.triggered.connect(self.showSettingsWidget)

    def showSettingsWidget(self):
        self.settingsWidget.resetTabIndexes()
        self.settingsWidget.show()

    def applySettings(self):
        if self.settingsWidget.applySettings():
            self.controller.applySettings(self.settingsWidget.settings)
            self.settingsWidget.hide()

    def cancelSettings(self):
        log.debug('Cancel button pressed')  # LEO: we can use this later to test ESC button once implemented.
        self.settingsWidget.hide()
        self.controller.cancelSettings()

    def connectHelp(self):
        self.ui.actionHelp.triggered.connect(self.helpDialog.show)
        if hasattr(self.ui, 'actionRepairProject'):
            self.ui.actionRepairProject.triggered.connect(self.showRepairDialog)

    def showRepairDialog(self):
        from ui.repairDialog import RepairDialog
        dlg = RepairDialog(self.ui.centralwidget)
        dlg.exec()

    def connectConfig(self):
        self.ui.actionConfig.triggered.connect(self.configDialog.show)

    def connectExportJson(self):
        self.ui.actionExportJson.triggered.connect(self.exportAsJson)

    def connectAppExit(self):
        self.ui.actionExit.triggered.connect(self.appExit)

    def exportAsJson(self):
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.ui.centralwidget, 'Export as JSON', self.controller.getCWD(), filter='JSON file (*.json)')
        if filename:
            self.controller.exportAsJson(filename)

    def appExit(self):
        if self._app_exit_in_progress:
            return
        # Mark as in-progress early to prevent re-entrancy from subsequent QEvent.Close events.
        self._app_exit_in_progress = True
        try:
            # the parameter indicates that we are exiting the application
            if not self.dealWithCurrentProject(True):
                # User canceled exit; allow subsequent close attempts.
                self._app_exit_in_progress = False
                return
            self.closeProject()
            log.info('Exiting application..')
            from PyQt6.QtCore import QCoreApplication
            QCoreApplication.quit()
        except Exception:
            # Avoid an unhandled exception during shutdown which can leave Qt in a bad state.
            log.exception("Unhandled exception during appExit()")
            try:
                from PyQt6.QtCore import QCoreApplication
                QCoreApplication.quit()
            except Exception:
                pass

    ### TABLE ACTIONS ###

    def connectAddHostsOverlayClick(self):
        self.ui.addHostsOverlay.selectionChanged.connect(self.connectAddHostsDialog)

    def connectHostTableClick(self):
        self.ui.HostsTableView.clicked.connect(self.hostTableClick)

    # TODO: review - especially what tab is selected when coming from another host
    def hostTableClick(self):
        if self.ui.HostsTableView.selectionModel().selectedRows():  # get the IP address of the selected host (if any)
            row = self.ui.HostsTableView.selectionModel().selectedRows()[len(self.ui.HostsTableView.
                                                                             selectionModel().selectedRows())-1].row()
            ip = self.HostsTableModel.getHostIPForRow(row)
            self.viewState.ip_clicked = ip
            save = self.ui.ServicesTabWidget.currentIndex()
            self.removeToolTabs()
            self.restoreToolTabsForHost(self.viewState.ip_clicked)
            # display services tab if we are coming from a dynamic tab (non-fixed)
            self.ui.ServicesTabWidget.setCurrentIndex(save)
            self.updateRightPanel(self.viewState.ip_clicked)
        else:
            self.removeToolTabs()
            self.updateRightPanel('')

    ###
    
    def connectServiceNamesTableClick(self):
        self.ui.ServiceNamesTableView.clicked.connect(self.serviceNamesTableClick)

    def hostTableDoubleClick(self, index):
        # Get the item from the model using the index
        model = self.ui.HostsTableView.model()
        row = index.row()
        new_index = model.index(row, 3)
        data = model.data(new_index, QtCore.Qt.ItemDataRole.DisplayRole)
        if data:
            self.controller.copyToClipboard(data)
        
    def serviceNamesTableClick(self):
        if self.ui.ServiceNamesTableView.selectionModel().selectedRows():
            row = self.ui.ServiceNamesTableView.selectionModel().selectedRows()[len(
                self.ui.ServiceNamesTableView.selectionModel().selectedRows())-1].row()
            self.viewState.service_clicked = self.ServiceNamesTableModel.getServiceNameForRow(row)
            self.updatePortsByServiceTableView(self.viewState.service_clicked)
        
    ###
    
    def connectToolsTableClick(self):
        self.ui.ToolsTableView.clicked.connect(self.toolsTableClick)
        
    def toolsTableClick(self):
        if self.ui.ToolsTableView.selectionModel().selectedRows():
            row = self.ui.ToolsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolsTableView.selectionModel().selectedRows())-1].row()
            self.viewState.tool_clicked = self.ToolsTableModel.getToolNameForRow(row)
            self.updateToolHostsTableView(self.viewState.tool_clicked)
            # if we clicked on the screenshooter we need to display the screenshot widget
            self.displayScreenshots(self.viewState.tool_clicked == 'screenshooter')

        # update the updateToolHostsTableView when the user closes all the host tabs
        # TODO: this doesn't seem right
        else:
            self.updateToolHostsTableView('')
            self.ui.DisplayWidgetLayout.addWidget(self.ui.toolOutputTextView)
            
    ###
    
    def connectScriptTableClick(self):
        self.ui.ScriptsTableView.clicked.connect(self.scriptTableClick)
        
    def scriptTableClick(self):
        if self.ui.ScriptsTableView.selectionModel().selectedRows():
            row = self.ui.ScriptsTableView.selectionModel().selectedRows()[len(
                self.ui.ScriptsTableView.selectionModel().selectedRows())-1].row()
            self.viewState.script_clicked = self.ScriptsTableModel.getScriptDBIdForRow(row)
            self.updateScriptsOutputView(self.viewState.script_clicked)
                
    ###

    def connectToolHostsClick(self):
        self.ui.ToolHostsTableView.clicked.connect(self.toolHostsClick)

    # TODO: review / duplicate code
    def toolHostsClick(self):
        if self.ui.ToolHostsTableView.selectionModel().selectedRows():
            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            self.viewState.tool_host_clicked = self.ToolHostsTableModel.getProcessIdForRow(row)
            ip = self.ToolHostsTableModel.getIpForRow(row)
            
            if self.viewState.tool_clicked == 'screenshooter':
                filename = self.ToolHostsTableModel.getOutputfileForRow(row)
                self.ui.ScreenshotWidget.open(str(self.controller.getOutputFolder())+'/screenshots/'+str(filename))
            
            else:
                # restore the tool output textview now showing in the tools display panel to its original host tool tab
                self.restoreToolTabWidget()

                # remove the tool output currently in the tools display panel (if any)
                if self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit):
                    self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit).setParent(None)

                tabs = []                                               # fetch tab list for this host (if any)
                if str(ip) in self.viewState.hostTabs:
                    tabs = self.viewState.hostTabs[str(ip)]
                
                for tab in tabs: # place the tool output textview in the tools display panel
                    if tab.findChild(QtWidgets.QPlainTextEdit) and \
                            str(tab.findChild(QtWidgets.QPlainTextEdit).property('dbId')) == \
                            str(self.viewState.tool_host_clicked):
                        self.ui.DisplayWidgetLayout.addWidget(tab.findChild(QtWidgets.QPlainTextEdit))
                        break

    ###

    def connectAddHostClick(self):
        self.ui.AddHostButton.clicked.connect(self.connectAddHostsDialog)

    def connectAdvancedFilterClick(self):
        self.ui.FilterAdvancedButton.clicked.connect(self.advancedFilterClick)

    def advancedFilterClick(self, current):
        # to make sure we don't show filters than have been clicked but cancelled
        self.filterdialog.setCurrentFilters(self.viewState.filters.getFilters())
        self.filterdialog.show()

    def updateFilter(self):
        f = self.filterdialog.getFilters()
        self.viewState.filters.apply(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8])
        self.ui.keywordTextInput.setText(" ".join(f[8]))
        self.updateInterface()

    def updateFilterKeywords(self):
        self.viewState.filters.setKeywords(unicode(self.ui.keywordTextInput.text()).split())
        self.updateInterface()

    ###
    
    def connectTableDoubleClick(self):
        self.ui.ServicesTableView.doubleClicked.connect(self.tableDoubleClick)
        self.ui.ToolHostsTableView.doubleClicked.connect(self.tableDoubleClick)
        self.ui.OsHostsTableView.doubleClicked.connect(self.tableDoubleClick)
        self.ui.CvesTableView.doubleClicked.connect(self.rightTableDoubleClick)
 
    def rightTableDoubleClick(self, signal):
        row = signal.row()  # RETRIEVES ROW OF CELL THAT WAS DOUBLE CLICKED
        column = signal.column()  # RETRIEVES COLUMN OF CELL THAT WAS DOUBLE CLICKED
        model = self.CvesTableModel
        cell_dict = model.itemData(signal)  # RETURNS DICT VALUE OF SIGNAL
        cell_value = cell_dict.get(0)  # RETRIEVE VALUE FROM DICT
 
        index = signal.sibling(row, 0)
        index_dict = model.itemData(index)
        index_value = index_dict.get(0)
        log.info('Row {}, Column {} clicked - value: {}\nColumn 1 contents: {}'
                 .format(row, column, cell_value, index_value))

        ## Does not work under WSL!
        df = pd.DataFrame([cell_value])
        df.to_clipboard(index = False, header = False)


    def tableDoubleClick(self):
        tab = self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex())

        if tab == 'Services':
            row = self.ui.ServicesTableView.selectionModel().selectedRows()[len(
                self.ui.ServicesTableView.selectionModel().selectedRows())-1].row()
            ip = self.PortsByServiceTableModel.getIpForRow(row)
        elif tab == 'Tools':
            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            ip = self.ToolHostsTableModel.getIpForRow(row)
        elif tab == 'OS':
            if not self.ui.OsHostsTableView.selectionModel().selectedRows():
                return
            row = self.ui.OsHostsTableView.selectionModel().selectedRows()[
                len(self.ui.OsHostsTableView.selectionModel().selectedRows())-1].row()
            ip = self.OsHostsTableModel.getIpForRow(row)
        else:
            return

        hostrow = self.HostsTableModel.getRowForIp(ip)
        if hostrow is not None:
            self.ui.HostsTabWidget.setCurrentIndex(0)
            self.ui.HostsTableView.selectRow(hostrow)
            self.hostTableClick()
    
    ###
    
    def connectSwitchTabClick(self):
        self.ui.HostsTabWidget.currentChanged.connect(self.switchTabClick)

    def switchTabClick(self):
        if self.ServiceNamesTableModel:                                 # fixes bug when switching tabs at start-up
            selectedTab = self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex())
        
            if selectedTab == 'Hosts':
                self.ui.ServicesTabWidget.insertTab(1,self.ui.ScriptsTab,("Scripts"))
                self.ui.ServicesTabWidget.insertTab(2,self.ui.InformationTab,("Information"))
                self.ui.ServicesTabWidget.insertTab(3,self.ui.CvesRightTab,("CVEs"))
                self.ui.ServicesTabWidget.insertTab(4,self.ui.NotesTab,("Notes"))
                self.ui.ServicesTabWidget.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(1, QTabBar.ButtonPosition.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(2, QTabBar.ButtonPosition.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(3, QTabBar.ButtonPosition.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(4, QTabBar.ButtonPosition.RightSide, None)

                self.restoreToolTabWidget()
                ###
                if self.viewState.lazy_update_hosts == True:
                    self.updateHostsTableView()
                ###
                self.hostTableClick()
                    
            elif selectedTab == 'Services':
                self.ui.ServicesTabWidget.setCurrentIndex(0)
                self.removeToolTabs(0)                                  # remove the tool tabs
                self.controller.saveProject(self.viewState.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())
                if self.viewState.lazy_update_services == True:
                    self.updateServiceNamesTableView()
                self.serviceNamesTableClick()

            # Todo
            #elif selectedTab == 'CVEs':
            #    self.ui.ServicesTabWidget.setCurrentIndex(0)
            #    self.removeToolTabs(0)                                  # remove the tool tabs
            #    self.controller.saveProject(self.viewState.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())
            #    if self.viewState.lazy_update_services == True:
            #        self.updateServiceNamesTableView()
            #    self.serviceNamesTableClick()
                
            elif selectedTab == 'Tools':
                self.updateToolsTableView()

            elif selectedTab == 'OS':
                if self.viewState.lazy_update_os or not self.OsListTableModel:
                    self.updateOsListView()
                else:
                    self.updateOsHostsTableView(self.viewState.os_clicked or 'Unknown')

            # display tool panel if we are in tools tab, hide it otherwise
            self.displayToolPanel(selectedTab == 'Tools')
    
    ###

    def connectSwitchMainTabClick(self):
        self.ui.MainTabWidget.currentChanged.connect(self.switchMainTabClick)

    def switchMainTabClick(self):
        selectedTab = self.ui.MainTabWidget.tabText(self.ui.MainTabWidget.currentIndex())
        
        if selectedTab == 'Scan':
            self.switchTabClick()
        
        elif selectedTab == 'Brute':
            self.ui.BruteTabWidget.currentWidget().runButton.setFocus()
            self.restoreToolTabWidget()

        # in case the Brute tab was red because hydra found stuff, change it back to black
        self.ui.MainTabWidget.tabBar().setTabTextColor(1, QtGui.QColor())

    ###
    # indicates that a context menu is showing so that the ui doesn't get updated disrupting the user
    def setVisible(self):
        self.viewState.menuVisible = True

    # indicates that a context menu has now closed and any pending ui updates can take place now
    def setInvisible(self):
        self.viewState.menuVisible = False
    ###
    
    def connectHostsTableContextMenu(self):
        self.ui.HostsTableView.customContextMenuRequested.connect(self.contextMenuHostsTableView)

    def contextMenuHostsTableView(self, pos):
        if len(self.ui.HostsTableView.selectionModel().selectedRows()) > 0:
            row = self.ui.HostsTableView.selectionModel().selectedRows()[
                len(self.ui.HostsTableView.selectionModel().selectedRows())-1].row()
            # because when we right click on a different host, we need to select it
            self.viewState.ip_clicked = self.HostsTableModel.getHostIPForRow(row)
            self.ui.HostsTableView.selectRow(row)                       # select host when right-clicked
            self.hostTableClick()

            menu, actions = self.controller.getContextMenuForHost(
                str(self.HostsTableModel.getHostCheckStatusForRow(row)))
            # Add Copy action
            copyAction = menu.addAction("Copy")
            addPortAction = menu.addAction("Add Port")
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)
            hostid = self.HostsTableModel.getHostIdForRow(row)
            action = menu.exec(self.ui.HostsTableView.viewport().mapToGlobal(pos))

            if action == copyAction:
                # Copy selected hosts' IP and Hostname to clipboard (tab-separated, one per line)
                selected_rows = self.ui.HostsTableView.selectionModel().selectedRows()
                clipboard_data = ""
                for idx in selected_rows:
                    ip = self.HostsTableModel.getHostIPForRow(idx.row())
                    hostname = self.HostsTableModel.getHostnameForRow(idx.row()) if hasattr(self.HostsTableModel, "getHostnameForRow") else ""
                    clipboard_data += f"{ip}\t{hostname}\n"
                clipboard = QtWidgets.QApplication.clipboard()
                clipboard.setText(clipboard_data.strip())
            elif action == addPortAction:
                dialog = AddPortDialog(self.ui.centralwidget)
                if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                    port_data = dialog.get_port_data()
                    # Pass the selected host's IP and port data to the controller
                    self.controller.addPortToHost(self.viewState.ip_clicked, port_data)
            elif action:
                self.controller.handleHostAction(self.viewState.ip_clicked, hostid, actions, action)

    ###

    def connectServiceNamesTableContextMenu(self):
        self.ui.ServiceNamesTableView.customContextMenuRequested.connect(self.contextMenuServiceNamesTableView)

    def contextMenuServiceNamesTableView(self, pos):
        if len(self.ui.ServiceNamesTableView.selectionModel().selectedRows()) > 0:
            row = self.ui.ServiceNamesTableView.selectionModel().selectedRows()[len(
                self.ui.ServiceNamesTableView.selectionModel().selectedRows())-1].row()
            self.viewState.service_clicked = self.ServiceNamesTableModel.getServiceNameForRow(row)
            self.ui.ServiceNamesTableView.selectRow(row)                # select service when right-clicked
            self.serviceNamesTableClick()

            menu, actions, shiftPressed = self.controller.getContextMenuForServiceName(self.viewState.service_clicked)
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)
            action = menu.exec(self.ui.ServiceNamesTableView.viewport().mapToGlobal(pos))

            if action:
                # because we will need to populate the right-side panel in order to select those rows
                self.serviceNamesTableClick()
                # we must only fetch the targets on which we haven't run the tool yet
                tool = None
                for i in range(0,len(actions)):                         # fetch the tool name
                    if action == actions[i][1]:
                        srvc_num = actions[i][0]
                        tool = self.controller.getSettings().portActions[srvc_num][1]
                        break

                if action.text() == 'Take screenshot':
                    tool = 'screenshooter'
                        
                targets = []  # get (IP,port,protocol) combinations for this service
                for row in range(self.PortsByServiceTableModel.rowCount("")):
                    targets.append([self.PortsByServiceTableModel.getIpForRow(row),
                                    self.PortsByServiceTableModel.getPortForRow(row),
                                    self.PortsByServiceTableModel.getProtocolForRow(row)])

                # if the user pressed SHIFT+Right-click, ignore the rule of only running the tool on targets on
                # which we haven't ran it yet
                if shiftPressed:
                    tool=None

                if tool:
                    # fetch the hosts that we already ran the tool on
                    hosts=self.controller.getHostsForTool(tool, 'FetchAll')
                    oldTargets = []
                    for i in range(0,len(hosts)):
                        oldTargets.append([hosts[i][5], hosts[i][6], hosts[i][7]])

                    # remove from the targets the hosts:ports we have already run the tool on
                    for host in oldTargets:
                        if host in targets:
                            targets.remove(host)
                
                self.controller.handleServiceNameAction(targets, actions, action)

    ###
    
    def connectToolHostsTableContextMenu(self):
        self.ui.ToolHostsTableView.customContextMenuRequested.connect(self.contextToolHostsTableContextMenu)

    @staticmethod
    def _extract_service_name(service_row):
        if not service_row:
            return ''
        try:
            if isinstance(service_row, dict):
                return service_row.get('name') or service_row.get('services.name') or \
                    (next(iter(service_row.values())) if service_row else '')
            if hasattr(service_row, '_mapping'):
                mapping = service_row._mapping
                for key in ('name', 'services.name'):
                    if key in mapping:
                        return mapping[key]
                try:
                    return next(iter(mapping.values()))
                except StopIteration:
                    return ''
            if isinstance(service_row, (list, tuple)):
                return service_row[0] if service_row else ''
            if hasattr(service_row, 'name'):
                return service_row.name
            return service_row[0]
        except Exception:
            return ''

    def contextToolHostsTableContextMenu(self, pos):
        if len(self.ui.ToolHostsTableView.selectionModel().selectedRows()) > 0:
            
            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            ip = self.ToolHostsTableModel.getIpForRow(row)
            port = self.ToolHostsTableModel.getPortForRow(row)
            
            if port:
                service_row = self.controller.getServiceNameForHostAndPort(ip, port)
                serviceName = self._extract_service_name(service_row)

                menu, actions, terminalActions = self.controller.getContextMenuForPort(str(serviceName))
                menu.aboutToShow.connect(self.setVisible)
                menu.aboutToHide.connect(self.setInvisible)
     
                 # this can handle multiple host selection if we apply it in the future
                targets = []  # get (IP,port,protocol,serviceName) combinations for each selected row
                # context menu when the left services tab is selected
                for row in self.ui.ToolHostsTableView.selectionModel().selectedRows():
                    targets.append([self.ToolHostsTableModel.getIpForRow(row.row()),
                                    self.ToolHostsTableModel.getPortForRow(row.row()),
                                    self.ToolHostsTableModel.getProtocolForRow(row.row()),
                                    self._extract_service_name(
                                        self.controller.getServiceNameForHostAndPort(
                                            self.ToolHostsTableModel.getIpForRow(row.row()),
                                            self.ToolHostsTableModel.getPortForRow(row.row())
                                        )
                                    )])
                    restore = True

                action = menu.exec(self.ui.ToolHostsTableView.viewport().mapToGlobal(pos))
     
                if action:
                    self.controller.handlePortAction(targets, actions, terminalActions, action, restore)
            
            else:   # in case there was no port, we show the host menu (without the portscan / mark as checked)
                host_row = self.HostsTableModel.getRowForIp(ip)
                if host_row is None:
                    log.warning(f"ToolHosts context menu: unable to find host row for IP {ip}")
                    return
                menu, actions = self.controller.getContextMenuForHost(
                    str(self.HostsTableModel.getHostCheckStatusForRow(host_row)), False)
                menu.aboutToShow.connect(self.setVisible)
                menu.aboutToHide.connect(self.setInvisible)
                hostid = self.HostsTableModel.getHostIdForRow(host_row)

                action = menu.exec(self.ui.ToolHostsTableView.viewport().mapToGlobal(pos))

                if action:
                    self.controller.handleHostAction(self.viewState.ip_clicked, hostid, actions, action)
    
    ###

    def connectServicesTableContextMenu(self):
        self.ui.ServicesTableView.customContextMenuRequested.connect(self.contextMenuServicesTableView)

    # this function is longer because there are two cases we are in the services table
    def contextMenuServicesTableView(self, pos):
        if len(self.ui.ServicesTableView.selectionModel().selectedRows()) > 0:
            # if there is only one row selected, get service name
            if len(self.ui.ServicesTableView.selectionModel().selectedRows()) == 1:
                row = self.ui.ServicesTableView.selectionModel().selectedRows()[len(
                    self.ui.ServicesTableView.selectionModel().selectedRows())-1].row()
                
                if self.ui.ServicesTableView.isColumnHidden(0):   # if we are in the services tab of the hosts view
                    serviceName = self.ServicesTableModel.getServiceNameForRow(row)
                else:   # if we are in the services tab of the services view
                    serviceName = self.PortsByServiceTableModel.getServiceNameForRow(row)
                    
            else:
                serviceName = '*'                                       # otherwise show full menu
                
            menu, actions, terminalActions = self.controller.getContextMenuForPort(serviceName)
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)

            targets = []   # get (IP,port,protocol,serviceName) combinations for each selected row
            if self.ui.ServicesTableView.isColumnHidden(0):
                for row in self.ui.ServicesTableView.selectionModel().selectedRows():
                    targets.append([self.ServicesTableModel.getIpForRow(row.row()),
                                    self.ServicesTableModel.getPortForRow(row.row()),
                                    self.ServicesTableModel.getProtocolForRow(row.row()),
                                    self.ServicesTableModel.getServiceNameForRow(row.row())])
                    restore = False
            
            else:   # context menu when the left services tab is selected
                for row in self.ui.ServicesTableView.selectionModel().selectedRows():
                    targets.append([self.PortsByServiceTableModel.getIpForRow(row.row()),
                                    self.PortsByServiceTableModel.getPortForRow(row.row()),
                                    self.PortsByServiceTableModel.getProtocolForRow(row.row()),
                                    self.PortsByServiceTableModel.getServiceNameForRow(row.row())])
                    restore = True

            action = menu.exec(self.ui.ServicesTableView.viewport().mapToGlobal(pos))

            if action:
                self.controller.handlePortAction(targets, actions, terminalActions, action, restore)
    
    ###

    def connectProcessesTableContextMenu(self):
        self.ui.ProcessesTableView.customContextMenuRequested.connect(self.contextMenuProcessesTableView)

    def contextMenuProcessesTableView(self, pos):
        if self.ui.ProcessesTableView.selectionModel() and self.ui.ProcessesTableView.selectionModel().selectedRows():
    
            menu = self.controller.getContextMenuForProcess()
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)

            selectedProcesses = []                                  # list of tuples (pid, status, procId)
            for row in self.ui.ProcessesTableView.selectionModel().selectedRows():
                pid = self.ProcessesTableModel.getProcessPidForRow(row.row())
                selectedProcesses.append([int(pid), self.ProcessesTableModel.getProcessStatusForRow(row.row()),
                                          self.ProcessesTableModel.getProcessIdForRow(row.row())])

            action = menu.exec(self.ui.ProcessesTableView.viewport().mapToGlobal(pos))

            if action:
                self.controller.handleProcessAction(selectedProcesses, action)

    ###
    
    def connectScreenshotContextMenu(self):
        self.ui.ScreenshotWidget.scrollArea.customContextMenuRequested.connect(self.contextMenuScreenshot)

    def contextMenuScreenshot(self, pos):
        menu = QMenu()

        zoomInAction = menu.addAction("Zoom in (25%)")
        zoomOutAction = menu.addAction("Zoom out (25%)")
        fitToWindowAction = menu.addAction("Fit to window")
        normalSizeAction = menu.addAction("Original size")

        menu.aboutToShow.connect(self.setVisible)
        menu.aboutToHide.connect(self.setInvisible)
        
        action = menu.exec(self.ui.ScreenshotWidget.scrollArea.viewport().mapToGlobal(pos))

        if action == zoomInAction:
            self.ui.ScreenshotWidget.zoomIn()
        elif action == zoomOutAction:
            self.ui.ScreenshotWidget.zoomOut()
        elif action == fitToWindowAction:
            self.ui.ScreenshotWidget.fitToWindow()
        elif action == normalSizeAction:
            self.ui.ScreenshotWidget.normalSize()
            
    #################### LEFT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def updateHostsTableView(self):
        # Update the data source of the model with the hosts from the database
        self.HostsTableModel.setHosts(self.controller.getHostsFromDB(self.viewState.filters))

        # Set the viewState.lazy_update_hosts to False to indicate that it doesn't need to be updated anymore
        self.viewState.lazy_update_hosts = False

        ## Resize the OS column of the HostsTableView
        #self.ui.HostsTableView.horizontalHeader().resizeSection(1, 120)

        # Sort the model by the Host column in descending order
        self.HostsTableModel.sort(3, Qt.SortOrder.DescendingOrder)

        # Get the list of IPs from the model
        ips = []   # ensure that there is always something selected
        for row in range(self.HostsTableModel.rowCount("")):
            ips.append(self.HostsTableModel.getHostIPForRow(row))

        # Check if the IP we previously clicked is still visible
        if self.viewState.ip_clicked in ips:
            # Get the row for the IP we previously clicked
            row = self.HostsTableModel.getRowForIp(self.viewState.ip_clicked)
        else:
            # Select the first row
            row = 0

        # Check if the row is not None
        if row is not None:
            # Select the row in the HostsTableView
            self.ui.HostsTableView.selectRow(row)
            # Call the hostTableClick() method
            self.hostTableClick()

        # Resize the OS column of the HostsTableView
        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 120)

        # Hide colmns we don't want
        for i in [0, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]:
            self.ui.HostsTableView.hideColumn(i)

        self.viewState.lazy_update_os = True

    def updateHostsTableViewX(self):
        headers = ["Id", "OS", "Accuracy", "Host", "IPv4", "IPv6", "Mac", "Status", "Hostname", "Vendor", "Uptime",
                   "Lastboot", "Distance", "CheckedHost", "Country Code", "State", "City", "Latitude", "Longitude",
                   "Count", "Closed"]
        self.HostsTableModel = HostsTableModel(self.controller.getHostsFromDB(self.viewState.filters), headers)
        self.ui.HostsTableView.setModel(self.HostsTableModel)
        #self.HostsTableModel.setHosts(self.controller.getHostsFromDB(self.viewState.filters))

        self.viewState.lazy_update_hosts = False  # to indicate that it doesn't need to be updated anymore

        # hide some columns
        for i in [0, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]:
            self.ui.HostsTableView.setColumnHidden(i, True)

        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 120)
        self.HostsTableModel.sort(3, Qt.SortOrder.DescendingOrder)

        self.ui.HostsTableView.repaint()
        self.ui.HostsTableView.update()

        ips = []   # ensure that there is always something selected
        for row in range(self.HostsTableModel.rowCount("")):
            ips.append(self.HostsTableModel.getHostIPForRow(row))

        # the ip we previously clicked may not be visible anymore (eg: due to filters)
        if self.viewState.ip_clicked in ips:
            row = self.HostsTableModel.getRowForIp(self.viewState.ip_clicked)
        else:
            row = 0                                                     # or select the first row
            
        if not row == None:
            self.ui.HostsTableView.selectRow(row)
            self.hostTableClick()

        self.viewState.lazy_update_os = True

    def updateServiceNamesTableView(self):
        headers = ["Name"]
        self.ServiceNamesTableModel = ServiceNamesTableModel(
            self.controller.getServiceNamesFromDB(self.viewState.filters), headers)
        self.ui.ServiceNamesTableView.setModel(self.ServiceNamesTableModel)

        self.viewState.lazy_update_services = False   # to indicate that it doesn't need to be updated anymore

        services = []                                                   # ensure that there is always something selected
        for row in range(self.ServiceNamesTableModel.rowCount("")):
            services.append(self.ServiceNamesTableModel.getServiceNameForRow(row))

        # the service we previously clicked may not be visible anymore (eg: due to filters)
        if self.viewState.service_clicked in services:
            row = self.ServiceNamesTableModel.getRowForServiceName(self.viewState.service_clicked)
        else:
            row = 0                                                     # or select the first row
            
        if not row == None:
            self.ui.ServiceNamesTableView.selectRow(row)
            self.serviceNamesTableClick()

    def setupToolsTableView(self):
        headers = ["Progress", "Display", "Elapsed", "Percent Complete", "Pid", "Name", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
        tools = self.controller.getProcessesFromDB(
            self.viewState.filters, showProcesses='noNmap',
            sort=self.toolsTableViewSort,
            ncol=self.toolsTableViewSortColumn)
        self.ToolsTableModel = ProcessesTableModel(self, self._dedupeTools(tools), headers)
        self.ui.ToolsTableView.setModel(self.ToolsTableModel)

    def refreshToolsTableModel(self):
        if not self.ToolsTableModel:
            return
        processes = self.controller.getProcessesFromDB(
            self.viewState.filters,
            showProcesses='noNmap',
            sort=self.toolsTableViewSort,
            ncol=self.toolsTableViewSortColumn
        )
        self.ToolsTableModel.setDataList(self._dedupeTools(processes))

    def updateToolsTableView(self):
        if self.ui.MainTabWidget.tabText(self.ui.MainTabWidget.currentIndex()) == 'Scan' and \
                self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            processes = self.controller.getProcessesFromDB(
                self.viewState.filters,
                showProcesses='noNmap',
                sort=self.toolsTableViewSort,
                ncol=self.toolsTableViewSortColumn)
            self.ToolsTableModel.setDataList(self._dedupeTools(processes))
            self.ui.ToolsTableView.repaint()
            self.ui.ToolsTableView.update()

            self.viewState.lazy_update_tools = False  # to indicate that it doesn't need to be updated anymore

            # Hides columns we don't want to see
            column_count = self.ToolsTableModel.columnCount(None)
            for i in range(column_count):
                self.ui.ToolsTableView.setColumnHidden(i, i != 5)

            tools = []                                                  # ensure that there is always something selected
            for row in range(self.ToolsTableModel.rowCount("")):
                tools.append(self.ToolsTableModel.getToolNameForRow(row))

            # the tool we previously clicked may not be visible anymore (eg: due to filters)
            if self.viewState.tool_clicked in tools:
                row = self.ToolsTableModel.getRowForToolName(self.viewState.tool_clicked)
            else:
                row = 0                                                 # or select the first row

            if not row == None:
                self.ui.ToolsTableView.selectRow(row)
                self.toolsTableClick()

    def setupOsTabViews(self):
        headers = ["OS", "Hosts"]
        summary = self.controller.getOperatingSystemsSummary()
        self.OsListTableModel = OsSummaryTableModel(summary, headers)
        self.ui.OsListTableView.setModel(self.OsListTableModel)
        self.ui.OsListTableView.horizontalHeader().setStretchLastSection(False)
        self.ui.OsListTableView.horizontalHeader().resizeSection(0, 160)
        if self.OsListTableModel.columnCount(None) > 1:
            self.ui.OsListTableView.horizontalHeader().resizeSection(1, 80)
        self._ensureOsSelectionModelConnection()

        if summary:
            if self.viewState.os_clicked and self.OsListTableModel.getRowForOs(self.viewState.os_clicked) is not None:
                selected_os = self.viewState.os_clicked
            else:
                selected_os = summary[0].get('os')
                self.viewState.os_clicked = selected_os
            row = self.OsListTableModel.getRowForOs(selected_os)
            if row is not None:
                self.ui.OsListTableView.selectRow(row)
        else:
            self.viewState.os_clicked = 'Unknown'

        self.updateOsHostsTableView(self.viewState.os_clicked or 'Unknown')
        self.viewState.lazy_update_os = False

    def setupOsHostsTableModel(self):
        headers = ["IP", "Hostname", "OS", "Status"]
        self.OsHostsTableModel = OsHostsTableModel([], headers)
        self.ui.OsHostsTableView.setModel(self.OsHostsTableModel)
        self.ui.OsHostsTableView.horizontalHeader().setStretchLastSection(False)
        self.ui.OsHostsTableView.horizontalHeader().resizeSection(0, 150)
        self.ui.OsHostsTableView.horizontalHeader().resizeSection(1, 200)
        self.ui.OsHostsTableView.horizontalHeader().resizeSection(2, 200)

    def updateOsListView(self):
        summary = self.controller.getOperatingSystemsSummary()
        if not self.OsListTableModel:
            self.setupOsTabViews()
            return

        self.OsListTableModel.setEntries(summary)
        self._ensureOsSelectionModelConnection()

        if not summary:
            self.viewState.os_clicked = 'Unknown'
            self.updateOsHostsTableView('Unknown')
            self.viewState.lazy_update_os = False
            return

        selected_os = self.viewState.os_clicked
        if not selected_os and summary:
            selected_os = summary[0].get('os')
            self.viewState.os_clicked = selected_os

        row = self.OsListTableModel.getRowForOs(selected_os)
        if row is None and summary:
            row = 0
            self.viewState.os_clicked = self.OsListTableModel.getOsForRow(row)

        if row is not None:
            self.ui.OsListTableView.selectRow(row)

        self.updateOsHostsTableView(self.viewState.os_clicked or 'Unknown')
        self.viewState.lazy_update_os = False

    def updateOsHostsTableView(self, os_name):
        if not self.OsHostsTableModel:
            self.setupOsHostsTableModel()
        target_os = os_name or 'Unknown'
        hosts = self.controller.getHostsForOperatingSystem(target_os)
        self.OsHostsTableModel.setHosts(hosts)
        self.ui.OsHostsTableView.repaint()
        self.ui.OsHostsTableView.update()
        if not hosts:
            self.ui.OsHostsTableView.clearSelection()
        else:
            self.ui.OsHostsTableView.selectRow(0)

    def connectOsListClick(self):
        self.ui.OsListTableView.clicked.connect(self.osListClick)
        self._ensureOsSelectionModelConnection()

    def _osCurrentRowChanged(self, current, _previous):
        if not current.isValid():
            return
        self.osListClick(current)

    def _ensureOsSelectionModelConnection(self):
        selection_model = self.ui.OsListTableView.selectionModel()
        if selection_model and selection_model is not self._os_selection_model:
            if self._os_selection_model:
                try:
                    self._os_selection_model.currentRowChanged.disconnect(self._osCurrentRowChanged)
                except (TypeError, RuntimeError):
                    pass
            selection_model.currentRowChanged.connect(self._osCurrentRowChanged)
            self._os_selection_model = selection_model

    def osListClick(self, index):
        if not self.OsListTableModel:
            return
        os_name = self.OsListTableModel.getOsForRow(index.row())
        if os_name is None:
            return
        self.viewState.os_clicked = os_name
        self.updateOsHostsTableView(os_name)

    def connectOsHostsClick(self):
        self.ui.OsHostsTableView.clicked.connect(self.osHostsClick)
        self.ui.OsHostsTableView.doubleClicked.connect(self.osHostsDoubleClick)

    def osHostsClick(self, index):
        host_entry = self.OsHostsTableModel.getHostDisplay(index.row()) if self.OsHostsTableModel else None
        if not host_entry:
            return
        ip = host_entry.get('ip')
        hostname = host_entry.get('hostname')
        identifier = ip
        if hostname:
            identifier = f"{ip} ({hostname})"
        self.viewState.ip_clicked = identifier
        host_row = self.HostsTableModel.getRowForIp(ip)
        if host_row is not None:
            self.ui.HostsTableView.selectRow(host_row)
            self.hostTableClick()
        self.viewState.os_clicked = self.OsListTableModel.getOsForRow(
            self.ui.OsListTableView.selectionModel().currentIndex().row()
        ) if self.OsListTableModel else ''

    def osHostsDoubleClick(self, index):
        self.osHostsClick(index)

        
    #################### RIGHT PANEL INTERFACE UPDATE FUNCTIONS ####################
    
    def updateServiceTableView(self, hostIP):
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId", "ServiceId", "Name", "Product", "Version",
                   "Extrainfo", "Fingerprint"]
        self.ServicesTableModel = ServicesTableModel(
            self.controller.getPortsAndServicesForHostFromDB(hostIP, self.viewState.filters), headers)
        self.ui.ServicesTableView.setModel(self.ServicesTableModel)

        for i in range(0, len(headers)): # reset all the hidden columns
                self.ui.ServicesTableView.setColumnHidden(i, False)

        for i in [0,1,5,6,8,10,11]: # hide some columns
            self.ui.ServicesTableView.setColumnHidden(i, True)
        
        self.ServicesTableModel.sort(2, Qt.SortOrder.DescendingOrder) # sort by port by default (override default)

    def updatePortsByServiceTableView(self, serviceName):
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId", "ServiceId", "Name", "Product", "Version",
                   "Extrainfo", "Fingerprint"]
        self.PortsByServiceTableModel = ServicesTableModel(
            self.controller.getHostsAndPortsForServiceFromDB(serviceName, self.viewState.filters), headers)
        self.ui.ServicesTableView.setModel(self.PortsByServiceTableModel)

        for i in range(0, len(headers)):# reset all the hidden columns
                self.ui.ServicesTableView.setColumnHidden(i, False)

        for i in [2,5,6,7,8,10,11]: # hide some columns
            self.ui.ServicesTableView.setColumnHidden(i, True)
        
        self.ui.ServicesTableView.horizontalHeader().resizeSection(0,165) # resize IP
        self.ui.ServicesTableView.horizontalHeader().resizeSection(1,65) # resize port
        self.ui.ServicesTableView.horizontalHeader().resizeSection(3,100) # resize protocol
        self.PortsByServiceTableModel.sort(0, Qt.SortOrder.DescendingOrder) # sort by IP by default (override default)

    def updateInformationView(self, hostIP):

        if hostIP:
            host = self.controller.getHostInformation(hostIP)
            
            if host:
                states = self.controller.getPortStatesForHost(host.id)
                counterOpen = counterClosed = counterFiltered = 0

                for s in states:
                    if s[0] == 'open':
                        counterOpen+=1
                    elif s[0] == 'closed':
                        counterClosed+=1
                    else:
                        counterFiltered+=1
                
                if host.state == 'closed':                              # check the extra ports
                    counterClosed = 65535 - counterOpen - counterFiltered
                else:
                    counterFiltered = 65535 - counterOpen - counterClosed

                self.hostInfoWidget.updateFields(status=host.status, openPorts=counterOpen, closedPorts=counterClosed,
                                                 filteredPorts=counterFiltered, ipv4=host.ipv4, ipv6=host.ipv6,
                                                 macaddr=host.macaddr, osMatch=host.osMatch, osAccuracy=host.osAccuracy,
                                                 vendor=host.vendor, asn=host.asn, isp=host.isp,
                                                 countryCode=host.countryCode, city=host.city, latitude=host.latitude,
                                                 longitude=host.longitude)

    def updateScriptsView(self, hostIP):
        headers = ["Id", "Script", "Port", "Protocol"]
        self.ScriptsTableModel = ScriptsTableModel(self,self.controller.getScriptsFromDB(hostIP), headers)
        self.ui.ScriptsTableView.setModel(self.ScriptsTableModel)

        for i in [0,3]:                                                 # hide some columns
            self.ui.ScriptsTableView.setColumnHidden(i, True)
    
        scripts = []                                                    # ensure that there is always something selected
        for row in range(self.ScriptsTableModel.rowCount("")):
            scripts.append(self.ScriptsTableModel.getScriptDBIdForRow(row))

        # the script we previously clicked may not be visible anymore (eg: due to filters)
        if self.viewState.script_clicked in scripts:
            row = self.ScriptsTableModel.getRowForDBId(self.viewState.script_clicked)

        else:
            row = 0                                                     # or select the first row
            
        if not row == None:
            self.ui.ScriptsTableView.selectRow(row)
            self.scriptTableClick()

        self.ui.ScriptsTableView.repaint()
        self.ui.ScriptsTableView.update()

    def updateCvesByHostView(self, hostIP):
        headers = ["CVE Id", "CVSS Score", "Product", "Version", "CVE URL", "Source", "ExploitDb ID", "ExploitDb",
                   "ExploitDb URL"]
        cves = self.controller.getCvesFromDB(hostIP)
        self.CvesTableModel = CvesTableModel(self, cves, headers)

        self.ui.CvesTableView.horizontalHeader().resizeSection(0,175)
        self.ui.CvesTableView.horizontalHeader().resizeSection(2,175)
        self.ui.CvesTableView.horizontalHeader().resizeSection(4,225)

        self.ui.CvesTableView.setModel(self.CvesTableModel)
        self.ui.CvesTableView.repaint()
        self.ui.CvesTableView.update()

    def updateScriptsOutputView(self, scriptId):
        self.ui.ScriptsOutputTextEdit.clear()
        lines = self.controller.getScriptOutputFromDB(scriptId)
        for line in lines:
            self.ui.ScriptsOutputTextEdit.insertPlainText(line['output'].rstrip())

    # TODO: check if this hack can be improved because we are calling setDirty more than we need
    def updateNotesView(self, hostid):
        self.viewState.lastHostIdClicked = str(hostid)
        note = self.controller.getNoteFromDB(hostid)
        
        saved_dirty = self.viewState.dirty  # save the status so we can restore it after we update the note panel
        self.ui.NotesTextEdit.clear()                                   # clear the text box from the previous notes
            
        if note:
            self.ui.NotesTextEdit.insertPlainText(note.text)
        
        if saved_dirty == False:
            self.setDirty(False)

    def updateToolHostsTableView(self, toolname):
        headers = ["Progress", "Display", "Elapsed", "Percent Complete", "Pid", "Name", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
        self.ToolHostsTableModel = ProcessesTableModel(self, self.controller.getHostsForTool(toolname), headers)
        self.ui.ToolHostsTableView.setModel(self.ToolHostsTableModel)

        for i in [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15]:                         # hide some columns
            self.ui.ToolHostsTableView.setColumnHidden(i, True)
        
        self.ui.ToolHostsTableView.horizontalHeader().resizeSection(7, 150)  # default width for Host column

        ids = []                                                        # ensure that there is always something selected
        for row in range(self.ToolHostsTableModel.rowCount("")):
            ids.append(self.ToolHostsTableModel.getProcessIdForRow(row))

        # the host we previously clicked may not be visible anymore (eg: due to filters)
        if self.viewState.tool_host_clicked in ids:
            row = self.ToolHostsTableModel.getRowForDBId(self.viewState.tool_host_clicked)

        else:
            row = 0  # or select the first row

        if not row == None and self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            self.ui.ToolHostsTableView.selectRow(row)
            self.toolHostsClick()

    def updateRightPanel(self, hostIP):
        self.updateServiceTableView(hostIP)
        self.updateScriptsView(hostIP)
        self.updateCvesByHostView(hostIP)
        self.updateInformationView(hostIP)                              # populate host info tab
        self.controller.saveProject(self.viewState.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

        if hostIP:
            self.updateNotesView(self.HostsTableModel.getHostIdForRow(self.HostsTableModel.getRowForIp(hostIP)))
        else:
            self.updateNotesView('')
            
    def displayToolPanel(self, display=False):
        size = self.ui.splitter.parentWidget().width() - self.leftPanelSize - 24       # note: 24 is a fixed value
        if display:
            self.ui.ServicesTabWidget.hide()
            self.ui.splitter_3.show()
            self.ui.splitter.setSizes([self.leftPanelSize, 0, size])                     # reset hoststableview width
            
            if self.viewState.tool_clicked == 'screenshooter':
                self.displayScreenshots(True)
            else:
                self.displayScreenshots(False)
                #self.ui.splitter_3.setSizes([275,size-275,0])          # reset middle panel width

        else:
            self.ui.splitter_3.hide()
            self.ui.ServicesTabWidget.show()
            self.ui.splitter.setSizes([self.leftPanelSize, size, 0])

    def displayScreenshots(self, display=False):
        size = self.ui.splitter.parentWidget().width() - self.leftPanelSize - 24       # note: 24 is a fixed value

        if display:
            self.ui.DisplayWidget.hide()
            self.ui.ScreenshotWidget.scrollArea.show()
            self.ui.splitter_3.setSizes([275, 0, size - 275])               # reset middle panel width

        else:
            self.ui.ScreenshotWidget.scrollArea.hide()
            self.ui.DisplayWidget.show()
            self.ui.splitter_3.setSizes([275, size - 275, 0])               # reset middle panel width

    def displayAddHostsOverlay(self, display=False):
        if display:
            self.ui.addHostsOverlay.show()
            self.ui.HostsTableView.hide()
        else:
            self.ui.addHostsOverlay.hide()
            self.ui.HostsTableView.show()
            
    #################### BOTTOM PANEL INTERFACE UPDATE FUNCTIONS ####################

    def onProcessStatusFilterChanged(self, _index):
        self.processStatusFilter = self.ui.ProcessStatusFilterComboBox.currentData()
        if self.ProcessesTableModel is None:
            self.setupProcessesTableView()
        else:
            self.updateProcessesTableView()

    def _normalizeProcessRows(self, raw_processes):
        process_columns = [
            "pid", "id", "display", "name", "tabTitle", "hostIp", "port", "protocol", "command",
            "startTime", "endTime", "estimatedRemaining", "elapsed", "outputfile", "status", "closed", "percent"
        ]
        processes = []
        for row in raw_processes:
            if isinstance(row, dict):
                proc = dict(row)
            else:
                try:
                    proc = dict(zip(process_columns, row))
                except Exception:
                    proc = {}
            if "percent" not in proc:
                proc["percent"] = "Unknown"
            if proc.get("elapsed") in (None, ""):
                proc["elapsed"] = 0
            processes.append(proc)
        return processes

    def _getProcessesForDisplay(self):
        try:
            raw_processes = self.controller.getProcessesFromDB(
                self.viewState.filters,
                showProcesses=True,
                sort=self.processesTableViewSort,
                ncol=self.processesTableViewSortColumn,
                status_filter=self.processStatusFilter
            )
        except Exception as exc:
            # During shutdown or project teardown the temporary DB file may already be gone, which can
            # surface as "no such table: process" when SQLite re-creates an empty file on open.
            try:
                from sqlalchemy.exc import OperationalError
            except Exception:
                OperationalError = None
            msg = str(exc).lower()
            if OperationalError is not None and isinstance(exc, OperationalError) and "no such table" in msg:
                log.info("Process table not available; returning empty processes list.")
            else:
                log.exception("Failed to fetch processes from DB for display")
            raw_processes = []
        return self._normalizeProcessRows(raw_processes)

    def setupProcessesTableView(self):
        headers = ["Progress", "Display", "Run time", "Percent Complete", "Pid", "Name", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
        processes = self._getProcessesForDisplay()
        self.ProcessesTableModel = ProcessesTableModel(self, processes, headers)
        self.ui.ProcessesTableView.setModel(self.ProcessesTableModel)
        self.ProcessesTableModel.sort(15, Qt.SortOrder.DescendingOrder)
        self._configureProcessesColumns()

    def updateProcessesTableView(self):
        processes = self._getProcessesForDisplay()
        self.ProcessesTableModel.setDataList(processes)
        self._configureProcessesColumns()
        self.ui.ProcessesTableView.repaint()
        self.ui.ProcessesTableView.update()
        # Update animations
        self.updateProcessesIcon()

    def _configureProcessesColumns(self):
        if not self.ProcessesTableModel:
            return
        header = self.ui.ProcessesTableView.horizontalHeader()
        visible_columns = {0, 2, 6, 7, 15}
        total_columns = self.ProcessesTableModel.columnCount(None)
        for col in range(total_columns):
            self.ui.ProcessesTableView.setColumnHidden(col, col not in visible_columns)
        header.resizeSection(0, 125)
        header.resizeSection(2, 110)
        header.resizeSection(6, 260)
        header.resizeSection(7, 260)
        header.resizeSection(15, 110)

    def _initToolTabContextMenu(self):
        tabBar = self.ui.ServicesTabWidget.tabBar()
        tabBar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tabBar.customContextMenuRequested.connect(self._showToolTabContextMenu)

    def _showToolTabContextMenu(self, pos):
        tabBar = self.ui.ServicesTabWidget.tabBar()
        index = tabBar.tabAt(pos)
        if index < 0 or index < getattr(self, 'fixedTabsCount', 0):
            return

        widget = self.ui.ServicesTabWidget.widget(index)
        if widget is None:
            return

        menu = QtWidgets.QMenu(self.ui.ServicesTabWidget)
        saveAction = menu.addAction('Save')
        globalPos = tabBar.mapToGlobal(pos)
        chosen = menu.exec(globalPos)
        if chosen == saveAction:
            self._saveToolTabContent(index, widget)

    def _suggest_filename(self, base_name, extension):
        safe = ''.join(ch if ch.isalnum() or ch in (' ', '_', '-') else '_' for ch in base_name or 'output')
        safe = safe.strip().replace(' ', '_') or 'output'
        if not safe.lower().endswith(f".{extension}"):
            safe += f".{extension}"
        return safe

    def _save_tool_text(self, widget, tab_title):
        text_edit = widget if isinstance(widget, QtWidgets.QPlainTextEdit) else widget.findChild(QtWidgets.QPlainTextEdit)
        if not text_edit:
            log.info(f"No textual content found for tab '{tab_title}'")
            return
        content = text_edit.toPlainText()
        default_path = self._suggest_filename(tab_title, 'txt')
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.ui.centralwidget,
            'Save Tool Output',
            default_path,
            'Text Files (*.txt);;All Files (*)'
        )
        if not filename:
            return
        if not filename.lower().endswith('.txt'):
            filename += '.txt'
        try:
            log.info(f"Saving tool output from tab '{tab_title}' to {filename}")
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write(content)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(
                self.ui.centralwidget,
                'Save Failed',
                f'Unable to save file:\n{exc}'
            )

    def _save_tool_image(self, widget, tab_title):
        image_viewer = None
        if isinstance(widget, ImageViewer):
            image_viewer = widget
        elif isinstance(widget, QtWidgets.QScrollArea):
            viewer_ref = getattr(widget, '_imageViewerRef', None)
            if isinstance(viewer_ref, ImageViewer):
                image_viewer = viewer_ref
        elif hasattr(widget, 'imageLabel') and isinstance(widget, QtWidgets.QWidget):
            image_viewer = widget

        if image_viewer is None and isinstance(widget, QtWidgets.QWidget):
            parent = widget.parentWidget()
            while parent and image_viewer is None:
                if isinstance(parent, ImageViewer):
                    image_viewer = parent
                    break
                parent = parent.parentWidget()

        if image_viewer is None:
            log.info(f"No screenshot content found for tab '{tab_title}'")
            return

        default_path = self._suggest_filename(tab_title, 'png')
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.ui.centralwidget,
            'Save Screenshot',
            default_path,
            'PNG Images (*.png);;All Files (*)'
        )
        if not filename:
            return
        if not filename.lower().endswith('.png'):
            filename += '.png'

        image_path = getattr(image_viewer, 'currentImagePath', None)
        try:
            if image_path and os.path.isfile(image_path):
                log.info(f"Copying screenshot from {image_path} to {filename}")
                shutil.copyfile(image_path, filename)
                return
            image_label = getattr(image_viewer, 'imageLabel', None)
            pixmap = image_label.pixmap() if image_label else None
            if pixmap:
                log.info(f"Saving screenshot pixmap from tab '{tab_title}' to {filename}")
                pixmap.save(filename, 'PNG')
            else:
                raise IOError('No image data available.')
        except Exception as exc:
            QtWidgets.QMessageBox.warning(
                self.ui.centralwidget,
                'Save Failed',
                f'Unable to save screenshot:\n{exc}'
            )

    def _saveToolTabContent(self, index, widget):
        tab_title = self.ui.ServicesTabWidget.tabText(index)
        log.info(f"Tool tab save requested: index={index}, title='{tab_title}', widget={type(widget)}")
        if widget.findChild(QtWidgets.QPlainTextEdit):
            self._save_tool_text(widget, tab_title)
            return
        if hasattr(widget, 'imageLabel'):
            self._save_tool_image(widget, tab_title)
            return
        # If widget is directly a QPlainTextEdit or ImageViewer
        if isinstance(widget, QtWidgets.QPlainTextEdit):
            self._save_tool_text(widget, tab_title)
        elif isinstance(widget, ImageViewer):
            self._save_tool_image(widget, tab_title)
        elif isinstance(widget, QtWidgets.QScrollArea):
            self._save_tool_image(widget, tab_title)

    def updateProcessesIcon(self):
        if self.ProcessesTableModel:
            for row in range(len(self.ProcessesTableModel.getProcesses())):
                status = self.ProcessesTableModel.getProcesses()[row]['status']
                
                directStatus = {'Waiting':'waiting', 'Running':'running', 'Finished':'finished', 'Crashed':'killed'}
                defaultStatus = 'killed'

                processIconName = directStatus.get(status) or defaultStatus
                processIcon = './images/{processIconName}.gif'.format(processIconName=processIconName)

                self.runningWidget = ImagePlayer(processIcon)
                self.ui.ProcessesTableView.setIndexWidget(self.ui.ProcessesTableView.model().index(row,0),
                                                          self.runningWidget)

    #################### GLOBAL INTERFACE UPDATE FUNCTION ####################
    
    # TODO: when nmap file is imported select last IP clicked (or first row if none)
    from PyQt6 import QtCore
    @QtCore.pyqtSlot()
    def updateInterface(self):
        self.ui_mainwindow.show()

        if self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Hosts':
            self.updateHostsTableView()
            self.viewState.lazy_update_services = True
            self.viewState.lazy_update_tools = True
            self.viewState.lazy_update_os = True

        elif self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Services':
            self.updateServiceNamesTableView()
            self.viewState.lazy_update_hosts = True
            self.viewState.lazy_update_tools = True
            self.viewState.lazy_update_os = True

        elif self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            self.updateToolsTableView()
            self.viewState.lazy_update_hosts = True
            self.viewState.lazy_update_services = True
            self.viewState.lazy_update_os = True

        elif self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'OS':
            if self.viewState.lazy_update_os or not self.OsListTableModel:
                self.updateOsListView()
            else:
                self.updateOsHostsTableView(self.viewState.os_clicked or 'Unknown')
            self.viewState.lazy_update_hosts = True
            self.viewState.lazy_update_services = True
            self.viewState.lazy_update_tools = True
        
    #################### TOOL TABS ####################

    # this function creates a new tool tab for a given host
    # TODO: refactor/review, especially the restoring part. we should not check if toolname=nmap everywhere in the code
    # ..maybe we should do it here. rethink
    def createNewTabForHost(self, ip, tabTitle, restoring=False, content='', filename=''):
        # TODO: use regex otherwise tools with 'screenshot' in the name are screwed.
        if 'screenshot' in str(tabTitle):
            image_viewer = ImageViewer()
            image_viewer.setObjectName(str(tabTitle))
            image_viewer.open(str(filename))
            tempWidget = image_viewer.scrollArea
            tempWidget.setObjectName(str(tabTitle))
            tempWidget._imageViewerRef = image_viewer
        else:
            tempWidget = QtWidgets.QWidget()
            tempWidget.setObjectName(str(tabTitle))
            tempTextView = QtWidgets.QPlainTextEdit(tempWidget)
            tempTextView.setReadOnly(True)
            if self.controller.getSettings().general_tool_output_black_background == 'True':
                p = tempTextView.palette()
                p.setColor(QtGui.QPalette.ColorRole.Base, Qt.GlobalColor.black)               # black background
                p.setColor(QtGui.QPalette.ColorRole.Text, Qt.GlobalColor.white)               # white font
                tempTextView.setPalette(p)
                # font-size:18px; width: 150px; color:red; left: 20px;}"); # set the menu font color: black
                tempTextView.setStyleSheet("QMenu { color:black;}")
            tempLayout = QtWidgets.QHBoxLayout(tempWidget)
            tempLayout.addWidget(tempTextView)
        
            if not content == '':                                       # if there is any content to display
                tempTextView.appendPlainText(content)

        # if restoring tabs (after opening a project) don't show the tab in the ui
        if restoring == False:
            self.ui.ServicesTabWidget.addTab(tempWidget, str(tabTitle))
    
        hosttabs = []                                                   # fetch tab list for this host (if any)
        if str(ip) in self.viewState.hostTabs:
            hosttabs = self.viewState.hostTabs[str(ip)]
        
        if 'screenshot' in str(tabTitle):
            hosttabs.append(tempWidget)                                 # add scroll area for screenshot tabs
        else:
            hosttabs.append(tempWidget)                                 # add the new tab to the list
        
        self.viewState.hostTabs.update({str(ip):hosttabs})

        if 'screenshot' in str(tabTitle):
            return tempWidget
        return tempTextView


    def createNewConsole(self, tabTitle, content='Hello\n', filename=''):

        tempWidget = QtWidgets.QWidget()
        tempWidget.setObjectName(str(tabTitle))
        tempTextView = QtWidgets.QPlainTextEdit(tempWidget)
        tempTextView.setReadOnly(True)
        if self.controller.getSettings().general_tool_output_black_background == 'True':
            p = tempTextView.palette()
            p.setColor(QtGui.QPalette.ColorRole.Base, Qt.GlobalColor.black)               # black background
            p.setColor(QtGui.QPalette.ColorRole.Text, Qt.GlobalColor.white)               # white font
            tempTextView.setPalette(p)
            # font-size:18px; width: 150px; color:red; left: 20px;}"); # set the menu font color: black
            tempTextView.setStyleSheet("QMenu { color:black;}")
        tempLayout = QtWidgets.QHBoxLayout(tempWidget)
        tempLayout.addWidget(tempTextView)
        self.ui.PythonTabLayout.addWidget(tempWidget)

        if not content == '':                                       # if there is any content to display
            tempTextView.appendPlainText(content)


        return tempTextView

    def closeHostToolTab(self, index):
        self._closeProcessTab(
            tabWidget=self.ui.ServicesTabWidget,
            index=index,
            getStatusFunc=self.controller.getProcessStatusForDBId,
            getPidFunc=self.controller.getPidForProcess,
            killFunc=self.controller.killProcess,
            cancelFunc=self.controller.cancelProcess,
            storeCloseFunc=self.controller.storeCloseTabStatusInDB,
            hostTabsDict=self.viewState.hostTabs,
            isBruteTab=False
        )

    def _closeProcessTab(self, tabWidget, index, getStatusFunc, getPidFunc, killFunc, cancelFunc, storeCloseFunc, hostTabsDict, isBruteTab):
        """
        Helper to close a process tab (host tool or brute tab) with shared logic.
        """
        currentTabIndex = tabWidget.currentIndex()
        tabWidget.setCurrentIndex(index)
        currentWidget = tabWidget.currentWidget()

        # Get dbId depending on tab type
        if not isBruteTab and 'screenshot' in str(currentWidget.objectName()):
            dbId_prop = currentWidget.property('dbId')
            dbId = int(dbId_prop) if dbId_prop is not None else None
        elif not isBruteTab:
            text_widget = currentWidget.findChild(QtWidgets.QPlainTextEdit)
            dbId_prop = text_widget.property('dbId') if text_widget else None
            dbId = int(dbId_prop) if dbId_prop is not None else None
        else:
            dbId_prop = getattr(currentWidget.display, 'property', lambda x: None)('dbId')
            dbId = int(dbId_prop) if dbId_prop not in (None, '') else None

        if dbId is None:
            log.warning("No dbId found for tab being closed; skipping DB status update.")
            tabWidget.removeTab(index)
            return

        pid = getPidFunc(dbId)

        status = str(getStatusFunc(dbId))
        if status == 'Running':
            message = "This process is still running. Are you sure you want to kill it?"
            reply = self.yesNoDialog(message, 'Confirm')
            if reply == QtWidgets.QMessageBox.StandardButton.Yes:
                killFunc(pid, dbId)
            else:
                return

        if status == 'Waiting':
            message = "This process is waiting to start. Are you sure you want to cancel it?"
            reply = self.yesNoDialog(message, 'Confirm')
            if reply == QtWidgets.QMessageBox.StandardButton.Yes:
                cancelFunc(dbId)
            else:
                return

        # Remove tab from hostTabs
        for ip in list(hostTabsDict.keys()):
            if currentWidget in hostTabsDict[ip]:
                hostTabsDict[ip].remove(currentWidget)
                hostTabsDict.update({ip: hostTabsDict[ip]})
                break

        storeCloseFunc(dbId)
        tabWidget.removeTab(index)

        if currentTabIndex >= tabWidget.currentIndex():
            tabWidget.setCurrentIndex(currentTabIndex - 1)
        else:
            tabWidget.setCurrentIndex(currentTabIndex)

        # For brute tabs, add default tab if none remain
        if isBruteTab and tabWidget.count() == 0:
            self.createNewBruteTab('127.0.0.1', '22', 'ssh')

    # this function removes tabs that were created when running tools (starting from the end to avoid index problems)
    def removeToolTabs(self, position=-1):
        if position == -1:
            position = self.fixedTabsCount-1
        for i in range(self.ui.ServicesTabWidget.count()-1, position, -1):
            self.ui.ServicesTabWidget.removeTab(i)

    # this function restores the tool tabs based on the DB content (should be called when opening an existing project).
    def restoreToolTabs(self):
        # false means we are fetching processes with display flag=False, which is the case for every process once
        # a project is closed.
        tools = self.controller.getProcessesForRestore()
        nbr = len(tools)  # show a progress bar because this could take long
        if nbr==0:
            nbr=1
        progress = 100.0 / nbr
        totalprogress = 0
        self.tick.emit(int(totalprogress))
        def _get_process_field(process_info, key, default_value=''):
            if isinstance(process_info, dict):
                return process_info.get(key, default_value)
            return getattr(process_info, key, default_value)
        for t in tools:
            tab_title = _get_process_field(t, 'tabTitle', '')
            if tab_title != '':
                host_ip = _get_process_field(t, 'hostIp', '')
                output_file = _get_process_field(t, 'outputfile', '')
                output_content = _get_process_field(t, 'output', '')
                process_id = _get_process_field(t, 'id', '')
                if 'screenshot' in str(tab_title):
                    imageviewer = self.createNewTabForHost(
                        host_ip, tab_title, True, '',
                        str(self.controller.getOutputFolder())+'/screenshots/'+str(output_file))
                    imageviewer.setObjectName(str(tab_title))
                    imageviewer.setProperty('dbId', str(process_id))
                else:
                    # True means we are restoring tabs. Set the widget's object name to the DB id of the process
                    tab_widget = self.createNewTabForHost(host_ip, tab_title, True, output_content)
                    tab_widget.setProperty('dbId', str(process_id))

            totalprogress += progress                                   # update the progress bar
            self.tick.emit(int(totalprogress))
        
    def restoreToolTabsForHost(self, ip):
        if (self.viewState.hostTabs) and (ip in self.viewState.hostTabs):
            tabs = self.viewState.hostTabs[ip]    # use the ip as a key to retrieve its list of tooltabs
            for tab in tabs:
                # do not display hydra and nmap tabs when restoring for that host
                if 'hydra' not in tab.objectName() and 'nmap' not in tab.objectName():
                    self.ui.ServicesTabWidget.addTab(tab, tab.objectName())

    # this function restores the textview widget (now in the tools display widget) to its original tool tab
    # (under the correct host)
    def restoreToolTabWidget(self, clear=False):
        if self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit) == self.ui.toolOutputTextView:
            return
        
        for host in self.viewState.hostTabs.keys():
            hosttabs = self.viewState.hostTabs[host]
            for tab in hosttabs:
                if 'screenshot' not in str(tab.objectName()) and not tab.findChild(QtWidgets.QPlainTextEdit):
                    tab.layout().addWidget(self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit))
                    break

        if clear:
            # remove the tool output currently in the tools display panel
            if self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit):
                self.ui.DisplayWidget.findChild(QtWidgets.QPlainTextEdit).setParent(None)
                
            self.ui.DisplayWidgetLayout.addWidget(self.ui.toolOutputTextView)

    #################### BRUTE TABS ####################
    
    def createNewBruteTab(self, ip, port, service):
        self.ui.statusbar.showMessage('Sending to Brute: '+str(ip)+':'+str(port)+' ('+str(service)+')', msecs=1000)
        bWidget = BruteWidget(ip, port, service, self.controller.getSettings())
        bWidget.runButton.clicked.connect(lambda: self.callHydra(bWidget))
        self.ui.BruteTabWidget.addTab(bWidget, str(self.viewState.bruteTabCount))
        self.viewState.bruteTabCount += 1                                                     # update tab count
        # show the last added tab in the brute widget
        self.ui.BruteTabWidget.setCurrentIndex(self.ui.BruteTabWidget.count()-1)

    def closeBruteTab(self, index):
        self._closeProcessTab(
            tabWidget=self.ui.BruteTabWidget,
            index=index,
            getStatusFunc=lambda dbId: self.ProcessesTableModel.getProcessStatusForPid(self.ui.BruteTabWidget.currentWidget().pid),
            getPidFunc=lambda dbId: self.ui.BruteTabWidget.currentWidget().pid,
            killFunc=lambda pid, dbId: self.killBruteProcess(self.ui.BruteTabWidget.currentWidget()),
            cancelFunc=lambda dbId: self.killBruteProcess(self.ui.BruteTabWidget.currentWidget()),
            storeCloseFunc=lambda dbId: self.controller.storeCloseTabStatusInDB(int(self.ui.BruteTabWidget.currentWidget().display.property('dbId'))),
            hostTabsDict=self.viewState.hostTabs,
            isBruteTab=True
        )

    def resetBruteTabs(self):
        count = self.ui.BruteTabWidget.count()
        for i in range(0, count):
            self.ui.BruteTabWidget.removeTab(count -i -1)
        self.createNewBruteTab('127.0.0.1', '22', 'ssh')

    # TODO: show udp in tabTitle when udp service
    def callHydra(self, bWidget):
        if validateNmapInput(bWidget.ipTextinput.text()) and validateNmapInput(bWidget.portTextinput.text()):
                                                                        # check if host is already in scope
            if not self.controller.isHostInDB(bWidget.ipTextinput.text()):
                message = "This host is not in scope. Add it to scope and continue?"
                reply = self.yesNoDialog(message, 'Confirm')
                if reply == QtWidgets.QMessageBox.StandardButton.No:
                    return
                else:
                    log.info('Adding host to scope here!!')
                    self.controller.addHosts(
                        targetHosts=str(bWidget.ipTextinput.text()).replace(';', ' '),
                        runHostDiscovery=False,
                        runStagedNmap=False,
                        nmapSpeed="unset",
                        scanMode="unset",
                        nmapOptions=[],
                        enableIPv6=False
                    )
            
            bWidget.validationLabel.hide()
            bWidget.toggleRunButton()
            bWidget.resetDisplay()                                      # fixes tab bug
            
            hydraCommand = bWidget.buildHydraCommand(self.controller.getRunningFolder(),
                                                     self.controller.getUserlistPath(),
                                                     self.controller.getPasslistPath())
            bWidget.setObjectName(str("hydra"+" ("+bWidget.getPort()+"/tcp)"))
            
            hosttabs = []  # add widget to host tabs (needed to be able to move the widget between brute/tools tabs)
            if str(bWidget.ip) in self.viewState.hostTabs:
                hosttabs = self.viewState.hostTabs[str(bWidget.ip)]
                
            hosttabs.append(bWidget)
            self.viewState.hostTabs.update({str(bWidget.ip):hosttabs})
            
            bWidget.pid = self.controller.runCommand("hydra", bWidget.objectName(), bWidget.ip, bWidget.getPort(),
                                                     'tcp', unicode(hydraCommand), getTimestamp(human=True),
                                                     bWidget.outputfile, bWidget.display)
            bWidget.runButton.clicked.disconnect()
            bWidget.runButton.clicked.connect(lambda: self.killBruteProcess(bWidget))
            
        else:
            bWidget.validationLabel.show()
        
    def killBruteProcess(self, bWidget):
        dbId = str(bWidget.display.property('dbId'))
        status = self.controller.getProcessStatusForDBId(dbId)
        if status == "Running":                                         # check if we need to kill or cancel
            self.controller.killProcess(self.controller.getPidForProcess(dbId), dbId)
            
        elif status == "Waiting":
            self.controller.cancelProcess(dbId)
        self.bruteProcessFinished(bWidget)
        
    def bruteProcessFinished(self, bWidget):
        bWidget.toggleRunButton()
        bWidget.pid = -1
        
        # disassociate textview from bWidget (create new textview for bWidget) and replace it with a new host tab
        self.createNewTabForHost(
            str(bWidget.ip), str(bWidget.objectName()), restoring=True,
            content=unicode(bWidget.display.toPlainText())).setProperty('dbId', str(bWidget.display.property('dbId')))
        
        hosttabs = []  # go through host tabs and find the correct bWidget
        if str(bWidget.ip) in self.viewState.hostTabs:
            hosttabs = self.viewState.hostTabs[str(bWidget.ip)]

        if hosttabs.count(bWidget) > 1:
            hosttabs.remove(bWidget)
        
        self.viewState.hostTabs.update({str(bWidget.ip):hosttabs})

        bWidget.runButton.clicked.disconnect()
        bWidget.runButton.clicked.connect(lambda: self.callHydra(bWidget))

    def findFinishedBruteTab(self, pid):
        for i in range(0, self.ui.BruteTabWidget.count()):
            if str(self.ui.BruteTabWidget.widget(i)) == pid:
                self.bruteProcessFinished(self.ui.BruteTabWidget.widget(i))
                return

    def findFinishedServiceTab(self, pid):
        for i in range(0, self.ui.ServicesTabWidget.count()):
            if str(self.ui.ServicesTabWidget.widget(i)) == pid:
                self.bruteProcessFinished(self.ui.BruteTabWidget.widget(i))
                log.info("Close Tab: {0}".format(str(i)))
                return

    def blinkBruteTab(self, bWidget):
        self.ui.MainTabWidget.tabBar().setTabTextColor(1, QtGui.QColor('red'))
        for i in range(0, self.ui.BruteTabWidget.count()):
            if self.ui.BruteTabWidget.widget(i) == bWidget:
                self.ui.BruteTabWidget.tabBar().setTabTextColor(i, QtGui.QColor('red'))
                return

    def _tool_executable_exists(self, executable: str, friendly_name: str) -> bool:
        if not executable:
            return False
        exists = False
        if os.path.isabs(executable):
            exists = os.path.isfile(executable) and os.access(executable, os.X_OK)
        else:
            exists = shutil.which(executable) is not None

        if not exists:
            QtWidgets.QMessageBox.warning(
                self.ui.centralwidget,
                f"{friendly_name} Not Found",
                (
                    f"{friendly_name} executable '{executable}' was not found.\n\n"
                    "Please install the tool or set the correct path via Help > Config."
                )
            )
        return exists

    #################### RESPONDER / RELAY TABS ####################

    def resetResponderTabs(self):
        count = self.ui.ResponderTabWidget.count()
        for i in range(count - 1, -1, -1):
            self.ui.ResponderTabWidget.removeTab(i)
        self.viewState.responderTabCount = 1
        self.responderWidgets.clear()
        self.createNewResponderTab()

    def createNewResponderTab(self):
        widget = ResponderWidget(self.controller.getSettings())
        widget.runButton.clicked.connect(lambda: self.callResponder(widget))
        label = f"Session {self.viewState.responderTabCount}"
        self.ui.ResponderTabWidget.addTab(widget, label)
        self.viewState.responderTabCount += 1
        self.ui.ResponderTabWidget.setCurrentIndex(self.ui.ResponderTabWidget.count() - 1)

    def closeResponderTab(self, index):
        widget = self.ui.ResponderTabWidget.widget(index)
        db_id = str(widget.display.property('dbId')) if widget.display.property('dbId') else ''

        def status_lookup(dbId):
            return self.controller.getProcessStatusForDBId(dbId) if dbId else 'Finished'

        def pid_lookup(dbId):
            return self.controller.getPidForProcess(dbId) if dbId else -1

        self._closeProcessTab(
            tabWidget=self.ui.ResponderTabWidget,
            index=index,
            getStatusFunc=status_lookup,
            getPidFunc=pid_lookup,
            killFunc=lambda pid, dbId: self.killResponderProcess(widget),
            cancelFunc=lambda dbId: self.killResponderProcess(widget),
            storeCloseFunc=lambda dbId: self.controller.storeCloseTabStatusInDB(int(dbId)) if dbId else None,
            hostTabsDict=self.viewState.hostTabs,
            isBruteTab=False
        )
        if db_id in self.responderWidgets:
            self.responderWidgets.pop(db_id, None)

    def callResponder(self, widget):
        try:
            command = widget.buildCommand(self.controller.getRunningFolder())
        except ValueError as exc:
            widget.showValidation(str(exc))
            return
        except Exception as exc:
            log.exception("Failed to build responder/relay command")
            widget.showValidation(str(exc))
            return

        tool_name = widget.getTool()
        executable = getattr(widget, 'command_executable', '') or tool_name.lower()
        if not self._tool_executable_exists(executable, tool_name):
            widget.showValidation(
                f"{tool_name} executable not found. Install it or set the path via Help > Config."
            )
            return

        widget.hideValidation()
        widget.resetDisplay()
        widget.toggleRunButton(True)
        self.ui.statusbar.showMessage(f'Launching {tool_name} session', msecs=1000)
        widget.setObjectName(f"{tool_name.lower()}-session")

        host_value = widget.getTarget() or widget.getSource() or '0.0.0.0'
        pid = self.controller.runCommand(
            tool_name.lower(),
            widget.objectName(),
            host_value,
            widget.getTarget() or '0',
            'tcp',
            command,
            getTimestamp(human=True),
            widget.outputfile,
            widget.display
        )
        widget.pid = pid
        try:
            widget.runButton.clicked.disconnect()
        except Exception:
            pass
        widget.runButton.clicked.connect(lambda: self.killResponderProcess(widget))

        db_id = widget.display.property('dbId')
        if db_id:
            self.responderWidgets[str(db_id)] = widget

    def killResponderProcess(self, widget):
        db_id = widget.display.property('dbId')
        if not db_id:
            widget.toggleRunButton(False)
            return
        db_id = str(db_id)
        status = self.controller.getProcessStatusForDBId(db_id)
        if status in ("Running", "Waiting"):
            try:
                pid = self.controller.getPidForProcess(db_id)
                self.controller.killProcess(pid, db_id)
            except Exception:
                log.exception(f"Failed to terminate responder/relay process {db_id}")
        self.responderProcessFinished(db_id)

    def responderProcessFinished(self, db_id):
        widget = self.responderWidgets.pop(str(db_id), None)
        if not widget:
            return
        widget.toggleRunButton(False)
        widget.pid = -1
        try:
            widget.runButton.clicked.disconnect()
        except Exception:
            pass
        widget.runButton.clicked.connect(lambda: self.callResponder(widget))
        widget.hideValidation()
        self.updateResponderResultsTable()

    def updateResponderResultsTable(self):
        if not hasattr(self, 'credentialModel'):
            return
        captures = []
        try:
            captures = self.controller.logic.activeProject.repositoryContainer.credentialRepository.getAllCaptures()
        except Exception:
            log.exception("Failed to refresh credential capture data")
        self.credentialModel.setCaptures(captures)
        self.ui.ResponderResultsTableView.resizeColumnsToContents()
    def _dedupeTools(self, processes):
        deduped = OrderedDict()
        for proc in processes:
            if isinstance(proc, Mapping):
                name = proc.get('name')
            else:
                name = getattr(proc, 'name', None)
            if not name:
                continue
            if name not in deduped:
                deduped[name] = dict(proc) if isinstance(proc, Mapping) else proc
        if deduped:
            return list(deduped.values())
        return list(processes)
