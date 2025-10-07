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

import os, sys, socket, locale, webbrowser, \
    re, platform  # for webrequests, screenshot timeouts, timestamps, browser stuff and regex
import tempfile
from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import QProcess, QObject, pyqtSignal, pyqtSlot, QThread, Qt
from six import u as unicode
import ipaddress

from app.httputil.isHttps import isHttps
from app.logging.legionLog import getAppLogger
from app.timing import timing

from PyQt6.QtWidgets import QAbstractItemView
import subprocess

log = getAppLogger()

# Convert Windows path to Posix
def winPath2Unix(windowsPath):
    windowsPath = windowsPath.replace("\\", "/")
    windowsPath = windowsPath.replace("C:", "/mnt/c")
    return windowsPath

# Convert Posix path to Windows
def unixPath2Win(posixPath):
    posixPath = posixPath.replace("/", "\\")
    posixPath = posixPath.replace("\\mnt\\c", "C:")
    return posixPath

# Check if running in WSL
def isWsl():
    release = str(platform.uname().release).lower()
    return "microsoft" in release

# Check if running in Kali
def isKali():
    release = str(platform.uname().release).lower()
    return "kali" in release

# Get the AppData Temp directory path if WSL
def getAppdataTemp():
    try:
        username = os.environ["WSL_USER_NAME"]
    except KeyError:
        raise Exception(
            "WSL detected but environment variable 'WSL_USER_NAME' is unset. "
            "Please run 'export WSL_USER_NAME=' followed by your username as it appears in c:\\Users\\"
        )

    appDataTemp = "C:\\Users\\{0}\\AppData\\Local\\Temp".format(username)
    appDataTempUnix = winPath2Unix(appDataTemp)

    if os.path.exists(appDataTempUnix):
        return appDataTemp
    else:
        raise Exception("The AppData Temp directory path {0} does not exist.".format(appDataTemp))

# Get the temp folder based on os. Create if missing from *nix
def getTempFolder():
    # Prefer environment variable for configurability
    tempPath = os.environ.get("LEGION_TMPDIR")
    if tempPath is None:
        # Use system temp dir + 'legion'
        tempPath = os.path.join(tempfile.gettempdir(), "legion")
    if not os.path.isdir(tempPath):
        os.makedirs(tempPath, exist_ok=True)
    log.info(f"Using temp directory: {tempPath}")
    return tempPath

def getPid(qprocess):
    pid = qprocess.processId()
    return pid

def formatCommandQProcess(inputCommand):
    parts = inputCommand.split()
    program = parts[0]
    arguments = parts[1:]
    return program, arguments

# bubble sort algorithm that sorts an array (in place) based on the values in another array
# the values in the array must be comparable and in the corresponding positions
# used to sort objects by one of their attributes.
@timing
def sortArrayWithArray(array, arrayToSort):
    # Sorts array and arrayToSort in place based on the values in array
    combined = sorted(zip(array, arrayToSort), key=lambda x: x[0])
    if combined:
        array[:], arrayToSort[:] = zip(*combined)
    else:
        array[:], arrayToSort[:] = [], []


# converts an IP address to an integer (for the sort function)
def IP2Int(ip):
    try:
        ip_clean = str(ip).split("/")[0].strip()
        return int(ipaddress.ip_address(ip_clean))
    except Exception:
        log.error("Input IP {0} is not valid. Passing for now.".format(str(ip)))
        return 0


# used by the settings dialog when a user cancels and the GUI needs to be reset
def clearLayout(layout):
    if layout != None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget != None:
                widget.deleteLater()
            else:
                clearLayout(item.layout())


# this function sets a table view's properties
@timing
def setTableProperties(table, headersLen, hiddenColumnIndexes=[]):
    table.verticalHeader().setVisible(False)  # hide the row headers
    table.setShowGrid(False)  # hide the table grid
    # select entire row instead of single cell
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSortingEnabled(True)  # enable column sorting
    table.horizontalHeader().setStretchLastSection(True)  # header behaviour
    table.horizontalHeader().setSortIndicatorShown(False)  # hide sort arrow from column header
    table.setWordWrap(False)  # row behaviour
    table.resizeRowsToContents()

    for i in range(0, headersLen):  # reset all the hidden columns
        table.setColumnHidden(i, False)

    for i in hiddenColumnIndexes:  # hide some columns
        table.hideColumn(i)

    table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)  # create the right-click context menu


def checkHydraResults(output):
    usernames = []
    passwords = []
    string = r'\[[0-9]+\]\[[a-z-]+\].+'  # when a password is found, the line contains [port#][plugin-name]
    results = re.findall(string, output, re.I)
    if results:
        for line in results:
            login = re.search(r'(login:[\s]*)([^\s]+)', line)
            if login:
                log.info('Found username: ' + login.group(2))
                usernames.append(login.group(2))
            password = re.search(r'(password:[\s]*)([^\s]+)', line)
            if password:
                # print 'Found password: ' + password.group(2)

                passwords.append(password.group(2))
        return True, usernames, passwords  # returns the lists of found usernames and passwords
    return False, [], []


# this class is used for example to store found usernames/passwords
class Wordlist():
    def __init__(self, filename):  # needs full path
        self.filename = filename
        self.wordlist = []
        with open(filename, 'a+') as f:  # open for appending + reading
            self.wordlist = f.readlines()
            log.info('Wordlist was created/opened: ' + str(filename))

    def setFilename(self, filename):
        self.filename = filename

    # adds a word to the wordlist (without duplicates)
    def add(self, word):
        with open(self.filename, 'a+') as f:
            f.seek(0)
            self.wordlist = f.readlines()
            if not word + '\n' in self.wordlist:
                log.info('Adding ' + word + ' to the wordlist..')
                self.wordlist.append(word + '\n')
                f.write(word + '\n')


# Custom QProcess class
class MyQProcess(QProcess):
    sigHydra = QtCore.pyqtSignal(QObject, list, list, name="hydra")  # signal to indicate Hydra found stuff

    def __init__(self, name, tabTitle, hostIp, port, protocol, command, startTime, outputfile, textbox):
        QProcess.__init__(self)
        self.id = -1
        self.name = name
        self.tabTitle = tabTitle
        self.hostIp = hostIp
        self.port = port
        self.protocol = protocol
        self.command = command
        self.startTime = startTime
        self.outputfile = outputfile
        self.display = textbox  # has its own display widget to be able to display its output in the GUI
        self.elapsed = -1

    @pyqtSlot()  # this slot allows the process to append its output to the display widget
    def readStdOutput(self):
        output = str(self.readAllStandardOutput())
        self.display.appendPlainText(unicode(output).strip())

        # check if any usernames/passwords were found (if so emit a signal so that the gui can tell the user about it)
        if self.name == 'hydra':
            found, userlist, passlist = checkHydraResults(output)
            if found:  # send the brutewidget object along with lists of found usernames/passwords
                self.sigHydra.emit(self.display.parentWidget(), userlist, passlist)

        stderror = str(self.readAllStandardError())

        if len(stderror) > 0:
            self.display.appendPlainText(unicode(stderror).strip())  # append standard error too


# browser opener class with queue and semaphores
class BrowserOpener(QtCore.QThread):
    done = QtCore.pyqtSignal(name="done")  # signals that we are done opening urls in browser
    log = QtCore.pyqtSignal(str, name="log")

    def __init__(self):
        QtCore.QThread.__init__(self, parent=None)
        self.urls = []
        self.processing = False

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def addToQueue(self, url):
        self.urls.append(url)

    def run(self):
        while self.processing:
            self.sleep(1)  # effectively a semaphore

        self.processing = True
        first = True
        while self.urls:
            try:
                url = self.urls.pop(0)
                self.tsLog('Opening url in browser: ' + url)
                if isHttps(url.split(':')[0], url.split(':')[1]):
                    webbrowser.open_new_tab('https://' + url)
                else:
                    webbrowser.open_new_tab('http://' + url)
                if first:
                    self.sleep(3)
                    first = False
                else:
                    self.sleep(1)
            except Exception:
                self.tsLog('Problem while opening url in browser. Moving on..')
                continue

        self.processing = False
        self.done.emit()


# This class handles what is to be shown in each panel
class Filters():
    def __init__(self):
        # host filters
        self.checked = True
        self.up = True
        self.down = False
        # port/service filters
        self.tcp = True
        self.udp = True
        self.portopen = True
        self.portclosed = False
        self.portfiltered = False
        self.keywords = []

    @timing
    def apply(self, up, down, checked, portopen, portfiltered, portclosed, tcp, udp, keywords=[]):
        self.checked = checked
        self.up = up
        self.down = down
        self.tcp = tcp
        self.udp = udp
        self.portopen = portopen
        self.portclosed = portclosed
        self.portfiltered = portfiltered
        self.keywords = keywords

    @timing
    def setKeywords(self, keywords):
        log.info(str(keywords))
        self.keywords = keywords

    @timing
    def getFilters(self):
        return [self.up, self.down, self.checked, self.portopen, self.portfiltered, self.portclosed, self.tcp, self.udp,
                self.keywords]

    @timing
    def display(self):
        log.info('Filters are:')
        log.info('Show checked hosts: ' + str(self.checked))
        log.info('Show up hosts: ' + str(self.up))
        log.info('Show down hosts: ' + str(self.down))
        log.info('Show tcp: ' + str(self.tcp))
        log.info('Show udp: ' + str(self.udp))
        log.info('Show open ports: ' + str(self.portopen))
        log.info('Show closed ports: ' + str(self.portclosed))
        log.info('Show filtered ports: ' + str(self.portfiltered))
        log.info('Keyword search:')
        for w in self.keywords:
            log.info(w)


# Validation functions moved to app/validation.py
from app.validation import (
    validateNmapInput,
    validateCommandFormat,
    validateNumeric,
    validateString,
    validateStringWithSpace,
    validateNmapPorts,
)
