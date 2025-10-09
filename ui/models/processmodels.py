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

import re
from PyQt6 import QtWidgets, QtGui, QtCore

from app.ModelHelpers import resolveHeaders, itemInteractive
from app.auxiliary import *                                                 # for bubble sort

class ProcessesTableModel(QtCore.QAbstractTableModel):

    def __init__(self, controller, processes = [[]], headers = [], parent = None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self.__headers = headers
        self.__processes = processes
        self.__controller = controller

    @staticmethod
    def _format_duration(seconds):
        try:
            seconds = float(seconds)
        except (TypeError, ValueError):
            return "00:00:00"
        if seconds < 0:
            seconds = 0
        total_seconds = int(seconds)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def _runtime_seconds_for_row(self, row):
        proc = self.__processes[row]
        pid_value = proc.get('pid')
        runtime = None
        measurements = getattr(self.__controller.controller, 'processMeasurements', {})
        if pid_value not in (None, '', '0'):
            try:
                runtime = measurements.get(int(pid_value))
            except (ValueError, TypeError):
                runtime = measurements.get(pid_value)
        if runtime is None or runtime == 0:
            runtime = proc.get('elapsed')
        if runtime in ('', None):
            runtime = 0
        try:
            return float(runtime)
        except (TypeError, ValueError):
            return 0.0
        
    def setProcesses(self, processes):
        self.__processes = processes
        
    def getProcesses(self):
        return self.__processes

    def rowCount(self, parent):
        return len(self.__processes)

    def columnCount(self, parent):
        if len(self.__processes) != 0:
            return len(self.__processes[0])
        return 0

    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self.__headers)

    # this method takes care of how the information is displayed
    def data(self, index, role):
        if role == QtCore.Qt.ItemDataRole.DisplayRole or role == QtCore.Qt.ItemDataRole.EditRole: # how to display each cell
            value = ''
            row = index.row()
            column = index.column()
            processColumns = {0: 'progress', 1: 'display', 2: 'elapsed', 3: 'percent',
                              4: 'pid', 5: 'name', 6: 'tabTitle', 7: 'hostIp', 8: 'port', 9: 'protocol', 10: 'command',
                              11: 'startTime', 12: 'endTime', 13: 'outputfile', 14: 'output', 15: 'status',
                              16: 'closed'}
            try:
                if column == 0:
                    value = ''
                elif column == 2:
                    runtime_seconds = self._runtime_seconds_for_row(row)
                    value = self._format_duration(runtime_seconds)
                elif column == 3:
                    percent = self.__processes[row].get('percent')
                    if percent is not None and percent != "":
                        value = f"{percent}%" if not str(percent).endswith("%") else str(percent)
                    else:
                        value = "Unknown"
                elif column == 6:
                    if not self.__processes[row]['tabTitle'] == '':
                        value = self.__processes[row]['tabTitle']
                    else:
                        value = self.__processes[row]['name']
                elif column == 8:
                    if not self.__processes[row]['port'] == '' and not self.__processes[row]['protocol'] == '':
                        value = self.__processes[row]['port'] + '/' + self.__processes[row]['protocol']
                    else:
                        value = self.__processes[row]['port']
                elif column == 16:
                    value = ""
                else:
                    try:
                        value = self.__processes[row][processColumns.get(int(column))]
                    except:
                        value = ""
            except Exception:
                value = ""
            return value

    def sort(self, Ncol, order):
        self.layoutAboutToBeChanged.emit()
        array=[]

        sortColumns = {2: 'elapsed', 5:'name', 6:'tabTitle', 11:'startTime', 12:'endTime'}
        field = sortColumns.get(int(Ncol)) or 'status'

        try:
            if Ncol == 7:
                for i in range(len(self.__processes)):
                    array.append(IP2Int(self.__processes[i]['hostIp']))

            elif Ncol == 8:
                for i in range(len(self.__processes)):
                    if self.__processes[i]['port'] == '':
                        return
                    else:
                        array.append(int(self.__processes[i]['port']))
            else:
                for i in range(len(self.__processes)):
                    value = self.__processes[i].get(field)
                    if field == 'elapsed':
                        try:
                            value = float(value)
                        except (TypeError, ValueError):
                            value = 0.0
                    array.append(value)
        
            sortArrayWithArray(array, self.__processes)  # sort the services based on the values in the array

            if order == Qt.SortOrder.AscendingOrder:                                  # reverse if needed
                self.__processes.reverse()
                self.__controller.processesTableViewSort = 'desc'
            else:
                self.__controller.processesTableViewSort = 'asc'

            self.__controller.processesTableViewSortColumn = field

        ## Extra?
        #self.__controller.updateProcessesIcon()  # to make sure the progress GIF is displayed in the right place
            self.layoutChanged.emit()
        except:
            log.error("Failed to sort")
            pass

    # method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
    def flags(self, index):
        return itemInteractive()

    def setDataList(self, processes):
        self.__processes = processes
        self.layoutAboutToBeChanged.emit()
        self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(self.rowCount(0), self.columnCount(0)))
        self.layoutChanged.emit()

    ### getter functions ###

    def getProcessPidForRow(self, row):
        return self.__processes[row]['pid']
        
    def getProcessPidForId(self, dbId):
        for i in range(len(self.__processes)):
            if str(self.__processes[i]['id']) == str(dbId):
                return self.__processes[i]['pid']

    def getProcessStatusForRow(self, row):
        return self.__processes[row]['status']

    def getProcessStatusForPid(self, pid):
        for i in range(len(self.__processes)):
            if str(self.__processes[i]['pid']) == str(pid):
                return self.__processes[i]['status']
                
    def getProcessStatusForId(self, dbId):
        for i in range(len(self.__processes)):
            if str(self.__processes[i]['id']) == str(dbId):
                return self.__processes[i]['status']

    def getProcessIdForRow(self, row):
        return self.__processes[row]['id']
        
    def getToolNameForRow(self, row):
        return self.__processes[row]['name']
        
    def getRowForToolName(self, toolname):
        for i in range(len(self.__processes)):
            if self.__processes[i]['name'] == toolname:
                return i

    def getRowForDBId(self, dbid):  # new
        for i in range(len(self.__processes)):
            if self.__processes[i]['id'] == dbid:
                return i

    def getIpForRow(self, row):
        return self.__processes[row]['hostIp']

    def getPortForRow(self, row):
        return self.__processes[row]['port']

    def getProtocolForRow(self, row):
        return self.__processes[row]['protocol']
        
    def getOutputfileForRow(self, row):
        return self.__processes[row]['outputfile']
