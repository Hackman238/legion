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

from PyQt6 import QtWidgets, QtGui, QtCore
from PyQt6.QtGui import QFont
from PyQt6.QtCore import pyqtSignal, QObject

from app.ModelHelpers import resolveHeaders, itemSelectable
from app.auxiliary import *                                                 # for bubble sort
from app.osclassification import classify_os, get_icon_path, ORDERED_OS_CATEGORIES


class HostsTableModel(QtCore.QAbstractTableModel):
    
    def __init__(self, hosts = [[]], headers = [], parent = None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self.__headers = headers
        self.__hosts = hosts
        
    def setHosts(self, hosts):
        self.__hosts = hosts

    def rowCount(self, parent):
        return len(self.__hosts)

    def columnCount(self, parent):
        if len(self.__hosts) != 0:
            return len(self.__hosts[0])
        return 0
        
    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self.__headers)

    def data(self, index, role):                # this method takes care of how the information is displayed
        if role == QtCore.Qt.ItemDataRole.DecorationRole:    # to show the operating system icon instead of text
            if index.column() == 1:                                     # if trying to display the operating system
                os_string = self.__hosts[index.row()].get('osMatch', '')
                category = classify_os(os_string)
                return QtGui.QIcon(get_icon_path(category))

        if role == QtCore.Qt.ItemDataRole.DisplayRole:                               # how to display each cell
            value = ''
            row = index.row()
            column = index.column()
            if column == 0:
                value = self.__hosts[row]['id']
            elif column == 1:
                value = classify_os(self.__hosts[row].get('osMatch', ''))
            elif column == 2:
                value = self.__hosts[row]['osAccuracy']
            elif column == 3:
                if not self.__hosts[row]['hostname'] == '':
                    value = self.__hosts[row]['ip'] + ' ('+ self.__hosts[row]['hostname'] +')'
                else:
                    value = self.__hosts[row]['ip']
            elif column == 4:
                value = self.__hosts[row]['ipv4']
            elif column == 5:
                value = self.__hosts[row]['ipv6']
            elif column == 6:
                value = self.__hosts[row]['macaddr']
            elif column == 7:
                value = self.__hosts[row]['status']
            elif column == 8:
                value = self.__hosts[row]['hostname']
            elif column == 9:
                value = self.__hosts[row]['vendor']
            elif column == 10:
                value = self.__hosts[row]['uptime']
            elif column == 11:
                value = self.__hosts[row]['lastboot']
            elif column == 12:
                value = self.__hosts[row]['distance']
            elif column == 13:
                value = self.__hosts[row]['checked']
            elif column == 14:
                value = self.__hosts[row]['state']
            elif column == 15:
                value = self.__hosts[row]['count']
            else:
                value = 'Not set in view model'
            return value
            
        if role == QtCore.Qt.ItemDataRole.FontRole:
            # if a host is checked strike it out and make it italic
            if index.column() == 3 and self.__hosts[index.row()]['checked'] == 'True':
                checkedFont=QFont()
                checkedFont.setStrikeOut(True)
                checkedFont.setItalic(True)
                return checkedFont

    # method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
    def flags(self, index):
        return itemSelectable()

    # sort function called when the user clicks on a header
    def sort(self, Ncol, order):
        
        self.layoutAboutToBeChanged.emit()
        array = []
        
        if Ncol == 0 or Ncol == 3:                                      # if sorting by IP address (and by default)
            log.debug("__hosts: {0}".format(str(self.__hosts)))
            for i in range(len(self.__hosts)):
                array.append(IP2Int(self.__hosts[i]['ip']))

        elif Ncol == 1:                                                 # if sorting by OS
            order_map = {cat: idx for idx, cat in enumerate(ORDERED_OS_CATEGORIES)}
            for i in range(len(self.__hosts)):
                category = classify_os(self.__hosts[i].get('osMatch', ''))
                array.append(order_map.get(category, len(order_map)))

        sortArrayWithArray(array, self.__hosts)                         # sort the array of OS

        if order == Qt.SortOrder.AscendingOrder:                                  # reverse if needed
            self.__hosts.reverse()

        self.layoutChanged.emit()                            # update the UI (built-in signal)

    ### getter functions ###

    def getHostIPForRow(self, row):
        return self.__hosts[row]['ip']

    def getHostIdForRow(self, row):
        return self.__hosts[row]['id']
        
    def getHostCheckStatusForRow(self, row):
        return self.__hosts[row]['checked']

    def getHostCheckStatusForIp(self, ip):
        for i in range(len(self.__hosts)):
            if str(self.__hosts[i]['ip']) == str(ip):
                return self.__hosts[i]['checked']
            
    def getRowForIp(self, ip):
        for i in range(len(self.__hosts)):
            host = self.__hosts[i]
            if host.get('ip') == ip or host.get('ipv4') == ip or host.get('hostname') == ip:
                return i
