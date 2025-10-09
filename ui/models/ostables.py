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

from PyQt6 import QtCore

from app.ModelHelpers import resolveHeaders, itemSelectable
from app.auxiliary import IP2Int, sortArrayWithArray


class OsSummaryTableModel(QtCore.QAbstractTableModel):
    def __init__(self, entries=None, headers=None, parent=None):
        super().__init__(parent)
        self._headers = headers or []
        self._entries = entries or []

    def rowCount(self, parent=None):
        return len(self._entries)

    def columnCount(self, parent=None):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self._headers)

    def data(self, index, role):
        if not index.isValid():
            return None
        row = index.row()
        column = index.column()
        if row >= len(self._entries):
            return None
        entry = self._entries[row]
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return entry.get('os', '')
            if column == 1:
                return entry.get('count', 0)
        return None

    def flags(self, index):
        return itemSelectable()

    def setEntries(self, entries):
        self.layoutAboutToBeChanged.emit()
        self._entries = entries or []
        self.layoutChanged.emit()

    def getOsForRow(self, row):
        if 0 <= row < len(self._entries):
            return self._entries[row].get('os')
        return None

    def getRowForOs(self, os_name):
        for idx, entry in enumerate(self._entries):
            if entry.get('os') == os_name:
                return idx
        return None


class OsHostsTableModel(QtCore.QAbstractTableModel):
    def __init__(self, hosts=None, headers=None, parent=None):
        super().__init__(parent)
        self._headers = headers or []
        self._hosts = hosts or []

    def rowCount(self, parent=None):
        return len(self._hosts)

    def columnCount(self, parent=None):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self._headers)

    def data(self, index, role):
        if not index.isValid():
            return None
        row = index.row()
        column = index.column()
        if row >= len(self._hosts):
            return None
        host = self._hosts[row]
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return host.get('ip', '')
            if column == 1:
                return host.get('hostname', '')
            if column == 2:
                return host.get('os', '')
            if column == 3:
                return host.get('status', '')
        return None

    def flags(self, index):
        return itemSelectable()

    def setHosts(self, hosts):
        self.layoutAboutToBeChanged.emit()
        self._hosts = hosts or []
        self.layoutChanged.emit()

    def getIpForRow(self, row):
        if 0 <= row < len(self._hosts):
            return self._hosts[row].get('ip')
        return None

    def sort(self, column, order):
        if not self._hosts:
            return
        self.layoutAboutToBeChanged.emit()
        if column == 0:
            keys = [IP2Int(host.get('ip', '0.0.0.0') or '0.0.0.0') for host in self._hosts]
        else:
            field_map = {1: 'hostname', 2: 'os', 3: 'status'}
            field = field_map.get(column, 'ip')
            keys = [host.get(field, '') for host in self._hosts]
        sortArrayWithArray(keys, self._hosts)
        if order == QtCore.Qt.SortOrder.AscendingOrder:
            self._hosts.reverse()
        self.layoutChanged.emit()

    def getHostDisplay(self, row):
        if 0 <= row < len(self._hosts):
            return self._hosts[row]
        return None
