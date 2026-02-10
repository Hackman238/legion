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
from typing import List, Dict

from PyQt6 import QtCore

from app.ModelHelpers import resolveHeaders, itemInteractive


class CredentialCaptureModel(QtCore.QAbstractTableModel):
    headers = ['Captured', 'Tool', 'Source', 'Username', 'Hash', 'Details']

    def __init__(self, captures: List[Dict] = None, parent=None):
        super().__init__(parent)
        self._captures = captures or []

    def setCaptures(self, captures: List[Dict]):
        self.beginResetModel()
        self._captures = captures
        self.endResetModel()

    def rowCount(self, parent=None):
        return len(self._captures)

    def columnCount(self, parent=None):
        return len(self.headers)

    def headerData(self, section, orientation, role=QtCore.Qt.ItemDataRole.DisplayRole):
        return resolveHeaders(role, orientation, section, self.headers)

    def data(self, index, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role not in (QtCore.Qt.ItemDataRole.DisplayRole, QtCore.Qt.ItemDataRole.EditRole):
            return None

        row = self._captures[index.row()]
        column = index.column()
        if column == 0:
            return row.get('capturedAt', '')
        if column == 1:
            return row.get('tool', '')
        if column == 2:
            return row.get('source', '')
        if column == 3:
            return row.get('username', '')
        if column == 4:
            return row.get('hash', '')
        if column == 5:
            return row.get('details', '')
        return None

    def flags(self, index):
        return itemInteractive()

    def getCaptureForRow(self, row: int) -> Dict:
        return self._captures[row]
