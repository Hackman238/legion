#!/usr/bin/env python

"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2024 Shane Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

"""

import re
from PyQt6 import QtWidgets, QtGui, QtCore

from app.ModelHelpers import resolveHeaders, itemSelectable
from app.auxiliary import *                                                 # for bubble sort

class ScriptsTableModel(QtCore.QAbstractTableModel):
    
    def __init__(self, controller, scripts = [[]], headers = [], parent = None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self.__headers = headers
        self.__scripts = scripts
        self.__controller = controller
        
    def setScripts(self, scripts):
        self.__scripts = scripts
        
    def getScripts(self):
        return self.__scripts

    def rowCount(self, parent):
        return len(self.__scripts)

    def columnCount(self, parent):
        if len(self.__scripts) != 0:
            return len(self.__scripts[0])
        return 0

    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self.__headers)
                
    def data(self, index, role):   # this method takes care of how the information is displayed

        if role == QtCore.Qt.ItemDataRole.DisplayRole:                               # how to display each cell
            value = ''
            row = index.row()
            column = index.column()

            if column == 0:
                value = self.__scripts[row]['id']
            elif column == 1:
                value = self.__scripts[row]['scriptId']
            elif column == 2:
                if self.__scripts[row]['portId'] and self.__scripts[row]['protocol'] and \
                        not self.__scripts[row]['portId'] == '' and not self.__scripts[row]['protocol'] == '':
                    value = self.__scripts[row]['portId'] + '/' + self.__scripts[row]['protocol']
                else:
                    value = ''
            elif column == 3:
                value = self.__scripts[row]['protocol']
            return value
                    

    def sort(self, Ncol, order):
        self.layoutAboutToBeChanged.emit()
        array=[]
        
        if Ncol == 1:
            for i in range(len(self.__scripts)):
                array.append(self.__scripts[i]['scriptId'])
        if Ncol == 2:
            for i in range(len(self.__scripts)):
                array.append(int(self.__scripts[i]['portId']))

        sortArrayWithArray(array, self.__scripts)  # sort the services based on the values in the array

        if order == Qt.SortOrder.AscendingOrder:                                  # reverse if needed
            self.__scripts.reverse()
            
        self.layoutChanged.emit()

    # method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
    def flags(self, index):
        return itemSelectable()

    ### getter functions ###

    def getScriptDBIdForRow(self, row):
        return self.__scripts[row]['id']
    
    def getRowForDBId(self, id):
        for i in range(len(self.__scripts)):
            if self.__scripts[i]['id'] == id:
                return i
