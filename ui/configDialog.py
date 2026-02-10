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

import os
from PyQt6.QtGui import *                                               # for filters dialog
from PyQt6.QtWidgets import *
from PyQt6 import QtWidgets, QtGui, QtCore
from app.auxiliary import *                                             # for timestamps
from six import u as unicode
from ui.ancillaryDialog import flipState
from app.settings import AppSettings

class Config(QtWidgets.QPlainTextEdit):
    def __init__(self, qss, parent = None):
        super(Config, self).__init__(parent)
        self.setMinimumHeight(550)
        self.setStyleSheet(qss)
        self.setPlainText(open(os.path.expanduser('~/.local/share/legion/legion.conf'),'r').read())
        self.setReadOnly(False)

    def getText(self):
        return self.toPlainText()

class ConfigDialog(QtWidgets.QDialog):
    def __init__(self, controller, qss, parent = None):
        super(ConfigDialog, self).__init__(parent)
        self.controller = controller
        self.qss = qss
        self.setWindowTitle("Config")
        self.Main = QtWidgets.QVBoxLayout()
        self.frm = QtWidgets.QFormLayout()
        self.setGeometry(0, 0, 800, 600)
        self.center()
        self.Qui_update()
        self.setStyleSheet(self.qss)

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QtGui.QGuiApplication.primaryScreen().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Qui_update(self):
        self.form = QtWidgets.QFormLayout()
        self.form2 = QtWidgets.QVBoxLayout()
        self.tabwid = QtWidgets.QTabWidget(self)
        self.TabConfig = QtWidgets.QWidget(self)
        self.toolsTab = QtWidgets.QWidget(self)
        self.cmdSave = QtWidgets.QPushButton("Save")
        self.cmdSave.setFixedWidth(90)
        self.cmdSave.setIcon(QtGui.QIcon('images/save.png'))
        self.cmdSave.clicked.connect(self.save)
        self.cmdClose = QtWidgets.QPushButton("Close")
        self.cmdClose.setFixedWidth(90)
        self.cmdClose.setIcon(QtGui.QIcon('images/close.png'))
        self.cmdClose.clicked.connect(self.close)

        self.formConfig = QtWidgets.QFormLayout()

        # Config Section
        self.configObj = Config(qss = self.qss)
        self.formConfig.addRow(self.configObj)
        self.TabConfig.setLayout(self.formConfig)

        self._buildToolsTab()

        self.tabwid.addTab(self.TabConfig,'Config')
        self.tabwid.addTab(self.toolsTab, 'Tools')
        self.form.addRow(self.tabwid)
        self.form2.addWidget(QtWidgets.QLabel('<br>'))
        self.form2.addWidget(self.cmdSave, alignment = Qt.AlignmentFlag.AlignCenter)
        self.form2.addWidget(self.cmdClose, alignment = Qt.AlignmentFlag.AlignCenter)
        self.form.addRow(self.form2)
        self.Main.addLayout(self.form)
        self.setLayout(self.Main)

    def save(self):
        fileObj = open(os.path.expanduser('~/.local/share/legion/legion.conf'),'w')
        fileObj.write(self.configObj.getText())
        fileObj.close()
        self._save_tool_settings()
        self.controller.loadSettings()
        self.configObj.setPlainText(open(os.path.expanduser('~/.local/share/legion/legion.conf'),'r').read())

    def _buildToolsTab(self):
        layout = QtWidgets.QFormLayout()
        settings = self.controller.getSettings()

        self.responderPathEdit = QtWidgets.QLineEdit()
        self.responderPathEdit.setText(getattr(settings, 'tools_path_responder', 'responder'))
        responderBrowse = QtWidgets.QPushButton('Browse')
        responderBrowse.clicked.connect(lambda: self._browse_tool(self.responderPathEdit))
        responderRow = QtWidgets.QHBoxLayout()
        responderRow.addWidget(self.responderPathEdit)
        responderRow.addWidget(responderBrowse)
        layout.addRow(QtWidgets.QLabel('Responder path'), responderRow)

        self.ntlmrelayPathEdit = QtWidgets.QLineEdit()
        self.ntlmrelayPathEdit.setText(getattr(settings, 'tools_path_ntlmrelay', 'ntlmrelayx.py'))
        ntlmBrowse = QtWidgets.QPushButton('Browse')
        ntlmBrowse.clicked.connect(lambda: self._browse_tool(self.ntlmrelayPathEdit))
        ntlmRow = QtWidgets.QHBoxLayout()
        ntlmRow.addWidget(self.ntlmrelayPathEdit)
        ntlmRow.addWidget(ntlmBrowse)
        layout.addRow(QtWidgets.QLabel('NTLMRelay path'), ntlmRow)

        hint = QtWidgets.QLabel('Set full paths if these tools are not in $PATH. Changes take effect immediately after saving.')
        hint.setWordWrap(True)
        layout.addRow(hint)
        self.toolsTab.setLayout(layout)

    def _browse_tool(self, line_edit):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Select executable', '', filter='All files (*)')
        if filename:
            line_edit.setText(filename)

    def _save_tool_settings(self):
        config_path = os.path.expanduser('~/.local/share/legion/legion.conf')
        qsettings = QtCore.QSettings(config_path, QtCore.QSettings.Format.NativeFormat)
        qsettings.beginGroup('ToolSettings')
        qsettings.setValue('responder-path', self.responderPathEdit.text().strip())
        qsettings.setValue('ntlmrelay-path', self.ntlmrelayPathEdit.text().strip())
        qsettings.endGroup()
        qsettings.sync()
