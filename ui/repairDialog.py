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
import subprocess
import shlex

from PyQt6 import QtWidgets, QtGui, QtCore


class RepairDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Repair Legion File')
        self.setModal(True)
        self.resize(540, 300)
        self._setup_ui()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        file_layout = QtWidgets.QHBoxLayout()
        self.file_edit = QtWidgets.QLineEdit()
        self.file_edit.setPlaceholderText('Select a .legion project file to repair')
        browse_btn = QtWidgets.QPushButton('Browse...')
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(browse_btn)

        output_layout = QtWidgets.QHBoxLayout()
        self.output_label = QtWidgets.QLabel('Repaired file:')
        self.output_path = QtWidgets.QLineEdit()
        self.output_path.setReadOnly(True)
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.output_path)

        self.status_label = QtWidgets.QLabel('')
        self.status_label.setStyleSheet('QLabel { color: red }')

        self.log_output = QtWidgets.QPlainTextEdit()
        self.log_output.setReadOnly(True)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch(1)
        self.run_button = QtWidgets.QPushButton('Repair')
        self.run_button.clicked.connect(self._run_repair)
        close_button = QtWidgets.QPushButton('Close')
        close_button.clicked.connect(self.close)
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(close_button)

        layout.addLayout(file_layout)
        layout.addLayout(output_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.log_output)
        layout.addLayout(button_layout)

    def _browse_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Select Legion Project', '', filter='Legion project (*.legion)' )
        if not filename:
            return
        self.file_edit.setText(filename)
        repaired = self._derive_output_path(filename)
        self.output_path.setText(repaired)
        self.status_label.clear()
        self.log_output.clear()

    @staticmethod
    def _derive_output_path(path: str) -> str:
        base, ext = os.path.splitext(path)
        if ext.lower() != '.legion':
            ext = '.legion'
        return f"{base}-Repaired{ext}"

    def _run_repair(self):
        source = self.file_edit.text().strip()
        if not source:
            self.status_label.setText('Please select a project file to repair.')
            return
        if not os.path.isfile(source):
            self.status_label.setText('Selected file does not exist.')
            return

        destination = self.output_path.text().strip() or self._derive_output_path(source)
        self.output_path.setText(destination)

        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts', 'python', 'repair_legion_db.py')
        script = os.path.normpath(script)
        if not os.path.isfile(script):
            self.status_label.setText('Repair script not found.')
            return

        command = f"python3 {shlex.quote(script)} {shlex.quote(source)} {shlex.quote(destination)} --force"
        self.status_label.setStyleSheet('QLabel { color: #ffaa00 }')
        self.status_label.setText('Repair in progress...')
        self.run_button.setEnabled(False)
        QtWidgets.QApplication.processEvents()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(script)
            )
        except Exception as exc:
            self.status_label.setStyleSheet('QLabel { color: red }')
            self.status_label.setText(f'Failed to execute repair script: {exc}')
            self.run_button.setEnabled(True)
            return

        output = proc.stdout or ''
        if proc.stderr:
            output += '\n' + proc.stderr
        self.log_output.setPlainText(output.strip())

        if proc.returncode == 0 and os.path.isfile(destination):
            self.status_label.setStyleSheet('QLabel { color: green }')
            self.status_label.setText('Repair completed successfully.')
        else:
            self.status_label.setStyleSheet('QLabel { color: red }')
            self.status_label.setText('Repair failed. Review the output above.')
        self.run_button.setEnabled(True)
