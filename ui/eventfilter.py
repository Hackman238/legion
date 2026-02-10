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
from PyQt6.QtCore import QObject, QEvent, Qt
from PyQt6.QtWidgets import QApplication


# This class is used to catch events such as arrow key presses or close window (X)
class MyEventFilter(QObject):
    def __init__(self, view, main_window):
        super().__init__()
        self.view = view
        self.main_window = main_window
        self.hosts_table_views = {
            view.ui.HostsTableView,
            view.ui.ServiceNamesTableView,
            view.ui.ToolsTableView,
            view.ui.ToolHostsTableView,
            view.ui.ScriptsTableView,
            view.ui.ServicesTableView,
            view.settingsWidget.toolForHostsTableWidget,
            view.settingsWidget.toolForServiceTableWidget,
            view.settingsWidget.toolForTerminalTableWidget,
        }

    def eventFilter(self, receiver, event):
        # catch up/down arrow key presses in hosts table
        if event.type() == QEvent.Type.KeyPress and receiver in self.hosts_table_views:
            return self.filterKeyPressInHostsTableView(event.key(), receiver)
        elif event.type() == QEvent.Type.Close and receiver == self.main_window:
            # When the user closes the main window, route through View.appExit() so we can
            # prompt to save/discard changes and run cleanup. During an already-in-progress
            # shutdown, let Qt handle the close normally to avoid re-entrancy/double cleanup.
            if getattr(self.view, "_app_exit_in_progress", False) is True:
                return False
            event.ignore()
            self.view.appExit()
            return True
        else:
            parent = super(MyEventFilter, self)
            return parent.eventFilter(receiver, event)  # normal event processing

    def filterKeyPressInHostsTableView(self, key, receiver):
        if not receiver.selectionModel().selectedRows():
            return True

        index = receiver.selectionModel().selectedRows()[0].row()

        if key == Qt.Key.Key_Down:
            new_index = index + 1
            receiver.selectRow(new_index)
            receiver.clicked.emit(receiver.selectionModel().selectedRows()[0])
        elif key == Qt.Key.Key_Up:
            new_index = index - 1
            receiver.selectRow(new_index)
            receiver.clicked.emit(receiver.selectionModel().selectedRows()[0])
        elif QApplication.keyboardModifiers() == Qt.KeyboardModifier.ControlModifier and key == Qt.Key.Key_C:
            selected = receiver.selectionModel().currentIndex()
            clipboard = QApplication.clipboard()
            clipboard.setText(selected.data().toString())
        return True
