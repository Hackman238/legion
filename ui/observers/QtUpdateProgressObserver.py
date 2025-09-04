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
from app.actions.updateProgress.AbstractUpdateProgressObserver import AbstractUpdateProgressObserver
from ui.ancillaryDialog import ProgressWidget
from PyQt6 import QtCore


class QtUpdateProgressObserver(AbstractUpdateProgressObserver):
    def __init__(self, progressWidget: ProgressWidget):
        self.progressWidget = progressWidget

    def onStart(self) -> None:
        QtCore.QMetaObject.invokeMethod(self.progressWidget, "show", QtCore.Qt.ConnectionType.QueuedConnection)

    def onFinished(self) -> None:
        QtCore.QMetaObject.invokeMethod(self.progressWidget, "hide", QtCore.Qt.ConnectionType.QueuedConnection)

    def onProgressUpdate(self, progress: int, title: str) -> None:
        print(f"[DEBUG] QtUpdateProgressObserver.onProgressUpdate called: progress={progress}, title={title}")
        # Directly call setText and setProgress, as ProgressWidget is not a QObject with registered slots
        self.progressWidget.setText(title)
        self.progressWidget.setProgress(progress)
        self.progressWidget.show()
