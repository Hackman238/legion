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
import unittest
from unittest.mock import MagicMock, patch


class QtUpdateProgressObserverTest(unittest.TestCase):
    def setUp(self) -> None:
        from ui.observers.QtUpdateProgressObserver import QtUpdateProgressObserver

        self.mockProgressWidget = MagicMock()
        self.qtUpdateProgressObserver = QtUpdateProgressObserver(self.mockProgressWidget)

    def test_onStart_callsShowOnProgressWidget(self):
        with patch("ui.observers.QtUpdateProgressObserver.QtCore.QMetaObject.invokeMethod") as invoke_method:
            self.qtUpdateProgressObserver.onStart()

        invoke_method.assert_called_once()
        self.assertEqual(self.mockProgressWidget, invoke_method.call_args.args[0])
        self.assertEqual("show", invoke_method.call_args.args[1])

    def test_onFinished_callsHideOnProgressWidget(self):
        with patch("ui.observers.QtUpdateProgressObserver.QtCore.QMetaObject.invokeMethod") as invoke_method:
            self.qtUpdateProgressObserver.onFinished()

        invoke_method.assert_called_once()
        self.assertEqual(self.mockProgressWidget, invoke_method.call_args.args[0])
        self.assertEqual("hide", invoke_method.call_args.args[1])

    def test_onProgressUpdate_callsSetProgressAndShow(self):
        self.qtUpdateProgressObserver.onProgressUpdate(25)
        self.mockProgressWidget.setText.assert_called_once_with("")
        self.mockProgressWidget.setProgress.assert_called_once_with(25)
        self.mockProgressWidget.show.assert_called_once()
