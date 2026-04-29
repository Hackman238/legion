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
from unittest import mock
from unittest.mock import MagicMock, patch


class ToolCoordinatorTest(unittest.TestCase):
    def setUp(self) -> None:
        from app.tools.ToolCoordinator import ToolCoordinator
        self.mockShell = MagicMock()
        self.mockNmapExporter = MagicMock()
        self.nmapFileExists_patcher = patch("app.tools.ToolCoordinator.nmapFileExists")
        self.nmapFileExists = self.nmapFileExists_patcher.start()
        self.addCleanup(self.nmapFileExists_patcher.stop)
        self.nmapFileExists.return_value = False
        self.outputFolder = "some-output-folder"
        self.toolCoordinator = ToolCoordinator(self.mockShell, self.mockNmapExporter)

    def _configure_existing_paths(self, *, files=None, directories=None):
        files = set(files or [])
        directories = set(directories or [])

        def directory_or_file_exists(path):
            return path in files or path in directories

        self.mockShell.directoryOrFileExists.side_effect = directory_or_file_exists
        self.mockShell.isFile.side_effect = lambda path: path in files

    def test_saveToolOutput_WhenGivenProjectOutputFolderAndNmapFileNameToSaveOutputIn_SavesOutputSuccessfully(self):
        fileName = "running/nmap/some-output-nmap-file"

        self._configure_existing_paths(directories={self.outputFolder})
        self.nmapFileExists.return_value = True

        self.toolCoordinator.saveToolOutput(self.outputFolder, fileName)
        self.mockNmapExporter.exportOutputToHtml.assert_called_once_with(
            "running/nmap/some-output-nmap-file",
            "some-output-folder/nmap",
        )
        self.mockShell.move.assert_has_calls([
            mock.call("running/nmap/some-output-nmap-file.xml", "some-output-folder/nmap"),
            mock.call("running/nmap/some-output-nmap-file.nmap", "some-output-folder/nmap"),
            mock.call("running/nmap/some-output-nmap-file.gnmap", "some-output-folder/nmap"),
        ])

    def test_saveToolOutput_WhenGivenProjectOutputDirAndGenericFileNameToSaveOutputIn_SavesOutputSuccessfully(self):
        fileName = "some-output-file"

        self._configure_existing_paths(files={fileName})

        self.toolCoordinator.saveToolOutput(self.outputFolder, fileName)
        self.mockShell.move.assert_called_once_with("some-output-file", "some-output-folder")

    def test_saveToolOutput_WhenGivenProjectOutputFolderAndXmlFileNameToSaveOutputIn_SavesOutputSuccessfully(self):
        fileName = "some-output-xml-file"

        self._configure_existing_paths(files={f"{fileName}.xml"})

        self.toolCoordinator.saveToolOutput(self.outputFolder, fileName)
        self.mockShell.move.assert_called_once_with("some-output-xml-file.xml", "some-output-folder")

    def test_saveToolOutput_WhenGivenProjectOutputFolderAndTxtFileNameToSaveOutputIn_SavesOutputSuccessfully(self):
        fileName = "some-output-txt-file"

        self._configure_existing_paths(files={f"{fileName}.txt"})

        self.toolCoordinator.saveToolOutput(self.outputFolder, fileName)
        self.mockShell.move.assert_called_once_with("some-output-txt-file.txt", "some-output-folder")
