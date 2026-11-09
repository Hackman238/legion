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
import os
import unittest
from unittest.mock import MagicMock, patch


class DefaultNmapExporterTest(unittest.TestCase):
    def setUp(self) -> None:
        from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
        self.log = MagicMock()
        self.mockShell = MagicMock()
        self.nmapExporter = DefaultNmapExporter(self.mockShell, self.log)

    def assertExportCommandShape(self, processOpen, baseName):
        # Independent check (not built from findNmapXsl() itself): argv list
        # (no shell) whose xsl path actually exists on disk, so file names
        # with spaces survive.
        processOpen.assert_called_once()
        argv = processOpen.call_args[0][0]
        self.assertEqual({}, processOpen.call_args[1])
        self.assertIsInstance(argv, list)
        self.assertEqual("xsltproc", argv[0])
        self.assertEqual(["-o", f"{baseName}.html"], argv[1:3])
        self.assertEqual(f"{baseName}.xml", argv[4])
        self.assertTrue(argv[3].endswith("nmap.xsl"), argv)
        self.assertTrue(os.path.exists(argv[3]), f"nmap.xsl does not exist: {argv[3]}")

    @patch("subprocess.Popen")
    def test_exportOutputToHtml_WhenProvidedFileNameAndOutputFolder_ExportsOutputSuccessfully(self, processOpen):
        self.nmapExporter.exportOutputToHtml("some-file", "some-folder/")
        self.assertExportCommandShape(processOpen, "some-file")
        self.mockShell.move.assert_called_once_with("some-file.html", "some-folder/")

    @patch("subprocess.Popen")
    def test_exportOutputToHtml_WhenExportFailsDueToProcessError_DoesNotMoveAnyFilesToOutputFolder(self, processOpen):
        processOpen.side_effect = Exception("something went wrong")
        self.nmapExporter.exportOutputToHtml("some-bad-file", "some-folder/")
        self.assertExportCommandShape(processOpen, "some-bad-file")
        self.mockShell.move.assert_not_called()
        self.log.error.assert_called()
