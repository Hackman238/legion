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


class DefaultNmapExporterTest(unittest.TestCase):
    def setUp(self) -> None:
        from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
        self.log = MagicMock()
        self.mockShell = MagicMock()
        self.nmapExporter = DefaultNmapExporter(self.mockShell, self.log)

    EXPECTED_ARGV = ["xsltproc", "-o", "some file.html", "/usr/share/nmap/nmap.xsl", "some file.xml"]

    @patch("subprocess.run")
    def test_exportOutputToHtml_WhenProvidedFileNameAndOutputFolder_ExportsOutputSuccessfully(self, processRun):
        self.nmapExporter.exportOutputToHtml("some file", "some-folder/")
        args, kwargs = processRun.call_args
        self.assertEqual(self.EXPECTED_ARGV, args[0])
        self.assertNotIn("shell", kwargs)
        self.assertTrue(kwargs["check"])
        self.assertGreater(kwargs["timeout"], 0)
        self.mockShell.move.assert_called_once_with("some file.html", "some-folder/")

    @patch("subprocess.run")
    def test_exportOutputToHtml_WhenExportFailsWithoutReport_DoesNotMoveAnyFilesToOutputFolder(self, processRun):
        import subprocess
        processRun.side_effect = subprocess.CalledProcessError(1, self.EXPECTED_ARGV, stderr=b"bad xml")
        self.mockShell.isFile.return_value = False
        self.nmapExporter.exportOutputToHtml("some file", "some-folder/")
        self.mockShell.move.assert_not_called()
        self.log.error.assert_called()

    @patch("subprocess.run")
    def test_exportOutputToHtml_WhenExportReportsErrorsButWritesReport_MovesIt(self, processRun):
        import subprocess
        processRun.side_effect = subprocess.CalledProcessError(1, self.EXPECTED_ARGV, stderr=b"partial xml")
        self.mockShell.isFile.return_value = True
        self.nmapExporter.exportOutputToHtml("some file", "some-folder/")
        self.mockShell.move.assert_called_once_with("some file.html", "some-folder/")
        self.log.error.assert_called()

    @patch("subprocess.run")
    def test_exportOutputToHtml_WhenExportTimesOut_LogsAndDoesNotMove(self, processRun):
        import subprocess
        processRun.side_effect = subprocess.TimeoutExpired(self.EXPECTED_ARGV, 60)
        self.nmapExporter.exportOutputToHtml("some file", "some-folder/")
        self.mockShell.move.assert_not_called()
        self.log.error.assert_called()

    @patch("subprocess.run")
    def test_exportOutputToHtml_WhenXsltprocMissing_LogsAndDoesNotMove(self, processRun):
        processRun.side_effect = FileNotFoundError("xsltproc")
        self.nmapExporter.exportOutputToHtml("some file", "some-folder/")
        self.mockShell.move.assert_not_called()
        self.log.error.assert_called()
