import os
import unittest
from unittest.mock import patch

from app.ProjectManager import ProjectManager
from app.importers.NmapImporter import NmapImporter
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from db.RepositoryFactory import RepositoryFactory

VALID_XML = os.path.join("tests", "parsers", "nmap-fixtures", "valid-nmap-report.xml")
DUPLICATE_XML = os.path.join("tests", "parsers", "nmap-fixtures", "duplicate-ip-nmap-report.xml")


class NmapImporterFailureHandlingTest(unittest.TestCase):
    def setUp(self):
        self.project_manager = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        self.addCleanup(self.project_manager.closeProject, self.project)
        repo = self.project.repositoryContainer.hostRepository
        self.importer = NmapImporter(None, repo)
        self.importer.setDB(self.project.database)
        self.importer.setHostRepository(repo)

    def test_thread_entry_point_reports_failures_instead_of_raising(self):
        failures, done = [], []
        self.importer.failed.connect(failures.append)
        self.importer.done.connect(lambda: done.append(True))
        self.importer.setFilename(VALID_XML)
        with patch("app.importers.NmapImporter.parseNmapReport", side_effect=RuntimeError("boom")):
            self.importer.run()  # must not raise: callers rely on `failed` instead
        self.assertEqual(1, len(failures))
        self.assertIn("boom", failures[0])
        self.assertEqual([], done)  # `done` means hosts were imported; a failure must not trigger that UI path

    def test_missing_or_malformed_report_emits_failed_not_done(self):
        malformed = os.path.join("tests", "parsers", "nmap-fixtures", "malformed-nmap-report.xml")
        for filename in (malformed, os.path.join("tests", "no-such-dir", "missing.xml")):
            failures, done = [], []
            importer = NmapImporter(None, self.project.repositoryContainer.hostRepository)
            importer.setDB(self.project.database)
            importer.failed.connect(failures.append)
            importer.done.connect(lambda: done.append(True))
            importer.setFilename(filename)
            importer.run()  # reports the failure instead of a silent "done"
            self.assertEqual(1, len(failures), filename)
            self.assertIn(filename, failures[0])
            self.assertEqual([], done, filename)

    def test_synchronous_import_still_raises_for_callers_that_report_errors(self):
        self.importer.setFilename(VALID_XML)
        with patch("app.importers.NmapImporter.parseNmapReport", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.importer.importFile()

    def test_a_cancel_pressed_right_after_start_is_honoured(self):
        self.importer.resetCancel()    # what a caller does when it starts an import
        self.importer.cancel()         # Cancel pressed before the thread reaches importFile()
        self.importer.setFilename(VALID_XML)
        self.importer.importFile()
        self.assertEqual([], self.project.repositoryContainer.hostRepository.getAllHostObjs())

    def test_a_cancelled_import_does_not_cancel_the_next_one(self):
        self.importer.cancel()
        self.importer.resetCancel()    # the next import is started fresh
        self.importer.setFilename(VALID_XML)
        self.importer.importFile()
        self.importer.resetCancel()
        self.importer.setFilename(DUPLICATE_XML)
        self.importer.importFile()
        ips = sorted(h.ip for h in self.project.repositoryContainer.hostRepository.getAllHostObjs())
        self.assertEqual(["172.67.68.11", "192.168.1.1"], ips)

    def test_host_without_address_is_skipped_instead_of_aborting(self):
        import tempfile
        xml = (
            '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap" start="1" version="7.94">'
            '<host><status state="up" reason="syn-ack"/><ports><port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/><service name="ssh"/></port></ports></host>'
            '<host><status state="up" reason="syn-ack"/><address addr="10.9.9.9" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port></ports></host>'
            '<runstats><finished time="3" elapsed="1"/><hosts up="2" down="0" total="2"/></runstats></nmaprun>'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(xml)
        self.addCleanup(os.remove, handle.name)
        self.importer.setFilename(handle.name)
        self.importer.importFile()
        ips = [h.ip for h in self.project.repositoryContainer.hostRepository.getAllHostObjs()]
        self.assertEqual(["10.9.9.9"], ips)


if __name__ == "__main__":
    unittest.main()
