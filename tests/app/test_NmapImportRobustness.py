import os
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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
            self.importer.run()  # must not raise: under PyQt6 that aborts the application
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
        self.importer.resetCancel()    # what the controller does when it starts an import
        self.importer.cancel()         # Cancel pressed before the thread reaches importFile()
        self.importer.setFilename(VALID_XML)
        self.importer.importFile()
        self.assertEqual([], self.project.repositoryContainer.hostRepository.getAllHostObjs())

    def test_a_cancelled_import_does_not_cancel_the_next_one(self):
        self.importer.cancel()
        self.importer.resetCancel()    # the next import is started through the controller
        self.importer.setFilename(VALID_XML)
        self.importer.importFile()
        self.importer.resetCancel()
        self.importer.setFilename(DUPLICATE_XML)
        self.importer.importFile()
        ips = sorted(h.ip for h in self.project.repositoryContainer.hostRepository.getAllHostObjs())
        self.assertEqual(["172.67.68.11", "192.168.1.1"], ips)


class NmapImportInQtThreadTest(unittest.TestCase):
    def test_failed_import_in_a_qthread_does_not_abort_the_process(self):
        # An exception escaping QThread.run() makes PyQt6 abort (SIGABRT); run it in a child process.
        script = textwrap.dedent(f"""
            import os, sys
            sys.path.insert(0, {os.getcwd()!r})
            os.environ["QT_QPA_PLATFORM"] = "offscreen"
            from unittest.mock import patch
            from PyQt6 import QtCore, QtWidgets
            from app.ProjectManager import ProjectManager
            from app.importers.NmapImporter import NmapImporter
            from app.logging.legionLog import getAppLogger, getDbLogger
            from app.shell.DefaultShell import DefaultShell
            from db.RepositoryFactory import RepositoryFactory
            app = QtWidgets.QApplication([])
            pm = ProjectManager(DefaultShell(), RepositoryFactory(getDbLogger()), getAppLogger())
            project = pm.createNewProject(projectType="legion", isTemp=True)
            imp = NmapImporter(None, project.repositoryContainer.hostRepository)
            imp.setDB(project.database)
            imp.setFilename({VALID_XML!r})
            failures = []
            imp.failed.connect(failures.append)
            imp.finished.connect(app.quit)
            with patch("app.importers.NmapImporter.parseNmapReport", side_effect=RuntimeError("boom")):
                imp.start()
                app.exec()
            imp.wait()
            print("FAILED_SIGNALS", len(failures))
        """)
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr[-2000:])
        self.assertIn("FAILED_SIGNALS 1", result.stdout)


class ControllerNmapImportQueueTest(unittest.TestCase):
    def _controller(self, running):
        from controller.controller import Controller

        ctrl = Controller.__new__(Controller)
        ctrl.nmapImporter = MagicMock()
        ctrl.nmapImporter.isRunning.side_effect = lambda: running["value"]
        ctrl.nmapImporter.wait.side_effect = AssertionError("must not block the UI thread")
        ctrl.view = MagicMock()
        return ctrl

    def test_second_import_waits_for_the_first_then_runs(self):
        running = {"value": False}
        ctrl = self._controller(running)

        ctrl.queueNmapImport("/tmp/first.xml")
        running["value"] = True
        ctrl.queueNmapImport("/tmp/second.xml", "terminal output")

        self.assertEqual(["/tmp/first.xml"], [c.args[0] for c in ctrl.nmapImporter.setFilename.call_args_list])
        self.assertEqual(1, ctrl.nmapImporter.start.call_count)   # not restarted while running

        running["value"] = False
        ctrl._startNextNmapImport(from_finished=True)              # QThread.finished of the first import
        self.assertEqual("/tmp/second.xml", ctrl.nmapImporter.setFilename.call_args.args[0])
        self.assertEqual("terminal output", ctrl.nmapImporter.setOutput.call_args.args[0])
        self.assertEqual(2, ctrl.nmapImporter.start.call_count)

    def test_file_imports_do_not_reuse_a_previous_scan_output(self):
        ctrl = self._controller({"value": False})
        ctrl.queueNmapImport("/tmp/scan.xml", "nmap terminal output")
        ctrl.queueNmapImport("/tmp/file.xml")
        self.assertEqual("", ctrl.nmapImporter.setOutput.call_args.args[0])

    def test_cancel_drops_queued_user_imports_but_keeps_background_ones(self):
        running = {"value": True}
        ctrl = self._controller(running)
        ctrl.queueNmapImport("/tmp/a.xml")
        ctrl.queueNmapImport("/tmp/stage3.xml", "out", interactive=False)
        ctrl.cancelNmapImports()
        ctrl.nmapImporter.cancel.assert_called_once_with()
        running["value"] = False
        ctrl._startNextNmapImport(from_finished=True)
        self.assertEqual(["/tmp/stage3.xml"], [c.args[0] for c in ctrl.nmapImporter.setFilename.call_args_list])

    def test_each_started_import_clears_a_previous_cancel(self):
        ctrl = self._controller({"value": False})
        ctrl.queueNmapImport("/tmp/a.xml")
        ctrl.nmapImporter.resetCancel.assert_called_once_with()

    def test_background_imports_do_not_show_the_progress_ui(self):
        ctrl = self._controller({"value": False})
        ctrl.queueNmapImport("/tmp/stage1.xml", "out", interactive=False)
        ctrl.view.showImportProgress.assert_not_called()
        ctrl.queueNmapImport("/tmp/user.xml")
        ctrl.view.showImportProgress.assert_called_once_with()

    @patch("controller.controller.QTimer")
    def test_finished_before_thread_stopped_retries_later_without_blocking(self, qtimer):
        running = {"value": True}
        ctrl = self._controller(running)
        ctrl.queueNmapImport("/tmp/next.xml")      # running: just queued, no wait
        ctrl._startNextNmapImport(from_finished=True)  # finished delivered while isRunning() is still True
        qtimer.singleShot.assert_called_once()
        ctrl.nmapImporter.start.assert_not_called()
        running["value"] = False
        qtimer.singleShot.call_args.args[1]()      # the scheduled re-check
        ctrl.nmapImporter.start.assert_called_once_with()


class ImportFinishedDelayedHideTest(unittest.TestCase):
    @patch("PyQt6.QtCore.QTimer")
    def test_delayed_hide_keeps_progress_of_a_queued_import(self, qtimer):
        from types import SimpleNamespace
        from ui.view import View

        view = SimpleNamespace(importProgressBar=MagicMock(), cancelImportButton=MagicMock())
        View.importFinished(view)
        delayed_hide = qtimer.singleShot.call_args.args[1]
        view.importProgressBar.reset_mock()
        view.importInProgress = True               # the next queued import started meanwhile
        delayed_hide()
        view.importProgressBar.setVisible.assert_not_called()


if __name__ == "__main__":
    unittest.main()
