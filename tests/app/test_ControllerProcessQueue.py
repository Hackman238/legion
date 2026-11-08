import os
import queue
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import QtCore

from controller.controller import Controller


def _fake_process(proc_id, name, pid=1000):
    proc = MagicMock()
    proc.id = proc_id
    proc.name = name
    proc.command = f"{name} target"
    proc.outputfile = ""
    proc.processId.return_value = pid
    return proc


def _make_controller(max_fast=10, max_scans=1):
    ctrl = Controller.__new__(Controller)
    ctrl.settings = SimpleNamespace(general_max_fast_processes=str(max_fast),
                                    general_max_concurrent_scans=max_scans)
    ctrl.processRepository = MagicMock()
    ctrl.processRepository.isCancelledProcess.return_value = False
    ctrl.processRepository.isKilledProcess.return_value = False
    ctrl.logic = MagicMock()
    ctrl.logic.activeProject.repositoryContainer.processRepository = ctrl.processRepository
    ctrl.view = MagicMock()
    ctrl.processes = []
    ctrl.fastProcessQueue = queue.Queue()
    ctrl.fastProcessesRunning = 0
    ctrl.processTimers = {}
    ctrl.processMeasurements = {}
    ctrl.updateUITimer = MagicMock()
    ctrl.processTableUiUpdateTimer = MagicMock()
    ctrl.processTableUiUpdateTimer.isActive.return_value = False
    return ctrl


class PartitionQueuedProcessesTest(unittest.TestCase):
    def _partition(self, pending, **kwargs):
        defaults = dict(running=0, running_scans=0, max_processes=10, max_scans=1,
                        is_cancelled=lambda p: False, is_scan=lambda p: p.startswith("nmap"))
        defaults.update(kwargs)
        return Controller._partitionQueuedProcesses(pending, **defaults)

    def test_scan_cap_only_blocks_scans(self):
        to_start, cancelled, waiting = self._partition(["nmap1", "nikto", "nmap2", "hydra"], running_scans=1)
        self.assertEqual(["nikto", "hydra"], to_start)
        self.assertEqual(["nmap1", "nmap2"], waiting)
        self.assertEqual([], cancelled)

    def test_process_cap_applies_to_all_and_keeps_fifo(self):
        to_start, _cancelled, waiting = self._partition(["nmap1", "nikto", "hydra"], max_processes=2)
        self.assertEqual(["nmap1", "nikto"], to_start)
        self.assertEqual(["hydra"], waiting)

    def test_cancelled_jobs_are_dropped(self):
        to_start, cancelled, waiting = self._partition(["nikto", "hydra"], is_cancelled=lambda p: p == "nikto")
        self.assertEqual(["hydra"], to_start)
        self.assertEqual(["nikto"], cancelled)
        self.assertEqual([], waiting)


class ControllerProcessQueueTest(unittest.TestCase):
    def test_finished_scan_frees_slot_for_next_queued_scan(self):
        ctrl = _make_controller(max_scans=1)
        first = _fake_process(1, "nmap")
        second = _fake_process(2, "nmap")
        ctrl.fastProcessQueue.put(first)
        ctrl.checkProcessQueue()
        ctrl.fastProcessQueue.put(second)
        ctrl.checkProcessQueue()
        self.assertEqual([first], ctrl.processes)
        second.start.assert_not_called()

        ctrl.processFinished(first)

        second.start.assert_called_once()
        self.assertEqual([second], ctrl.processes)
        self.assertEqual(1, ctrl.fastProcessesRunning)
        self.assertTrue(ctrl.fastProcessQueue.empty())

    def test_table_timer_kept_running_while_processes_run(self):
        ctrl = _make_controller()
        proc = _fake_process(1, "nikto")
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()
        ctrl.processTableUiUpdateTimer.isActive.return_value = True
        ctrl.checkProcessQueue()  # queue empty but a process is still running
        ctrl.processTableUiUpdateTimer.stop.assert_not_called()

        ctrl.processFinished(proc)
        ctrl.processTableUiUpdateTimer.stop.assert_called_once()

    @patch("controller.controller.QTimer")
    @patch("controller.controller.sip")
    def test_failed_to_start_releases_slot_once(self, mock_sip, mock_qtimer):
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        proc = _fake_process(1, "nikto", pid=0)
        elapsed_timer = MagicMock()
        ctrl.processTimers[1] = elapsed_timer
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()
        self.assertEqual(1, ctrl.fastProcessesRunning)

        ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.FailedToStart)
        ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.FailedToStart)

        self.assertEqual(0, ctrl.fastProcessesRunning)
        self.assertEqual([], ctrl.processes)
        elapsed_timer.stop.assert_called_once()
        self.assertNotIn(1, ctrl.processTimers)
        mock_qtimer.singleShot.assert_called_once()

    @patch("controller.controller.QTimer")
    @patch("controller.controller.sip")
    def test_failed_to_start_inside_start_is_not_marked_running(self, mock_sip, _mock_qtimer):
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        proc = _fake_process(1, "nikto")
        proc.start.side_effect = lambda *_a: ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.FailedToStart)
        ctrl.fastProcessQueue.put(proc)

        ctrl.checkProcessQueue()

        ctrl.processRepository.storeProcessCrashStatus.assert_called_once_with("1")
        ctrl.processRepository.storeProcessRunningStatus.assert_not_called()
        self.assertEqual(0, ctrl.fastProcessesRunning)

    @patch("controller.controller.os.kill")
    def test_killing_a_queued_process_removes_it_from_the_queue(self, mock_kill):
        ctrl = _make_controller(max_fast=1)
        running = _fake_process(1, "nikto")
        queued = _fake_process(2, "responder", pid=0)
        ctrl.fastProcessQueue.put(running)
        ctrl.checkProcessQueue()
        ctrl.fastProcessQueue.put(queued)
        ctrl.checkProcessQueue()

        ctrl.killProcess(0, 2)

        mock_kill.assert_not_called()
        self.assertTrue(ctrl.fastProcessQueue.empty())
        queued.start.assert_not_called()

    @patch("controller.controller.QTimer")
    @patch("controller.controller.sip")
    def test_crash_while_running_waits_for_finished(self, mock_sip, _mock_qtimer):
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        proc = _fake_process(1, "nikto")
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()

        ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.Crashed)
        self.assertEqual(1, ctrl.fastProcessesRunning)
        ctrl.processFinished(proc)
        self.assertEqual(0, ctrl.fastProcessesRunning)

    def test_cancel_drops_queued_process_and_its_timer(self):
        ctrl = _make_controller(max_fast=0)
        proc = _fake_process(5, "nikto")
        other = _fake_process(6, "hydra")
        timer = MagicMock()
        ctrl.processTimers[5] = timer
        ctrl.fastProcessQueue.put(proc)
        ctrl.fastProcessQueue.put(other)

        ctrl.cancelProcess(5)

        timer.stop.assert_called_once()
        self.assertEqual([other], list(ctrl.fastProcessQueue.queue))

    @patch("controller.controller.os.kill")
    def test_kill_process_ignores_non_positive_pid(self, mock_kill):
        ctrl = _make_controller()
        ctrl.killProcess(0, 1)
        ctrl.killProcess(-1, 1)
        ctrl.killProcess(None, 1)
        mock_kill.assert_not_called()
        ctrl.killProcess(4242, 1)
        mock_kill.assert_called_once()


class ControllerMiscTest(unittest.TestCase):
    def test_screenshot_finished_ignores_empty_filename(self):
        ctrl = _make_controller()
        ctrl.screenshotFinished("10.0.0.1", "80", "")
        ctrl.processRepository.storeScreenshot.assert_not_called()
        ctrl.view.createNewTabForHost.assert_not_called()

    @patch("app.screenshot_targets.socket.getaddrinfo")
    def test_deferred_target_url_does_not_resolve_until_called(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(None, None, None, None, ("10.0.0.9", 0))]
        build = Controller._deferred_target_url("deferred-test.example", "10.0.0.9", "443")
        mock_getaddrinfo.assert_not_called()
        self.assertEqual("deferred-test.example:443", build())

    def test_skipped_nmap_stage_advances_without_creating_tab(self):
        ctrl = _make_controller()
        ctrl.logic.activeProject.properties.runningFolder = "/tmp"
        ctrl.logic.activeProject.sessionFile = None
        ctrl.settings.tools_nmap_stage1_ports = "SKIP|"
        ctrl.settings.tools_nmap_stage2_ports = "NOOP|"
        ctrl.settings.tools_nmap_stage3_ports = "PORTS|T:80"
        ctrl.runCommand = MagicMock()

        ctrl.runStagedNmap("10.0.0.1", stage=1)

        ctrl.view.createNewTabForHost.assert_called_once()
        self.assertIn("stage 3", ctrl.view.createNewTabForHost.call_args[0][1])
        ctrl.runCommand.assert_called_once()
        self.assertEqual(3, ctrl.runCommand.call_args.kwargs["stage"])



class ControllerQueueResilienceTest(unittest.TestCase):
    def test_status_lookup_failure_keeps_processes_queued(self):
        ctrl = _make_controller(max_fast=1)
        running = _fake_process(1, "nikto")
        ctrl.fastProcessQueue.put(running)
        ctrl.checkProcessQueue()
        queued = [_fake_process(2, "hydra"), _fake_process(3, "nikto")]
        for proc in queued:
            ctrl.fastProcessQueue.put(proc)
        ctrl.processRepository.getStatusByProcessId.side_effect = RuntimeError("database is locked")

        ctrl._releaseProcessSlot(running)
        ctrl.checkProcessQueue()

        # The first queued job starts (status unreadable is treated as "not stopped"); none are lost.
        self.assertEqual([queued[0]], ctrl.processes)
        self.assertEqual([queued[1]], list(ctrl.fastProcessQueue.queue))

    def test_one_failing_start_does_not_drop_the_others(self):
        ctrl = _make_controller(max_fast=5)
        bad = _fake_process(1, "nikto")
        bad.start.side_effect = RuntimeError("boom")
        good = _fake_process(2, "hydra")
        ctrl.fastProcessQueue.put(bad)
        ctrl.fastProcessQueue.put(good)

        ctrl.checkProcessQueue()

        good.start.assert_called_once()
        ctrl.processRepository.storeProcessRunningStatus.assert_called_once_with(2, 1000)
        self.assertEqual([good], ctrl.processes)          # the failed start released its slot
        self.assertEqual(1, ctrl.fastProcessesRunning)
        ctrl.processRepository.storeProcessCrashStatus.assert_called_once_with("1")


class ControllerProcessFinishedSafetyTest(unittest.TestCase):
    def test_unexpected_error_does_not_escape_the_slot(self):
        # Under PyQt6 an exception escaping a slot aborts the whole application.
        ctrl = _make_controller()
        proc = _fake_process(1, "nikto")
        ctrl.processRepository.isKilledProcess.side_effect = RuntimeError("database is locked")
        ctrl.processFinished(proc)  # must not raise
        proc.close.assert_called()


class ControllerSaveAsDuringImportTest(unittest.TestCase):
    def test_save_as_is_refused_while_an_import_is_running(self):
        ctrl = _make_controller()
        ctrl.nmapImporter = MagicMock()
        ctrl.nmapImporter.isRunning.return_value = True
        ctrl.pythonImporter = MagicMock()
        ctrl.pythonImporter.isRunning.return_value = False

        self.assertTrue(ctrl.isImportRunning())
        self.assertFalse(ctrl.saveProjectAs("/tmp/copy.legion", 1))
        ctrl.logic.saveProjectAs.assert_not_called()

        ctrl.nmapImporter.isRunning.return_value = False
        self.assertFalse(ctrl.isImportRunning())

    @patch("controller.controller.QTimer")
    def test_import_end_schedules_a_retired_database_check(self, qtimer):
        ctrl = _make_controller()
        ctrl.logic.hasRetiredDatabases.return_value = True
        ctrl._onImporterFinished()
        qtimer.singleShot.assert_called_once_with(0, ctrl._disposeRetiredDatabasesIfIdle)

        qtimer.reset_mock()
        ctrl.logic.hasRetiredDatabases.return_value = False
        ctrl._onImporterFinished()
        qtimer.singleShot.assert_not_called()

    def test_retired_databases_are_disposed_only_when_idle(self):
        ctrl = _make_controller()
        ctrl.nmapImporter = MagicMock()
        ctrl.nmapImporter.isRunning.return_value = False
        ctrl.pythonImporter = MagicMock()
        ctrl.pythonImporter.isRunning.return_value = False
        ctrl.logic.hasRetiredDatabases.return_value = True

        ctrl.processes = [_fake_process(1, "nikto")]
        ctrl._disposeRetiredDatabasesIfIdle()
        ctrl.logic.disposeRetiredDatabases.assert_not_called()   # a running tool may hold the old repos

        ctrl.processes = []
        with patch("controller.controller.QTimer") as qtimer:
            ctrl._syncProcessTableTimer()                          # the queue just went idle
        ctrl.logic.disposeRetiredDatabases.assert_not_called()    # deferred: other finished-slots may follow
        qtimer.singleShot.assert_called_once_with(0, ctrl._disposeRetiredDatabasesIfIdle)
        ctrl._disposeRetiredDatabasesIfIdle()                      # what the next event-loop turn runs
        ctrl.logic.disposeRetiredDatabases.assert_called_once_with()


_NMAP_XML_WITH_UP_HOST = (
    '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
    '<address addr="10.0.0.7" addrtype="ipv4"/></host></nmaprun>'
)


class ControllerToolOutputLocationTest(unittest.TestCase):
    def setUp(self):
        import shutil
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="legion-ctrl-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _dir(self, name):
        path = os.path.join(self.tmp, name)
        os.makedirs(path, exist_ok=True)
        return path

    def test_nmap_import_after_save_as_uses_the_moved_xml(self):
        from app.shell.DefaultShell import DefaultShell
        from app.tools.ToolCoordinator import ToolCoordinator

        old_running = self._dir("old-running")
        new_running = self._dir("new-running")       # Save As reopened the project with a new running folder
        new_output = self._dir("new-tool-output")
        outputfile = os.path.join(old_running, "20260101-nmapstage1")
        with open(outputfile + ".xml", "w") as handle:
            handle.write(_NMAP_XML_WITH_UP_HOST)

        ctrl = _make_controller()
        ctrl.logic.activeProject.properties.runningFolder = new_running
        ctrl.logic.activeProject.properties.outputFolder = new_output
        ctrl.logic.toolCoordinator = ToolCoordinator(DefaultShell(), MagicMock())
        ctrl.queueNmapImport = MagicMock()
        proc = _fake_process(1, "nmap")
        proc.command = f"nmap -oA {outputfile} 10.0.0.7"
        proc.outputfile = outputfile
        proc.exitCode.return_value = 0
        ctrl.processes.append(proc)
        ctrl.fastProcessesRunning = 1

        ctrl.processFinished(proc)

        expected = os.path.join(new_output, "20260101-nmapstage1.xml")
        self.assertTrue(os.path.isfile(expected))                 # saveToolOutput moved it here
        ctrl.queueNmapImport.assert_called_once()
        self.assertEqual(os.path.normpath(expected), os.path.normpath(ctrl.queueNmapImport.call_args[0][0]))

    def test_locate_tool_output_xml_prefers_moved_file_then_original(self):
        ctrl = _make_controller()
        running = self._dir("running")
        output = self._dir("output")
        nmap_running = self._dir(os.path.join("running", "nmap"))
        outputfile = os.path.join(running, "scan")

        self.assertEqual(os.path.join(output, "scan.xml"), ctrl._locateToolOutputXml(outputfile, output))
        with open(outputfile + ".xml", "w") as handle:
            handle.write("<nmaprun/>")
        self.assertEqual(outputfile + ".xml", ctrl._locateToolOutputXml(outputfile, output))
        with open(os.path.join(output, "scan.xml"), "w") as handle:
            handle.write("<nmaprun/>")
        self.assertEqual(os.path.join(output, "scan.xml"), ctrl._locateToolOutputXml(outputfile, output))
        # saveToolOutput keeps an "nmap" parent folder
        self.assertEqual(os.path.join(output, "nmap", "scan.xml"),
                         ctrl._locateToolOutputXml(os.path.join(nmap_running, "scan"), output))

    def test_broad_discovery_canary_reads_the_xml_moved_by_process_finished(self):
        running = self._dir("running")
        output = self._dir("output")
        ctrl = _make_controller()
        ctrl.logic.activeProject.properties.outputFolder = output
        ctrl.runCommand = MagicMock()

        self.assertTrue(ctrl._run_broad_rfc1918_discovery("10.0.0.0/24", 3, [], 16, running))
        ctrl.runCommand.assert_called_once()
        canary_outputfile = ctrl.runCommand.call_args[0][7]
        on_canary_finished = ctrl.runCommand.call_args.kwargs["completion_handler"]

        # processFinished (connected first) already moved <outputfile>.xml into the output folder.
        with open(os.path.join(output, os.path.basename(canary_outputfile) + ".xml"), "w") as handle:
            handle.write(_NMAP_XML_WITH_UP_HOST)
        proc = SimpleNamespace(outputfile=canary_outputfile, exitCode=lambda: 0)
        on_canary_finished(proc, 0, 0)

        self.assertEqual(2, ctrl.runCommand.call_count)               # the full-scan phase was launched
        self.assertIn("broad full", ctrl.runCommand.call_args[0][1])


class ControllerKillRunningProcessesTest(unittest.TestCase):
    @patch("controller.controller.os.kill")
    def test_kill_detaches_per_process_signals_and_releases_slots(self, mock_kill):
        ctrl = _make_controller()
        proc = _fake_process(1, "nikto")
        timer = MagicMock()
        ctrl.processTimers[1] = timer
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()

        ctrl.killRunningProcesses()

        for signal_name in ("finished", "errorOccurred", "readyReadStandardOutput", "sigHydra"):
            getattr(proc, signal_name).disconnect.assert_called_once_with()
        proc.finished.connect.assert_called_once()                   # frees the QProcess once it exits
        proc.finished.connect.call_args[0][0](0, 0)
        proc.deleteLater.assert_called_once_with()
        timer.stop.assert_called_once()
        self.assertEqual([], ctrl.processes)
        self.assertEqual(0, ctrl.fastProcessesRunning)
        ctrl.processRepository.storeProcessKillStatus.assert_called_once_with("1")
        mock_kill.assert_called_once()

    @patch("controller.controller.sip")
    def test_crash_of_a_process_from_a_previous_project_is_ignored(self, mock_sip):
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        old_proc = _fake_process(7, "hydra")       # killed by killRunningProcesses, then a new project started

        ctrl.processCrashed(old_proc, QtCore.QProcess.ProcessError.Crashed)

        ctrl.processRepository.storeProcessCrashStatus.assert_not_called()
        ctrl.view.findFinishedServiceTab.assert_not_called()
        ctrl._notifyProcessCrashed.assert_not_called()

    @patch("controller.controller.sip")
    def test_crash_of_a_running_process_is_recorded(self, mock_sip):
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        proc = _fake_process(3, "nikto")
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()
        ctrl.processRepository.storeProcessCrashStatus.side_effect = RuntimeError("database is locked")

        ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.Crashed)   # must not raise out of the slot

        ctrl.processRepository.storeProcessCrashStatus.assert_called_once_with("3")
        ctrl._notifyProcessCrashed.assert_called_once()

    @patch("controller.controller.sip")
    def test_crash_signal_of_a_killed_process_is_not_reported(self, mock_sip):
        # A user-initiated kill (SIGTERM) makes QProcess emit errorOccurred(Crashed) before finished.
        mock_sip.isdeleted.return_value = False
        ctrl = _make_controller()
        ctrl._notifyProcessCrashed = MagicMock()
        proc = _fake_process(4, "nikto")
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()
        ctrl.processRepository.getStatusByProcessId.return_value = "Killed"

        ctrl.processCrashed(proc, QtCore.QProcess.ProcessError.Crashed)

        ctrl._notifyProcessCrashed.assert_not_called()
        ctrl.processRepository.storeProcessCrashStatus.assert_not_called()
        self.assertEqual([proc], ctrl.processes)   # finished still releases its slot


class ControllerHandleProcessActionTest(unittest.TestCase):
    @staticmethod
    def _kill_action():
        action = MagicMock()
        action.text.return_value = "Kill"
        return action

    @patch("controller.controller.os.kill")
    def test_kill_on_waiting_row_cancels_and_drops_it_from_the_queue(self, mock_kill):
        ctrl = _make_controller(max_fast=0)
        ctrl.view.killProcessConfirmation.return_value = True
        ctrl.processRepository.getStatusByProcessId.return_value = "Waiting"
        queued = _fake_process(2, "nikto", pid=0)
        timer = MagicMock()
        ctrl.processTimers[2] = timer
        ctrl.fastProcessQueue.put(queued)

        ctrl.handleProcessAction([(0, "Waiting", 2)], self._kill_action())

        ctrl.processRepository.storeProcessCancelStatus.assert_called_once_with("2")
        ctrl.processRepository.storeProcessKillStatus.assert_not_called()
        self.assertTrue(ctrl.fastProcessQueue.empty())
        timer.stop.assert_called_once()
        mock_kill.assert_not_called()

    @patch("controller.controller.os.kill")
    def test_kill_on_a_waiting_row_that_already_finished_changes_nothing(self, mock_kill):
        # The table said Waiting, but the process ran to completion since the table was drawn.
        ctrl = _make_controller()
        ctrl.view.killProcessConfirmation.return_value = True
        ctrl.processRepository.getStatusByProcessId.return_value = "Finished"

        ctrl.handleProcessAction([(0, "Waiting", 5)], self._kill_action())

        ctrl.processRepository.storeProcessCancelStatus.assert_not_called()
        ctrl.processRepository.storeProcessKillStatus.assert_not_called()
        mock_kill.assert_not_called()

    @patch("controller.controller.os.kill")
    def test_kill_on_stale_waiting_row_uses_the_live_pid(self, mock_kill):
        # The row said Waiting (pid 0) but the process has started since the table was drawn.
        ctrl = _make_controller()
        ctrl.view.killProcessConfirmation.return_value = True
        ctrl.processRepository.getStatusByProcessId.return_value = "Running"
        ctrl.processRepository.getPIDByProcessId.return_value = 4242
        proc = _fake_process(3, "nikto", pid=4242)
        ctrl.fastProcessQueue.put(proc)
        ctrl.checkProcessQueue()

        ctrl.handleProcessAction([(0, "Waiting", 3)], self._kill_action())

        ctrl.processRepository.storeProcessKillStatus.assert_called_once_with("3")
        ctrl.processRepository.storeProcessCancelStatus.assert_not_called()
        mock_kill.assert_called_once()
        self.assertEqual(4242, mock_kill.call_args[0][0])

    @patch("controller.controller.os.kill")
    def test_kill_on_running_row_prefers_repository_pid_over_stale_table_pid(self, mock_kill):
        ctrl = _make_controller()
        ctrl.view.killProcessConfirmation.return_value = True
        ctrl.processRepository.getPIDByProcessId.return_value = 5151

        ctrl.handleProcessAction([(0, "Running", 9)], self._kill_action())

        ctrl.processRepository.storeProcessKillStatus.assert_called_once_with("9")
        mock_kill.assert_called_once()
        self.assertEqual(5151, mock_kill.call_args[0][0])


class ControllerProjectSwitchTest(unittest.TestCase):
    def test_discard_queued_processes_stops_their_timers(self):
        ctrl = _make_controller(max_fast=0)
        queued = _fake_process(8, "nikto", pid=0)
        timer = MagicMock()
        ctrl.processTimers[8] = timer
        ctrl.fastProcessQueue.put(queued)

        ctrl._discardQueuedProcesses()

        timer.stop.assert_called_once()
        timer.deleteLater.assert_called_once()
        self.assertEqual({}, ctrl.processTimers)
        self.assertTrue(ctrl.fastProcessQueue.empty())
        queued.start.assert_not_called()

    def test_discard_queued_processes_before_first_start_is_safe(self):
        ctrl = Controller.__new__(Controller)   # __init__ calls start() before processTimers exists
        ctrl._discardQueuedProcesses()


if __name__ == "__main__":
    unittest.main()
