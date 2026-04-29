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

from tests.db.helpers.db_helpers import mockExecuteRows, mockFirstBySideEffect, mockFirstByReturnValue, \
    mockQueryWithFilterBy


def build_mock_process(status: str, display: str) -> MagicMock:
    process = MagicMock()
    process.status = status
    process.display = display
    return process


class ProcessRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        from db.repositories.ProcessRepository import ProcessRepository
        self.mockProcess = MagicMock()
        self.mockDbSession = MagicMock()
        self.mockDbAdapter = MagicMock()
        self.mockLogger = MagicMock()
        self.mockFilters = MagicMock()
        self.mockDbAdapter.session.return_value = self.mockDbSession
        self.processRepository = ProcessRepository(self.mockDbAdapter, self.mockLogger)

    def test_getProcesses_WhenProvidedShowProcessesWithNoNmapFlag_ReturnsProcesses(self):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [('some-process',), ('some-process2',)],
            ['name'],
        )
        processes = self.processRepository.getProcesses(self.mockFilters, showProcesses='noNmap')
        self.assertEqual(processes, [{'name': 'some-process'}, {'name': 'some-process2'}])
        query = str(self.mockDbSession.execute.call_args.args[0])
        self.assertIn('FROM process AS process WHERE process.closed = "False"', query)
        self.assertIn('ORDER BY process.id DESC', query)

    def test_getProcesses_WhenProvidedShowProcessesWithFlagFalse_ReturnsProcesses(self):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [('some-process',), ('some-process2',)],
            ['name'],
        )
        processes = self.processRepository.getProcesses(self.mockFilters, showProcesses=False)
        self.assertEqual(processes, [{'name': 'some-process'}, {'name': 'some-process2'}])
        query, params = self.mockDbSession.execute.call_args.args
        self.assertIn('INNER JOIN process_output AS output ON process.id = output.processId', str(query))
        self.assertEqual({'display': 'False'}, params)

    def test_getProcesses_WhenProvidedShowProcessesWithNoFlag_ReturnsProcesses(self):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [('some-process',), ('some-process2',)],
            ['name'],
        )
        processes = self.processRepository.getProcesses(self.mockFilters, "True", sort='asc', ncol='id')
        self.assertEqual(processes, [{'name': 'some-process'}, {'name': 'some-process2'}])
        query, params = self.mockDbSession.execute.call_args.args
        self.assertIn('WHERE process.display=:display ORDER BY id asc', str(query))
        self.assertEqual({'display': 'True'}, params)

    def test_storeProcess_WhenProvidedAProcess_StoreProcess(self):
        self.processRepository.storeProcess(self.mockProcess)

        self.mockDbSession.add.assert_called_once()
        self.mockDbSession.commit.assert_called_once()

    def test_storeProcessOutput_WhenProvidedExistingProcessIdAndOutput_StoresProcessOutput(self):
        from db.entities.process import process
        from db.entities.processOutput import process_output

        expected_process: process = MagicMock()
        process.status = 'Running'
        expected_process_output: process_output = MagicMock()
        mock_query = MagicMock()
        mock_query.filter_by.return_value = mockFirstBySideEffect([expected_process, expected_process_output])
        self.mockDbSession.query.return_value = mock_query

        self.processRepository.storeProcessOutput("some_process_id", "this is some cool output")

        self.mockDbSession.add.assert_has_calls([
            mock.call(expected_process_output),
            mock.call(expected_process)
        ])
        self.mockDbSession.commit.assert_called_once()

    def test_storeProcessOutput_WhenProvidedProcessIdDoesNotExist_DoesNotPerformAnyUpdate(self):
        self.mockDbAdapter.session.return_value = self.mockDbSession
        self.mockDbSession.query.return_value = mockQueryWithFilterBy(mockFirstByReturnValue(False))

        self.processRepository.storeProcessOutput("some_non_existent_process_id", "this is some cool output")

        self.mockDbSession.add.assert_not_called()
        self.mockDbSession.commit.assert_not_called()

    def test_storeProcessOutput_WhenProvidedExistingProcessIdAndOutputButProcKilled_StoresOutputButStatusNotUpdated(
            self):
        self.whenProcessDoesNotFinishGracefully("Killed")

    def test_storeProcessOutput_WhenProvidedExistingProcessIdAndOutputButProcCancelled_StoresOutputButStatusNotUpdated(
            self):
        self.whenProcessDoesNotFinishGracefully("Cancelled")

    def test_storeProcessOutput_WhenProvidedExistingProcessIdAndOutputButProcCrashed_StoresOutputButStatusNotUpdated(
            self):
        self.whenProcessDoesNotFinishGracefully("Crashed")

    def test_storeProcessOutput_WhenProvidedExistingProcessIdAndOutputButProcProblem_StoresOutputButStatusNotUpdated(
            self):
        self.whenProcessDoesNotFinishGracefully("Problem")

    def test_getStatusByProcessId_WhenGivenProcId_FetchesProcessStatus(self):
        expectedQuery = 'SELECT process.status FROM process AS process WHERE process.id=:process_id'
        self.mockDbSession.execute.return_value = mockExecuteRows([('Running',)], ['status'])

        actual_status = self.processRepository.getStatusByProcessId("some_process_id")

        self.assertEqual(actual_status, 'Running')
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_getStatusByProcessId_WhenProcIdDoesNotExist_ReturnsNegativeOne(self):
        expectedQuery = 'SELECT process.status FROM process AS process WHERE process.id=:process_id'
        self.mockDbSession.execute.return_value = mockExecuteRows([], ['status'])

        actual_status = self.processRepository.getStatusByProcessId("some_process_id")

        self.assertEqual(actual_status, -1)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_getPIDByProcessId_WhenGivenProcId_FetchesProcessId(self):
        expectedQuery = 'SELECT process.pid FROM process AS process WHERE process.id=:process_id'
        self.mockDbSession.execute.return_value = mockExecuteRows([('1234',)], ['pid'])

        actual_status = self.processRepository.getPIDByProcessId("some_process_id")

        self.assertEqual(actual_status, '1234')
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_getPIDByProcessId_WhenProcIdDoesNotExist_ReturnsNegativeOne(self):
        expectedQuery = 'SELECT process.pid FROM process AS process WHERE process.id=:process_id'
        self.mockDbSession.execute.return_value = mockExecuteRows([], ['pid'])

        actual_status = self.processRepository.getPIDByProcessId("some_process_id")

        self.assertEqual(actual_status, -1)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_isKilledProcess_WhenProvidedKilledProcessId_ReturnsTrue(self):
        expectedQuery = "SELECT process.status FROM process AS process WHERE process.id=:process_id"
        self.mockDbSession.execute.return_value = mockExecuteRows([("Killed",)], ["status"])

        self.assertTrue(self.processRepository.isKilledProcess("some_process_id"))
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_isKilledProcess_WhenProvidedNonKilledProcessId_ReturnsFalse(self):
        expectedQuery = "SELECT process.status FROM process AS process WHERE process.id=:process_id"
        self.mockDbSession.execute.return_value = mockExecuteRows([("Running",)], ["status"])

        self.assertFalse(self.processRepository.isKilledProcess("some_process_id"))
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_isCancelledProcess_WhenProvidedCancelledProcessId_ReturnsTrue(self):
        expectedQuery = "SELECT process.status FROM process AS process WHERE process.id=:process_id"
        self.mockDbSession.execute.return_value = mockExecuteRows([("Cancelled",)], ["status"])

        self.assertTrue(self.processRepository.isCancelledProcess("some_process_id"))
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_isCancelledProcess_WhenProvidedNonCancelledProcessId_ReturnsFalse(self):
        expectedQuery = "SELECT process.status FROM process AS process WHERE process.id=:process_id"
        self.mockDbSession.execute.return_value = mockExecuteRows([("Running",)], ["status"])

        self.assertFalse(self.processRepository.isCancelledProcess("some_process_id"))
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({'process_id': 'some_process_id'}, params)

    def test_storeProcessCrashStatus_WhenProvidedProcessId_StoresProcessCrashStatus(self):
        self.mockProcessStatusAndReturnSingle("Running")
        self.processRepository.storeProcessCrashStatus("some-process-id")
        self.assertProcessStatusUpdatedTo("Crashed")

    def test_storeProcessCancelledStatus_WhenProvidedProcessId_StoresProcessCancelledStatus(self):
        self.mockProcessStatusAndReturnSingle("Running")
        self.processRepository.storeProcessCancelStatus("some-process-id")
        self.assertProcessStatusUpdatedTo("Cancelled")

    def test_storeProcessProblemStatus_WhenProvidedProcessId_StoresProcessProblemStatus(self):
        self.mockProcessStatusAndReturnSingle("Running")
        self.processRepository.storeProcessProblemStatus("some-process-id")
        self.assertProcessStatusUpdatedTo("Problem")

    def test_storeProcessRunningStatus_WhenProvidedProcessId_StoresProcessRunningStatus(self):
        self.mockProcessStatusAndReturnSingle("Waiting")
        self.processRepository.storeProcessRunningStatus("some-process-id", "3123")
        self.assertProcessStatusUpdatedTo("Running")

    def test_storeProcessKillStatus_WhenProvidedProcessId_StoresProcessKillStatus(self):
        self.mockProcessStatusAndReturnSingle("Running")
        self.processRepository.storeProcessKillStatus("some-process-id")
        self.assertProcessStatusUpdatedTo("Killed")

    def test_storeProcessRunningElapsedTime_WhenProvidedProcessId_StoresProcessRunningElapsedTime(self):
        self.mockProcess.elapsed = "some-time"
        self.mockDbSession.query.return_value = mockQueryWithFilterBy(mockFirstByReturnValue(self.mockProcess))

        self.processRepository.storeProcessRunningElapsedTime("some-process-id", "another-time")
        self.assertEqual("another-time", self.mockProcess.elapsed)
        self.mockDbSession.add.assert_called_once_with(self.mockProcess)
        self.mockDbSession.commit.assert_called_once()

    def test_getHostsByToolName_WhenProvidedToolNameAndClosedFalse_StoresProcessRunningElapsedTime(self):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [("some-host1",), ("some-host2",)],
            ["hostIp"],
        )

        hosts = self.processRepository.getHostsByToolName("some-toolname", "False")
        self.assertEqual([{"hostIp": "some-host1"}, {"hostIp": "some-host2"}], hosts)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertIn("WHERE process.name=:toolName AND process.closed=:closed", str(query))
        self.assertEqual({"toolName": "some-toolname", "closed": "False"}, params)

    def test_getHostsByToolName_WhenProvidedToolNameAndClosedAsFetchAll_StoresProcessRunningElapsedTime(self):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [("some-host1",), ("some-host2",)],
            ["hostIp"],
        )

        hosts = self.processRepository.getHostsByToolName("some-toolname", "FetchAll")
        self.assertEqual([{"hostIp": "some-host1"}, {"hostIp": "some-host2"}], hosts)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertIn("WHERE process.name=:toolName", str(query))
        self.assertEqual({"toolName": "some-toolname"}, params)

    def test_storeCloseStatus_WhenProvidedProcessId_StoresCloseStatus(self):
        self.mockProcess.closed = 'False'
        self.mockDbSession.query.return_value = mockQueryWithFilterBy(mockFirstByReturnValue(self.mockProcess))
        self.processRepository.storeCloseStatus("some-process-id")

        self.assertEqual('True', self.mockProcess.closed)
        self.mockDbSession.add.assert_called_once_with(self.mockProcess)
        self.mockDbSession.commit.assert_called_once()

    def test_storeScreenshot_WhenProvidedIPAndPortAndFileName_StoresScreenshot(self):
        self.processRepository.storeScreenshot("some-ip", "some-port", "some-filename")
        self.mockDbSession.add.assert_called_once()
        self.mockDbSession.commit.assert_called_once()

    def test_toggleProcessDisplayStatus_whenResetAllIsTrue_setDisplayToFalseForAllProcessesThatAreNotRunning(
            self):
        process1 = build_mock_process(status="Waiting", display="True")
        process2 = build_mock_process(status="Waiting", display="True")
        mock_query_response = MagicMock()
        mock_filtered_response = MagicMock()
        mock_filtered_response.all.return_value = [process1, process2]
        mock_query_response.filter_by.return_value = mock_filtered_response
        self.mockDbSession.query.return_value = mock_query_response
        self.processRepository.toggleProcessDisplayStatus(resetAll=True)

        self.assertEqual("False", process1.display)
        self.assertEqual("False", process2.display)
        self.mockDbSession.add.assert_has_calls([
            mock.call(process1),
            mock.call(process2),
        ])
        self.mockDbSession.commit.assert_called_once()

    def test_toggleProcessDisplayStatus_whenResetAllIFalse_setDisplayToFalseForAllProcessesThatAreNotRunningOrWaiting(
            self):
        process1 = build_mock_process(status="Random Status", display="True")
        process2 = build_mock_process(status="Another Random Status", display="True")
        process3 = build_mock_process(status="Running", display="True")
        mock_query_response = MagicMock()
        mock_filtered_response = MagicMock()
        mock_filtered_response.all.return_value = [process1, process2]
        mock_query_response.filter_by.return_value = mock_filtered_response
        self.mockDbSession.query.return_value = mock_query_response
        self.processRepository.toggleProcessDisplayStatus()

        self.assertEqual("False", process1.display)
        self.assertEqual("False", process2.display)
        self.assertEqual("True", process3.display)
        self.mockDbSession.add.assert_has_calls([
            mock.call(process1),
            mock.call(process2),
        ])
        self.mockDbSession.commit.assert_called_once()

    def mockProcessStatusAndReturnSingle(self, processStatus: str):
        self.mockProcess.status = processStatus
        self.mockDbSession.query.return_value = mockQueryWithFilterBy(mockFirstByReturnValue(self.mockProcess))

    def assertProcessStatusUpdatedTo(self, expected_status: str):
        self.assertEqual(expected_status, self.mockProcess.status)
        self.mockDbSession.add.assert_called_once_with(self.mockProcess)
        self.mockDbSession.commit.assert_called_once()

    def whenProcessDoesNotFinishGracefully(self, process_status: str):
        from db.entities.process import process
        from db.entities.processOutput import process_output

        expected_process: process = MagicMock()
        expected_process.status = process_status
        expected_process_output: process_output = MagicMock()
        self.mockDbSession.query.return_value = mockQueryWithFilterBy(
            mockFirstBySideEffect([expected_process, expected_process_output]))

        self.processRepository.storeProcessOutput("some_process_id", "this is some cool output")

        self.assertIn(mock.call(expected_process_output), self.mockDbSession.add.call_args_list)
        self.mockDbSession.commit.assert_called_once()
