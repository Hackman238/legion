import unittest
from unittest.mock import MagicMock

from db.repositories.ProcessRepository import ProcessRepository


class ProcessRepositoryHardeningTest(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        adapter = MagicMock()
        adapter.session.return_value = self.session
        self.repo = ProcessRepository(adapter, MagicMock())

    def _last_query(self):
        return str(self.session.execute.call_args.args[0])

    def test_getProcesses_rejects_unknown_sort_column_and_direction(self):
        self.session.execute.return_value.fetchall.return_value = []
        self.repo.getProcesses({}, "True", sort="asc; DROP TABLE process", ncol="id; DROP TABLE process")
        self.assertTrue(self._last_query().endswith("ORDER BY id desc"))

    def test_getProcesses_accepts_known_sort_column(self):
        self.session.execute.return_value.fetchall.return_value = []
        self.repo.getProcesses({}, "True", sort="ASC", ncol="startTime")
        self.assertTrue(self._last_query().endswith("ORDER BY startTime asc"))

    def test_getFieldByProcessId_rejects_unknown_field(self):
        with self.assertRaises(ValueError):
            self.repo.getFieldByProcessId("id FROM process; --", 1)
        self.session.execute.assert_not_called()

    def test_status_writers_roll_back_and_close_on_failure(self):
        self.session.commit.side_effect = RuntimeError("db locked")
        self.session.query.return_value.filter_by.return_value.first.return_value = MagicMock(status="Running")
        for method in (self.repo.storeProcessCrashStatus, self.repo.storeProcessProblemStatus,
                       self.repo.storeProcessCancelStatus, self.repo.storeProcessKillStatus,
                       self.repo.storeCloseStatus):
            self.session.reset_mock()
            with self.assertRaises(RuntimeError):
                method(1)
            self.session.rollback.assert_called_once()
            self.session.close.assert_called_once()

    def test_toggleProcessDisplayStatus_rolls_back_and_closes_on_failure(self):
        self.session.commit.side_effect = RuntimeError("db locked")
        self.session.query.return_value.filter_by.return_value.all.return_value = []
        with self.assertRaises(RuntimeError):
            self.repo.toggleProcessDisplayStatus()
        self.session.rollback.assert_called_once()
        self.session.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
