import os
import tempfile
import unittest
from unittest.mock import MagicMock

from db.SqliteDbAdapter import Database
from db.entities.process import process
from db.repositories.ProcessRepository import ProcessRepository


def add_process(database, status, pid="4242", end_time="", estimated_remaining=None):
    session = database.session()
    try:
        row = process(pid, name="nmap", tabTitle="nmap", hostIp="10.0.0.1", command="nmap 10.0.0.1",
                      startTime="2026-01-01 00:00:00", endTime=end_time, status=status,
                      estimatedRemaining=estimated_remaining)
        session.add(row)
        session.commit()
        return row.id
    finally:
        session.close()


class ProcessRepositoryMarkInterruptedTest(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.database = Database(os.path.join(tempdir.name, "project.legion"))
        self.addCleanup(self.database.dispose)
        self.repo = ProcessRepository(self.database, MagicMock())

    def test_running_and_waiting_rows_are_marked_crashed_with_an_end_time(self):
        running = add_process(self.database, "Running", estimated_remaining=120)
        waiting = add_process(self.database, "Waiting", pid="0")
        finished = add_process(self.database, "Finished", end_time="2026-01-01 00:01:00")
        killed = add_process(self.database, "Killed", end_time="2026-01-01 00:02:00")

        self.assertEqual(2, self.repo.markInterruptedProcesses())

        for process_id in (running, waiting):
            self.assertEqual("Crashed", self.repo.getStatusByProcessId(process_id))
            self.assertTrue(self.repo.getFieldByProcessId("endTime", process_id))
            self.assertIsNone(self.repo.getFieldByProcessId("estimatedRemaining", process_id))
        self.assertEqual("Finished", self.repo.getStatusByProcessId(finished))
        self.assertEqual("2026-01-01 00:01:00", self.repo.getFieldByProcessId("endTime", finished))
        self.assertEqual("Killed", self.repo.getStatusByProcessId(killed))
        self.assertEqual(0, self.repo.markInterruptedProcesses())

    def test_interrupted_rows_are_listed_by_the_failed_filter_and_stay_failed_when_output_is_stored(self):
        running = add_process(self.database, "Running")
        add_process(self.database, "Finished", end_time="2026-01-01 00:01:00")

        self.repo.markInterruptedProcesses()

        for status_filter in ("Failed", ["Crashed", "Cancelled", "Killed", "Failed"]):
            rows = self.repo.getProcesses({}, "True", status_filter=status_filter)
            self.assertEqual([running], [row["id"] for row in rows], status_filter)
        # A late completion callback must not turn the interrupted row into a finished one.
        self.repo.storeProcessOutput(str(running), "late output")
        self.assertEqual("Crashed", self.repo.getStatusByProcessId(running))


if __name__ == "__main__":
    unittest.main()
