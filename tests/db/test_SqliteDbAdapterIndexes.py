import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock

from db.SqliteDbAdapter import Database

EXPECTED_INDEXES = {
    "ix_hostObj_ip", "ix_portObj_hostId", "ix_serviceObj_hostId", "ix_l1ScriptObj_portId",
    "ix_l1ScriptObj_hostId", "ix_osObj_hostId", "ix_cve_hostId", "ix_note_hostId",
}


def _index_names(path):
    with sqlite3.connect(path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}


class SqliteDbAdapterIndexesTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = os.path.join(self.tempdir.name, "project.legion")

    def test_new_database_has_lookup_indexes(self):
        db = Database(self.path)
        db.dispose()
        self.assertTrue(EXPECTED_INDEXES.issubset(_index_names(self.path)))

    def test_existing_database_without_indexes_gets_them_on_open(self):
        db = Database(self.path)
        db.dispose()
        with sqlite3.connect(self.path) as conn:
            for name in EXPECTED_INDEXES:
                conn.execute(f'DROP INDEX IF EXISTS "{name}"')
        self.assertFalse(EXPECTED_INDEXES & _index_names(self.path))

        db = Database(self.path)
        db.dispose()
        self.assertTrue(EXPECTED_INDEXES.issubset(_index_names(self.path)))


class SqliteDbAdapterCommitTest(unittest.TestCase):
    def test_commit_failure_rolls_back_and_raises_and_releases_lock(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        db = Database(os.path.join(tempdir.name, "project.legion"))
        self.addCleanup(db.dispose)
        failing_session = MagicMock()
        failing_session.commit.side_effect = RuntimeError("boom")
        db.session = MagicMock(return_value=failing_session)

        with self.assertRaises(RuntimeError):
            db.commit()

        failing_session.rollback.assert_called_once()
        self.assertTrue(db.dbsemaphore.acquire(blocking=False))
        db.dbsemaphore.release()


if __name__ == "__main__":
    unittest.main()
