import os
import tempfile
import unittest

from db.SqliteDbAdapter import Database
from db.entities.host import hostObj


class DatabaseSessionIsolationTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.db = Database(os.path.join(self.tempdir.name, "project.legion"))
        self.addCleanup(self.db.dispose)

    def test_repository_close_on_the_same_thread_keeps_independent_session_work(self):
        work = self.db.new_session()
        try:
            work.add(hostObj(ip="10.0.0.1", hostname="a"))
            work.flush()
            # What a repository call does on this thread: use and close the thread-scoped session.
            scoped = self.db.session()
            scoped.query(hostObj).count()
            scoped.close()
            work.commit()
        finally:
            work.close()

        check = self.db.session()
        try:
            self.assertEqual(["10.0.0.1"], [row.ip for row in check.query(hostObj).all()])
        finally:
            check.close()


if __name__ == "__main__":
    unittest.main()
