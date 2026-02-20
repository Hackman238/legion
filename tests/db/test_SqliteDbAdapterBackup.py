import os
import tempfile
import unittest

from sqlalchemy import text

from db.SqliteDbAdapter import Database


class SqliteDbAdapterBackupTest(unittest.TestCase):
    def test_backup_to_same_path_returns_without_hanging(self):
        temp = tempfile.NamedTemporaryFile(prefix="legion-backup-", suffix=".legion", delete=False)
        temp.close()
        db_path = temp.name
        database = None
        try:
            database = Database(db_path)
            session = database.session()
            try:
                session.execute(text("CREATE TABLE IF NOT EXISTS backup_test_table (id INTEGER PRIMARY KEY, value TEXT)"))
                session.execute(text("INSERT INTO backup_test_table (value) VALUES ('ok')"))
                session.commit()
            finally:
                session.close()

            returned = database.backup_to(db_path)
            self.assertEqual(db_path, returned)
        finally:
            if database is not None:
                database.dispose()
            if os.path.isfile(db_path):
                os.remove(db_path)


if __name__ == "__main__":
    unittest.main()
