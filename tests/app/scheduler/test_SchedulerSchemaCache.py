import unittest

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.scheduler.schema_cache import ensure_column


class EnsureColumnTest(unittest.TestCase):
    def test_adds_a_missing_column_once_and_leaves_existing_ones_alone(self):
        engine = create_engine("sqlite://")
        session = sessionmaker(bind=engine)()
        try:
            session.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY)"))
            ensure_column(session, "t", "extra", "TEXT")
            ensure_column(session, "t", "extra", "TEXT")   # idempotent
            columns = [row[1] for row in session.execute(text("PRAGMA table_info(t)")).fetchall()]
        finally:
            session.close()
            engine.dispose()
        self.assertEqual(["id", "extra"], columns)


if __name__ == "__main__":
    unittest.main()
