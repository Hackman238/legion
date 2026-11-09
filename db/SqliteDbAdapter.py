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

"""

import sqlite3
import threading
from pathlib import Path
import time
from random import randint

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.exc import DatabaseError as SADatabaseError
from sqlalchemy.exc import OperationalError as SAOperationalError

from app.logging.legionLog import getDbLogger

# Import all entity classes to ensure their tables are registered with Base
from db.entities.host import hostObj
from db.entities.note import note
from db.entities.os import osObj
from db.entities.port import portObj
from db.entities.service import serviceObj
from db.entities.nmapSession import nmapSessionObj
from db.entities.l1script import l1ScriptObj
from db.entities.credentialCapture import credentialCapture
# Add any other entity classes as needed


class DatabaseIntegrityError(Exception):
    """Raised when the underlying SQLite database fails integrity checks."""


class Database:
    def __init__(self, dbfilename):
        from db.database import Base
        self.log = getDbLogger()
        self.base = Base
        try:
            self.establishSqliteConnection(dbfilename)
        except Exception as e:
            self.log.error('Could not create SQLite database. Please try again.')
            self.log.info(e)
            raise

    def openDB(self, dbfilename):
        try:
            self.establishSqliteConnection(dbfilename)
        except DatabaseIntegrityError:
            raise
        except Exception:
            self.log.error('Could not open SQLite database file. Is the file corrupted?')
            raise

    def establishSqliteConnection(self, dbFileName: str):
        self.name = dbFileName
        self.dbsemaphore = threading.Semaphore(1)  # to control concurrent write access to db
        self.engine = create_engine(
            'sqlite:///{dbFileName}'.format(dbFileName=dbFileName),
            connect_args={'check_same_thread': False}
        )
        self.session = scoped_session(sessionmaker(bind=self.engine))
        self.session.configure(bind=self.engine, autoflush=False)
        # Independent (non thread-scoped) sessions for long units of work. Repositories call close() on the
        # thread-scoped session above, which would discard a caller's uncommitted work if they shared it.
        self._independent_sessions = sessionmaker(bind=self.engine, autoflush=False)
        self.metadata = self.base.metadata

        try:
            self.metadata.create_all(self.engine)
            self.ensureIndexes()
        except SADatabaseError as exc:
            self.dispose()
            raise DatabaseIntegrityError(f"Failed to initialise SQLite metadata: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            self.dispose()
            raise DatabaseIntegrityError(f"Failed to initialise SQLite database: {exc}") from exc

        self.log.info(f"Established SQLite connection on file '{dbFileName}'")

    def new_session(self):
        """Return a session not shared with repositories on the same thread; the caller must close it."""
        return self._independent_sessions()

    def ensureIndexes(self):
        """
        create_all() only creates indexes for tables it creates, so add the declared (index=True) indexes to
        project files created before those indexes existed. CREATE INDEX IF NOT EXISTS is a no-op otherwise.
        """
        with self.engine.begin() as conn:
            for table in list(self.metadata.tables.values()):
                for index in table.indexes:
                    if not index.name:
                        continue
                    columns = ", ".join('"{0}"'.format(column.name) for column in index.columns)
                    unique = "UNIQUE " if index.unique else ""
                    try:
                        conn.exec_driver_sql(
                            'CREATE {0}INDEX IF NOT EXISTS "{1}" ON "{2}" ({3})'.format(
                                unique, index.name, table.name, columns
                            )
                        )
                    except SAOperationalError as exc:
                        # An index is only an optimisation; never make an older project unopenable over one.
                        self.log.warning(f"Could not create index {index.name} on {table.name}: {exc}")

    def commit(self):
        self.dbsemaphore.acquire()
        self.log.debug("DB lock acquired")
        try:
            session = self.session()
            try:
                rnd = float(randint(1, 99)) / 1000.00
                self.log.debug("Waiting {0}s before commit...".format(str(rnd)))
                time.sleep(rnd)
                session.commit()
            except Exception as e:
                self.log.error("DB Commit issue")
                self.log.error(str(e))
                # A failed commit leaves the session in a failed transaction and a rollback discards the pending
                # changes, so a blind retry would either fail again or silently commit nothing. Roll back so the
                # session stays usable and surface the error to the caller.
                session.rollback()
                raise
        finally:
            self.dbsemaphore.release()
            self.log.debug("DB lock released")

    def dispose(self):
        """Dispose of engine/session resources."""
        try:
            self.session.remove()
        except Exception:
            pass
        try:
            self.engine.dispose()
        except Exception:
            pass

    def verify_integrity(self):
        """
        Run PRAGMA quick_check to ensure the database is readable. Raises DatabaseIntegrityError on failure.
        """
        if not self.name:
            return True
        try:
            with sqlite3.connect(f"file:{self.name}?mode=ro", uri=True) as conn:
                cursor = conn.execute("PRAGMA quick_check")
                results = cursor.fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseIntegrityError(f"SQLite integrity check failed: {exc}") from exc

        if not results:
            raise DatabaseIntegrityError("SQLite integrity check returned no results.")

        errors = [row[0] for row in results if isinstance(row, (list, tuple)) and row and row[0].lower() != 'ok']
        if errors:
            raise DatabaseIntegrityError("SQLite integrity check reported issues: " + "; ".join(errors))
        return True

    def backup_to(self, destination: str):
        """
        Create a consistent backup of the database using SQLite's backup API.
        Raises DatabaseIntegrityError if the backup cannot be performed.
        """
        if not destination:
            raise ValueError("Destination path is required for database backup.")

        destination_path = Path(destination)
        if destination_path.parent and not destination_path.parent.exists():
            destination_path.parent.mkdir(parents=True, exist_ok=True)

        # Backing up a SQLite file onto itself can hang indefinitely.
        # Treat same-path backup as a no-op.
        try:
            src_norm = Path(self.name).resolve()
            dst_norm = destination_path.resolve()
        except Exception:
            src_norm = Path(str(self.name or "")).absolute()
            dst_norm = destination_path.absolute()
        if src_norm == dst_norm:
            return str(destination_path)

        try:
            with sqlite3.connect(f"file:{self.name}?mode=ro", uri=True) as src, \
                    sqlite3.connect(str(destination_path)) as dst:
                src.backup(dst)
        except sqlite3.DatabaseError as exc:
            raise DatabaseIntegrityError(f"SQLite backup failed: {exc}") from exc
        return str(destination_path)
