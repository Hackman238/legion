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

from PyQt6.QtCore import QSemaphore
import sqlite3
from pathlib import Path
import time
from random import randint

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.exc import DatabaseError as SADatabaseError

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
        self.dbsemaphore = QSemaphore(1)  # to control concurrent write access to db
        self.engine = create_engine(
            'sqlite:///{dbFileName}'.format(dbFileName=dbFileName),
            connect_args={'check_same_thread': False}
        )
        self.session = scoped_session(sessionmaker(bind=self.engine))
        self.session.configure(bind=self.engine, autoflush=False)
        self.metadata = self.base.metadata

        try:
            self.metadata.create_all(self.engine)
        except SADatabaseError as exc:
            self.dispose()
            raise DatabaseIntegrityError(f"Failed to initialise SQLite metadata: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            self.dispose()
            raise DatabaseIntegrityError(f"Failed to initialise SQLite database: {exc}") from exc

        self.metadata.echo = True
        self.metadata.bind = self.engine
        self.log.info(f"Established SQLite connection on file '{dbFileName}'")

    def commit(self):
        self.dbsemaphore.acquire()
        self.log.debug("DB lock acquired")
        try:
            session = self.session()
            rnd = float(randint(1, 99)) / 1000.00
            self.log.debug("Waiting {0}s before commit...".format(str(rnd)))
            time.sleep(rnd)
            session.commit()
        except Exception as e:
            self.log.error("DB Commit issue")
            self.log.error(str(e))
            try:
                rnd = float(randint(1, 99)) / 100.00
                time.sleep(rnd)
                self.log.debug("Waiting {0}s before commit...".format(str(rnd)))
                session.commit()
            except Exception as e:
                self.log.error("DB Commit issue on retry")
                self.log.error(str(e))
                pass
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
