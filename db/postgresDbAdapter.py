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

import time
import threading
from random import randint

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session

from app.logging.legionLog import getDbLogger


class Database:
    def __init__(self, user: str, passw: str, db: str, host='localhost', port=5432):
        from db.database import Base
        self.log = getDbLogger()
        self.base = Base
        try:
            self.establishPostgresConnection(user, passw, db, host, port)
        except Exception as e:
            self.log.error('Could not connect to the Postgres database. Please try again.')
            self.log.info(e)
            raise

    def openDB(self, dbfilename):
        raise NotImplementedError('openDB is not implemented for Postgres yet.')

    def establishPostgresConnection(self, user: str, passw: str, db: str, host='localhost', port=5432):
        self.name = db
        self.port = port
        self.host = host
        self.user = user
        self.passw = passw
        self.dbsemaphore = threading.Semaphore(1)  # to control concurrent write access to db
        # URL.create escapes credentials containing special characters such as '@' or ':'
        url = URL.create('postgresql', username=user, password=passw, host=host, port=port, database=db)
        # The return value of create_engine() is our connection object
        self.engine = create_engine(url, client_encoding='utf8')
        # We then bind the connection to MetaData()
        #meta = sqlalchemy.MetaData(bind=con, reflect=True)
        self.session = scoped_session(sessionmaker())
        self.session.configure(bind=self.engine, autoflush=False)
        self.metadata = self.base.metadata
        self.metadata.create_all(self.engine)
        self.metadata.echo = True
        self.metadata.bind = self.engine
        self.log.info(f"Established Postgres connection to '{host}:{port}/{db}'")

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
