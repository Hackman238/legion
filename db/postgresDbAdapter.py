"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2024 Shane Scott

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
import time
from random import randint

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session

from app.logging.legionLog import getDbLogger


class Database:
    def __init__(self, user: str, passw: str, db: str, host='localhost', port=5432):
        from db.database import Base
        self.log = getDbLogger()
        self.base = Base
        try:
            self.establishSqliteConnection(user, passw. db. host, port)
        except Exception as e:
            self.log.error('Could not create SQLite database. Please try again.')
            self.log.info(e)

    def openDB(self, dbfilename):
        try:
            self.log.error('Not implemented for Postgres yet.')
        except:
            self.log.error('Could not open SQLite database file. Is the file corrupted?')

    def establishSqliteConnection(self, user: str, passw: str, db: str, host='localhost', port=5432):
        self.name = db
        self.port = port
        self.host = host
        self.user = user
        self.passw = passw
        self.dbsemaphore = QSemaphore(1)  # to control concurrent write access to db
        url = 'postgresql://{}:{}@{}:{}/{}'
        url = url.format(user, password, host, port, db)
        # The return value of create_engine() is our connection object
        self.engine = sqlalchemy.create_engine(
            url, client_encoding='utf8')
        # We then bind the connection to MetaData()
        #meta = sqlalchemy.MetaData(bind=con, reflect=True)
        self.session = scoped_session(sessionmaker())
        self.session.configure(bind=self.engine, autoflush=False)
        self.metadata = self.base.metadata
        self.metadata.create_all(self.engine)
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
