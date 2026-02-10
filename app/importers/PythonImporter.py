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

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""
from PyQt6 import QtCore

from db.entities.host import hostObj
from scripts.python import pyShodan, macvendors
from time import time


class PythonImporter(QtCore.QThread):
    tick = QtCore.pyqtSignal(int, name="changed")                       # New style signal
    done = QtCore.pyqtSignal(name="done")                               # New style signal
    schedule = QtCore.pyqtSignal(object, bool, name="schedule")         # New style signal
    log = QtCore.pyqtSignal(str, name="log")

    def __init__(self):
        QtCore.QThread.__init__(self, parent=None)
        self.output = ''
        self.hostIp = ''
        self.pythonScriptDispatch = {'pyShodan': pyShodan.PyShodanScript(), 'macvendors': macvendors.macvendorsScript()}
        self.pythonScriptObj = None

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def setDB(self, db):
        self.db = db

    def setHostIp(self, hostIp):
        self.hostIp = hostIp

    def setPythonScript(self, pythonScript):
        self.pythonScriptObj = self.pythonScriptDispatch[pythonScript]

    def setOutput(self, output):
        self.output = output

    def run(self): # it is necessary to get the qprocess to send it back to the scheduler when we're done
        session = None
        db_lock_acquired = False
        try:
            session = self.db.session()
            startTime = time()
            self.db.dbsemaphore.acquire() # ensure that while this thread is running, no one else can write to the DB
            db_lock_acquired = True
            self.setPythonScript(self.pythonScript)
            db_host = session.query(hostObj).filter_by(ip = self.hostIp).first()
            self.pythonScriptObj.setDbHost(db_host)
            self.pythonScriptObj.setSession(session)
            self.pythonScriptObj.run()
            session.commit()
            if db_lock_acquired:
                self.db.dbsemaphore.release()                               # we are done with the DB
                db_lock_acquired = False
            self.tsLog('Finished in ' + str(time() - startTime) + ' seconds.')
            self.done.emit()

        except Exception as e:
            self.tsLog(e)
            raise
        finally:
            try:
                if db_lock_acquired:
                    self.db.dbsemaphore.release()
            except Exception:
                pass
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass
