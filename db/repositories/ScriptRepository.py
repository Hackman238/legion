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

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from db.SqliteDbAdapter import Database
from db.entities.l1script import l1ScriptObj


class ScriptRepository:
    def __init__(self, dbAdapter: Database):
        self.dbAdapter = dbAdapter

    def getScriptsByPortId(self, port_id):
        session = self.dbAdapter.session()
        try:
            return session.query(l1ScriptObj).filter_by(portId=port_id).all()
        except OperationalError:
            return []
        finally:
            session.close()


    def getScriptsByHostIP(self, hostIP):
        session = self.dbAdapter.session()
        try:
            query = text("SELECT host.id, host.scriptId, port.portId, port.protocol FROM l1ScriptObj AS host "
                         "INNER JOIN hostObj AS hosts ON hosts.id = host.hostId "
                         "LEFT OUTER JOIN portObj AS port ON port.id = host.portId WHERE hosts.ip=:hostIP")
            result = session.execute(query, {'hostIP': str(hostIP)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except OperationalError:
            return []
        finally:
            session.close()

    def getScriptOutputById(self, scriptDBId):
        session = self.dbAdapter.session()
        try:
            query = text("SELECT script.output FROM l1ScriptObj as script WHERE script.id = :scriptDBId")
            result = session.execute(query, {'scriptDBId': str(scriptDBId)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except OperationalError:
            return []
        finally:
            session.close()
