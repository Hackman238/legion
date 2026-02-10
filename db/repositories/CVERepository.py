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


class CVERepository:
    def __init__(self, dbAdapter: Database):
        self.dbAdapter = dbAdapter

    def getCVEsByHostIP(self, hostIP):
        session = self.dbAdapter.session()
        try:
            query = text('SELECT cves.name, cves.severity, cves.product, cves.version, cves.url, cves.source, '
                         'cves.exploitId, cves.exploit, cves.exploitUrl FROM cve AS cves '
                         'INNER JOIN hostObj AS hosts ON hosts.id = cves.hostId '
                         'WHERE hosts.ip = :hostIP')
            result = session.execute(query, {'hostIP': str(hostIP)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except OperationalError:
            return []
        finally:
            session.close()
