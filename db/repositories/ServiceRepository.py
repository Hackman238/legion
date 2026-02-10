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
from app.auxiliary import Filters
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from db.SqliteDbAdapter import Database
from db.filters import applyFilters
from db.entities.service import serviceObj


class ServiceRepository:
    def __init__(self, db_adapter: Database):
        self.dbAdapter = db_adapter

    def getServiceNames(self, filters: Filters):
        session = self.dbAdapter.session()
        try:
            query = ("SELECT DISTINCT service.name FROM serviceObj as service "
                     "INNER JOIN portObj as ports "
                     "INNER JOIN hostObj AS hosts "
                     "ON hosts.id = ports.hostId AND service.id=ports.serviceId WHERE 1=1")
            query += applyFilters(filters)
            query += ' ORDER BY service.name ASC'
            query = text(query)
            result = session.execute(query)
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except OperationalError:
            # Database unavailable (e.g. "unable to open database file").
            return []
        finally:
            session.close()

    def getServiceNamesByHostIPAndPort(self, host_ip, port):
        session = self.dbAdapter.session()
        try:
            query = text("SELECT services.name FROM serviceObj AS services "
                         "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                         "INNER JOIN portObj AS ports ON services.id=ports.serviceId "
                         "WHERE hosts.ip=:host_ip and ports.portId = :port")
            return session.execute(query, {'host_ip': str(host_ip), 'port': str(port)}).first()
        except OperationalError:
            return None
        finally:
            session.close()

    def getServiceById(self, service_id):
        session = self.dbAdapter.session()
        try:
            return session.query(serviceObj).filter_by(id=service_id).first()
        except OperationalError:
            return None
        finally:
            session.close()
