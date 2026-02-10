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
from db.entities.port import portObj
from db.filters import applyPortFilters


class PortRepository:
    def __init__(self, dbAdapter: Database):
        self.dbAdapter = dbAdapter

    def getPortsByHostId(self, host_id):
        """
        Return all portObj ORM objects for a given host ID.
        """
        session = self.dbAdapter.session()
        try:
            return session.query(portObj).filter_by(hostId=host_id).all()
        except OperationalError:
            return []
        finally:
            session.close()

    def getPortsByIPAndProtocol(self, host_ip, protocol):
        session = self.dbAdapter.session()
        try:
            query = text("SELECT ports.portId FROM portObj AS ports INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                         "WHERE hosts.ip = :host_ip and ports.protocol = :protocol")
            return session.execute(query, {'host_ip': str(host_ip), 'protocol': str(protocol)}).first()
        except OperationalError:
            return None
        finally:
            session.close()

    def getPortStatesByHostId(self, host_id):
        session = self.dbAdapter.session()
        try:
            query = text('SELECT port.state FROM portObj as port WHERE port.hostId = :host_id')
            return session.execute(query, {'host_id': str(host_id)}).fetchall()
        except OperationalError:
            return []
        finally:
            session.close()

    def getPortsAndServicesByHostIP(self, host_ip, filters):
        session = self.dbAdapter.session()
        try:
            query = ("SELECT hosts.ip, ports.portId, ports.protocol, ports.state, ports.hostId, ports.serviceId, "
                     "services.name, services.product, services.version, services.extrainfo, services.fingerprint "
                     "FROM portObj AS ports INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                     "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId WHERE hosts.ip = :host_ip")
            query += applyPortFilters(filters)
            query = text(query)
            result = session.execute(query, {'host_ip': str(host_ip)})
            rows = result.fetchall()
            keys = result.keys()
            return [dict(zip(keys, row)) for row in rows]
        except OperationalError:
            return []
        finally:
            session.close()

    # used to delete all port/script data related to a host - to overwrite portscan info with the latest scan
    def deleteAllPortsAndScriptsByHostId(self, hostID, protocol):
        session = self.dbAdapter.session()
        try:
            ports_for_host = session.query(portObj)\
                .filter(portObj.hostId == hostID)\
                .filter(portObj.protocol == str(protocol)).all()

            for p in ports_for_host:
                scripts_for_ports = session.query(l1ScriptObj).filter(l1ScriptObj.portId == p.id).all()
                for s in scripts_for_ports:
                    session.delete(s)
            for p in ports_for_host:
                session.delete(p)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # delete a single port (and its scripts) by hostId, port, and protocol
    def deletePortByHostIdAndPort(self, hostID, port, protocol):
        session = self.dbAdapter.session()
        try:
            port_entry = session.query(portObj)\
                .filter(portObj.hostId == hostID)\
                .filter(portObj.portId == str(port))\
                .filter(portObj.protocol == str(protocol)).first()
            if port_entry:
                scripts_for_port = session.query(l1ScriptObj).filter(l1ScriptObj.portId == port_entry.id).all()
                for s in scripts_for_port:
                    session.delete(s)
                session.delete(port_entry)
                session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # fetch a single port by hostId, port, and protocol
    def getPortByHostIdAndPort(self, hostID, port, protocol):
        session = self.dbAdapter.session()
        try:
            return session.query(portObj)\
                .filter(portObj.hostId == hostID)\
                .filter(portObj.portId == str(port))\
                .filter(portObj.protocol == str(protocol)).first()
        except OperationalError:
            return None
        finally:
            session.close()
