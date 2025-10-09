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
from db.SqliteDbAdapter import Database
from db.entities.host import hostObj
from app.osclassification import classify_os, ORDERED_OS_CATEGORIES
from db.filters import applyFilters, applyHostsFilters


class HostRepository:
    def __init__(self, dbAdapter: Database):
        self.dbAdapter = dbAdapter


    def exists(self, host: str):
        session = self.dbAdapter.session()
        query = text('SELECT host.ip FROM hostObj AS host WHERE host.ip == :host OR host.hostname == :host')
        result = session.execute(query, {'host': str(host)}).fetchall()
        session.close()
        return True if result else False

    def getHosts(self, filters):
        session = self.dbAdapter.session()
        query = 'SELECT * FROM hostObj AS hosts WHERE 1=1'
        query += applyHostsFilters(filters)
        query = text(query)
        result = session.execute(query)
        rows = result.fetchall()
        # Get column names from result metadata
        keys = result.keys()
        # Convert each row (tuple) to a dict
        hosts = [dict(zip(keys, row)) for row in rows]
        session.close()
        return hosts

    def getHostsAndPortsByServiceName(self, service_name, filters: Filters):
        session = self.dbAdapter.session()
        query = ("SELECT hosts.ip,ports.portId,ports.protocol,ports.state,ports.hostId,ports.serviceId,"
                 "services.name,services.product,services.version,services.extrainfo,services.fingerprint "
                 "FROM portObj AS ports "
                 "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                 "LEFT OUTER JOIN serviceObj AS services ON services.id=ports.serviceId "
                 "WHERE services.name=:service_name")
        query += applyFilters(filters)
        query = text(query)
        result = session.execute(query, {'service_name': str(service_name)})
        rows = result.fetchall()
        keys = result.keys()
        services = [dict(zip(keys, row)) for row in rows]
        session.close()
        return services

    def getHostInformation(self, host_ip_address: str):
        session = self.dbAdapter.session()
        result = session.query(hostObj).filter_by(ip=str(host_ip_address)).first()
        session.close()
        return result

    def deleteHost(self, hostIP):
        session = self.dbAdapter.session()
        host = session.query(hostObj).filter_by(ip=str(hostIP)).first()
        if host:
            session.delete(host)
            session.commit()
        session.close()

    def toggleHostCheckStatus(self, ipAddress):
        session = self.dbAdapter.session()
        host = session.query(hostObj).filter_by(ip=ipAddress).first()
        if host:
            if host.checked == 'False':
                host.checked = 'True'
            else:
                host.checked = 'False'
            session.add(host)
            session.commit()
        session.close()

    def getHostByIP(self, ip):
        """
        Return the hostObj for a given IP address, or None if not found.
        """
        session = self.dbAdapter.session()
        host = session.query(hostObj).filter_by(ip=str(ip)).first()
        session.close()
        return host

    def getHostByHostname(self, hostname):
        """
        Return the hostObj for a given hostname, or None if not found.
        """
        session = self.dbAdapter.session()
        try:
            host = session.query(hostObj).filter_by(hostname=str(hostname)).first()
        finally:
            session.close()
        return host

    def getAllHostObjs(self):
        """
        Return all hostObj ORM objects in the database.
        """
        session = self.dbAdapter.session()
        hosts = session.query(hostObj).all()
        session.close()
        return hosts

    def getOperatingSystemsSummary(self):
        hosts = self.getAllHostObjs()
        counts = {}
        for host in hosts:
            os_category = classify_os(getattr(host, 'osMatch', '') or '')
            counts[os_category] = counts.get(os_category, 0) + 1

        summary = []
        for category in ORDERED_OS_CATEGORIES:
            count = counts.pop(category, 0)
            if count > 0 or category == 'Unknown':
                summary.append({'os': category, 'count': count})

        # Include any remaining categories that may have been introduced dynamically
        for category in sorted(counts.keys()):
            summary.append({'os': category, 'count': counts[category]})

        if not summary:
            summary.append({'os': 'Unknown', 'count': 0})

        return summary

    def getHostsByOperatingSystem(self, os_name: str):
        desired = (os_name or 'Unknown').strip()
        hosts = self.getAllHostObjs()
        results = []
        for host in hosts:
            os_match = getattr(host, 'osMatch', '') or ''
            os_category = classify_os(os_match)
            if os_category.lower() == desired.lower():
                results.append({
                    'ip': getattr(host, 'ip', '') or getattr(host, 'ipv4', ''),
                    'hostname': getattr(host, 'hostname', ''),
                    'os': os_match,
                    'status': getattr(host, 'status', ''),
                })

        return results
