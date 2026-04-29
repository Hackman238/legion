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
import unittest
from unittest.mock import MagicMock

from tests.db.helpers.db_helpers import mockExecuteRows


class ServiceRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        from db.repositories.ServiceRepository import ServiceRepository
        self.mockDbAdapter = MagicMock()
        self.mockDbSession = MagicMock()
        self.mockDbAdapter.session.return_value = self.mockDbSession
        self.repository = ServiceRepository(self.mockDbAdapter)

    def getServiceNamesTestCase(self, filters, expectedQuery):
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [('service_name1',), ('service_name2',)],
            ['name'],
        )
        service_names = self.repository.getServiceNames(filters)

        query = self.mockDbSession.execute.call_args.args[0]
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual([{'name': 'service_name1'}, {'name': 'service_name2'}], service_names)

    def test_getServiceNames_InvokedWithNoFilters_FetchesAllServiceNames(self):
        from app.auxiliary import Filters

        expectedQuery = ("SELECT DISTINCT service.name FROM serviceObj as service "
                         "INNER JOIN portObj as ports "
                         "INNER JOIN hostObj AS hosts "
                         "ON hosts.id = ports.hostId AND service.id=ports.serviceId WHERE 1=1 "
                         "ORDER BY service.name ASC")
        filters: Filters = Filters()
        filters.apply(up=True, down=True, checked=True, portopen=True, portfiltered=True, portclosed=True,
                      tcp=True, udp=True)
        self.getServiceNamesTestCase(filters=filters, expectedQuery=expectedQuery)

    def test_getServiceNames_InvokedWithFewFilters_FetchesAllServiceNamesWithFiltersApplied(self):
        from app.auxiliary import Filters

        expectedQuery = ("SELECT DISTINCT service.name FROM serviceObj as service "
                         "INNER JOIN portObj as ports "
                         "INNER JOIN hostObj AS hosts "
                         "ON hosts.id = ports.hostId AND service.id=ports.serviceId WHERE 1=1 "
                         "AND hosts.status != 'down' AND ports.protocol != 'udp' "
                         "ORDER BY service.name ASC")
        filters: Filters = Filters()
        filters.apply(up=True, down=False, checked=True, portopen=True, portfiltered=True, portclosed=True,
                      tcp=True, udp=False)
        self.getServiceNamesTestCase(filters=filters, expectedQuery=expectedQuery)

    def test_getServiceNamesByHostIPAndPort_WhenProvidedWithHostIpAndPort_ReturnsServiceNames(self):
        query_result = MagicMock()
        query_result.first.return_value = ("service-name1",)
        self.mockDbSession.execute.return_value = query_result
        expectedQuery = ("SELECT services.name FROM serviceObj AS services "
                         "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                         "INNER JOIN portObj AS ports ON services.id=ports.serviceId "
                         "WHERE hosts.ip=:host_ip and ports.portId = :port")
        result = self.repository.getServiceNamesByHostIPAndPort("some_host", "1234")
        self.assertEqual(("service-name1",), result)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({"host_ip": "some_host", "port": "1234"}, params)
