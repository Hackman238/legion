"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2018-2025 Shane William Scott

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
from unittest import mock
from unittest.mock import MagicMock

from tests.db.helpers.db_helpers import mockExecuteRows


class PortRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        from db.repositories.PortRepository import PortRepository
        self.mockDbAdapter = MagicMock()
        self.mockDbSession = MagicMock()
        self.mockDbAdapter.session.return_value = self.mockDbSession
        self.repository = PortRepository(self.mockDbAdapter)

    def test_getPortsByIPAndProtocol_ReturnsPorts(self):
        expected_query = ("SELECT ports.portId FROM portObj AS ports "
                          "INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                          "WHERE hosts.ip = :host_ip and ports.protocol = :protocol")
        query_result = MagicMock()
        query_result.first.return_value = ("port-id1",)
        self.mockDbSession.execute.return_value = query_result
        ports = self.repository.getPortsByIPAndProtocol("some_host_ip", "tcp")

        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expected_query, str(query))
        self.assertEqual({"host_ip": "some_host_ip", "protocol": "tcp"}, params)
        self.assertEqual(("port-id1",), ports)

    def test_getPortStatesByHostId_ReturnsPortsStates(self):
        expected_query = 'SELECT port.state FROM portObj as port WHERE port.hostId = :host_id'
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [('port-state1',), ('port-state2',)],
            ['state'],
        )
        port_states = self.repository.getPortStatesByHostId("some_host_id")

        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expected_query, str(query))
        self.assertEqual({"host_id": "some_host_id"}, params)
        self.assertEqual([('port-state1',), ('port-state2',)], port_states)

    def test_getPortsAndServicesByHostIP_InvokedWithNoFilters_ReturnsPortsAndServices(self):
        from app.auxiliary import Filters

        expected_query = ("SELECT hosts.ip, ports.portId, ports.protocol, ports.state, ports.hostId, ports.serviceId, "
                          "services.name, services.product, services.version, services.extrainfo, services.fingerprint "
                          "FROM portObj AS ports INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                          "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                          "WHERE hosts.ip = :host_ip")
        self.mockDbSession.execute.return_value = mockExecuteRows([('ip1',), ('ip2',)], ['ip'])

        filters: Filters = Filters()
        filters.apply(up=True, down=True, checked=True, portopen=True, portfiltered=True, portclosed=True,
                      tcp=True, udp=True)
        results = self.repository.getPortsAndServicesByHostIP("some_host_ip", filters)

        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expected_query, str(query))
        self.assertEqual({"host_ip": "some_host_ip"}, params)
        self.assertEqual([{'ip': 'ip1'}, {'ip': 'ip2'}], results)

    def test_getPortsAndServicesByHostIP_InvokedWithFewFilters_ReturnsPortsAndServices(self):
        from app.auxiliary import Filters

        expected_query = ("SELECT hosts.ip, ports.portId, ports.protocol, ports.state, ports.hostId, ports.serviceId, "
                          "services.name, services.product, services.version, services.extrainfo, services.fingerprint "
                          "FROM portObj AS ports INNER JOIN hostObj AS hosts ON hosts.id = ports.hostId "
                          "LEFT OUTER JOIN serviceObj AS services ON services.id = ports.serviceId "
                          "WHERE hosts.ip = :host_ip AND ports.protocol != 'tcp' AND ports.protocol != 'udp'")
        self.mockDbSession.execute.return_value = mockExecuteRows([('ip1',), ('ip2',)], ['ip'])

        filters: Filters = Filters()
        filters.apply(up=True, down=True, checked=True, portopen=True, portfiltered=True, portclosed=True,
                      tcp=False, udp=False)
        results = self.repository.getPortsAndServicesByHostIP("some_host_ip", filters)

        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expected_query, str(query))
        self.assertEqual({"host_ip": "some_host_ip"}, params)
        self.assertEqual([{'ip': 'ip1'}, {'ip': 'ip2'}], results)

    def test_deleteAllPortsAndScriptsByHostId_WhenProvidedByHostIDAndProtocol_DeletesAllPortsAndScripts(self):
        mockFilterHost = mockProtocolFilter = mockReturnAll = MagicMock()
        mockPort1 = mockPort2 = MagicMock()
        mockReturnAll.all.return_value = [mockPort1, mockPort2]
        mockProtocolFilter.filter.return_value = mockReturnAll
        mockFilterHost.filter.return_value = mockProtocolFilter

        mockFilterScript = mockReturnAllScripts = MagicMock()
        mockReturnAllScripts.all.return_value = ['some-script1', 'some-script2']
        mockFilterScript.filter.return_value = mockReturnAllScripts

        self.mockDbSession.query.side_effect = [mockFilterHost, mockFilterScript, mockFilterScript]

        self.repository.deleteAllPortsAndScriptsByHostId("some-host-id", "some-protocol")
        self.mockDbSession.delete.assert_has_calls([
            mock.call('some-script1'), mock.call('some-script2'),
            mock.call('some-script1'), mock.call('some-script2'),
            mock.call(mockPort1), mock.call(mockPort2)
        ])
        self.mockDbSession.commit.assert_called_once()
