#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'
__modified_by = 'ketchup'

import parsers.Service as Service
import parsers.Script as Script
import parsers.OS as OS
import parsers.Port as Port

class Host:
    ipv4 = ''
    ipv6 = ''
    macaddr = ''
    status = None
    hostname = ''
    vendor = ''
    uptime = ''
    lastboot = ''
    distance = 0
    state = ''
    count = ''

    def __init__( self, HostNode ):
        self.hostNodes = []
        self.hostNode = HostNode
        self._merge_host_node(HostNode)

    def _merge_host_node(self, HostNode):
        if HostNode is None:
            return
        self.hostNode = HostNode
        self.hostNodes.append(HostNode)

        status_nodes = HostNode.getElementsByTagName('status')
        status_value = status_nodes[0].getAttribute('state') if status_nodes and \
            status_nodes[0].hasAttribute('state') else 'unknown'
        if self.status in [None, '', 'unknown'] or str(status_value).lower() == 'up':
            self.status = status_value

        for e in HostNode.getElementsByTagName('address'):
            if e.getAttribute('addrtype') == 'ipv4' and not self.ipv4:
                self.ipv4 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'ipv6' and not self.ipv6:
                self.ipv6 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'mac' and not self.macaddr:
                self.macaddr = e.getAttribute('addr')
                if not self.vendor:
                    self.vendor = e.getAttribute('vendor')

        address_nodes = HostNode.getElementsByTagName('address')
        if (not getattr(self, 'ip', '')) and address_nodes and address_nodes[0].hasAttribute('addr'):
            self.ip = address_nodes[0].getAttribute('addr')

        hostname_nodes = HostNode.getElementsByTagName('hostname')
        if hostname_nodes:
            hostname_value = hostname_nodes[0].getAttribute('name')
            if not self.hostname:
                self.hostname = hostname_value

        uptime_nodes = HostNode.getElementsByTagName('uptime')
        if uptime_nodes:
            uptime_node = uptime_nodes[0]
            if not self.uptime:
                self.uptime = uptime_node.getAttribute('seconds')
            if not self.lastboot:
                self.lastboot = uptime_node.getAttribute('lastboot')

        distance_nodes = HostNode.getElementsByTagName('distance')
        if distance_nodes and distance_nodes[0].hasAttribute('value'):
            try:
                candidate_distance = int(distance_nodes[0].getAttribute('value'))
            except Exception:
                candidate_distance = 0
            if not self.distance:
                self.distance = candidate_distance

        extraports_nodes = HostNode.getElementsByTagName('extraports')
        if extraports_nodes:
            extraports_node = extraports_nodes[0]
            candidate_state = extraports_node.getAttribute('state')
            candidate_count = extraports_node.getAttribute('count')
            if not self.state:
                self.state = candidate_state
            if not self.count:
                self.count = candidate_count
            else:
                try:
                    if int(candidate_count or 0) > int(self.count or 0):
                        self.state = candidate_state
                        self.count = candidate_count
                except Exception:
                    pass

    def merge(self, other):
        if other is None:
            return
        for host_node in list(getattr(other, 'hostNodes', []) or []):
            self._merge_host_node(host_node)

    @staticmethod
    def _port_score(port):
        if port is None:
            return 0
        score = 0
        if str(getattr(port, 'state', '')).lower() == 'open':
            score += 5
        service = port.getService()
        if service is not None:
            score += 5
            for value in [service.name, service.product, service.version, service.extrainfo, service.fingerprint]:
                if value:
                    score += 1
        score += len(port.getScripts())
        return score

    def _unique_ports(self):
        ports = {}
        for hostNode in getattr(self, 'hostNodes', [self.hostNode]):
            for portNode in hostNode.getElementsByTagName('port'):
                port = Port.Port(portNode)
                key = (str(port.protocol), str(port.portId))
                existing = ports.get(key)
                if existing is None or self._port_score(port) >= self._port_score(existing):
                    ports[key] = port
        return list(ports.values())

    @staticmethod
    def _script_key(script):
        return (str(getattr(script, 'scriptId', '')), str(getattr(script, 'output', '')))

    def getOs(self):
        oss = []
        seen = set()

        for hostNode in getattr(self, 'hostNodes', [self.hostNode]):
            for osNode in hostNode.getElementsByTagName('osfamily'):
                os = OS.OS(osNode)
                key = (os.name, os.family, os.generation, os.osType, os.vendor, os.accuracy)
                if key not in seen:
                    seen.add(key)
                    oss.append(os)

            for osNode in hostNode.getElementsByTagName('osclass'):
                os = OS.OS(osNode)
                key = (os.name, os.family, os.generation, os.osType, os.vendor, os.accuracy)
                if key not in seen:
                    seen.add(key)
                    oss.append(os)

            for osNode in hostNode.getElementsByTagName('osmatch'):
                os = OS.OS(osNode)
                key = (os.name, os.family, os.generation, os.osType, os.vendor, os.accuracy)
                if key not in seen:
                    seen.add(key)
                    oss.append(os)

        return oss

    def all_ports( self ):
        return self._unique_ports()

    def getPorts( self, protocol, state ):
        '''get a list of ports which is in the special state'''

        open_ports = []

        for port in self._unique_ports():
            if str(port.protocol) != str(protocol):
                continue
            if str(port.state) == str(state):
                open_ports.append(port.portId)

        return open_ports

    def getScripts( self ):
        scripts = []
        seen = set()

        for hostNode in getattr(self, 'hostNodes', [self.hostNode]):
            for scriptNode in hostNode.getElementsByTagName('script'):
                scr = Script.Script(scriptNode)
                scr.hostId = self.ipv4
                key = self._script_key(scr)
                if key not in seen:
                    seen.add(key)
                    scripts.append(scr)

        return scripts

    def getHostScripts( self ):
        scripts = []
        seen = set()
        for hostNode in getattr(self, 'hostNodes', [self.hostNode]):
            for hostscriptNode in hostNode.getElementsByTagName('hostscript'):
                for scriptNode in hostscriptNode.getElementsByTagName('script'):
                    scr = Script.Script(scriptNode)
                    key = self._script_key(scr)
                    if key not in seen:
                        seen.add(key)
                        scripts.append(scr)

        return scripts

    def getService( self, protocol, port ):
        '''return a Service object'''
        for merged_port in self._unique_ports():
            if str(merged_port.protocol) == str(protocol) and str(merged_port.portId) == str(port):
                service = merged_port.getService()
                if service is not None:
                    return service
        return None
