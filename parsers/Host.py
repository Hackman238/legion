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
        self.hostNode = HostNode
        status_nodes = HostNode.getElementsByTagName('status')
        self.status = status_nodes[0].getAttribute('state') if status_nodes and \
            status_nodes[0].hasAttribute('state') else 'unknown'
        for e in HostNode.getElementsByTagName('address'):
            if e.getAttribute('addrtype') == 'ipv4':
                self.ipv4 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'ipv6':
                self.ipv6 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'mac':
                self.macaddr = e.getAttribute('addr')
                self.vendor = e.getAttribute('vendor')
        address_nodes = HostNode.getElementsByTagName('address')
        self.ip = address_nodes[0].getAttribute('addr') if address_nodes and \
            address_nodes[0].hasAttribute('addr') else ''
        #self.ip = self.ipv4 # for compatibility with the original library
        hostname_nodes = HostNode.getElementsByTagName('hostname')
        if hostname_nodes:
            self.hostname = hostname_nodes[0].getAttribute('name')
        uptime_nodes = HostNode.getElementsByTagName('uptime')
        if uptime_nodes:
            uptime_node = uptime_nodes[0]
            self.uptime = uptime_node.getAttribute('seconds')
            self.lastboot = uptime_node.getAttribute('lastboot')
        distance_nodes = HostNode.getElementsByTagName('distance')
        if distance_nodes and distance_nodes[0].hasAttribute('value'):
            try:
                self.distance = int(distance_nodes[0].getAttribute('value'))
            except Exception:
                self.distance = 0
        extraports_nodes = HostNode.getElementsByTagName('extraports')
        if extraports_nodes:
            extraports_node = extraports_nodes[0]
            self.state = extraports_node.getAttribute('state')
            self.count = extraports_node.getAttribute('count')

    def getOs(self):
        oss = []

        for osNode in self.hostNode.getElementsByTagName('osfamily'):
            os = OS.OS(osNode)
            oss.append(os)

        for osNode in self.hostNode.getElementsByTagName('osclass'):
            os = OS.OS(osNode)
            oss.append(os)

        for osNode in self.hostNode.getElementsByTagName('osmatch'):
            os = OS.OS(osNode)
            oss.append(os)

        return oss

    def all_ports( self ):
        
        ports = []

        for portNode in self.hostNode.getElementsByTagName('port'):
            p = Port.Port(portNode)
            ports.append(p)

        return ports

    def getPorts( self, protocol, state ):
        '''get a list of ports which is in the special state'''

        open_ports = []

        for portNode in self.hostNode.getElementsByTagName('port'):
            if portNode.getAttribute('protocol') != protocol:
                continue
            state_nodes = portNode.getElementsByTagName('state')
            if state_nodes and state_nodes[0].hasAttribute('state') and \
                    state_nodes[0].getAttribute('state') == state:
                open_ports.append(portNode.getAttribute('portid'))

        return open_ports

    def getScripts( self ):

        scripts = []

        for scriptNode in self.hostNode.getElementsByTagName('script'):
            scr = Script.Script(scriptNode)
            scr.hostId = self.ipv4
            scripts.append(scr)

        return scripts

    def getHostScripts( self ):

        scripts = []
        for hostscriptNode in self.hostNode.getElementsByTagName('hostscript'):
            for scriptNode in hostscriptNode.getElementsByTagName('script'):
                scr = Script.Script(scriptNode)
                scripts.append(scr)

        return scripts

    def getService( self, protocol, port ):
        '''return a Service object'''

        for portNode in self.hostNode.getElementsByTagName('port'):
            if portNode.getAttribute('protocol') == protocol and portNode.getAttribute('portid') == port and \
                    len(portNode.getElementsByTagName('service')) > 0:
                service_node = portNode.getElementsByTagName('service')[0]
                service = Service.Service( service_node )
                return service
        return None
