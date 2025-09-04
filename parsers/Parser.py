#!/usr/bin/python

'''this module used to parse nmap xml report'''

__author__ = 'yunshu(wustyunshu@hotmail.com)'
__version__ = '0.2'

from typing import Optional
from xml.dom.minidom import parse, Document

__modified_by = 'ketchup'
__modified_by = 'SECFORCE'

import parsers.Session as Session
import parsers.Host as Host


class MalformedXmlDocumentException(BaseException):
    pass


class Parser:
    '''Parser class, parse a xml format nmap report'''

    def __init__(self, dom: Document):
        self.__dom = dom
        self.__session = None
        self.__hosts = {}
        for hostNode in self.__dom.getElementsByTagName('host'):
            __host = Host.Host(hostNode)
            self.__hosts[__host.ip] = __host

    def get_highest_percent(self):
        '''Return the highest percent value from all <taskprogress> elements, or None if not found.'''
        taskprogress_nodes = self.__dom.getElementsByTagName('taskprogress')
        max_percent = None
        for node in taskprogress_nodes:
            if node.hasAttribute('percent'):
                try:
                    percent_val = float(node.getAttribute('percent'))
                    if max_percent is None or percent_val > max_percent:
                        max_percent = percent_val
                except Exception:
                    continue
        return max_percent

    def getSession(self):
        '''get this scans information, return a Session object'''
        run_node = self.__dom.getElementsByTagName('nmaprun')[0]
        hosts_node = self.__dom.getElementsByTagName('hosts')[0]

        finish_time = self.__dom.getElementsByTagName('finished')[0].getAttribute('timestr')

        nmapVersion = run_node.getAttribute('version')
        startTime = run_node.getAttribute('startstr')
        scanArgs = run_node.getAttribute('args')

        totalHosts = hosts_node.getAttribute('total')
        upHosts = hosts_node.getAttribute('up')
        downHosts = hosts_node.getAttribute('down')

        MySession = {'finish_time': finish_time,
                     'nmapVersion': nmapVersion,
                     'scanArgs': scanArgs,
                     'startTime': startTime,
                     'totalHosts': totalHosts,
                     'upHosts': upHosts,
                     'downHosts': downHosts}

        self.__session = Session.Session(MySession)

        # Parse <taskprogress> elements for progress/ETA data (if present)
        taskprogress_nodes = self.__dom.getElementsByTagName('taskprogress')
        for node in taskprogress_nodes:
            progress_dict = {}
            # Extract common attributes if present
            for attr in ['task', 'percent', 'remaining', 'elapsed', 'etc']:
                if node.hasAttribute(attr):
                    progress_dict[attr] = node.getAttribute(attr)
            self.__session.add_progress(progress_dict)

        return self.__session

    def getHost(self, ipaddr: str) -> Optional[Host.Host]:
        '''get a Host object by ip address'''
        return self.__hosts.get(ipaddr)

    def getAllHosts(self, status=None):
        '''get a list of Host object'''
        if status is None:
            return self.__hosts.values()

        else:
            __tmp_hosts = []
            for __host in self.__hosts.values():

                if __host.status == status:
                    __tmp_hosts.append(__host)

            return __tmp_hosts

    def getAllIps(self, status=None):
        '''get a list of ip address'''
        __tmp_ips = []

        if status is None:
            for __host in self.__hosts.values():
                __tmp_ips.append(__host.ip)

        else:
            for __host in self.__hosts.values():

                if __host.status == status:
                    __tmp_ips.append(__host.ip)

        return __tmp_ips


def parseNmapReport(nmapXmlReportFileName: str) -> Parser:
    try:
        return Parser(parse(nmapXmlReportFileName))
    except Exception as e:
        raise MalformedXmlDocumentException(e)
