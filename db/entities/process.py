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
from sqlalchemy import Column, String, Integer
from sqlalchemy.orm import relationship

from db.database import Base


class process(Base):
    __tablename__ = 'process'
    pid = Column(String)
    id = Column(Integer, primary_key = True)
    display = Column(String)
    name = Column(String)
    tabTitle = Column(String)
    hostIp = Column(String)
    port = Column(String)
    protocol = Column(String)
    command = Column(String)
    startTime = Column(String)
    endTime = Column(String)
    estimatedRemaining = Column(Integer)
    elapsed = Column(Integer)
    outputfile = Column(String)
    output = relationship("process_output")
    status = Column(String)
    closed = Column(String)
    percent = Column(String)  # New: percent complete for nmap scans

    def __init__(
        self,
        pid,
        name='',
        tabTitle='',
        hostIp='',
        port='',
        protocol='',
        command='',
        startTime='',
        endTime='',
        outputfile='',
        status='',
        output=None,
        estimatedRemaining=0,
        elapsed=0,
        percent=None,
        **kwargs
    ):
        self.display = 'True'
        self.pid = pid
        self.name = kwargs.get('name', name) or ''
        self.tabTitle = kwargs.get('tabTitle', tabTitle) or ''
        self.hostIp = kwargs.get('hostIp', hostIp) or ''
        self.port = kwargs.get('port', port) or ''
        self.protocol = kwargs.get('protocol', protocol) or ''
        self.command = kwargs.get('command', command) or ''
        self.startTime = kwargs.get('startTime', startTime) or ''
        self.endTime = kwargs.get('endTime', endTime) or ''
        self.outputfile = kwargs.get('outputfile', outputfile) or ''
        output_value = kwargs.get('output', output if output is not None else [])
        self.output = output_value
        self.status = kwargs.get('status', status) or ''
        self.closed = kwargs.get('closed', 'False') or 'False'
        self.estimatedRemaining = kwargs.get('estimatedRemaining', estimatedRemaining) or 0
        self.elapsed = kwargs.get('elapsed', elapsed) or 0
        self.percent = kwargs.get('percent', percent)
