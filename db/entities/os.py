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
from sqlalchemy import Integer, Column, String, ForeignKey

from db.database import Base


class osObj(Base):
    __tablename__ = 'osObj'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    family = Column(String)
    generation = Column(String)
    osType = Column(String)
    vendor = Column(String)
    accuracy = Column(String)
    hostId = Column(String, ForeignKey('hostObj.id'))

    def __init__(
        self,
        name,
        family='',
        generation='',
        osType='',
        vendor='',
        accuracy='',
        hostId='',
        **kwargs
    ):
        self.name = name
        self.family = kwargs.get('family', family) or ''
        self.generation = kwargs.get('generation', generation) or ''
        self.osType = kwargs.get('osType', osType) or ''
        self.vendor = kwargs.get('vendor', vendor) or ''
        self.accuracy = kwargs.get('accuracy', accuracy) or ''
        self.hostId = kwargs.get('hostId', hostId) or ''
