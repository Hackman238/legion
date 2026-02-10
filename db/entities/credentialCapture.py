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
"""
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from db.database import Base


class credentialCapture(Base):
    __tablename__ = 'credentialCapture'

    id = Column(Integer, primary_key=True)
    tool = Column(String)
    source = Column(String)
    username = Column(String)
    hash = Column(Text)
    details = Column(Text)
    capturedAt = Column(DateTime)

    def __init__(self, tool, source='', username='', hash_value='', details=''):
        self.tool = tool
        self.source = source or ''
        self.username = username or ''
        self.hash = hash_value or ''
        self.details = details or ''
        self.capturedAt = datetime.utcnow()
