
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
from typing import List, Dict

from sqlalchemy import select

from db.SqliteDbAdapter import Database
from db.entities.credentialCapture import credentialCapture


class CredentialRepository:
    def __init__(self, dbAdapter: Database):
        self.dbAdapter = dbAdapter

    def storeCapture(self, tool: str, source: str, details: str, username: str = '', hash_value: str = '') -> None:
        session = self.dbAdapter.session()
        try:
            capture = credentialCapture(tool=tool, source=source, username=username, hash_value=hash_value,
                                        details=details)
            session.add(capture)
            session.commit()
        finally:
            session.close()

    def getAllCaptures(self) -> List[Dict]:
        session = self.dbAdapter.session()
        try:
            stmt = select(credentialCapture).order_by(credentialCapture.capturedAt.desc())
            rows = session.execute(stmt).scalars().all()
            return [self._to_dict(row) for row in rows]
        finally:
            session.close()

    def getCapturesBySource(self, source: str) -> List[Dict]:
        session = self.dbAdapter.session()
        try:
            stmt = select(credentialCapture).where(credentialCapture.source == str(source)).order_by(
                credentialCapture.capturedAt.desc())
            rows = session.execute(stmt).scalars().all()
            return [self._to_dict(row) for row in rows]
        finally:
            session.close()

    @staticmethod
    def _to_dict(row: credentialCapture) -> Dict:
        return {
            'id': row.id,
            'tool': row.tool,
            'source': row.source,
            'username': row.username,
            'hash': row.hash,
            'details': row.details,
            'capturedAt': row.capturedAt.strftime('%Y-%m-%d %H:%M:%S UTC') if row.capturedAt else ''
        }
