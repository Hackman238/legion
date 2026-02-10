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

from db.SqliteDbAdapter import Database
from six import u as unicode

from db.entities.note import note

from sqlalchemy.exc import OperationalError


class NoteRepository:
    def __init__(self, dbAdapter: Database, log):
        self.dbAdapter = dbAdapter
        self.log = log

    def getNoteByHostId(self, hostId):
        session = self.dbAdapter.session()
        try:
            return session.query(note).filter_by(hostId=str(hostId)).first()
        except OperationalError:
            # Typically indicates DB unavailable (e.g., "unable to open database file").
            return None
        finally:
            session.close()

    def storeNotes(self, hostId, notes):
        session = self.dbAdapter.session()
        try:
            if len(notes) == 0:
                notes = unicode("".format(hostId=hostId))
            self.log.debug("Storing notes for {hostId}, Notes {notes}".format(hostId=hostId, notes=notes))

            # Use the same session for lookup + write to avoid scoped_session re-entrancy issues.
            t_note = session.query(note).filter_by(hostId=str(hostId)).first()
            if t_note:
                t_note.text = unicode(notes)
            else:
                t_note = note(hostId, unicode(notes))
            session.add(t_note)
            session.commit()
            return True
        except OperationalError as exc:
            # Harden against cases where the DB cannot be opened (e.g. "Too many open files", perms, missing path).
            try:
                session.rollback()
            except Exception:
                pass
            try:
                self.log.warning(f"Failed to store notes for host {hostId}: {exc}")
            except Exception:
                pass
            return False
        finally:
            session.close()
