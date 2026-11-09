import threading
import weakref
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple

from sqlalchemy import text

# Remembers which scheduler schema blocks are already present per engine, so that the
# CREATE TABLE / PRAGMA table_info / ALTER TABLE passes run once per database instead of
# on every read and write.
_ensured_lock = threading.Lock()
_ensured_by_engine: "weakref.WeakKeyDictionary[Any, Set[str]]" = weakref.WeakKeyDictionary()


def _session_engine(session) -> Optional[Any]:
    try:
        return session.get_bind()
    except Exception:
        return None


def _table_columns(session, table_name: str) -> Tuple[str, ...]:
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    return tuple(sorted(str(row[1]) for row in rows if len(row) > 1))


def ensure_schema_once(
        session,
        key: str,
        ensure_fn: Callable[[Any], None],
        tables: Iterable[str],
        is_complete: Optional[Callable[[Any], bool]] = None,
):
    """Run ensure_fn, then remember the schema as ensured for this engine if nothing needed changing.

    is_complete (optional) checks schema objects that table_info does not show, such as indexes; it is
    evaluated before ensure_fn, so work done in a transaction that might still be rolled back is
    never cached.
    """
    engine = _session_engine(session)
    if engine is None:
        ensure_fn(session)
        return
    with _ensured_lock:
        try:
            ensured = _ensured_by_engine.get(engine)
        except TypeError:
            ensured = None
        if ensured is not None and key in ensured:
            return

    table_names = [str(name) for name in tables]
    before: Dict[str, Tuple[str, ...]] = {name: _table_columns(session, name) for name in table_names}
    complete_before = True
    if is_complete is not None and all(before.values()):
        try:
            complete_before = bool(is_complete(session))
        except Exception:
            complete_before = False
    ensure_fn(session)
    if not complete_before:
        return
    # Only remember the schema once a pass found everything already in place; a pass that
    # created or altered tables may still be rolled back with the surrounding transaction.
    if not all(before.values()):
        return
    after = {name: _table_columns(session, name) for name in table_names}
    if after != before:
        return
    with _ensured_lock:
        try:
            _ensured_by_engine.setdefault(engine, set()).add(str(key))
        except TypeError:
            pass


def index_exists(session, index_name: str) -> bool:
    row = session.execute(
        text("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :name"), {"name": str(index_name)}
    ).fetchone()
    return row is not None


def ensure_column(session, table_name: str, column_name: str, column_type: str) -> None:
    """Add column_name to table_name if it is missing (SQLite has no ADD COLUMN IF NOT EXISTS)."""
    rows = session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing = {str(row[1]) for row in rows if len(row) > 1}
    if str(column_name) in existing:
        return
    session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def is_schema_ensured(engine, key: str) -> bool:
    """Cheap check (no session or query) whether ensure_schema_once already cached key for engine."""
    if engine is None:
        return False
    with _ensured_lock:
        try:
            ensured = _ensured_by_engine.get(engine)
        except TypeError:
            return False
        return ensured is not None and str(key) in ensured


def clear_schema_cache():
    with _ensured_lock:
        _ensured_by_engine.clear()
