"""
Ephemeral In-Memory Session Store for Vestige.

Retains parsed Polars DataFrames keyed by session_id so that drill-down
expand queries can operate on the already-parsed data without re-reading
the uploaded file.

Design: module-level dict — intentionally simple. The entire application
is ephemeral and session-scoped; there is no persistence layer.
"""

import threading
import time
from typing import Dict, Optional, Tuple

import polars as pl

_lock = threading.Lock()

# session_id → (df_unified, created_at_epoch)
_store: Dict[str, Tuple[pl.DataFrame, float]] = {}

# Maximum session TTL in seconds (30 minutes default)
SESSION_TTL_SECONDS = 1800


def store_session(session_id: str, df: pl.DataFrame) -> None:
    """Store a parsed unified DataFrame under the given session_id."""
    with _lock:
        _store[session_id] = (df, time.time())


def get_session(session_id: str) -> Optional[pl.DataFrame]:
    """Retrieve the stored DataFrame for a session. Returns None if expired or missing."""
    with _lock:
        entry = _store.get(session_id)
        if entry is None:
            return None
        df, created_at = entry
        if time.time() - created_at > SESSION_TTL_SECONDS:
            del _store[session_id]
            return None
        return df


def purge_session(session_id: str) -> bool:
    """Explicitly delete a session's DataFrame from memory. Returns True if it existed."""
    with _lock:
        if session_id in _store:
            del _store[session_id]
            return True
        return False


def purge_all() -> int:
    """Purge all sessions. Returns count of sessions cleared."""
    with _lock:
        count = len(_store)
        _store.clear()
        return count


def active_session_count() -> int:
    """Return the number of currently stored sessions."""
    with _lock:
        return len(_store)
