"""
Spill-to-Disk Session Store for Vestige.

Stores parsed Polars DataFrames as ephemeral snappy-compressed Parquet files
on disk rather than keeping 2 GB+ DataFrames live in RAM.

Public API (backward-compatible surface):
  store_session(session_id, df)  → writes Parquet, frees df from caller
  get_session(session_id)        → returns pl.LazyFrame (zero RAM until .collect())
  purge_session(session_id)      → unlinks Parquet file + removes dict entry
  purge_all()                    → unlinks all Parquet files + clears dict
  active_session_count()         → int

Architecture
────────────
• Temp directory: /tmp/vestige_sessions/ (auto-created on import, auto-purged
  on reboot by the OS — exactly the ephemeral semantics we want).
• TTL check in get_session(): expired sessions have their file deleted lazily
  on the next access attempt.
• All mutations are protected by a threading.Lock for multi-worker safety.

Caller contract
───────────────
  lf = session_store.get_session(session_id)   # LazyFrame
  df_slice = lf.filter(pl.col("protocol") == "SSH").collect()
"""

import os
import threading
import time
import tempfile
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

import polars as pl

logger = logging.getLogger(__name__)

_lock = threading.Lock()

# session_id → (parquet_path, created_at_epoch)
_store: Dict[str, Tuple[Path, float]] = {}

# Maximum session TTL in seconds (30 minutes default)
SESSION_TTL_SECONDS = 1800

# Temp directory for Parquet files — use OS tmpdir so files are auto-cleaned on reboot
_SESSION_DIR = Path(tempfile.gettempdir()) / "vestige_sessions"


def _ensure_session_dir() -> None:
    """Create the session directory if it does not exist."""
    _SESSION_DIR.mkdir(parents=True, exist_ok=True)


# Create on module import so the directory is always ready
_ensure_session_dir()


def _parquet_path(session_id: str) -> Path:
    """Return the canonical Parquet file path for a session."""
    # Sanitise session_id to a safe filename
    safe_id = "".join(c if c.isalnum() or c in "_-" else "_" for c in session_id)
    return _SESSION_DIR / f"{safe_id}.parquet"


def store_session(session_id: str, df: pl.DataFrame) -> Path:
    """Write *df* to a snappy-compressed Parquet file and register the session.

    The caller should ``del df`` immediately after this call to release RAM.

    Returns the Path of the written Parquet file.
    """
    _ensure_session_dir()
    path = _parquet_path(session_id)

    # Write with snappy compression — good balance of speed vs size for log data
    df.write_parquet(str(path), compression="snappy")
    row_count = len(df)

    with _lock:
        _store[session_id] = (path, time.time())

    logger.info(
        "Session '%s' spilled to disk: %s (%d rows, %.1f MB)",
        session_id,
        path,
        row_count,
        path.stat().st_size / 1_048_576,
    )
    return path


def get_session(session_id: str) -> Optional[pl.LazyFrame]:
    """Return a LazyFrame for the session's Parquet file.

    Returns None if the session is expired, missing, or the file was deleted.
    Expired sessions are purged lazily on access.
    """
    with _lock:
        entry = _store.get(session_id)

    if entry is None:
        return None

    path, created_at = entry

    # TTL check — purge lazily
    if time.time() - created_at > SESSION_TTL_SECONDS:
        purge_session(session_id)
        logger.info("Session '%s' expired and purged.", session_id)
        return None

    if not path.exists():
        # File was deleted externally — clean up the dict entry
        with _lock:
            _store.pop(session_id, None)
        logger.warning("Session '%s' Parquet file missing from disk.", session_id)
        return None

    # Return a zero-RAM LazyFrame — no data is loaded until .collect()
    return pl.scan_parquet(str(path))


def purge_session(session_id: str) -> bool:
    """Delete the Parquet file and remove the session entry.

    Returns True if the session existed, False otherwise.
    """
    with _lock:
        entry = _store.pop(session_id, None)

    if entry is None:
        return False

    path, _ = entry
    try:
        path.unlink(missing_ok=True)
        logger.info("Session '%s' purged from disk.", session_id)
    except OSError as exc:
        logger.warning("Could not delete session Parquet '%s': %s", path, exc)

    return True


def purge_all() -> int:
    """Purge all sessions and delete all Parquet files.

    Returns the count of sessions cleared.
    """
    with _lock:
        entries = list(_store.items())
        _store.clear()

    count = len(entries)
    for session_id, (path, _) in entries:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not delete session Parquet '%s': %s", path, exc)

    logger.info("purge_all: cleared %d sessions.", count)
    return count


def active_session_count() -> int:
    """Return the number of currently stored sessions."""
    with _lock:
        return len(_store)
