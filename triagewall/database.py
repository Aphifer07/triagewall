"""Shared SQLite connection setup for triagewall processes."""

import sqlite3
from pathlib import Path


SQLITE_TIMEOUT_SECONDS = 30.0
SQLITE_BUSY_TIMEOUT_MS = 10_000
WAL_AUTOCHECKPOINT_PAGES = 1_000


def connect_database(
    path: str | Path,
    *,
    readonly: bool = False,
) -> sqlite3.Connection:
    """Open SQLite with the project's concurrency and checkpoint policy."""
    if readonly:
        conn = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
    else:
        conn = sqlite3.connect(path, timeout=SQLITE_TIMEOUT_SECONDS)

    try:
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys=ON")
        if not readonly:
            journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise sqlite3.OperationalError(
                    f"SQLite refused WAL journal mode (reported {journal_mode!r})"
                )
            conn.execute(
                f"PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES}"
            )
        return conn
    except Exception:
        conn.close()
        raise
