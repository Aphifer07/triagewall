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
    busy_timeout_ms: int | None = None,
) -> sqlite3.Connection:
    """Open SQLite with the project's concurrency and checkpoint policy."""
    if busy_timeout_ms is not None and (
        type(busy_timeout_ms) is not int or busy_timeout_ms < 0
    ):
        raise ValueError("busy_timeout_ms must be a non-negative integer")
    effective_busy_timeout_ms = (
        SQLITE_BUSY_TIMEOUT_MS
        if busy_timeout_ms is None
        else busy_timeout_ms
    )
    connect_timeout_seconds = (
        SQLITE_TIMEOUT_SECONDS
        if busy_timeout_ms is None
        else min(SQLITE_TIMEOUT_SECONDS, busy_timeout_ms / 1_000)
    )
    if readonly:
        conn = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=connect_timeout_seconds,
        )
    else:
        conn = sqlite3.connect(path, timeout=connect_timeout_seconds)

    try:
        conn.execute(f"PRAGMA busy_timeout={effective_busy_timeout_ms}")
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
