"""Read-only provider for optional Core lookups against the Zeek index."""

from __future__ import annotations

import sqlite3
from pathlib import Path

try:
    from .database import connect_database
    from .zeek_context import (
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )
    from .zeek_index import lookup_connection
except ImportError:  # Direct script-style imports used by container entrypoints.
    from database import connect_database
    from zeek_context import (
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )
    from zeek_index import lookup_connection


DEFAULT_LOOKUP_BUSY_TIMEOUT_MS = 250
MAX_LOOKUP_BUSY_TIMEOUT_MS = 10_000


class SQLiteZeekContextProvider:
    """Open the standalone index read-only for one bounded alert lookup."""

    def __init__(
        self,
        index_path: str | Path,
        source_instance: str,
        *,
        busy_timeout_ms: int = DEFAULT_LOOKUP_BUSY_TIMEOUT_MS,
    ) -> None:
        if (
            type(busy_timeout_ms) is not int
            or not 0 <= busy_timeout_ms <= MAX_LOOKUP_BUSY_TIMEOUT_MS
        ):
            raise ValueError(
                "busy_timeout_ms must be from 0 to "
                f"{MAX_LOOKUP_BUSY_TIMEOUT_MS}"
            )
        self.index_path = Path(index_path)
        self.source_instance = source_instance
        self.busy_timeout_ms = busy_timeout_ms

    def lookup(self, request: ZeekLookupRequest) -> ZeekLookupResult:
        """Return unavailable on index I/O failure without creating a database."""

        try:
            conn = connect_database(
                self.index_path,
                readonly=True,
                busy_timeout_ms=self.busy_timeout_ms,
            )
        except (OSError, ValueError, sqlite3.Error):
            return ZeekLookupResult(status=ZeekLookupStatus.UNAVAILABLE)
        try:
            return lookup_connection(conn, request, self.source_instance)
        except (OSError, ValueError, sqlite3.Error):
            return ZeekLookupResult(status=ZeekLookupStatus.UNAVAILABLE)
        finally:
            conn.close()
