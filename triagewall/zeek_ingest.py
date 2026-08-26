#!/usr/bin/env python3
"""Private local service that continuously indexes Zeek ``conn.log``."""

from __future__ import annotations

import logging
import os
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from .zeek_follower import (
        MAX_RECORDS_PER_POLL,
        ZeekFollower,
        ZeekFollowerError,
    )
    from .zeek_index import (
        ZeekCheckpointConflict,
        ZeekConnValidationError,
        connect_zeek_index,
    )
except ImportError:  # Direct execution in the ingest container.
    from zeek_follower import (
        MAX_RECORDS_PER_POLL,
        ZeekFollower,
        ZeekFollowerError,
    )
    from zeek_index import (
        ZeekCheckpointConflict,
        ZeekConnValidationError,
        connect_zeek_index,
    )


log = logging.getLogger("zeek_ingest")
_stop = False


@dataclass(frozen=True)
class ZeekIngestSettings:
    conn_path: Path
    index_path: Path
    source_instance: str
    poll_interval_seconds: float
    max_records_per_poll: int
    eof_stable_observations: int


def settings_from_environment() -> ZeekIngestSettings:
    poll_interval = float(os.environ.get("ZEEK_POLL_INTERVAL", "2"))
    if not 0.1 <= poll_interval <= 300:
        raise RuntimeError("ZEEK_POLL_INTERVAL must be from 0.1 to 300 seconds")
    max_records = int(os.environ.get("ZEEK_MAX_RECORDS_PER_POLL", "1000"))
    if not 1 <= max_records <= MAX_RECORDS_PER_POLL:
        raise RuntimeError(
            f"ZEEK_MAX_RECORDS_PER_POLL must be from 1 to {MAX_RECORDS_PER_POLL}"
        )
    stable_observations = int(
        os.environ.get("ZEEK_EOF_STABLE_OBSERVATIONS", "2")
    )
    if stable_observations < 2:
        raise RuntimeError("ZEEK_EOF_STABLE_OBSERVATIONS must be at least 2")
    return ZeekIngestSettings(
        conn_path=Path(
            os.environ.get("ZEEK_CONN_PATH", "/var/log/zeek/current/conn.log")
        ),
        index_path=Path(
            os.environ.get(
                "ZEEK_INDEX_PATH",
                "/var/lib/triagewall/zeek-context.db",
            )
        ),
        source_instance=os.environ.get("ZEEK_SOURCE_ID", "zeek-local"),
        poll_interval_seconds=poll_interval,
        max_records_per_poll=max_records,
        eof_stable_observations=stable_observations,
    )


def _handle_signal(signum, _frame) -> None:
    global _stop
    _stop = True
    log.info("Received signal %s, stopping Zeek ingest", signum)


def tail_zeek(settings: ZeekIngestSettings | None = None) -> int:
    """Run the local follower until stopped or a gap risk is detected."""

    global _stop
    _stop = False
    try:
        settings = settings or settings_from_environment()
        follower = ZeekFollower(
            settings.conn_path,
            settings.source_instance,
            max_records_per_poll=settings.max_records_per_poll,
            eof_stable_observations=settings.eof_stable_observations,
        )
        conn = connect_zeek_index(settings.index_path)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        log.critical("Zeek ingest startup failed: %s", exc)
        return 1

    log.info("Starting Zeek conn.log ingest")
    log.info("  source:   %s", settings.source_instance)
    log.info("  conn.log: %s", settings.conn_path)
    log.info("  index:    %s", settings.index_path)
    try:
        while not _stop:
            try:
                result = follower.poll(conn)
            except (
                ZeekCheckpointConflict,
                ZeekConnValidationError,
                ZeekFollowerError,
                OSError,
                sqlite3.Error,
            ) as exc:
                log.critical(
                    "Zeek ingest stopped to prevent a context gap: %s",
                    exc,
                )
                return 1
            if result.scanned or result.rotated:
                log.info(
                    "Zeek batch scanned=%s indexed=%s failures=%s rotated=%s",
                    result.scanned,
                    result.indexed,
                    result.failures,
                    result.rotated,
                )
            time.sleep(settings.poll_interval_seconds)
    finally:
        follower.close()
        conn.close()
    log.info("Zeek ingest stopped cleanly")
    return 0


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    return tail_zeek()


if __name__ == "__main__":
    sys.exit(main())
