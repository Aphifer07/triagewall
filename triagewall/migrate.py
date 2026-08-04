#!/usr/bin/env python3
"""One-shot container entrypoint for Triagewall database migrations."""

import logging
import os
import sqlite3
import sys
from pathlib import Path

try:
    from .migrations import ensure_db_initialized
except ImportError:  # Direct script entrypoint used by Docker Compose.
    from migrations import ensure_db_initialized


DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or str(Path(__file__).resolve().parent.parent / "triage.db")
)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


def main() -> int:
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    try:
        ensure_db_initialized(DB_PATH)
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        logging.getLogger("migrate").critical(
            "Database migration failed: %s: %s",
            type(exc).__name__,
            exc,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
