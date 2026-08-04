"""Single-owner SQLite schema migrations for Triagewall."""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

try:
    from . import spc
    from .database import connect_database
except ImportError:  # Direct script-style imports used by container entrypoints.
    import spc
    from database import connect_database


log = logging.getLogger(__name__)

REQUIRED_TABLES = {
    "triage_events",
    "ingest_failures",
    "asset_snapshots",
    "sensor_event_context",
    "spc_ip_state",
    "spc_rate_buckets",
    "spc_seen_sids",
    "spc_anomalies",
}

REQUIRED_INDEXES = {
    "idx_triage_dup_check",
    "idx_model_processed_at",
    "idx_triage_timestamp",
    "idx_triage_signature_id",
    "idx_triage_verdict",
    "idx_triage_processed",
    "idx_triage_src_asset_snapshot",
    "idx_triage_dest_asset_snapshot",
    "idx_sensor_event_source_identity",
    "idx_spc_anom_ip",
    "idx_spc_anom_detected",
    "idx_spc_buckets_ip",
}


def _execute_statements(conn: sqlite3.Connection, script: str) -> None:
    """Execute a SQL script without ``executescript``'s implicit commit."""
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if not sqlite3.complete_statement(pending):
            continue
        statement = pending.strip()
        pending = ""
        if statement:
            conn.execute(statement)
    if pending.strip():
        raise sqlite3.OperationalError("schema script ends with incomplete SQL")


def ensure_db_initialized(db_path: str | Path) -> None:
    """Apply all idempotent schema work under one immediate transaction."""
    target_path = Path(db_path)
    os.makedirs(target_path.parent, exist_ok=True)
    schema_sql = (Path(__file__).parent / "schema.sql").read_text()
    started = time.monotonic()
    log.info("Database migration owner starting for %s", target_path)

    for attempt in range(5):
        conn = None
        try:
            conn = connect_database(target_path)
            conn.execute("BEGIN IMMEDIATE")

            event_table_exists = conn.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type = 'table' AND name = 'triage_events'"""
            ).fetchone()
            if event_table_exists:
                event_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('triage_events')")
                }
                for column_name in (
                    "src_asset_snapshot_id",
                    "dest_asset_snapshot_id",
                ):
                    if column_name not in event_columns:
                        conn.execute(
                            f"ALTER TABLE triage_events "
                            f"ADD COLUMN {column_name} INTEGER"
                        )

            failure_table_exists = conn.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type = 'table' AND name = 'ingest_failures'"""
            ).fetchone()
            if failure_table_exists:
                failure_columns = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info('ingest_failures')"
                    )
                }
                if "source_type" not in failure_columns:
                    conn.execute(
                        "ALTER TABLE ingest_failures ADD COLUMN source_type TEXT "
                        "NOT NULL DEFAULT 'suricata'"
                    )

            _execute_statements(conn, schema_sql)
            _execute_statements(conn, spc.SCHEMA)
            conn.commit()
            break
        except sqlite3.OperationalError as exc:
            if conn is not None:
                conn.rollback()
            if "locked" not in str(exc).lower() or attempt == 4:
                raise
            delay = 0.1 * (2**attempt)
            log.warning(
                "Database migration lock retry %s/5 in %.1fs",
                attempt + 1,
                delay,
            )
            time.sleep(delay)
        finally:
            if conn is not None:
                conn.close()

    verify_db_initialized(target_path)
    log.info(
        "Database migration owner completed in %.1fs",
        time.monotonic() - started,
    )


def verify_db_initialized(db_path: str | Path) -> None:
    """Fail closed when a non-owner starts before the required schema exists."""
    target_path = Path(db_path)
    conn = connect_database(target_path, readonly=True)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        event_columns = {
            row[1] for row in conn.execute("PRAGMA table_info('triage_events')")
        }
        failure_columns = {
            row[1] for row in conn.execute("PRAGMA table_info('ingest_failures')")
        }
    finally:
        conn.close()

    missing_tables = REQUIRED_TABLES - tables
    missing_indexes = REQUIRED_INDEXES - indexes
    missing_columns = {
        "src_asset_snapshot_id",
        "dest_asset_snapshot_id",
    } - event_columns
    if "source_type" not in failure_columns:
        missing_columns.add("ingest_failures.source_type")
    if missing_tables or missing_indexes or missing_columns:
        details = []
        if missing_tables:
            details.append(f"tables={sorted(missing_tables)}")
        if missing_indexes:
            details.append(f"indexes={sorted(missing_indexes)}")
        if missing_columns:
            details.append(f"columns={sorted(missing_columns)}")
        raise RuntimeError(
            "database schema is not initialized; run the migration owner first "
            f"({'; '.join(details)})"
        )
