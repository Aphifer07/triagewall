#!/usr/bin/env python3
"""Regression tests for database schema setup during ingest startup."""

import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import ingest


EXPECTED_INDEXES = {
    "idx_triage_dup_check",
    "idx_model_processed_at",
    "idx_triage_timestamp",
    "idx_triage_signature_id",
    "idx_triage_verdict",
    "idx_triage_processed",
    "idx_triage_src_asset_snapshot",
    "idx_triage_dest_asset_snapshot",
}
SENSOR_IDENTITY_INDEX = "idx_sensor_event_source_identity"


def create_existing_database_without_indexes(db_path: Path) -> None:
    """Create a realistic existing database that has no indexes."""
    schema_path = PROJECT_ROOT / "triagewall" / "schema.sql"
    schema_sql = schema_path.read_text()

    table_sql = schema_sql.split("CREATE INDEX", 1)[0]

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(table_sql)
        conn.execute(
            """
            INSERT INTO triage_events (
                timestamp,
                signature_id,
                signature,
                raw_alert,
                verdict
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "2026-01-01T00:00:00+00:00",
                999999,
                "Existing test alert",
                "{}",
                "uncertain",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def create_legacy_database_without_asset_columns(db_path: Path) -> None:
    """Create the pre-v0.3 schema with a historical verdict row."""
    schema_sql = (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
    schema_sql = schema_sql.split("\n-- Source provenance", 1)[0]
    schema_sql = schema_sql.replace(
        "    src_asset_snapshot_id INTEGER,\n"
        "    dest_asset_snapshot_id INTEGER,\n",
        "",
    )
    schema_sql = schema_sql.replace(
        "    source_type TEXT NOT NULL DEFAULT 'suricata',\n",
        "",
    )
    schema_sql = schema_sql.replace(
        "CREATE INDEX IF NOT EXISTS idx_triage_src_asset_snapshot\n"
        "ON triage_events(src_asset_snapshot_id)\n"
        "WHERE src_asset_snapshot_id IS NOT NULL;\n"
        "CREATE INDEX IF NOT EXISTS idx_triage_dest_asset_snapshot\n"
        "ON triage_events(dest_asset_snapshot_id)\n"
        "WHERE dest_asset_snapshot_id IS NOT NULL;\n",
        "",
    )
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_sql)
        conn.execute(
            """INSERT INTO triage_events
               (timestamp, signature_id, signature, raw_alert, verdict)
               VALUES (?, ?, ?, ?, ?)""",
            ("2026-01-01T00:00:00Z", 42, "Historical", "{}", "uncertain"),
        )
        conn.commit()
    finally:
        conn.close()


class DatabaseStartupTests(unittest.TestCase):
    def test_concurrent_startup_creates_sensor_schema_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            errors = []

            def initialize():
                try:
                    with patch.object(ingest, "DB_PATH", db_path):
                        ingest.ensure_db_initialized()
                except Exception as exc:  # pragma: no cover - assertion reports it
                    errors.append(exc)

            workers = [threading.Thread(target=initialize) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

            self.assertEqual(errors, [])
            conn = sqlite3.connect(db_path)
            try:
                context_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'sensor_event_context'"""
                ).fetchone()
                context_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('sensor_event_context')"
                    ).fetchall()
                }
                failure_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('ingest_failures')")
                }
            finally:
                conn.close()

            self.assertEqual(context_table, ("sensor_event_context",))
            self.assertIn(SENSOR_IDENTITY_INDEX, context_indexes)
            self.assertIn("source_type", failure_columns)

    def test_existing_database_receives_idempotent_asset_metadata_migration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            create_legacy_database_without_asset_columns(db_path)

            with patch.object(ingest, "DB_PATH", db_path):
                ingest.ensure_db_initialized()
                ingest.ensure_db_initialized()

            conn = sqlite3.connect(db_path)
            try:
                columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('triage_events')")
                }
                historical = conn.execute(
                    """SELECT src_asset_snapshot_id, dest_asset_snapshot_id
                       FROM triage_events WHERE signature_id = 42"""
                ).fetchone()
                snapshot_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'asset_snapshots'"""
                ).fetchone()
                sensor_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'sensor_event_context'"""
                ).fetchone()
                sensor_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('sensor_event_context')"
                    ).fetchall()
                }
                failure_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('ingest_failures')")
                }
            finally:
                conn.close()

            self.assertIn("src_asset_snapshot_id", columns)
            self.assertIn("dest_asset_snapshot_id", columns)
            self.assertEqual(historical, (None, None))
            self.assertEqual(snapshot_table, ("asset_snapshots",))
            self.assertEqual(sensor_table, ("sensor_event_context",))
            self.assertIn(SENSOR_IDENTITY_INDEX, sensor_indexes)
            self.assertIn("source_type", failure_columns)

    def test_existing_database_receives_indexes_without_data_loss(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            create_existing_database_without_indexes(db_path)

            with patch.object(ingest, "DB_PATH", db_path):
                ingest.ensure_db_initialized()
                ingest.ensure_db_initialized()

            conn = sqlite3.connect(db_path)
            try:
                actual_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('triage_events')"
                    ).fetchall()
                }
                existing_row = conn.execute(
                    "SELECT signature_id, signature, verdict FROM triage_events"
                ).fetchone()
            finally:
                conn.close()

            missing_indexes = EXPECTED_INDEXES - actual_indexes

            self.assertFalse(
                missing_indexes,
                f"Missing indexes: {sorted(missing_indexes)}",
            )
            self.assertEqual(
                existing_row,
                (999999, "Existing test alert", "uncertain"),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
