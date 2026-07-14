#!/usr/bin/env python3
"""Regression tests for database schema setup during ingest startup."""

import sqlite3
import sys
import tempfile
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
}


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


class DatabaseStartupTests(unittest.TestCase):
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
