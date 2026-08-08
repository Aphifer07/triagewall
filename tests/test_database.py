#!/usr/bin/env python3
"""Regression tests for shared SQLite connection setup."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from triagewall.database import (
    SQLITE_BUSY_TIMEOUT_MS,
    WAL_AUTOCHECKPOINT_PAGES,
    connect_database,
)


class DatabaseConnectionTests(unittest.TestCase):
    def test_writer_enables_wal_and_bounded_autocheckpoint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"

            conn = connect_database(db_path)
            try:
                self.assertEqual(
                    conn.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                self.assertEqual(
                    conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                    WAL_AUTOCHECKPOINT_PAGES,
                )
                self.assertEqual(
                    conn.execute("PRAGMA busy_timeout").fetchone()[0],
                    SQLITE_BUSY_TIMEOUT_MS,
                )
                conn.execute("CREATE TABLE example (id INTEGER PRIMARY KEY)")
                conn.commit()
            finally:
                conn.close()

            reopened = sqlite3.connect(db_path)
            try:
                self.assertEqual(
                    reopened.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
            finally:
                reopened.close()

    def test_readonly_connection_does_not_require_write_access(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            writer = connect_database(db_path)
            try:
                writer.execute("CREATE TABLE example (id INTEGER PRIMARY KEY)")
                writer.commit()
            finally:
                writer.close()

            reader = connect_database(db_path, readonly=True)
            try:
                self.assertEqual(
                    reader.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                with self.assertRaises(sqlite3.OperationalError):
                    reader.execute("INSERT INTO example DEFAULT VALUES")
            finally:
                reader.close()

    def test_connection_accepts_a_shorter_busy_timeout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"

            conn = connect_database(db_path, busy_timeout_ms=250)
            try:
                self.assertEqual(
                    conn.execute("PRAGMA busy_timeout").fetchone()[0],
                    250,
                )
            finally:
                conn.close()

        with self.assertRaises(ValueError):
            connect_database(":memory:", busy_timeout_ms=-1)

    def test_write_connection_supports_read_only_uri_attach(self):
        """Retention's backup authorization depends on URI filenames."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            other_path = Path(temp_dir) / "verified-backup.db"
            for path in (db_path, other_path):
                seed = connect_database(path)
                try:
                    seed.execute("CREATE TABLE example (id INTEGER PRIMARY KEY)")
                    seed.execute("INSERT INTO example (id) VALUES (1)")
                    seed.commit()
                finally:
                    seed.close()

            conn = connect_database(db_path)
            try:
                # Without SQLITE_OPEN_URI on this connection, SQLite treats the
                # URI as a literal filename and the read-only request is lost.
                conn.execute(
                    "ATTACH DATABASE ? AS verified_backup",
                    (f"{other_path.resolve().as_uri()}?mode=ro",),
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT id FROM verified_backup.example"
                    ).fetchone()[0],
                    1,
                )
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute(
                        "INSERT INTO verified_backup.example (id) VALUES (2)"
                    )
                conn.execute("DETACH DATABASE verified_backup")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
