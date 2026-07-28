#!/usr/bin/env python3
"""Regression tests for storage visibility and retention controls."""

from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from triagewall.database import connect_database
from triagewall import retention
from triagewall.retention import (
    build_retention_plan,
    create_online_backup,
    prune_events,
)
from triagewall.storage import get_storage_metrics
from triagewall.time_utils import format_utc_timestamp


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "triage.db"
        self.conn = connect_database(self.db_path)
        self.conn.executescript(
            (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
        )
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def insert_event(
        self,
        *,
        age_days: int,
        signature_id: int,
        human_verdict: str | None = None,
        src_snapshot_id: int | None = None,
        source_event_id: str | None = None,
    ) -> int:
        timestamp = format_utc_timestamp(
            self.now - timedelta(days=age_days)
        )
        cursor = self.conn.execute(
            """INSERT INTO triage_events (
                   timestamp, signature_id, signature, raw_alert,
                   verdict, model_used, processed_at, human_verdict,
                   src_asset_snapshot_id
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp,
                signature_id,
                f"Test {signature_id}",
                '{"padding":"' + ("x" * 8_192) + '"}',
                "false_positive",
                "prefilter",
                timestamp,
                human_verdict,
                src_snapshot_id,
            ),
        )
        self.conn.execute(
            """INSERT INTO sensor_event_context (
                   triage_event_id, source_type, source_event_id
               ) VALUES (?, 'suricata', ?)""",
            (cursor.lastrowid, source_event_id),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def insert_snapshot(self, snapshot_id: int) -> None:
        self.conn.execute(
            """INSERT INTO asset_snapshots (
                   id, snapshot_hash, asset_json, created_at
               ) VALUES (?, ?, '{}', ?)""",
            (
                snapshot_id,
                f"sha256:test-{snapshot_id}",
                format_utc_timestamp(self.now),
            ),
        )
        self.conn.commit()

    def test_plan_protects_reviewed_rows_by_default(self):
        self.insert_event(age_days=60, signature_id=1)
        self.insert_event(
            age_days=60,
            signature_id=2,
            human_verdict="real",
        )
        self.insert_event(age_days=5, signature_id=3)
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        plan = build_retention_plan(self.conn, cutoff)

        self.assertEqual(plan.eligible_rows, 1)
        self.assertEqual(plan.reviewed_rows_below_cutoff, 1)
        self.assertEqual(plan.lifetime_rows_inserted, 3)

        including_reviewed = build_retention_plan(
            self.conn,
            cutoff,
            include_reviewed=True,
        )
        self.assertEqual(including_reviewed.eligible_rows, 2)

    def test_prune_is_batched_cascades_context_and_cleans_only_orphans(self):
        self.insert_snapshot(1)
        self.insert_snapshot(2)
        old_id = self.insert_event(
            age_days=60,
            signature_id=10,
            src_snapshot_id=1,
            source_event_id="old",
        )
        self.insert_event(
            age_days=60,
            signature_id=11,
            source_event_id="old-two",
        )
        reviewed_id = self.insert_event(
            age_days=60,
            signature_id=12,
            human_verdict="real",
            src_snapshot_id=2,
            source_event_id="reviewed",
        )
        new_id = self.insert_event(
            age_days=5,
            signature_id=13,
            src_snapshot_id=2,
            source_event_id="new",
        )
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        result = prune_events(
            self.conn,
            cutoff,
            batch_size=1,
            pause_ms=0,
        )

        self.assertEqual(result.deleted_rows, 2)
        self.assertEqual(result.batches, 2)
        self.assertEqual(result.deleted_asset_snapshots, 1)
        remaining_ids = {
            row[0]
            for row in self.conn.execute(
                "SELECT id FROM triage_events"
            ).fetchall()
        }
        self.assertEqual(remaining_ids, {reviewed_id, new_id})
        self.assertIsNone(
            self.conn.execute(
                """SELECT 1 FROM sensor_event_context
                   WHERE triage_event_id = ?""",
                (old_id,),
            ).fetchone()
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT id FROM asset_snapshots"
            ).fetchall(),
            [(2,)],
        )

    def test_max_rows_supports_a_canary_prune(self):
        for signature_id in range(20, 25):
            self.insert_event(
                age_days=60,
                signature_id=signature_id,
            )
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        result = prune_events(
            self.conn,
            cutoff,
            batch_size=3,
            pause_ms=0,
            max_rows=2,
        )

        self.assertEqual(result.deleted_rows, 2)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            3,
        )

    def test_prune_rejects_unbounded_batch_parameters(self):
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        with self.assertRaises(ValueError):
            prune_events(
                self.conn,
                cutoff,
                batch_size=10_001,
            )
        with self.assertRaises(ValueError):
            prune_events(
                self.conn,
                cutoff,
                pause_ms=60_001,
            )

    def test_online_backup_is_valid_and_never_overwrites(self):
        self.insert_event(age_days=5, signature_id=30)
        backup_path = Path(self.temp_dir.name) / "backup.db"

        created = create_online_backup(self.conn, backup_path)

        self.assertEqual(created, backup_path)
        backup = sqlite3.connect(backup_path)
        try:
            self.assertEqual(
                backup.execute(
                    "SELECT COUNT(*) FROM triage_events"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                backup.execute("PRAGMA quick_check").fetchone()[0],
                "ok",
            )
        finally:
            backup.close()
        with self.assertRaises(FileExistsError):
            create_online_backup(self.conn, backup_path)

    def test_cli_is_dry_run_by_default_and_requires_apply_acknowledgement(self):
        self.insert_event(age_days=60, signature_id=35)
        self.conn.close()
        output = io.StringIO()
        with redirect_stdout(output):
            result = retention.main(
                [
                    "prune",
                    "--db",
                    str(self.db_path),
                    "--keep-days",
                    "30",
                    "--json",
                ]
            )
        self.conn = connect_database(self.db_path)

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "dry_run")
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            1,
        )

        self.conn.close()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                retention.main(
                    [
                        "prune",
                        "--db",
                        str(self.db_path),
                        "--keep-days",
                        "30",
                        "--apply",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)
        self.conn = connect_database(self.db_path)

    def test_dry_run_does_not_change_a_legacy_database_journal_mode(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        legacy = sqlite3.connect(legacy_path)
        try:
            legacy.executescript(
                (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
            )
            self.assertEqual(
                legacy.execute("PRAGMA journal_mode").fetchone()[0],
                "delete",
            )
        finally:
            legacy.close()

        with redirect_stdout(io.StringIO()):
            result = retention.main(
                [
                    "prune",
                    "--db",
                    str(legacy_path),
                    "--keep-days",
                    "30",
                    "--json",
                ]
            )

        self.assertEqual(result, 0)
        legacy = sqlite3.connect(legacy_path)
        try:
            self.assertEqual(
                legacy.execute("PRAGMA journal_mode").fetchone()[0],
                "delete",
            )
        finally:
            legacy.close()

    def test_storage_metrics_report_reusable_pages_without_table_scan(self):
        for signature_id in range(40, 50):
            self.insert_event(age_days=5, signature_id=signature_id)
        self.conn.execute(
            "DELETE FROM triage_events WHERE signature_id < 49"
        )
        self.conn.commit()

        metrics = get_storage_metrics(self.conn, self.db_path)

        self.assertGreater(metrics["page_size_bytes"], 0)
        self.assertGreater(metrics["page_count"], 0)
        self.assertEqual(
            metrics["reusable_bytes"],
            metrics["freelist_pages"] * metrics["page_size_bytes"],
        )
        self.assertGreaterEqual(
            metrics["total_on_disk_bytes"],
            metrics["database_bytes"],
        )
        self.assertEqual(metrics["auto_vacuum"], "none")

    def test_retention_lookup_uses_processed_at_index(self):
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        plan = self.conn.execute(
            """EXPLAIN QUERY PLAN
               SELECT id FROM triage_events
               WHERE processed_at IS NOT NULL
                 AND processed_at < ?
                 AND human_verdict IS NULL
               ORDER BY processed_at, id
               LIMIT ?""",
            (cutoff, 500),
        ).fetchall()

        details = " ".join(row[3] for row in plan)
        self.assertIn("idx_triage_processed", details)

    def test_orphan_cleanup_uses_snapshot_reference_indexes(self):
        plan = self.conn.execute(
            """EXPLAIN QUERY PLAN
               SELECT 1 FROM triage_events
               WHERE src_asset_snapshot_id = ?
                  OR dest_asset_snapshot_id = ?""",
            (1, 1),
        ).fetchall()

        details = " ".join(row[3] for row in plan)
        self.assertIn("idx_triage_src_asset_snapshot", details)
        self.assertIn("idx_triage_dest_asset_snapshot", details)


if __name__ == "__main__":
    unittest.main(verbosity=2)
