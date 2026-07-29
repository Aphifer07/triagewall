#!/usr/bin/env python3
"""Regression tests for storage visibility and retention controls."""

from datetime import datetime, timedelta, timezone
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

from triagewall.database import connect_database
from triagewall import retention
from triagewall.retention import (
    BACKUP_FILE_MODE,
    SQLITE_BUSY,
    SQLITE_LOCKED,
    SQLITE_OK,
    BackupLimitExceeded,
    BackupLimits,
    BackupProgressMonitor,
    IntegrityCheckMonitor,
    build_retention_plan,
    create_online_backup,
    prune_events,
)
from triagewall.storage import get_storage_metrics
from triagewall.time_utils import format_utc_timestamp


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


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
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE(backup_path.stat().st_mode),
                BACKUP_FILE_MODE,
            )
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

    def test_apply_with_backup_requires_writers_stopped_acknowledgement(self):
        self.insert_event(age_days=60, signature_id=36)
        backup_path = Path(self.temp_dir.name) / "missing-ack.db"
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
                        "--backup",
                        str(backup_path),
                    ]
                )
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(backup_path.exists())
        self.conn = connect_database(self.db_path)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            1,
        )

    def test_apply_with_no_backup_requires_writers_stopped_acknowledgement(self):
        self.insert_event(age_days=60, signature_id=37)
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
                        "--no-backup",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)
        self.conn = connect_database(self.db_path)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            1,
        )

    def test_status_does_not_require_writers_stopped_acknowledgement(self):
        self.conn.close()
        output = io.StringIO()
        with redirect_stdout(output):
            result = retention.main(
                ["status", "--db", str(self.db_path), "--json"]
            )
        self.conn = connect_database(self.db_path)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertIn("storage", payload)
        self.assertIn("history", payload)

    def test_backup_progress_monitor_tracks_forward_progress(self):
        clock = FakeClock()
        reports: list[str] = []
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=60,
                stall_seconds=30,
                max_restarts=3,
                progress_interval_seconds=10,
            ),
            clock=clock,
            report=reports.append,
        )
        monitor(SQLITE_OK, 100, 100)
        clock.advance(1)
        monitor(SQLITE_OK, 50, 100)
        self.assertEqual(monitor.previous_remaining, 50)
        self.assertEqual(monitor.restarts, 0)
        clock.advance(10)
        monitor(SQLITE_OK, 25, 100)
        self.assertEqual(len(reports), 1)
        self.assertIn("phase=backup", reports[0])
        self.assertIn("remaining_pages=25", reports[0])

    def test_backup_progress_reporting_is_rate_limited(self):
        clock = FakeClock()
        reports: list[str] = []
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=1_000,
                stall_seconds=1_000,
                max_restarts=10,
                progress_interval_seconds=30,
            ),
            clock=clock,
            report=reports.append,
        )
        monitor(SQLITE_OK, 100, 100)
        for remaining in range(99, 89, -1):
            clock.advance(1)
            monitor(SQLITE_OK, remaining, 100)
        self.assertEqual(reports, [])
        clock.advance(30)
        monitor(SQLITE_OK, 80, 100)
        self.assertEqual(len(reports), 1)
        clock.advance(5)
        monitor(SQLITE_OK, 70, 100)
        self.assertEqual(len(reports), 1)

    def test_backup_restart_detection_and_limit(self):
        clock = FakeClock()
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=1_000,
                stall_seconds=1_000,
                max_restarts=2,
                progress_interval_seconds=1_000,
            ),
            clock=clock,
            report=lambda _message: None,
        )
        monitor(SQLITE_OK, 50, 100)
        clock.advance(1)
        monitor(SQLITE_OK, 80, 100)
        self.assertEqual(monitor.restarts, 1)
        clock.advance(1)
        monitor(SQLITE_OK, 90, 100)
        self.assertEqual(monitor.restarts, 2)
        clock.advance(1)
        with self.assertRaises(BackupLimitExceeded) as raised:
            monitor(SQLITE_OK, 95, 100)
        self.assertIn("restarts", str(raised.exception).lower())

    def test_backup_stall_aborts_without_forward_progress(self):
        clock = FakeClock()
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=1_000,
                stall_seconds=120,
                max_restarts=10,
                progress_interval_seconds=1_000,
            ),
            clock=clock,
            report=lambda _message: None,
        )
        monitor(SQLITE_OK, 50, 100)
        clock.advance(119)
        monitor(SQLITE_OK, 50, 100)
        clock.advance(1)
        with self.assertRaises(BackupLimitExceeded) as raised:
            monitor(SQLITE_OK, 50, 100)
        self.assertIn("stalled", str(raised.exception).lower())

    def test_busy_and_locked_callbacks_do_not_reset_stall_timer(self):
        clock = FakeClock()
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=1_000,
                stall_seconds=100,
                max_restarts=10,
                progress_interval_seconds=1_000,
            ),
            clock=clock,
            report=lambda _message: None,
        )
        monitor(SQLITE_BUSY, 0, 0)
        self.assertIsNone(monitor.previous_remaining)
        clock.advance(25)
        monitor(SQLITE_LOCKED, 0, 0)
        self.assertIsNone(monitor.previous_remaining)
        clock.advance(25)
        monitor(SQLITE_OK, 100, 100)
        self.assertEqual(monitor.previous_remaining, 100)
        self.assertEqual(monitor.restarts, 0)
        clock.advance(25)
        monitor(SQLITE_BUSY, 90, 100)
        self.assertEqual(monitor.previous_remaining, 100)
        self.assertEqual(monitor.restarts, 0)
        clock.advance(25)
        with self.assertRaises(BackupLimitExceeded) as raised:
            monitor(SQLITE_LOCKED, 80, 100)
        self.assertIn("stalled", str(raised.exception).lower())

    def test_backup_copy_timeout_aborts(self):
        clock = FakeClock()
        monitor = BackupProgressMonitor(
            BackupLimits(
                max_copy_seconds=30,
                stall_seconds=1_000,
                max_restarts=10,
                progress_interval_seconds=1_000,
            ),
            clock=clock,
            report=lambda _message: None,
        )
        monitor(SQLITE_OK, 100, 100)
        clock.advance(30)
        with self.assertRaises(BackupLimitExceeded) as raised:
            monitor(SQLITE_OK, 90, 100)
        self.assertIn("maximum duration", str(raised.exception).lower())

    def test_partial_backup_is_removed_after_copy_abort(self):
        self.insert_event(age_days=5, signature_id=40)
        backup_path = Path(self.temp_dir.name) / "partial.db"

        def aborting_monitor(_status, _remaining, _total):
            raise BackupLimitExceeded(
                "backup copy exceeded maximum duration of 1 seconds"
            )

        with self.assertRaises(BackupLimitExceeded):
            create_online_backup(
                self.conn,
                backup_path,
                limits=BackupLimits(max_copy_seconds=1),
                progress_monitor=aborting_monitor,
            )
        self.assertFalse(backup_path.exists())

    def test_preexisting_backup_is_never_removed_on_collision(self):
        self.insert_event(age_days=5, signature_id=41)
        backup_path = Path(self.temp_dir.name) / "existing.db"
        backup_path.write_text("do-not-touch", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            create_online_backup(self.conn, backup_path)
        self.assertEqual(
            backup_path.read_text(encoding="utf-8"),
            "do-not-touch",
        )

    def test_permission_failure_removes_owned_backup(self):
        self.insert_event(age_days=5, signature_id=411)
        backup_path = Path(self.temp_dir.name) / "permission-failure.db"
        with mock.patch.object(
            retention,
            "_ensure_backup_permissions",
            side_effect=OSError("permission update failed"),
        ):
            with self.assertRaises(OSError):
                create_online_backup(self.conn, backup_path)
        self.assertFalse(backup_path.exists())

    def test_integrity_timeout_removes_owned_backup(self):
        self.insert_event(age_days=5, signature_id=42)
        backup_path = Path(self.temp_dir.name) / "integrity-timeout.db"
        monitors: list[IntegrityCheckMonitor] = []

        class InstantTimeoutMonitor(IntegrityCheckMonitor):
            def start(self) -> None:
                self.timed_out = True
                self.thread = threading.Thread(target=lambda: None, daemon=True)
                self.thread.start()
                monitors.append(self)

        with self.assertRaises(BackupLimitExceeded):
            create_online_backup(
                self.conn,
                backup_path,
                integrity_check=lambda _conn: "ok",
                monitor_factory=InstantTimeoutMonitor,
            )
        self.assertFalse(backup_path.exists())
        self.assertTrue(monitors)
        self.assertFalse(monitors[0].thread.is_alive())

    def test_integrity_heartbeat_and_monitor_cleanup_on_success(self):
        self.insert_event(age_days=5, signature_id=43)
        backup_path = Path(self.temp_dir.name) / "heartbeat.db"
        reports: list[str] = []
        monitors: list[IntegrityCheckMonitor] = []

        class HeartbeatMonitor(IntegrityCheckMonitor):
            def start(self) -> None:
                monitors.append(self)
                self.report(
                    "retention backup progress: phase=integrity elapsed=30.0s"
                )
                self.thread = threading.Thread(target=lambda: None, daemon=True)
                self.thread.start()

            def stop(self) -> None:
                super().stop()
                self.stopped = True  # type: ignore[attr-defined]

        created = create_online_backup(
            self.conn,
            backup_path,
            report=reports.append,
            integrity_check=lambda _conn: "ok",
            monitor_factory=HeartbeatMonitor,
        )
        self.assertEqual(created, backup_path)
        self.assertTrue(any("phase=integrity" in message for message in reports))
        self.assertTrue(monitors)
        self.assertTrue(getattr(monitors[0], "stopped", False))
        self.assertFalse(monitors[0].thread.is_alive())

    def test_integrity_monitor_emits_rate_limited_heartbeats(self):
        clock = FakeClock()
        reports: list[str] = []
        limits = BackupLimits(
            integrity_max_seconds=10_800,
            integrity_progress_interval_seconds=30,
        )
        started_at = clock()
        last_report_at = started_at
        for _ in range(5):
            clock.advance(10)
            now = clock()
            if now - last_report_at < limits.integrity_progress_interval_seconds:
                continue
            elapsed = now - started_at
            reports.append(
                "retention backup progress: phase=integrity "
                f"elapsed={elapsed:.1f}s"
            )
            last_report_at = now
        self.assertEqual(clock(), 50.0)
        self.assertEqual(len(reports), 1)
        self.assertIn("phase=integrity", reports[0])
        self.assertIn("elapsed=30.0s", reports[0])

    def test_integrity_failure_removes_owned_backup_and_monitor_stops(self):
        self.insert_event(age_days=5, signature_id=44)
        backup_path = Path(self.temp_dir.name) / "bad-integrity.db"
        monitors: list[IntegrityCheckMonitor] = []

        class RecordingMonitor(IntegrityCheckMonitor):
            def start(self) -> None:
                monitors.append(self)
                super().start()

            def stop(self) -> None:
                super().stop()
                self.stopped = True  # type: ignore[attr-defined]

        with self.assertRaises(sqlite3.DatabaseError):
            create_online_backup(
                self.conn,
                backup_path,
                integrity_check=lambda _conn: "not ok",
                monitor_factory=RecordingMonitor,
            )
        self.assertFalse(backup_path.exists())
        self.assertTrue(monitors)
        self.assertTrue(getattr(monitors[0], "stopped", False))
        self.assertFalse(monitors[0].thread.is_alive())

    def test_successful_backup_and_bounded_prune_json_contract(self):
        for signature_id in range(50, 60):
            self.insert_event(age_days=60, signature_id=signature_id)
        self.insert_event(
            age_days=60,
            signature_id=61,
            human_verdict="real",
        )
        self.insert_event(age_days=5, signature_id=62)
        backup_path = Path(self.temp_dir.name) / "canary.db"
        self.conn.close()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = retention.main(
                [
                    "prune",
                    "--db",
                    str(self.db_path),
                    "--keep-days",
                    "30",
                    "--apply",
                    "--confirm-writers-stopped",
                    "--backup",
                    str(backup_path),
                    "--max-rows",
                    "10000",
                    "--batch-size",
                    "500",
                    "--pause-ms",
                    "0",
                    "--json",
                ]
            )
        self.conn = connect_database(self.db_path)
        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["mode"], "apply")
        self.assertEqual(payload["backup"], str(backup_path))
        self.assertIn("plan", payload)
        self.assertIn("storage_before", payload)
        self.assertIn("storage_after", payload)
        self.assertIn("result", payload)
        result_payload = payload["result"]
        for key in (
            "batches",
            "checkpoint_busy_frames",
            "checkpoint_log_frames",
            "checkpointed_frames",
            "deleted_asset_snapshots",
            "deleted_rows",
        ):
            self.assertIn(key, result_payload)
        self.assertEqual(result_payload["deleted_rows"], 10)
        self.assertTrue(backup_path.exists())
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE(backup_path.stat().st_mode),
                BACKUP_FILE_MODE,
            )
        remaining = {
            row[0]
            for row in self.conn.execute(
                "SELECT signature_id FROM triage_events"
            ).fetchall()
        }
        self.assertEqual(remaining, {61, 62})

    def test_failed_backup_does_not_enter_prune(self):
        self.insert_event(age_days=60, signature_id=70)
        backup_path = Path(self.temp_dir.name) / "blocked.db"
        backup_path.write_bytes(b"existing")
        self.conn.close()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = retention.main(
                [
                    "prune",
                    "--db",
                    str(self.db_path),
                    "--keep-days",
                    "30",
                    "--apply",
                    "--confirm-writers-stopped",
                    "--backup",
                    str(backup_path),
                    "--json",
                ]
            )
        self.conn = connect_database(self.db_path)
        self.assertEqual(result, 1)
        self.assertIn("retention failed", stderr.getvalue())
        self.assertEqual(backup_path.read_bytes(), b"existing")
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            1,
        )

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
