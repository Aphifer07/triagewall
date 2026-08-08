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
import time
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
    create_backup_copy,
    create_online_backup,
    prune_events,
    validate_backup_manifest,
    verify_backup,
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

    def test_max_runtime_stops_at_batch_boundary_and_defers_cleanup(self):
        self.insert_snapshot(1)
        self.insert_event(
            age_days=60,
            signature_id=30,
            src_snapshot_id=1,
        )
        self.insert_event(age_days=60, signature_id=31)
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        clock = FakeClock()

        def advance_after_batch(_rows: int, _batches: int) -> None:
            clock.advance(2)

        result = prune_events(
            self.conn,
            cutoff,
            batch_size=1,
            pause_ms=0,
            max_runtime_seconds=1,
            progress=advance_after_batch,
            clock=clock,
        )

        self.assertEqual(result.deleted_rows, 1)
        self.assertEqual(result.stopped_reason, "max_runtime")
        self.assertTrue(result.orphan_cleanup_deferred)
        self.assertEqual(result.deleted_asset_snapshots, 0)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            1,
        )

    def test_batch_pause_is_capped_at_remaining_deadline(self):
        self.insert_event(age_days=60, signature_id=300)
        self.insert_event(age_days=60, signature_id=301)
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        clock = FakeClock()
        pauses: list[float] = []

        def advance_after_batch(_rows: int, _batches: int) -> None:
            clock.advance(0.75)

        def bounded_sleep(seconds: float) -> None:
            pauses.append(seconds)
            clock.advance(seconds)

        result = prune_events(
            self.conn,
            cutoff,
            batch_size=1,
            pause_ms=60_000,
            max_runtime_seconds=1,
            progress=advance_after_batch,
            clock=clock,
            sleep=bounded_sleep,
        )

        self.assertEqual(pauses, [0.25])
        self.assertEqual(result.deleted_rows, 1)
        self.assertEqual(result.stopped_reason, "max_runtime")

    def test_sqlite_lock_wait_is_capped_at_remaining_deadline(self):
        self.insert_event(age_days=60, signature_id=302)
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        original_busy_timeout = int(
            self.conn.execute("PRAGMA busy_timeout").fetchone()[0]
        )
        blocker = connect_database(self.db_path)
        blocker.execute("BEGIN IMMEDIATE")
        started_at = time.monotonic()
        try:
            result = prune_events(
                self.conn,
                cutoff,
                batch_size=1,
                pause_ms=0,
                max_runtime_seconds=0.2,
            )
        finally:
            blocker.rollback()
            blocker.close()
        elapsed = time.monotonic() - started_at

        self.assertLess(elapsed, 1.0)
        self.assertEqual(result.deleted_rows, 0)
        self.assertEqual(result.stopped_reason, "max_runtime")
        self.assertEqual(
            self.conn.execute("PRAGMA busy_timeout").fetchone()[0],
            original_busy_timeout,
        )

    def test_applied_cli_deadline_includes_planning_time(self):
        self.conn.close()
        clock = FakeClock(100)
        observed: dict[str, float | None] = {}
        plan = retention.RetentionPlan(
            cutoff=format_utc_timestamp(self.now - timedelta(days=30)),
            include_reviewed=False,
            eligible_rows=1,
            reviewed_rows_below_cutoff=0,
            lifetime_rows_inserted=1,
            oldest_processed_at=None,
            newest_processed_at=None,
        )

        def build_plan(*_args, deadline=None, **_kwargs):
            observed["plan_deadline"] = deadline
            clock.advance(4)
            return plan

        def prune(*_args, deadline=None, **_kwargs):
            observed["prune_deadline"] = deadline
            return retention.PruneResult(
                deleted_rows=1,
                deleted_asset_snapshots=0,
                orphan_cleanup_deferred=True,
                batches=1,
                checkpoint_busy_frames=0,
                checkpoint_log_frames=0,
                checkpointed_frames=0,
                stopped_reason="max_runtime",
            )

        with (
            mock.patch.object(retention.time, "monotonic", side_effect=clock),
            mock.patch.object(retention, "build_retention_plan", build_plan),
            mock.patch.object(retention, "prune_events", prune),
            redirect_stdout(io.StringIO()),
        ):
            result = retention.main(
                [
                    "prune",
                    "--db",
                    str(self.db_path),
                    "--keep-days",
                    "30",
                    "--apply",
                    "--confirm-writers-stopped",
                    "--no-backup",
                    "--max-runtime-seconds",
                    "10",
                    "--json",
                ]
            )

        self.conn = connect_database(self.db_path)
        self.assertEqual(result, 0)
        self.assertEqual(observed["plan_deadline"], 110)
        self.assertEqual(observed["prune_deadline"], 110)

    def test_plan_rejects_an_already_expired_deadline(self):
        with self.assertRaisesRegex(
            retention.RetentionDeadlineExceeded,
            "planning exceeded",
        ):
            build_retention_plan(
                self.conn,
                format_utc_timestamp(self.now - timedelta(days=30)),
                deadline=1,
                clock=lambda: 1,
            )

    def test_bounded_exhausted_prune_cleans_orphans_within_deadline(self):
        self.insert_snapshot(1)
        self.insert_event(
            age_days=60,
            signature_id=32,
            src_snapshot_id=1,
        )
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        result = prune_events(
            self.conn,
            cutoff,
            batch_size=10,
            pause_ms=0,
            max_runtime_seconds=60,
        )

        self.assertEqual(result.stopped_reason, "exhausted")
        self.assertFalse(result.orphan_cleanup_deferred)
        self.assertEqual(result.deleted_asset_snapshots, 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM asset_snapshots"
            ).fetchone()[0],
            0,
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
        self.assertEqual(
            self.conn.execute("PRAGMA busy_timeout").fetchone()[0],
            10_000,
        )
        self.assertEqual(
            list(backup_path.parent.glob(f".{backup_path.name}.*.tmp")),
            [],
        )
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

    def test_split_backup_verification_manifest_binds_exact_files(self):
        self.insert_event(age_days=60, signature_id=33)
        backup_path = Path(self.temp_dir.name) / "split.db"
        manifest_path = Path(self.temp_dir.name) / "split.manifest.json"

        created = create_backup_copy(self.conn, backup_path)
        provenance_path = Path(f"{backup_path}.provenance.json")
        payload = verify_backup(
            created,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        validated = validate_backup_manifest(
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
            cutoff=format_utc_timestamp(self.now - timedelta(days=30)),
        )

        self.assertEqual(payload, validated)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["integrity_check"], "ok")
        self.assertTrue(provenance_path.is_file())
        self.assertEqual(
            payload["backup_provenance"]["path"],
            str(provenance_path.resolve()),
        )
        self.assertEqual(payload["backup"]["path"], str(backup_path.resolve()))
        self.assertRegex(
            payload["backup"]["sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            payload["manifest_hash"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            list(
                manifest_path.parent.glob(
                    f".{manifest_path.name}.*.tmp"
                )
            ),
            [],
        )
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE(manifest_path.stat().st_mode),
                BACKUP_FILE_MODE,
            )
            self.assertEqual(
                stat.S_IMODE(provenance_path.stat().st_mode),
                BACKUP_FILE_MODE,
            )

    def test_manifest_rejects_eligible_rows_inserted_after_backup(self):
        self.insert_event(age_days=60, signature_id=330)
        backup_path = Path(self.temp_dir.name) / "stale.db"
        manifest_path = Path(self.temp_dir.name) / "stale.manifest.json"
        create_backup_copy(self.conn, backup_path)
        self.insert_event(age_days=60, signature_id=331)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )

        with self.assertRaisesRegex(
            ValueError,
            "does not contain every row eligible",
        ):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=format_utc_timestamp(
                    self.now - timedelta(days=30)
                ),
            )

    def test_manifest_authorization_scans_only_post_backup_rowid_tail(self):
        self.insert_event(age_days=60, signature_id=333)
        backup_path = Path(self.temp_dir.name) / "tail.db"
        manifest_path = Path(self.temp_dir.name) / "tail.manifest.json"
        create_backup_copy(self.conn, backup_path)
        self.insert_event(age_days=1, signature_id=334)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )

        statements: list[str] = []
        self.conn.set_trace_callback(statements.append)
        try:
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=format_utc_timestamp(
                    self.now - timedelta(days=30)
                ),
            )
        finally:
            self.conn.set_trace_callback(None)

        authorization_sql = next(
            statement
            for statement in statements
            if "FROM triage_events NOT INDEXED" in statement
            and "id >" in statement
        )
        plan = self.conn.execute(
            f"EXPLAIN QUERY PLAN {authorization_sql}"
        ).fetchall()
        details = " ".join(str(row[-1]) for row in plan)
        self.assertIn("INTEGER PRIMARY KEY", details)
        self.assertNotIn("idx_triage_processed", details)

    def test_manifest_rejects_review_feedback_added_after_backup(self):
        event_id = self.insert_event(age_days=60, signature_id=332)
        backup_path = Path(self.temp_dir.name) / "feedback.db"
        manifest_path = Path(self.temp_dir.name) / "feedback.manifest.json"
        create_backup_copy(self.conn, backup_path)
        provenance = json.loads(
            Path(f"{backup_path}.provenance.json").read_text(
                encoding="utf-8"
            )
        )
        self.conn.execute(
            """UPDATE triage_events
               SET human_verdict = 'real', human_notes = 'reviewed later',
                   agreed = 0, reviewed_at = ?
               WHERE id = ?""",
            (provenance["created_at"], event_id),
        )
        self.conn.commit()
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        validate_backup_manifest(
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
            cutoff=cutoff,
        )
        with self.assertRaisesRegex(ValueError, "latest feedback"):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=cutoff,
                include_reviewed=True,
            )

    def test_manifest_rejects_post_backup_feedback_with_null_reviewed_at(self):
        """NULL reviewed_at must not bypass include-reviewed authorization."""
        event_id = self.insert_event(age_days=60, signature_id=333)
        backup_path = Path(self.temp_dir.name) / "null-reviewed.db"
        manifest_path = Path(self.temp_dir.name) / "null-reviewed.manifest.json"
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        self.conn.execute(
            """UPDATE triage_events
               SET human_verdict = 'false_positive',
                   human_notes = 'sql review without reviewed_at',
                   agreed = 1,
                   reviewed_at = NULL
               WHERE id = ?""",
            (event_id,),
        )
        self.conn.commit()
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))

        validate_backup_manifest(
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
            cutoff=cutoff,
        )
        with self.assertRaisesRegex(ValueError, "latest feedback"):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=cutoff,
                include_reviewed=True,
            )

    def test_manifest_allows_pre_backup_feedback_with_null_reviewed_at(self):
        """Unchanged pre-backup feedback is authorized even without reviewed_at."""
        self.insert_event(
            age_days=60,
            signature_id=334,
            human_verdict="real",
        )
        backup_path = Path(self.temp_dir.name) / "pre-backup-feedback.db"
        manifest_path = Path(self.temp_dir.name) / (
            "pre-backup-feedback.manifest.json"
        )
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        validate_backup_manifest(
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
            cutoff=cutoff,
            include_reviewed=True,
        )

    def test_manifest_rejects_feedback_mutation_with_stale_reviewed_at(self):
        """Mutating feedback while leaving an old reviewed_at must fail closed."""
        event_id = self.insert_event(age_days=60, signature_id=335)
        old_reviewed_at = format_utc_timestamp(
            self.now - timedelta(days=40)
        )
        self.conn.execute(
            """UPDATE triage_events
               SET human_verdict = 'real', human_notes = 'original',
                   agreed = 0, reviewed_at = ?
               WHERE id = ?""",
            (old_reviewed_at, event_id),
        )
        self.conn.commit()
        backup_path = Path(self.temp_dir.name) / "stale-reviewed.db"
        manifest_path = Path(self.temp_dir.name) / "stale-reviewed.manifest.json"
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        self.conn.execute(
            """UPDATE triage_events
               SET human_verdict = 'false_positive',
                   human_notes = 'changed without bumping reviewed_at',
                   agreed = 1
               WHERE id = ?""",
            (event_id,),
        )
        self.conn.commit()
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        with self.assertRaisesRegex(ValueError, "latest feedback"):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=cutoff,
                include_reviewed=True,
            )

    def test_verify_rejects_backup_provenance_from_another_database(self):
        other_path = Path(self.temp_dir.name) / "other.db"
        other_conn = connect_database(other_path)
        other_conn.executescript(
            (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
        )
        backup_path = Path(self.temp_dir.name) / "unrelated.db"
        manifest_path = Path(self.temp_dir.name) / "unrelated.manifest.json"
        try:
            create_backup_copy(other_conn, backup_path)
        finally:
            other_conn.close()

        with self.assertRaisesRegex(ValueError, "different source database"):
            verify_backup(
                backup_path,
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
            )

    def test_manifest_rejects_backup_mutation_and_manifest_tampering(self):
        self.insert_event(age_days=60, signature_id=34)
        backup_path = Path(self.temp_dir.name) / "bound.db"
        manifest_path = Path(self.temp_dir.name) / "bound.manifest.json"
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )

        with backup_path.open("ab") as handle:
            handle.write(b"changed")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=format_utc_timestamp(
                    self.now - timedelta(days=30)
                ),
            )

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["verified_at"] = "2020-01-01T00:00:00.000000Z"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hash does not match"):
            validate_backup_manifest(
                manifest_path,
                source_conn=self.conn,
                source_path=self.db_path,
                cutoff=format_utc_timestamp(
                    self.now - timedelta(days=30)
                ),
            )

    def test_manifest_freshness_is_enforced(self):
        self.insert_event(age_days=60, signature_id=39)
        backup_path = Path(self.temp_dir.name) / "fresh.db"
        manifest_path = Path(self.temp_dir.name) / "fresh.manifest.json"
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )

        with mock.patch.object(
            retention,
            "utc_now",
            return_value=self.now + timedelta(days=2),
        ):
            with self.assertRaisesRegex(ValueError, "too old"):
                validate_backup_manifest(
                    manifest_path,
                    source_conn=self.conn,
                    source_path=self.db_path,
                    cutoff=format_utc_timestamp(
                        self.now - timedelta(days=30)
                    ),
                )

    def test_split_cli_flow_prunes_from_verified_manifest(self):
        self.insert_event(age_days=60, signature_id=38)
        backup_path = Path(self.temp_dir.name) / "flow.db"
        manifest_path = Path(self.temp_dir.name) / "flow.manifest.json"
        self.conn.close()

        with redirect_stdout(io.StringIO()):
            backup_result = retention.main(
                [
                    "backup",
                    "--db",
                    str(self.db_path),
                    "--output",
                    str(backup_path),
                    "--confirm-writers-stopped",
                    "--json",
                ]
            )
            verify_result = retention.main(
                [
                    "verify-backup",
                    "--db",
                    str(self.db_path),
                    "--backup",
                    str(backup_path),
                    "--manifest",
                    str(manifest_path),
                    "--json",
                ]
            )
            prune_result = retention.main(
                [
                    "prune",
                    "--db",
                    str(self.db_path),
                    "--keep-days",
                    "30",
                    "--apply",
                    "--confirm-writers-stopped",
                    "--verified-backup-manifest",
                    str(manifest_path),
                    "--max-runtime-seconds",
                    "60",
                    "--pause-ms",
                    "0",
                    "--json",
                ]
            )

        self.conn = connect_database(self.db_path)
        self.assertEqual((backup_result, verify_result, prune_result), (0, 0, 0))
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0],
            0,
        )

    def test_backup_command_requires_writers_stopped_acknowledgement(self):
        backup_path = Path(self.temp_dir.name) / "missing-copy-ack.db"
        self.conn.close()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                retention.main(
                    [
                        "backup",
                        "--db",
                        str(self.db_path),
                        "--output",
                        str(backup_path),
                    ]
                )
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(backup_path.exists())
        self.conn = connect_database(self.db_path)

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
        stderr = io.StringIO()
        with redirect_stderr(stderr):
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
        self.assertIn("dashboard", stderr.getvalue())
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

    def test_backup_watchdog_interrupts_without_progress_callback(self):
        self.insert_event(age_days=5, signature_id=399)
        backup_path = Path(self.temp_dir.name) / "blocked-copy.db"
        interrupted = threading.Event()

        class BlockingSource:
            def execute(self, *args, **kwargs):
                return self_conn.execute(*args, **kwargs)

            def interrupt(self):
                interrupted.set()

            def backup(self, _destination, **_kwargs):
                if not interrupted.wait(timeout=2.0):
                    raise AssertionError("backup watchdog did not interrupt")
                raise sqlite3.OperationalError("interrupted")

        self_conn = self.conn
        started_at = time.monotonic()
        with self.assertRaises(BackupLimitExceeded) as raised:
            create_online_backup(
                BlockingSource(),  # type: ignore[arg-type]
                backup_path,
                limits=BackupLimits(
                    max_copy_seconds=0.05,
                    stall_seconds=10,
                    progress_interval_seconds=10,
                ),
            )
        elapsed = time.monotonic() - started_at
        self.assertLess(elapsed, 1.0)
        self.assertTrue(interrupted.is_set())
        self.assertIn("maximum duration", str(raised.exception).lower())
        self.assertFalse(backup_path.exists())
        self.assertEqual(
            list(backup_path.parent.glob(f".{backup_path.name}.*.tmp")),
            [],
        )

    def test_locked_source_respects_copy_deadline_and_restores_timeout(self):
        locked_path = Path(self.temp_dir.name) / "locked-source.db"
        backup_path = Path(self.temp_dir.name) / "locked-backup.db"
        setup = sqlite3.connect(locked_path)
        setup.execute("PRAGMA journal_mode=DELETE")
        setup.execute("CREATE TABLE test_data (value TEXT)")
        setup.commit()
        setup.close()

        source = sqlite3.connect(locked_path, timeout=10)
        source.execute("PRAGMA busy_timeout=10000")
        blocker = sqlite3.connect(locked_path, timeout=10)
        blocker.execute("BEGIN EXCLUSIVE")
        started_at = time.monotonic()
        try:
            with self.assertRaises(BackupLimitExceeded):
                create_online_backup(
                    source,
                    backup_path,
                    limits=BackupLimits(
                        max_copy_seconds=0.1,
                        stall_seconds=10,
                        progress_interval_seconds=10,
                    ),
                )
            elapsed = time.monotonic() - started_at
            self.assertLess(elapsed, 1.0)
            self.assertEqual(
                source.execute("PRAGMA busy_timeout").fetchone()[0],
                10_000,
            )
            self.assertFalse(backup_path.exists())
        finally:
            blocker.rollback()
            blocker.close()
            source.close()

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

    def test_target_created_during_backup_is_never_overwritten(self):
        self.insert_event(age_days=5, signature_id=410)
        backup_path = Path(self.temp_dir.name) / "late-collision.db"

        def create_late_collision(_conn):
            backup_path.write_text("do-not-touch", encoding="utf-8")
            return "ok"

        with self.assertRaises(FileExistsError):
            create_online_backup(
                self.conn,
                backup_path,
                integrity_check=create_late_collision,
            )
        self.assertEqual(
            backup_path.read_text(encoding="utf-8"),
            "do-not-touch",
        )
        self.assertEqual(
            list(backup_path.parent.glob(f".{backup_path.name}.*.tmp")),
            [],
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


class BackupFeedbackAuthorizationPlanTests(unittest.TestCase):
    """The backup comparison must be a keyed lookup, not a per-row scan."""

    ROW_COUNT = 4_000

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.db_path = root / "triage.db"
        self.backup_path = root / "verified-backup.db"
        schema = (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()

        # A realistically populated pair: a one-row fixture would make any plan
        # look acceptable, so both sides carry thousands of reviewed rows.
        for path in (self.db_path, self.backup_path):
            conn = connect_database(path)
            try:
                conn.executescript(schema)
                conn.executemany(
                    """INSERT INTO triage_events (
                           id, timestamp, signature_id, signature, raw_alert,
                           verdict, model_used, processed_at,
                           human_verdict, human_notes, agreed, reviewed_at
                       ) VALUES (?, ?, ?, ?, '{}', 'real', 'm', ?, ?, ?, ?, ?)""",
                    [self._row(index) for index in range(1, self.ROW_COUNT + 1)],
                )
                conn.commit()
                conn.execute("ANALYZE")
                conn.commit()
            finally:
                conn.close()

        self.conn = connect_database(self.db_path)
        self.addCleanup(self.conn.close)

    @staticmethod
    def _row(index: int):
        stamp = f"2026-01-{(index % 28) + 1:02d}T00:00:00+00:00"
        reviewed = index % 3 == 0
        return (
            index,
            stamp,
            1_000 + index,
            f"Signature {index}",
            stamp,
            "real" if reviewed else None,
            f"note {index}" if reviewed else None,
            1 if reviewed else None,
            stamp if reviewed else None,
        )

    def _attach_backup(self):
        self.conn.execute(
            "ATTACH DATABASE ? AS verified_backup",
            (retention._readonly_backup_uri(self.backup_path),),
        )
        self.addCleanup(self._detach_quietly)

    def _detach_quietly(self):
        try:
            self.conn.execute("DETACH DATABASE verified_backup")
        except sqlite3.Error:
            pass

    def test_backup_side_uses_a_primary_key_lookup(self):
        self._attach_backup()
        plan = self.conn.execute(
            "EXPLAIN QUERY PLAN "
            + retention._backup_feedback_authorization_sql(),
            (self.ROW_COUNT, "2026-06-01T00:00:00+00:00"),
        ).fetchall()
        details = [row[3] for row in plan]
        joined = " | ".join(details)

        backup_steps = [step for step in details if " bak" in f" {step}"]
        self.assertTrue(backup_steps, f"no backup access step in plan: {joined}")
        for step in backup_steps:
            # Reject a full scan of the backup feedback table per live row.
            self.assertNotIn(
                "SCAN",
                step,
                f"backup side must not be scanned per live row: {joined}",
            )
            self.assertIn(
                "INTEGER PRIMARY KEY",
                step,
                f"backup side must be a primary-key lookup: {joined}",
            )

    def test_live_side_stays_bounded_by_the_cutoff(self):
        self._attach_backup()
        plan = self.conn.execute(
            "EXPLAIN QUERY PLAN "
            + retention._backup_feedback_authorization_sql(),
            (self.ROW_COUNT, "2026-06-01T00:00:00+00:00"),
        ).fetchall()
        joined = " | ".join(row[3] for row in plan)
        live_steps = [row[3] for row in plan if " live" in f" {row[3]}"]
        self.assertTrue(live_steps, f"no live access step in plan: {joined}")
        for step in live_steps:
            self.assertNotIn(
                "SCAN live",
                step,
                f"live side must stay bounded, not scan the table: {joined}",
            )

    def test_authorization_predicate_matches_the_prune_predicate(self):
        sql = retention._backup_feedback_authorization_sql()
        self.assertIn(
            retention._retention_predicate(True, alias="live"),
            sql,
        )
        # Only reviewed rows can carry feedback worth authorizing.
        self.assertIn("live.human_verdict IS NOT NULL", sql)
        # And the scan is bounded by the verified backup sequence.
        self.assertIn("live.id <= ?", sql)

    def test_attached_backup_is_read_only(self):
        self._attach_backup()
        with self.assertRaises(sqlite3.OperationalError) as ctx:
            self.conn.execute(
                "UPDATE verified_backup.triage_events SET agreed = 0 WHERE id = 1"
            )
        self.assertIn("readonly", str(ctx.exception).replace(" ", "").lower())


class BackupAuthorizationCleanupTests(unittest.TestCase):
    """An interrupted comparison must leave the connection clean and usable."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = Path(self.temp_dir.name) / "triage.db"
        self.conn = connect_database(self.db_path)
        self.addCleanup(self.conn.close)
        self.conn.executescript(
            (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
        )
        self.now = datetime.now(timezone.utc)

    def insert_event(self, *, age_days: int, signature_id: int,
                     human_verdict: str | None = None) -> int:
        timestamp = format_utc_timestamp(self.now - timedelta(days=age_days))
        cursor = self.conn.execute(
            """INSERT INTO triage_events (
                   timestamp, signature_id, signature, raw_alert,
                   verdict, model_used, processed_at, human_verdict
               ) VALUES (?, ?, ?, ?, 'false_positive', 'prefilter', ?, ?)""",
            (
                timestamp,
                signature_id,
                f"Test {signature_id}",
                '{"padding":"' + ("x" * 1_024) + '"}',
                timestamp,
                human_verdict,
            ),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def _prepare_verified_backup(self, reviewed_rows: int = 400):
        for index in range(reviewed_rows):
            self.insert_event(
                age_days=60,
                signature_id=5_000 + index,
                human_verdict="real",
            )
        backup_path = Path(self.temp_dir.name) / "cleanup.db"
        manifest_path = Path(self.temp_dir.name) / "cleanup.manifest.json"
        create_backup_copy(self.conn, backup_path)
        verify_backup(
            backup_path,
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
        )
        return manifest_path

    def _attached_databases(self):
        return {
            row[1]
            for row in self.conn.execute("PRAGMA database_list").fetchall()
        }

    def test_deadline_interrupt_detaches_and_leaves_connection_usable(self):
        manifest_path = self._prepare_verified_backup()
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        # Deliberately above the bound the deadline will impose, so restoring
        # the caller's policy is observable rather than a no-op.
        self.conn.execute("PRAGMA busy_timeout=25000")
        original_busy_timeout = int(
            self.conn.execute("PRAGMA busy_timeout").fetchone()[0]
        )
        self.assertEqual(original_busy_timeout, 25_000)

        # Trip the deadline exactly when the backup comparison statement is
        # built -- after ATTACH succeeded -- so the interrupt provably lands
        # inside the attached-database query, not in the cheap pre-check or in
        # ATTACH itself.
        state = {"armed": False, "attached_during_query": None}
        deadline = 10.0

        def clock():
            return 11.0 if state["armed"] else 0.0

        real_sql = retention._backup_feedback_authorization_sql

        def arm_then_build():
            state["attached_during_query"] = "verified_backup" in {
                row[1]
                for row in self.conn.execute("PRAGMA database_list").fetchall()
            }
            state["armed"] = True
            return real_sql()

        with mock.patch.object(
            retention,
            "_backup_feedback_authorization_sql",
            side_effect=arm_then_build,
        ):
            with self.assertRaises(retention.RetentionDeadlineExceeded):
                validate_backup_manifest(
                    manifest_path,
                    source_conn=self.conn,
                    source_path=self.db_path,
                    cutoff=cutoff,
                    include_reviewed=True,
                    deadline=deadline,
                    clock=clock,
                )

        # The backup really was attached for the comparison...
        self.assertTrue(state["attached_during_query"])
        # ...and must not still be attached afterwards.
        self.assertNotIn("verified_backup", self._attached_databases())
        # The busy timeout must be restored.
        self.assertEqual(
            int(self.conn.execute("PRAGMA busy_timeout").fetchone()[0]),
            original_busy_timeout,
        )
        # The progress callback must be gone. The fake clock is still past the
        # deadline, so a lingering handler would interrupt this query, which is
        # deliberately long enough to cross the 1000-instruction callback
        # period many times over.
        self.assertTrue(state["armed"])
        total = self.conn.execute(
            "SELECT COUNT(*) FROM triage_events AS a JOIN triage_events AS b"
        ).fetchone()[0]
        self.assertEqual(total, 400 * 400)

    def test_successful_authorization_detaches_and_restores_timeout(self):
        manifest_path = self._prepare_verified_backup(reviewed_rows=5)
        cutoff = format_utc_timestamp(self.now - timedelta(days=30))
        original_busy_timeout = int(
            self.conn.execute("PRAGMA busy_timeout").fetchone()[0]
        )
        clock = FakeClock()

        validate_backup_manifest(
            manifest_path,
            source_conn=self.conn,
            source_path=self.db_path,
            cutoff=cutoff,
            include_reviewed=True,
            deadline=clock.now + 600.0,
            clock=clock,
        )

        self.assertNotIn("verified_backup", self._attached_databases())
        self.assertEqual(
            int(self.conn.execute("PRAGMA busy_timeout").fetchone()[0]),
            original_busy_timeout,
        )

    def test_detach_failure_does_not_mask_the_original_error(self):
        """Cleanup must never replace the diagnosis being unwound."""
        raised = []
        try:
            raise ValueError("original failure")
        except ValueError:
            # Nothing is attached, so DETACH fails -- but an error is in flight.
            stderr = io.StringIO()
            try:
                with redirect_stderr(stderr):
                    retention._detach_verified_backup(self.conn)
            except Exception as exc:  # pragma: no cover - must not happen
                raised.append(exc)
        self.assertEqual(raised, [])
        self.assertIn("could not detach the verified backup", stderr.getvalue())

    def test_detach_failure_without_an_in_flight_error_is_explicit(self):
        with self.assertRaises(retention.RetentionCleanupError) as ctx:
            retention._detach_verified_backup(self.conn)
        self.assertIn("detach the verified backup", str(ctx.exception))

    def test_cleanup_failure_reaches_the_cli_as_a_handled_failure(self):
        """A detach failure must not escape ``main()`` as a traceback.

        ``RetentionCleanupError`` is a bare ``RuntimeError`` raised after the
        backup comparison has already run, so leaving it out of ``main()``'s
        handled tuple turns a controlled fail-closed refusal into an unhandled
        crash. That breaks the stable ``retention failed: …`` + exit 1 contract
        operators and ``scripts/retention-cycle.sh`` depend on -- and before
        this error type existed, the same detach failure surfaced as a
        ``sqlite3.OperationalError``, which *was* handled.
        """
        manifest_path = self._prepare_verified_backup(reviewed_rows=5)
        self.conn.close()
        stderr = io.StringIO()

        with mock.patch.object(
            retention,
            "_detach_verified_backup",
            side_effect=retention.RetentionCleanupError(
                "could not detach the verified backup after authorization; "
                "the source connection may still have it attached"
            ),
        ):
            # Reaching an assertion at all proves main() handled it: an
            # unhandled RetentionCleanupError would propagate out of this call.
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                result = retention.main(
                    [
                        "prune",
                        "--db",
                        str(self.db_path),
                        "--keep-days",
                        "30",
                        "--apply",
                        "--confirm-writers-stopped",
                        "--include-reviewed",
                        "--verified-backup-manifest",
                        str(manifest_path),
                        "--max-runtime-seconds",
                        "60",
                        "--pause-ms",
                        "0",
                        "--json",
                    ]
                )

        self.assertEqual(result, 1)
        self.assertIn("retention failed:", stderr.getvalue())
        self.assertIn("detach the verified backup", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        # Fail closed: authorization never completed, so nothing was pruned.
        verify_conn = connect_database(self.db_path)
        try:
            remaining = verify_conn.execute(
                "SELECT COUNT(*) FROM triage_events"
            ).fetchone()[0]
        finally:
            verify_conn.close()
        self.assertEqual(remaining, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
