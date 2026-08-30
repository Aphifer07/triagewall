"""Zeek ingest service configuration and fail-closed startup tests."""

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import zeek_ingest


class ZeekIngestSettingsTests(unittest.TestCase):
    def test_environment_defaults_are_private_local_paths(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            settings = zeek_ingest.settings_from_environment()

        self.assertEqual(
            settings.conn_path,
            Path("/var/log/zeek/current/conn.log"),
        )
        self.assertEqual(
            settings.index_path,
            Path("/var/lib/triagewall/zeek-context.db"),
        )
        self.assertEqual(settings.source_instance, "zeek-local")
        self.assertEqual(settings.poll_interval_seconds, 2.0)
        self.assertEqual(settings.max_records_per_poll, 1_000)
        self.assertEqual(settings.archive_root, Path("/var/log/zeek"))
        self.assertEqual(settings.retention_seconds, 7 * 24 * 60 * 60)
        self.assertEqual(settings.prune_interval_seconds, 60.0)
        self.assertEqual(settings.prune_batch_size, 1_000)
        self.assertEqual(settings.prune_max_rows, 10_000)

    def test_environment_rejects_unbounded_work_settings(self):
        cases = (
            {"ZEEK_POLL_INTERVAL": "0"},
            {"ZEEK_POLL_INTERVAL": "301"},
            {"ZEEK_MAX_RECORDS_PER_POLL": "0"},
            {"ZEEK_MAX_RECORDS_PER_POLL": "100001"},
            {"ZEEK_EOF_STABLE_OBSERVATIONS": "1"},
            {"ZEEK_RETENTION_DAYS": "0"},
            {"ZEEK_PRUNE_INTERVAL": "0"},
            {"ZEEK_PRUNE_BATCH_SIZE": "10001"},
            {"ZEEK_PRUNE_MAX_ROWS": "1"},
            {"ZEEK_PRUNE_MAX_ROWS": "100001"},
        )
        for values in cases:
            with self.subTest(values=values):
                with mock.patch.dict(os.environ, values, clear=True):
                    with self.assertRaises(RuntimeError):
                        zeek_ingest.settings_from_environment()


class ZeekIngestStartupTests(unittest.TestCase):
    def test_retention_failure_stops_writer_and_closes_lifecycle(self):
        settings = zeek_ingest.ZeekIngestSettings(
            conn_path=Path("/var/log/zeek/current/conn.log"),
            index_path=Path("/var/lib/triagewall/zeek-context.db"),
            source_instance="zeek-local",
            poll_interval_seconds=0.1,
            max_records_per_poll=10,
            eof_stable_observations=2,
        )
        fake_conn = mock.Mock()
        follower = mock.Mock()
        with (
            mock.patch.object(zeek_ingest, "ZeekFollower", return_value=follower),
            mock.patch.object(
                zeek_ingest,
                "connect_zeek_index",
                return_value=fake_conn,
            ),
            mock.patch.object(
                zeek_ingest,
                "prune_index",
                side_effect=sqlite3.OperationalError("database or disk is full"),
            ),
        ):
            result = zeek_ingest.tail_zeek(settings)

        self.assertEqual(result, 1)
        follower.poll.assert_not_called()
        follower.close.assert_called_once_with()
        fake_conn.close.assert_called_once_with()

    def test_production_loop_runs_bounded_retention_and_emits_counts(self):
        settings = zeek_ingest.ZeekIngestSettings(
            conn_path=Path("/var/log/zeek/current/conn.log"),
            index_path=Path("/var/lib/triagewall/zeek-context.db"),
            source_instance="zeek-local",
            poll_interval_seconds=0.1,
            max_records_per_poll=10,
            eof_stable_observations=2,
            archive_root=Path("/var/log/zeek"),
            retention_seconds=86_400,
            prune_interval_seconds=60,
            prune_batch_size=7,
            prune_max_rows=11,
        )
        fake_conn = mock.Mock()
        follower = mock.Mock()

        def stop_after_poll(_conn):
            zeek_ingest._stop = True
            return mock.Mock(scanned=0, indexed=0, failures=0, rotated=False)

        follower.poll.side_effect = stop_after_poll
        prune_result = mock.Mock(connections=3, failures=2)
        with (
            mock.patch.object(zeek_ingest, "ZeekFollower", return_value=follower),
            mock.patch.object(
                zeek_ingest,
                "connect_zeek_index",
                return_value=fake_conn,
            ),
            mock.patch.object(
                zeek_ingest,
                "prune_index",
                return_value=prune_result,
            ) as prune,
            mock.patch.object(zeek_ingest.time, "time", return_value=1_000_000),
            mock.patch.object(zeek_ingest.time, "monotonic", return_value=10),
            mock.patch.object(zeek_ingest.time, "sleep"),
        ):
            result = zeek_ingest.tail_zeek(settings)

        self.assertEqual(result, 0)
        prune.assert_called_once_with(
            fake_conn,
            1_000_000 - 86_400,
            batch_size=7,
            max_rows=11,
        )
        follower.close.assert_called_once_with()
        fake_conn.close.assert_called_once_with()

    def test_missing_conn_log_stops_service_without_creating_context_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = zeek_ingest.ZeekIngestSettings(
                conn_path=root / "missing" / "conn.log",
                index_path=root / "zeek-context.db",
                source_instance="zeek-local",
                poll_interval_seconds=0.1,
                max_records_per_poll=10,
                eof_stable_observations=2,
            )

            result = zeek_ingest.tail_zeek(settings)

            self.assertEqual(result, 1)
            self.assertTrue(settings.index_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
