"""Zeek ingest service configuration and fail-closed startup tests."""

import os
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

    def test_environment_rejects_unbounded_work_settings(self):
        cases = (
            {"ZEEK_POLL_INTERVAL": "0"},
            {"ZEEK_POLL_INTERVAL": "301"},
            {"ZEEK_MAX_RECORDS_PER_POLL": "0"},
            {"ZEEK_MAX_RECORDS_PER_POLL": "100001"},
            {"ZEEK_EOF_STABLE_OBSERVATIONS": "1"},
        )
        for values in cases:
            with self.subTest(values=values):
                with mock.patch.dict(os.environ, values, clear=True):
                    with self.assertRaises(RuntimeError):
                        zeek_ingest.settings_from_environment()


class ZeekIngestStartupTests(unittest.TestCase):
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
