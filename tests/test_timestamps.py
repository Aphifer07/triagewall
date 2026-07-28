#!/usr/bin/env python3
"""Regression tests for canonical UTC timestamp handling."""

import re
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import ingest
import triage
from triagewall import spc
from triagewall.time_utils import format_utc_timestamp, utc_hour_timestamp


CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class TimestampTests(unittest.TestCase):
    def test_equivalent_offsets_have_one_fixed_width_representation(self):
        expected = "2026-07-19T04:30:00.123456Z"
        for value in (
            "2026-07-19T04:30:00.123456Z",
            "2026-07-19T04:30:00.123456+0000",
            "2026-07-19T00:30:00.123456-04:00",
            "2026-07-19 04:30:00.123456",
        ):
            self.assertEqual(format_utc_timestamp(value), expected)

        self.assertEqual(
            utc_hour_timestamp("2026-07-19T00:30:00.123456-04:00"),
            "2026-07-19T04:00:00.000000Z",
        )

    def test_invalid_or_empty_timestamp_is_rejected(self):
        for value in (None, "", "not-a-timestamp"):
            with self.assertRaises((TypeError, ValueError)):
                format_utc_timestamp(value)

    def test_triage_writes_canonical_event_and_processing_times(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        alert = {
            "timestamp": "2026-07-19T00:30:00.123456-04:00",
            "flow_id": 42,
            "alert": {"signature_id": 7, "signature": "Test"},
        }
        verdict = {
            "verdict": "real",
            "confidence": 0.9,
            "reasoning": "test",
            "model_used": "test",
        }

        triage.insert_triage_row(conn, alert, verdict)
        timestamp, processed_at = conn.execute(
            "SELECT timestamp, processed_at FROM triage_events"
        ).fetchone()
        conn.close()

        self.assertEqual(timestamp, "2026-07-19T04:30:00.123456Z")
        self.assertRegex(processed_at, CANONICAL_UTC)

    def test_duplicate_check_uses_the_same_canonical_timestamp(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        conn.execute(
            """INSERT INTO triage_events
               (timestamp, flow_id, signature_id, signature, raw_alert)
               VALUES (?, ?, ?, ?, ?)""",
            ("2026-07-19T04:30:00.123456Z", 42, 7, "Test", "{}"),
        )

        duplicate = ingest.is_duplicate(
            conn,
            {
                "timestamp": "2026-07-19T00:30:00.123456-04:00",
                "flow_id": 42,
                "alert": {"signature_id": 7},
            },
        )
        conn.close()

        self.assertTrue(duplicate)

    def test_duplicate_check_recognizes_legacy_suricata_storage(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        legacy_timestamp = "2026-07-19T04:30:00.123456+0000"
        conn.execute(
            """INSERT INTO triage_events
               (timestamp, flow_id, signature_id, signature, raw_alert)
               VALUES (?, ?, ?, ?, ?)""",
            (legacy_timestamp, 42, 7, "Test", "{}"),
        )

        duplicate = ingest.is_duplicate(
            conn,
            {
                "timestamp": legacy_timestamp,
                "flow_id": 42,
                "alert": {"signature_id": 7},
            },
        )
        conn.close()

        self.assertTrue(duplicate)

    def test_process_line_skips_legacy_timestamp_duplicate_before_model(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        legacy_timestamp = "2026-07-19T04:30:00.123456+0000"
        conn.execute(
            """INSERT INTO triage_events
               (timestamp, flow_id, signature_id, signature, raw_alert)
               VALUES (?, ?, ?, ?, ?)""",
            (legacy_timestamp, 42, 7, "Test", "{}"),
        )
        line = (
            '{"event_type":"alert",'
            f'"timestamp":"{legacy_timestamp}","flow_id":42,'
            '"alert":{"signature_id":7,"signature":"Test"}}'
        )

        with patch.object(ingest, "call_ollama") as call_ollama:
            result = ingest.process_line(conn, line)

        row_count = conn.execute(
            "SELECT COUNT(*) FROM triage_events"
        ).fetchone()[0]
        conn.close()
        self.assertTrue(result.checkpoint)
        self.assertFalse(result.processed)
        self.assertEqual(row_count, 1)
        call_ollama.assert_not_called()

    def test_invalid_ingest_timestamp_is_quarantined_before_triage(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        line = (
            '{"event_type":"alert","timestamp":"invalid",'
            '"alert":{"signature_id":7,"signature":"Test"}}\n'
        )

        with patch.object(ingest, "call_ollama") as call_ollama:
            result = ingest.process_line(conn, line)

        failure = conn.execute(
            "SELECT error FROM ingest_failures"
        ).fetchone()[0]
        conn.close()

        self.assertTrue(result.checkpoint)
        self.assertFalse(result.processed)
        self.assertIn("invalid alert timestamp", failure)
        call_ollama.assert_not_called()

    def test_spc_writes_canonical_event_times(self):
        conn = sqlite3.connect(":memory:")
        spc.ensure_spc_schema(conn)
        spc.observe(
            conn,
            {
                "timestamp": "2026-07-19T00:30:00.123456-04:00",
                "src_ip": "10.0.0.10",
                "alert": {"signature_id": 7},
            },
        )
        first_seen, last_seen = conn.execute(
            "SELECT first_seen, last_seen FROM spc_ip_state"
        ).fetchone()
        sid_seen = conn.execute("SELECT first_seen FROM spc_seen_sids").fetchone()[0]
        conn.close()

        expected = "2026-07-19T04:30:00.123456Z"
        self.assertEqual((first_seen, last_seen, sid_seen), (expected,) * 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
