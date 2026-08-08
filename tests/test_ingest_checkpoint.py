#!/usr/bin/env python3
"""Regression coverage for retryable ingest checkpoint failures."""

import json
import sqlite3
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import ingest
import migrations
import triage
from sensor_event import (
    normalize_suricata_event,
    suricata_classification_alert,
)


class IngestCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())

    def tearDown(self):
        self.conn.close()

    def test_model_failure_is_retryable_and_not_checkpointable(self):
        raw = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-07-19T00:00:00Z",
            "alert": {"signature_id": 1, "signature": "Retry me"},
        })
        with patch.object(
            triage.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ), patch.object(triage, "OLLAMA_URL", "http://ollama.test/api/generate"):
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertFalse(result.checkpoint)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0],
            0,
        )

    def test_persistence_failure_is_retryable_and_not_checkpointable(self):
        raw = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-07-19T00:00:00Z",
            "src_ip": " 10.0.0.1 ",
            "proto": "tcp",
            "alert": {"signature_id": 2, "signature": "Persist me"},
        })
        verdict = {"verdict": "real", "confidence": 0.8, "reasoning": "test"}
        context = {
            "source": {"hostname": "example-host"},
            "destination": None,
        }
        with patch.object(
            ingest, "get_asset_context", return_value=context
        ) as get_asset_context, patch.object(
            ingest, "call_ollama", return_value=verdict
        ) as call_ollama, patch.object(
            ingest, "insert_with_retry", return_value=False
        ) as insert_with_retry:
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertFalse(result.checkpoint)
        event = json.loads(raw)
        normalized_event = normalize_suricata_event(event)
        classification_event = suricata_classification_alert(normalized_event)
        self.assertEqual(classification_event["src_ip"], "10.0.0.1")
        self.assertEqual(classification_event["proto"], "TCP")
        get_asset_context.assert_called_once_with(classification_event)
        call_ollama.assert_called_once_with(
            classification_event,
            asset_context=context,
        )
        insert_with_retry.assert_called_once_with(
            self.conn,
            normalized_event,
            verdict,
            asset_context=context,
        )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0],
            0,
        )

    def test_missing_timestamp_is_quarantined_before_triage(self):
        raw = json.dumps({
            "event_type": "alert",
            "alert": {"signature_id": 3, "signature": "Missing timestamp"},
        })
        with patch.object(ingest, "call_ollama") as call_ollama:
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertTrue(result.checkpoint)
        failure = self.conn.execute(
            "SELECT raw_line, error FROM ingest_failures"
        ).fetchone()
        self.assertEqual(failure[0], raw)
        self.assertIn("invalid alert timestamp", failure[1])
        call_ollama.assert_not_called()

    def test_tail_loop_checkpoints_invalid_record_and_processes_next_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            invalid = json.dumps({
                "event_type": "alert",
                "alert": {"signature_id": 4, "signature": "Missing timestamp"},
            }) + "\n"
            valid = json.dumps({
                "event_type": "alert",
                "timestamp": "2026-07-19T00:00:00+00:00",
                "alert": {"signature_id": 5, "signature": "Process after invalid"},
            }) + "\n"
            eve_path.write_text(invalid + valid)
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            verdict = {"verdict": "real", "confidence": 0.8, "reasoning": "test"}
            calls = []
            migrations.ensure_db_initialized(db_path)

            def return_verdict(event, asset_context=None):
                self.assertEqual(
                    asset_context,
                    {"source": None, "destination": None},
                )
                calls.append(event["alert"]["signature_id"])
                ingest._stop = True
                return verdict

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "call_ollama", side_effect=return_verdict
                ):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            conn = sqlite3.connect(db_path)
            try:
                failures = conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0]
                events = conn.execute("SELECT COUNT(*) FROM triage_events").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(calls, [5])
            self.assertEqual(failures, 1)
            self.assertEqual(events, 1)
            self.assertEqual(saved["offset"], eve_path.stat().st_size)

    def test_intentional_skip_remains_checkpointable(self):
        result = ingest.process_line(
            self.conn,
            json.dumps({"event_type": "flow", "flow_id": 7}),
        )
        self.assertFalse(result)
        self.assertTrue(result.checkpoint)

    def test_permanently_invalid_input_remains_quarantined_and_checkpointable(self):
        raw = '[{"event_type":"alert"}]'
        result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertTrue(result.checkpoint)
        self.assertEqual(
            self.conn.execute("SELECT raw_line FROM ingest_failures").fetchone()[0],
            raw,
        )

    def test_tail_loop_does_not_advance_past_retryable_failure(self):
        class RetryResult:
            processed = False
            checkpoint = False

            def __bool__(self):
                return self.processed

        class SuccessResult:
            processed = True
            checkpoint = True

            def __bool__(self):
                return self.processed

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            first = '{"event_type":"alert","alert":{"signature_id":1}}\n'
            second = '{"event_type":"alert","alert":{"signature_id":2}}\n'
            eve_path.write_text(first + second)
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            calls = []
            migrations.ensure_db_initialized(db_path)

            def process_once(conn, line):
                calls.append(line)
                if len(calls) == 1:
                    return RetryResult()
                ingest._stop = True
                return SuccessResult()

            def stop_after_backoff(_seconds):
                ingest._stop = True

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "process_line", side_effect=process_once
                ), patch.object(ingest.time, "sleep", side_effect=stop_after_backoff):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            self.assertEqual(calls, [first])
            self.assertEqual(saved["offset"], 0)

    def test_tail_loop_retries_same_record_then_checkpoints_success(self):
        class RetryResult:
            processed = False
            checkpoint = False

            def __bool__(self):
                return self.processed

        class SuccessResult:
            processed = True
            checkpoint = True

            def __bool__(self):
                return self.processed

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            first = '{"event_type":"alert","alert":{"signature_id":1}}\n'
            second = '{"event_type":"alert","alert":{"signature_id":2}}\n'
            eve_path.write_text(first + second)
            with eve_path.open("r") as handle:
                handle.readline()
                expected_offset = handle.tell()
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            calls = []
            migrations.ensure_db_initialized(db_path)

            def fail_then_succeed(conn, line):
                calls.append(line)
                if len(calls) == 1:
                    return RetryResult()
                ingest._stop = True
                return SuccessResult()

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "process_line", side_effect=fail_then_succeed
                ), patch.object(ingest.time, "sleep"):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            self.assertEqual(calls, [first, first])
            self.assertEqual(saved["offset"], expected_offset)


class SuricataCheckpointDurabilityTests(unittest.TestCase):
    """Atomic writes and fail-closed loads for position.json."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.position_path = Path(self.temp_dir.name) / "position.json"
        self.position_patch = patch.object(
            ingest, "POSITION_PATH", self.position_path
        )
        self.position_patch.start()

    def tearDown(self):
        self.position_patch.stop()
        self.temp_dir.cleanup()

    def test_missing_checkpoint_starts_at_origin(self):
        self.assertEqual(
            ingest.load_position(),
            {"offset": 0, "inode": None, "size": 0},
        )

    def test_save_position_is_atomic_and_leaves_no_tmp(self):
        state = {"offset": 42, "inode": 7, "size": 99}
        ingest.save_position(state)
        self.assertEqual(ingest.load_position(), state)
        self.assertFalse(any(self.position_path.parent.glob("*.tmp")))

    def test_save_position_replaces_previous_checkpoint(self):
        ingest.save_position({"offset": 1, "inode": 1, "size": 1})
        ingest.save_position({"offset": 8, "inode": 2, "size": 8})
        self.assertEqual(
            ingest.load_position(),
            {"offset": 8, "inode": 2, "size": 8},
        )

    def test_corrupt_checkpoint_fails_closed_instead_of_rewinding(self):
        """A torn write must not silently restart at offset 0.

        Trigger: crash mid-``write_text`` leaves truncated JSON. The old loader
        caught the decode error and returned offset 0, which re-ingests the
        whole eve.json. Flow-less alerts bypass ``is_duplicate`` and land as
        duplicate ``triage_events`` rows.
        """
        self.position_path.write_text('{"offset": 12, "inode":')
        with self.assertRaises(ingest.EveCheckpointError) as ctx:
            ingest.load_position()
        self.assertIn("could not read Suricata checkpoint", str(ctx.exception))

    def test_invalid_checkpoint_schema_fails_closed(self):
        self.position_path.write_text(json.dumps({"offset": 0}))
        with self.assertRaises(ingest.EveCheckpointError) as ctx:
            ingest.load_position()
        self.assertIn("invalid schema", str(ctx.exception))

    def test_negative_offset_fails_closed(self):
        self.position_path.write_text(
            json.dumps({"offset": -1, "inode": None, "size": 0})
        )
        with self.assertRaises(ingest.EveCheckpointError):
            ingest.load_position()

    def test_bool_offset_fails_closed(self):
        # bool is a subclass of int; must not be accepted as a cursor.
        self.position_path.write_text(
            json.dumps({"offset": True, "inode": None, "size": 0})
        )
        with self.assertRaises(ingest.EveCheckpointError):
            ingest.load_position()


if __name__ == "__main__":
    unittest.main(verbosity=2)
