"""Read-only provider boundary tests for the local Zeek context index."""

import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from zeek_context import ZeekLookupRequest, ZeekLookupStatus
from zeek_index import (
    ZeekLogCheckpoint,
    connect_zeek_index,
    index_conn_line,
)
from zeek_provider import SQLiteZeekContextProvider


BASE_EPOCH = 1_777_222_400.0
SOURCE_INSTANCE = "zeek-local"


def request():
    return ZeekLookupRequest(
        alert_timestamp="2026-04-26T16:53:21Z",
        src_ip="192.0.2.10",
        src_port=51000,
        dest_ip="198.51.100.20",
        dest_port=443,
        proto="TCP",
    )


def conn_line():
    record = {
        "ts": BASE_EPOCH,
        "uid": "C1",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 51000,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 5.0,
    }
    return json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n"


class SQLiteZeekContextProviderTests(unittest.TestCase):
    def test_provider_reads_exact_match_from_standalone_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "zeek-context.db"
            raw = conn_line()
            conn = connect_zeek_index(path)
            try:
                index_conn_line(
                    conn,
                    raw,
                    ZeekLogCheckpoint(
                        source_instance=SOURCE_INSTANCE,
                        log_name="conn",
                        device=7,
                        inode=11,
                        offset=len(raw),
                        file_size=len(raw),
                    ),
                    expected_checkpoint=None,
                )
            finally:
                conn.close()

            result = SQLiteZeekContextProvider(
                path,
                SOURCE_INSTANCE,
            ).lookup(request())

            self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
            self.assertEqual(result.record_count, 1)
            self.assertIn('"uid":"C1"', result.context_json)

    def test_missing_index_is_unavailable_and_is_not_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.db"

            result = SQLiteZeekContextProvider(
                path,
                SOURCE_INSTANCE,
            ).lookup(request())

            self.assertEqual(result.status, ZeekLookupStatus.UNAVAILABLE)
            self.assertFalse(path.exists())

    def test_wrong_schema_is_unavailable_instead_of_blocking_core(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "wrong.db"
            path.write_bytes(b"not sqlite")

            result = SQLiteZeekContextProvider(
                path,
                SOURCE_INSTANCE,
            ).lookup(request())

            self.assertEqual(result.status, ZeekLookupStatus.UNAVAILABLE)

    def test_provider_rejects_unbounded_busy_timeout(self):
        with self.assertRaises(ValueError):
            SQLiteZeekContextProvider(
                "zeek-context.db",
                SOURCE_INSTANCE,
                busy_timeout_ms=10_001,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
