"""Rotation-safe Zeek conn.log follower tests."""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from zeek_follower import (
    ZeekFollower,
    ZeekFollowerError,
)
from zeek_index import ensure_zeek_index, load_checkpoint


SOURCE_INSTANCE = "zeek-local"
BASE_EPOCH = 1_777_222_400.0


def conn_record(uid, *, timestamp=BASE_EPOCH):
    return {
        "ts": timestamp,
        "uid": uid,
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 51000,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 2.0,
    }


def json_line(uid, *, timestamp=BASE_EPOCH):
    return (
        json.dumps(
            conn_record(uid, timestamp=timestamp),
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class ZeekFollowerTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.live_path = self.directory / "conn.log"
        self.conn = sqlite3.connect(":memory:")
        ensure_zeek_index(self.conn)
        self.addCleanup(self.conn.close)

    def follower(self, **kwargs):
        follower = ZeekFollower(
            self.live_path,
            SOURCE_INSTANCE,
            eof_stable_observations=2,
            **kwargs,
        )
        self.addCleanup(follower.close)
        return follower

    def stored_uids(self):
        return [
            row[0]
            for row in self.conn.execute(
                "SELECT uid FROM zeek_connections ORDER BY ts, uid"
            )
        ]


class CompleteRecordTests(ZeekFollowerTestCase):
    def test_default_zeek_tsv_fails_before_checkpointing(self):
        self.live_path.write_bytes(
            b"#separator \\x09\n#fields\tts\tuid\n"
        )

        with self.assertRaises(ZeekFollowerError) as context:
            self.follower().poll(self.conn)

        self.assertIn("enable JSON logs", str(context.exception))
        self.assertIsNone(load_checkpoint(self.conn, SOURCE_INSTANCE))

    def test_complete_records_checkpoint_but_partial_tail_waits(self):
        first = json_line("C1")
        partial = json_line("C2")[:-1]
        self.live_path.write_bytes(first + partial)
        follower = self.follower()

        result = follower.poll(self.conn)

        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.indexed, 1)
        self.assertEqual(self.stored_uids(), ["C1"])
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual(checkpoint.offset, len(first))

        with self.live_path.open("ab") as handle:
            handle.write(b"\n")
        result = follower.poll(self.conn)

        self.assertEqual(result.scanned, 1)
        self.assertEqual(self.stored_uids(), ["C1", "C2"])
        self.assertEqual(
            load_checkpoint(self.conn, SOURCE_INSTANCE).offset,
            len(first) + len(partial) + 1,
        )

    def test_restart_resumes_at_the_durable_byte_checkpoint(self):
        first = json_line("C1")
        self.live_path.write_bytes(first)
        self.follower().poll(self.conn)
        with self.live_path.open("ab") as handle:
            handle.write(json_line("C2", timestamp=BASE_EPOCH + 1))

        result = self.follower().poll(self.conn)

        self.assertEqual(result.scanned, 1)
        self.assertEqual(self.stored_uids(), ["C1", "C2"])

    def test_per_poll_record_limit_is_a_hard_bound(self):
        self.live_path.write_bytes(
            b"".join(
                json_line(f"C{number}", timestamp=BASE_EPOCH + number)
                for number in range(1, 5)
            )
        )
        follower = self.follower(max_records_per_poll=2)

        first = follower.poll(self.conn)
        second = follower.poll(self.conn)

        self.assertEqual((first.scanned, second.scanned), (2, 2))
        self.assertEqual(self.stored_uids(), ["C1", "C2", "C3", "C4"])

    def test_oversized_record_is_bounded_failure_then_following_line_indexes(self):
        oversized = b"{" + (b"x" * (64 * 1024)) + b"}\n"
        self.live_path.write_bytes(oversized + json_line("C1"))
        follower = self.follower()

        result = follower.poll(self.conn)

        self.assertEqual(result.scanned, 2)
        self.assertEqual(result.failures, 1)
        self.assertEqual(result.indexed, 1)
        self.assertEqual(self.stored_uids(), ["C1"])
        error, digest = self.conn.execute(
            "SELECT error_code, record_sha256 FROM zeek_ingest_failures"
        ).fetchone()
        self.assertEqual(error, "record_too_large")
        self.assertEqual(len(digest), len("sha256:") + 64)


class RotationTests(ZeekFollowerTestCase):
    def test_rename_rotation_drains_old_inode_before_verified_successor(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)

        archive = self.directory / "conn.log.1"
        try:
            self.live_path.rename(archive)
        except OSError as exc:
            self.skipTest(f"platform cannot rename an open log: {exc}")
        with archive.open("ab") as handle:
            handle.write(json_line("C2", timestamp=BASE_EPOCH + 1))
        self.live_path.write_bytes(json_line("C3", timestamp=BASE_EPOCH + 2))

        first_eof = follower.poll(self.conn)
        stable_eof = follower.poll(self.conn)

        self.assertEqual(first_eof.indexed, 1)
        self.assertEqual(stable_eof.indexed, 1)
        self.assertTrue(stable_eof.rotated)
        self.assertEqual(self.stored_uids(), ["C1", "C2", "C3"])
        live_stat = self.live_path.stat()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual((checkpoint.device, checkpoint.inode), (
            live_stat.st_dev,
            live_stat.st_ino,
        ))

    def test_restart_can_complete_handoff_from_a_drained_archive(self):
        self.live_path.write_bytes(json_line("C1"))
        initial = self.follower()
        initial.poll(self.conn)
        initial.close()
        archive = self.directory / "conn.log.1"
        self.live_path.rename(archive)
        self.live_path.write_bytes(b"")

        restarted = self.follower()
        restarted.poll(self.conn)
        handoff = restarted.poll(self.conn)

        self.assertTrue(handoff.rotated)
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE).offset, 0)
        with self.live_path.open("ab") as handle:
            handle.write(json_line("C2", timestamp=BASE_EPOCH + 1))
        restarted.poll(self.conn)
        self.assertEqual(self.stored_uids(), ["C1", "C2"])

    def test_missing_checkpointed_inode_fails_closed(self):
        self.live_path.write_bytes(json_line("C1"))
        initial = self.follower()
        initial.poll(self.conn)
        initial.close()
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C2", timestamp=BASE_EPOCH + 1))

        with self.assertRaises(ZeekFollowerError) as context:
            self.follower().poll(self.conn)

        self.assertIn("checkpointed inode", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])

    def test_same_inode_truncation_fails_closed(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)
        original_inode = self.live_path.stat().st_ino
        with self.live_path.open("wb") as handle:
            handle.write(b"")
        if self.live_path.stat().st_ino != original_inode:
            self.skipTest("platform replaced inode during in-place truncation")

        with self.assertRaises(ZeekFollowerError) as context:
            follower.poll(self.conn)

        self.assertIn("shrank", str(context.exception))

    def test_rewrite_below_observed_size_fails_even_if_offset_still_exists(self):
        lines = b"".join(json_line(f"C{number}") for number in range(1, 4))
        self.live_path.write_bytes(lines)
        follower = self.follower(max_records_per_poll=1)
        follower.poll(self.conn)
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        replacement_size = checkpoint.offset + 1
        self.assertLess(replacement_size, checkpoint.file_size)
        original_inode = self.live_path.stat().st_ino
        with self.live_path.open("wb") as handle:
            handle.write(b"x" * replacement_size)
        if self.live_path.stat().st_ino != original_inode:
            self.skipTest("platform replaced inode during in-place rewrite")

        with self.assertRaises(ZeekFollowerError) as context:
            follower.poll(self.conn)

        self.assertIn("shrank", str(context.exception))

    def test_compressed_direct_successor_fails_closed(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)
        follower.close()
        archive = self.directory / "conn.log.1.gz"
        self.live_path.rename(archive)
        self.live_path.write_bytes(json_line("C2", timestamp=BASE_EPOCH + 1))

        with self.assertRaises(ZeekFollowerError) as context:
            follower.poll(self.conn)

        self.assertIn("compressed", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])

    def test_numbered_rotation_gap_fails_closed(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)
        follower.close()
        archive = self.directory / "conn.log.2"
        self.live_path.rename(archive)
        self.live_path.write_bytes(json_line("C3", timestamp=BASE_EPOCH + 2))

        follower.poll(self.conn)
        with self.assertRaises(ZeekFollowerError) as context:
            follower.poll(self.conn)

        self.assertIn("rotation chain has a gap", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])

    def test_retained_descriptor_survives_zeek_style_archive_move(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)
        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        archive = archive_directory / "conn.11-00-00.log"
        try:
            self.live_path.rename(archive)
        except OSError as exc:
            self.skipTest(f"platform cannot rename an open log: {exc}")
        self.live_path.write_bytes(json_line("C2", timestamp=BASE_EPOCH + 1))

        follower.poll(self.conn)
        handoff = follower.poll(self.conn)

        self.assertTrue(handoff.rotated)
        self.assertEqual(self.stored_uids(), ["C1", "C2"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_live_symlink_is_rejected(self):
        target = self.directory / "real.log"
        target.write_bytes(json_line("C1"))
        try:
            os.symlink(target, self.live_path)
        except OSError as exc:
            self.skipTest(f"cannot create symlink: {exc}")

        with self.assertRaises(ZeekFollowerError) as context:
            self.follower().poll(self.conn)

        self.assertIn("symlink", str(context.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
