"""Rotation-safe Zeek conn.log follower tests."""

import gzip
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import zeek_follower as zeek_follower_module
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

    def test_restart_rejects_reused_identity_when_record_anchor_changed(self):
        original = json_line("C1") + json_line(
            "C2", timestamp=BASE_EPOCH + 1
        )
        self.live_path.write_bytes(original)
        initial = self.follower(max_records_per_poll=1)
        initial.poll(self.conn)
        initial.close()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)

        replacement = json_line("R1") + json_line(
            "R2", timestamp=BASE_EPOCH + 1
        )
        self.assertEqual(len(replacement), len(original))
        self.live_path.unlink()
        self.live_path.write_bytes(replacement)
        physical = self.live_path.stat()
        reused_identity = zeek_follower_module._Source(
            path=self.live_path,
            device=checkpoint.device,
            inode=checkpoint.inode,
            size=len(replacement),
            compressed=False,
            physical_device=int(physical.st_dev),
            physical_inode=int(physical.st_ino),
        )
        real_safe_source = zeek_follower_module._safe_source

        def report_reused_identity(path):
            if Path(path) == self.live_path:
                return reused_identity
            return real_safe_source(path)

        with mock.patch.object(
            zeek_follower_module,
            "_safe_source",
            side_effect=report_reused_identity,
        ):
            with self.assertRaises(ZeekFollowerError) as context:
                self.follower().poll(self.conn)

        self.assertIn("record anchor", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

    def test_restart_rejects_unanchored_zero_offset_reused_identity(self):
        self.live_path.write_bytes(json_line("C1"))
        initial = self.follower()
        initial.poll(self.conn)
        initial.close()

        self.live_path.unlink()
        successor = json_line("B1", timestamp=BASE_EPOCH + 1)
        self.live_path.write_bytes(successor)
        successor_stat = self.live_path.stat()
        self.conn.execute(
            """UPDATE zeek_log_checkpoints
               SET device = ?, inode = ?, offset = 0, file_size = ?,
                   record_bytes = NULL, record_sha256 = NULL
               WHERE source_instance = ? AND log_name = 'conn'""",
            (
                int(successor_stat.st_dev),
                int(successor_stat.st_ino),
                len(successor),
                SOURCE_INSTANCE,
            ),
        )
        self.conn.commit()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)

        self.live_path.unlink()
        replacement = json_line("R1", timestamp=BASE_EPOCH + 1)
        self.assertEqual(len(replacement), len(successor))
        self.live_path.write_bytes(replacement)
        physical = self.live_path.stat()
        reused_identity = zeek_follower_module._Source(
            path=self.live_path,
            device=checkpoint.device,
            inode=checkpoint.inode,
            size=len(replacement),
            compressed=False,
            physical_device=int(physical.st_dev),
            physical_inode=int(physical.st_ino),
            modified_at=float(physical.st_mtime),
        )
        real_safe_source = zeek_follower_module._safe_source

        def report_reused_identity(path):
            if Path(path) == self.live_path:
                return reused_identity
            return real_safe_source(path)

        with mock.patch.object(
            zeek_follower_module,
            "_safe_source",
            side_effect=report_reused_identity,
        ):
            with self.assertRaises(ZeekFollowerError) as context:
                self.follower().poll(self.conn)

        self.assertIn("zero-offset", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

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
    def test_rotation_prefix_rejects_reused_zero_offset_successor(self):
        self.live_path.write_bytes(json_line("C1"))
        follower = self.follower()
        follower.poll(self.conn)
        follower.close()
        archive = self.directory / "conn.log.1"
        self.live_path.rename(archive)
        successor = json_line("B1", timestamp=BASE_EPOCH + 1)
        self.live_path.write_bytes(successor)
        successor_stat = self.live_path.stat()
        stale_successor = zeek_follower_module._Source(
            path=self.live_path,
            device=int(successor_stat.st_dev),
            inode=int(successor_stat.st_ino),
            size=1,
            compressed=False,
            physical_device=int(successor_stat.st_dev),
            physical_inode=int(successor_stat.st_ino),
            modified_at=float(successor_stat.st_mtime),
        )
        real_safe_source = zeek_follower_module._safe_source

        def report_stale_successor(path):
            if Path(path) == self.live_path:
                return stale_successor
            return real_safe_source(path)

        follower = self.follower()
        real_rotate_checkpoint = zeek_follower_module.rotate_checkpoint

        def crash_after_rotation(*args, **kwargs):
            real_rotate_checkpoint(*args, **kwargs)
            raise ZeekFollowerError("simulated crash after rotation commit")

        with mock.patch.object(
            zeek_follower_module,
            "_safe_source",
            side_effect=report_stale_successor,
        ):
            follower.poll(self.conn)
            with mock.patch.object(
                zeek_follower_module,
                "rotate_checkpoint",
                side_effect=crash_after_rotation,
            ):
                with self.assertRaisesRegex(ZeekFollowerError, "simulated crash"):
                    follower.poll(self.conn)
        follower.close()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual(checkpoint.offset, 0)
        self.assertGreater(checkpoint.prefix_bytes, 1)
        self.assertEqual(checkpoint.file_size, len(successor))
        self.assertIsNotNone(checkpoint.prefix_sha256)

        self.live_path.unlink()
        replacement = json_line("R1", timestamp=BASE_EPOCH + 1)
        self.assertEqual(len(replacement), len(successor))
        self.live_path.write_bytes(replacement)
        physical = self.live_path.stat()
        reused_identity = zeek_follower_module._Source(
            path=self.live_path,
            device=checkpoint.device,
            inode=checkpoint.inode,
            size=len(replacement),
            compressed=False,
            physical_device=int(physical.st_dev),
            physical_inode=int(physical.st_ino),
            modified_at=float(physical.st_mtime),
        )
        def report_reused_identity(path):
            if Path(path) == self.live_path:
                return reused_identity
            return real_safe_source(path)

        with mock.patch.object(
            zeek_follower_module,
            "_safe_source",
            side_effect=report_reused_identity,
        ):
            with self.assertRaises(ZeekFollowerError):
                self.follower().poll(self.conn)

        self.assertEqual(self.stored_uids(), ["C1"])
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

    def test_zero_offset_prefix_accepts_large_uncompressed_successor(self):
        self.live_path.write_bytes(json_line("C1"))
        initial = self.follower()
        initial.poll(self.conn)
        initial.close()
        archive = self.directory / "conn.log.1"
        self.live_path.rename(archive)
        successor = json_line("B1", timestamp=BASE_EPOCH + 1)
        with self.live_path.open("wb") as handle:
            handle.write(successor)
            handle.truncate(zeek_follower_module.MAX_ARCHIVE_VERIFY_BYTES + 1)

        restarted = self.follower(max_records_per_poll=1)
        real_rotate_checkpoint = zeek_follower_module.rotate_checkpoint

        def crash_after_rotation(*args, **kwargs):
            real_rotate_checkpoint(*args, **kwargs)
            raise ZeekFollowerError("simulated crash after rotation commit")

        restarted.poll(self.conn)
        with mock.patch.object(
            zeek_follower_module,
            "rotate_checkpoint",
            side_effect=crash_after_rotation,
        ):
            with self.assertRaisesRegex(ZeekFollowerError, "simulated crash"):
                restarted.poll(self.conn)
        restarted.close()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual(checkpoint.offset, 0)
        self.assertEqual(
            checkpoint.file_size,
            zeek_follower_module.MAX_ARCHIVE_VERIFY_BYTES + 1,
        )

        resumed = self.follower(max_records_per_poll=1).poll(self.conn)

        self.assertEqual(resumed.indexed, 1)
        self.assertEqual(self.stored_uids(), ["C1", "B1"])

    def test_restart_recovers_mid_file_checkpoint_from_dated_gzip_archive(self):
        current = self.directory / "current"
        current.mkdir()
        self.live_path = current / "conn.log"
        first = json_line("C1")
        second = json_line("C2", timestamp=BASE_EPOCH + 1)
        self.live_path.write_bytes(first + second)
        initial = self.follower(
            archive_root=self.directory,
            max_records_per_poll=1,
        )
        initial.poll(self.conn)
        initial.close()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)

        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        archive = archive_directory / "conn.16-00-00_17-00-00.log.gz"
        with gzip.open(archive, "wb") as compressed:
            compressed.write(first + second)
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C3", timestamp=BASE_EPOCH + 2))
        adjacent_mtime = datetime(2026, 8, 26, 17, 30).timestamp()
        os.utime(self.live_path, (adjacent_mtime, adjacent_mtime))
        physical = self.live_path.stat()
        reused_identity = zeek_follower_module._Source(
            path=self.live_path,
            device=checkpoint.device,
            inode=checkpoint.inode,
            size=int(physical.st_size),
            compressed=False,
            physical_device=int(physical.st_dev),
            physical_inode=int(physical.st_ino),
            modified_at=float(physical.st_mtime),
        )
        real_safe_source = zeek_follower_module._safe_source

        def report_reused_identity(path):
            if Path(path) == self.live_path:
                return reused_identity
            return real_safe_source(path)

        restarted = self.follower(
            archive_root=self.directory,
            max_records_per_poll=10,
        )
        with mock.patch.object(
            zeek_follower_module,
            "_safe_source",
            side_effect=report_reused_identity,
        ):
            first_poll = restarted.poll(self.conn)
            second_poll = restarted.poll(self.conn)

        self.assertEqual(first_poll.indexed, 1)
        self.assertTrue(second_poll.rotated)
        self.assertEqual(self.stored_uids(), ["C1", "C2", "C3"])

    def test_restart_traverses_consecutive_dated_gzip_archives(self):
        current = self.directory / "current"
        current.mkdir()
        self.live_path = current / "conn.log"
        first = json_line("C1")
        second = json_line("C2", timestamp=BASE_EPOCH + 1)
        self.live_path.write_bytes(first + second)
        initial = self.follower(
            archive_root=self.directory,
            max_records_per_poll=1,
        )
        initial.poll(self.conn)
        initial.close()

        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        with gzip.open(
            archive_directory / "conn.16-00-00_17-00-00.log.gz",
            "wb",
        ) as compressed:
            compressed.write(first + second)
        with gzip.open(
            archive_directory / "conn.17-00-00_18-00-00.log.gz",
            "wb",
        ) as compressed:
            compressed.write(json_line("C3", timestamp=BASE_EPOCH + 2))
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C4", timestamp=BASE_EPOCH + 3))
        adjacent_mtime = datetime(2026, 8, 26, 18, 30).timestamp()
        os.utime(self.live_path, (adjacent_mtime, adjacent_mtime))

        restarted = self.follower(
            archive_root=self.directory,
            max_records_per_poll=10,
        )
        first_poll = restarted.poll(self.conn)
        second_poll = restarted.poll(self.conn)
        third_poll = restarted.poll(self.conn)

        self.assertEqual(first_poll.indexed, 1)
        self.assertTrue(second_poll.rotated)
        self.assertTrue(third_poll.rotated)
        self.assertEqual(self.stored_uids(), ["C1", "C2", "C3", "C4"])

    def test_archive_recovery_rejects_ambiguous_checkpoint_anchor(self):
        current = self.directory / "current"
        current.mkdir()
        self.live_path = current / "conn.log"
        raw = json_line("C1")
        self.live_path.write_bytes(raw)
        initial = self.follower(archive_root=self.directory)
        initial.poll(self.conn)
        initial.close()

        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        for start, end in (("15", "16"), ("16", "17")):
            with gzip.open(
                archive_directory / f"conn.{start}-00-00_{end}-00-00.log.gz",
                "wb",
            ) as compressed:
                compressed.write(raw)
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C2", timestamp=BASE_EPOCH + 1))

        with self.assertRaises(ZeekFollowerError) as context:
            self.follower(archive_root=self.directory).poll(self.conn)

        self.assertIn("ambiguous", str(context.exception))
        self.assertEqual(self.stored_uids(), ["C1"])

    def test_dated_archive_chain_gap_stops_before_later_archive(self):
        current = self.directory / "current"
        current.mkdir()
        self.live_path = current / "conn.log"
        first = json_line("C1")
        self.live_path.write_bytes(first)
        initial = self.follower(archive_root=self.directory)
        initial.poll(self.conn)
        initial.close()

        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        with gzip.open(
            archive_directory / "conn.16-00-00_17-00-00.log.gz",
            "wb",
        ) as compressed:
            compressed.write(first)
        with gzip.open(
            archive_directory / "conn.18-00-00_19-00-00.log.gz",
            "wb",
        ) as compressed:
            compressed.write(json_line("C3", timestamp=BASE_EPOCH + 2))
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C4", timestamp=BASE_EPOCH + 3))
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        restarted = self.follower(archive_root=self.directory)

        restarted.poll(self.conn)
        with self.assertRaises(ZeekFollowerError) as context:
            restarted.poll(self.conn)

        self.assertIn("dated archive chain has a gap", str(context.exception))
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)
        self.assertEqual(self.stored_uids(), ["C1"])

    def test_dated_archive_to_live_requires_adjacent_interval_evidence(self):
        current = self.directory / "current"
        current.mkdir()
        self.live_path = current / "conn.log"
        first = json_line("C1")
        self.live_path.write_bytes(first)
        initial = self.follower(archive_root=self.directory)
        initial.poll(self.conn)
        initial.close()
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)

        archive_directory = self.directory / "2026-08-26"
        archive_directory.mkdir()
        with gzip.open(
            archive_directory / "conn.16-00-00_17-00-00.log.gz",
            "wb",
        ) as compressed:
            compressed.write(first)
        self.live_path.unlink()
        self.live_path.write_bytes(json_line("C3", timestamp=BASE_EPOCH + 2))
        missing_interval_mtime = datetime(2026, 8, 26, 18, 30).timestamp()
        os.utime(
            self.live_path,
            (missing_interval_mtime, missing_interval_mtime),
        )
        restarted = self.follower(archive_root=self.directory)

        restarted.poll(self.conn)
        with self.assertRaises(ZeekFollowerError) as context:
            restarted.poll(self.conn)

        self.assertIn("dated archive-to-live handoff", str(context.exception))
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)
        self.assertEqual(self.stored_uids(), ["C1"])

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

        self.assertFalse(handoff.rotated)
        self.assertNotEqual(load_checkpoint(self.conn, SOURCE_INSTANCE).offset, 0)
        with self.live_path.open("ab") as handle:
            handle.write(json_line("C2", timestamp=BASE_EPOCH + 1))
        resumed = restarted.poll(self.conn)
        self.assertTrue(resumed.rotated)
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
