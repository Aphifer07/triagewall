"""Bounded, fail-closed follower for a local Zeek ``conn.log`` file."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

try:
    from .zeek_index import (
        MAX_CONN_RECORD_BYTES,
        ZeekLogCheckpoint,
        index_conn_failure,
        index_conn_line,
        load_checkpoint,
        rotate_checkpoint,
    )
except ImportError:  # Direct script-style imports used by container entrypoints.
    from zeek_index import (
        MAX_CONN_RECORD_BYTES,
        ZeekLogCheckpoint,
        index_conn_failure,
        index_conn_line,
        load_checkpoint,
        rotate_checkpoint,
    )


MAX_ROTATION_SCAN_ENTRIES = 512
MAX_ROTATION_DIRECTORY_ENTRIES = 100_000
MAX_RECORDS_PER_POLL = 100_000
READ_CHUNK_BYTES = 64 * 1024
COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst")
_NUMBERED_ROTATION_RE = re.compile(r"^\.(\d+)$")


class ZeekFollowerError(RuntimeError):
    """The follower cannot advance without risking a Zeek context gap."""


@dataclass(frozen=True)
class ZeekPollResult:
    scanned: int = 0
    indexed: int = 0
    failures: int = 0
    rotated: bool = False


@dataclass(frozen=True)
class _Source:
    path: Path
    device: int
    inode: int
    size: int
    compressed: bool


@dataclass(frozen=True)
class _RecordRead:
    raw: bytes | None
    complete: bool
    byte_count: int = 0
    digest: str | None = None


def _is_compressed(path: Path) -> bool:
    return path.name.endswith(COMPRESSED_SUFFIXES)


def _rotation_sort_key(name: str, live_name: str):
    if name == live_name:
        return (2, 0, "")
    suffix = name[len(live_name):]
    for compressed in COMPRESSED_SUFFIXES:
        if suffix.endswith(compressed):
            suffix = suffix[: -len(compressed)]
            break
    numbered = _NUMBERED_ROTATION_RE.fullmatch(suffix)
    if numbered is not None:
        return (0, -int(numbered.group(1)), "")
    return (1, 0, suffix)


def _numbered_rotation(name: str, live_name: str) -> int | None:
    suffix = name[len(live_name):]
    for compressed in COMPRESSED_SUFFIXES:
        if suffix.endswith(compressed):
            suffix = suffix[: -len(compressed)]
            break
    match = _NUMBERED_ROTATION_RE.fullmatch(suffix)
    return int(match.group(1)) if match is not None else None


def _safe_source(path: Path) -> _Source:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ZeekFollowerError(f"could not inspect Zeek log {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ZeekFollowerError(f"Zeek log path must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ZeekFollowerError(f"Zeek log path is not a regular file: {path}")
    return _Source(
        path=path,
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        size=int(metadata.st_size),
        compressed=_is_compressed(path),
    )


def _optional_live_source(path: Path) -> _Source | None:
    try:
        return _safe_source(path)
    except ZeekFollowerError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise


def _scan_rotation_chain(live_path: Path) -> list[_Source]:
    chain: list[_Source] = []
    examined = 0
    matched = 0
    try:
        with os.scandir(live_path.parent) as entries:
            for entry in entries:
                examined += 1
                if examined > MAX_ROTATION_DIRECTORY_ENTRIES:
                    raise ZeekFollowerError(
                        "Zeek log directory exceeds its bounded scan limit"
                    )
                if not entry.name.startswith(live_path.name):
                    continue
                matched += 1
                if matched > MAX_ROTATION_SCAN_ENTRIES:
                    raise ZeekFollowerError(
                        "Zeek rotation chain exceeds its bounded scan limit"
                    )
                candidate = Path(entry.path)
                chain.append(_safe_source(candidate))
    except ZeekFollowerError:
        raise
    except OSError as exc:
        raise ZeekFollowerError(
            f"could not enumerate Zeek rotation chain: {exc}"
        ) from exc
    chain.sort(key=lambda item: _rotation_sort_key(item.path.name, live_path.name))
    identities = [(item.device, item.inode) for item in chain]
    if len(identities) != len(set(identities)):
        raise ZeekFollowerError("Zeek rotation chain contains duplicate file identities")
    return chain


def _read_record(stream) -> _RecordRead:
    first = stream.readline(MAX_CONN_RECORD_BYTES + 1)
    if not first:
        return _RecordRead(raw=None, complete=True)
    if len(first) <= MAX_CONN_RECORD_BYTES:
        return _RecordRead(
            raw=first,
            complete=first.endswith((b"\n", b"\r")),
            byte_count=len(first),
        )

    digest = hashlib.sha256(first)
    total = len(first)
    complete = first.endswith((b"\n", b"\r"))
    while not complete:
        chunk = stream.readline(READ_CHUNK_BYTES)
        if not chunk:
            return _RecordRead(raw=None, complete=False)
        digest.update(chunk)
        total += len(chunk)
        complete = chunk.endswith((b"\n", b"\r"))
    return _RecordRead(
        raw=None,
        complete=True,
        byte_count=total,
        digest="sha256:" + digest.hexdigest(),
    )


class ZeekFollower:
    """Read complete conn.log lines and preserve an exact SQLite cursor."""

    def __init__(
        self,
        live_path: str | Path,
        source_instance: str,
        *,
        max_records_per_poll: int = 1_000,
        eof_stable_observations: int = 2,
    ) -> None:
        if (
            type(max_records_per_poll) is not int
            or not 1 <= max_records_per_poll <= MAX_RECORDS_PER_POLL
        ):
            raise ValueError(
                f"max_records_per_poll must be from 1 to {MAX_RECORDS_PER_POLL}"
            )
        if type(eof_stable_observations) is not int or eof_stable_observations < 2:
            raise ValueError("eof_stable_observations must be at least 2")
        self.live_path = Path(live_path)
        self.source_instance = source_instance
        self.max_records_per_poll = max_records_per_poll
        self.eof_stable_observations = eof_stable_observations
        self._eof_key: tuple[int, int, int, int] | None = None
        self._eof_count = 0
        self._stream = None
        self._stream_source: _Source | None = None
        self._opened_as_live = False
        self._observed_successor: tuple[int, int] | None = None

    def close(self) -> None:
        """Release the retained descriptor used to drain renamed logs."""

        if self._stream is not None:
            self._stream.close()
        self._stream = None
        self._stream_source = None
        self._opened_as_live = False
        self._observed_successor = None
        self._reset_eof()

    def _open_source(
        self,
        source: _Source,
        *,
        opened_as_live: bool,
    ) -> None:
        self.close()
        try:
            stream = source.path.open("rb")
            opened = os.fstat(stream.fileno())
        except OSError as exc:
            raise ZeekFollowerError(
                f"could not open Zeek log {source.path}: {exc}"
            ) from exc
        if (
            int(opened.st_dev) != source.device
            or int(opened.st_ino) != source.inode
        ):
            stream.close()
            raise ZeekFollowerError(
                "Zeek log identity changed between inspection and open"
            )
        self._stream = stream
        self._stream_source = source
        self._opened_as_live = opened_as_live

    def _active_source(
        self,
        checkpoint: ZeekLogCheckpoint | None,
    ) -> _Source:
        if self._stream is not None and self._stream_source is not None:
            opened = os.fstat(self._stream.fileno())
            identity = (int(opened.st_dev), int(opened.st_ino))
            expected = (
                None
                if checkpoint is None
                else (checkpoint.device, checkpoint.inode)
            )
            if expected is None or identity == expected:
                return _Source(
                    path=self._stream_source.path,
                    device=identity[0],
                    inode=identity[1],
                    size=int(opened.st_size),
                    compressed=self._stream_source.compressed,
                )
            self.close()

        source, _chain = self._resolve_source(checkpoint)
        live = _safe_source(self.live_path)
        opened_as_live = (
            source.device == live.device and source.inode == live.inode
        )
        self._open_source(source, opened_as_live=opened_as_live)
        return source

    def _resolve_source(
        self,
        checkpoint: ZeekLogCheckpoint | None,
    ) -> tuple[_Source, list[_Source]]:
        live = _safe_source(self.live_path)
        if checkpoint is None or (
            checkpoint.device == live.device and checkpoint.inode == live.inode
        ):
            return live, [live]

        chain = _scan_rotation_chain(self.live_path)
        matches = [
            item
            for item in chain
            if item.device == checkpoint.device and item.inode == checkpoint.inode
        ]
        if len(matches) != 1:
            raise ZeekFollowerError(
                "the checkpointed inode is missing from the Zeek rotation chain; "
                "the follower will not skip to the live file"
            )
        return matches[0], chain

    def _observe_stable_eof(
        self,
        source: _Source,
        offset: int,
        size: int,
    ) -> bool:
        key = (source.device, source.inode, offset, size)
        if key == self._eof_key:
            self._eof_count += 1
        else:
            self._eof_key = key
            self._eof_count = 1
        return self._eof_count >= self.eof_stable_observations

    def _reset_eof(self) -> None:
        self._eof_key = None
        self._eof_count = 0

    def _successor(
        self,
        source: _Source,
        chain: list[_Source],
    ) -> _Source | None:
        for index, candidate in enumerate(chain):
            if (
                candidate.device == source.device
                and candidate.inode == source.inode
            ):
                if index + 1 < len(chain):
                    successor = chain[index + 1]
                    current_number = _numbered_rotation(
                        source.path.name,
                        self.live_path.name,
                    )
                    if current_number is not None:
                        successor_number = _numbered_rotation(
                            successor.path.name,
                            self.live_path.name,
                        )
                        expected_number = current_number - 1
                        valid_numbered = successor_number == expected_number
                        valid_live = (
                            expected_number == 0
                            and successor.path.name == self.live_path.name
                        )
                        if not valid_numbered and not valid_live:
                            raise ZeekFollowerError(
                                "the numbered Zeek rotation chain has a gap; "
                                "the follower will not skip an archive"
                            )
                    return successor
                return None
        return None

    def poll(self, conn: sqlite3.Connection) -> ZeekPollResult:
        """Process one bounded batch currently available on disk."""

        scanned = 0
        indexed = 0
        failures = 0
        rotated = False

        while scanned < self.max_records_per_poll:
            checkpoint = load_checkpoint(conn, self.source_instance)
            source = self._active_source(checkpoint)
            if source.compressed:
                raise ZeekFollowerError(
                    f"checkpointed Zeek log is compressed and cannot be read: {source.path}"
                )
            offset = 0 if checkpoint is None else checkpoint.offset
            if source.size < offset or (
                checkpoint is not None
                and source.size < checkpoint.file_size
            ):
                raise ZeekFollowerError(
                    f"Zeek log {source.path} shrank behind its durable checkpoint"
                )

            stream = self._stream
            if stream is None:
                raise ZeekFollowerError("Zeek log descriptor is unexpectedly closed")
            try:
                stream.seek(offset)
                if stream.tell() != offset:
                    raise ZeekFollowerError(
                        "Zeek log ends before its durable checkpoint"
                    )

                while scanned < self.max_records_per_poll:
                    record = _read_record(stream)
                    if not record.complete:
                        self._reset_eof()
                        return ZeekPollResult(scanned, indexed, failures, rotated)
                    if record.raw is None and record.digest is None:
                        break
                    if (
                        record.raw is not None
                        and checkpoint is None
                        and record.raw.lstrip().startswith(b"#separator")
                    ):
                        raise ZeekFollowerError(
                            "Zeek conn.log is TSV; enable JSON logs with "
                            "@load policy/tuning/json-logs"
                        )

                    observed = os.fstat(stream.fileno())
                    next_checkpoint = ZeekLogCheckpoint(
                        source_instance=self.source_instance,
                        log_name="conn",
                        device=source.device,
                        inode=source.inode,
                        offset=stream.tell(),
                        file_size=max(int(observed.st_size), stream.tell()),
                    )
                    if record.digest is not None:
                        outcome = index_conn_failure(
                            conn,
                            next_checkpoint,
                            expected_checkpoint=checkpoint,
                            record_bytes=record.byte_count,
                            record_sha256=record.digest,
                            error_code="record_too_large",
                            error=(
                                "Zeek conn.log record exceeded "
                                f"{MAX_CONN_RECORD_BYTES} bytes"
                            ),
                        )
                    else:
                        outcome = index_conn_line(
                            conn,
                            record.raw,
                            next_checkpoint,
                            expected_checkpoint=checkpoint,
                        )
                    checkpoint = next_checkpoint
                    scanned += 1
                    indexed += int(outcome.indexed)
                    failures += int(outcome.failure_code is not None)
                    self._reset_eof()

                if scanned >= self.max_records_per_poll:
                    return ZeekPollResult(scanned, indexed, failures, rotated)

                final_stat = os.fstat(stream.fileno())
                final_size = int(final_stat.st_size)
                final_offset = stream.tell()
            except ZeekFollowerError:
                raise
            except OSError as exc:
                raise ZeekFollowerError(
                    f"could not read Zeek log {source.path}: {exc}"
                ) from exc

            live = _optional_live_source(self.live_path)
            if live is None:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if source.device == live.device and source.inode == live.inode:
                self._reset_eof()
                self._observed_successor = None
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if self._opened_as_live:
                live_identity = (live.device, live.inode)
                if self._observed_successor is None:
                    self._observed_successor = live_identity
                elif self._observed_successor != live_identity:
                    raise ZeekFollowerError(
                        "Zeek live log rotated again before the prior handoff completed"
                    )
            if final_offset != final_size:
                self._reset_eof()
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if not self._observe_stable_eof(source, final_offset, final_size):
                return ZeekPollResult(scanned, indexed, failures, rotated)

            if checkpoint is None:
                if final_size != 0:
                    raise ZeekFollowerError(
                        "cannot rotate an uncheckpointed non-empty Zeek source"
                    )
                self.close()
                rotated = True
                continue
            if self._opened_as_live:
                successor = live
            else:
                chain = _scan_rotation_chain(self.live_path)
                successor = self._successor(source, chain)
            if successor is None:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if successor.compressed:
                raise ZeekFollowerError(
                    f"the next Zeek rotation is compressed: {successor.path}"
                )
            next_checkpoint = ZeekLogCheckpoint(
                source_instance=self.source_instance,
                log_name="conn",
                device=successor.device,
                inode=successor.inode,
                offset=0,
                file_size=successor.size,
            )
            rotate_checkpoint(
                conn,
                next_checkpoint,
                expected_checkpoint=checkpoint,
            )
            rotated = True
            self.close()

        return ZeekPollResult(scanned, indexed, failures, rotated)
