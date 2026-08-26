"""Standalone, bounded SQLite index for Zeek ``conn.log`` context.

The index is deliberately separate from TriageWall's verdict database.  It
accepts complete JSON-Lines records, stores a strict allowlisted projection,
and commits each record (or bounded failure metadata) atomically with a
compare-and-swap byte checkpoint.  A later service can therefore follow log
rotation without letting stale readers skip or replay data silently.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from .database import connect_database
    from .sensor_event import MAX_SQLITE_INTEGER
    from .time_utils import format_utc_timestamp, parse_utc_timestamp
    from .zeek_context import (
        MAX_CANDIDATES,
        ZEEK_CONTEXT_SCHEMA_VERSION,
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )
except ImportError:  # Direct script-style imports used by container entrypoints.
    from database import connect_database
    from sensor_event import MAX_SQLITE_INTEGER
    from time_utils import format_utc_timestamp, parse_utc_timestamp
    from zeek_context import (
        MAX_CANDIDATES,
        ZEEK_CONTEXT_SCHEMA_VERSION,
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )


MAX_CONN_RECORD_BYTES = 64 * 1024
MAX_UID_CHARS = 128
MAX_SOURCE_INSTANCE_CHARS = 128
MAX_LOG_NAME_CHARS = 32
MAX_OPTIONAL_TEXT_CHARS = 128
MAX_FAILURE_ERROR_CHARS = 256
MAX_CONNECTION_DURATION_SECONDS = 7 * 24 * 60 * 60
DEFAULT_PRUNE_BATCH_SIZE = 1_000
MAX_PRUNE_BATCH_SIZE = 10_000
DEFAULT_PRUNE_MAX_ROWS = 10_000
MAX_PRUNE_ROWS = 100_000

UID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
PRINTABLE_TEXT_RE = re.compile(r"^[\x20-\x7e]+$")


SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS zeek_connections (
           source_instance TEXT NOT NULL,
           uid TEXT NOT NULL,
           ts REAL NOT NULL,
           end_ts REAL NOT NULL,
           orig_h TEXT NOT NULL,
           orig_p INTEGER NOT NULL,
           resp_h TEXT NOT NULL,
           resp_p INTEGER NOT NULL,
           proto TEXT NOT NULL CHECK (proto IN ('TCP', 'UDP')),
           service TEXT,
           duration REAL,
           orig_bytes INTEGER,
           resp_bytes INTEGER,
           conn_state TEXT,
           missed_bytes INTEGER,
           orig_pkts INTEGER,
           resp_pkts INTEGER,
           indexed_at REAL NOT NULL,
           PRIMARY KEY (source_instance, uid)
       ) WITHOUT ROWID""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_conn_tuple_time
       ON zeek_connections (
           source_instance, proto,
           orig_h, orig_p, resp_h, resp_p,
           ts, end_ts
       )""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_conn_end
       ON zeek_connections (end_ts, source_instance, uid)""",
    """CREATE TABLE IF NOT EXISTS zeek_log_checkpoints (
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           device INTEGER NOT NULL,
           inode INTEGER NOT NULL,
           offset INTEGER NOT NULL CHECK (offset >= 0),
           file_size INTEGER NOT NULL CHECK (file_size >= offset),
           updated_at REAL NOT NULL,
           PRIMARY KEY (source_instance, log_name)
       ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS zeek_ingest_failures (
           id INTEGER PRIMARY KEY,
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           device INTEGER NOT NULL,
           inode INTEGER NOT NULL,
           record_end_offset INTEGER NOT NULL,
           record_sha256 TEXT NOT NULL,
           error_code TEXT NOT NULL,
           error TEXT NOT NULL,
           recorded_at REAL NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_failures_recorded
       ON zeek_ingest_failures (recorded_at, id)""",
)


class ZeekConnValidationError(ValueError):
    """A complete conn.log record cannot enter the bounded index."""


class ZeekIncompleteRecordError(ValueError):
    """A line lacks its terminator and must remain uncheckpointed."""


class ZeekCheckpointConflict(RuntimeError):
    """The durable log cursor changed since a reader last observed it."""


@dataclass(frozen=True)
class ZeekConnection:
    source_instance: str
    uid: str
    ts: float
    end_ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    conn_state: str | None = None
    missed_bytes: int | None = None
    orig_pkts: int | None = None
    resp_pkts: int | None = None


@dataclass(frozen=True)
class ZeekLogCheckpoint:
    source_instance: str
    log_name: str
    device: int
    inode: int
    offset: int
    file_size: int

    def __post_init__(self) -> None:
        _validate_safe_name(
            self.source_instance,
            "source_instance",
            MAX_SOURCE_INSTANCE_CHARS,
        )
        _validate_safe_name(self.log_name, "log_name", MAX_LOG_NAME_CHARS)
        for label, value in (("device", self.device), ("inode", self.inode)):
            if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
                raise ZeekConnValidationError(
                    f"checkpoint {label} must be a non-negative SQLite integer"
                )
        if type(self.offset) is not int or self.offset < 0:
            raise ZeekConnValidationError(
                "checkpoint offset must be a non-negative integer"
            )
        if type(self.file_size) is not int or self.file_size < self.offset:
            raise ZeekConnValidationError(
                "checkpoint file_size must be an integer at least as large as offset"
            )


@dataclass(frozen=True)
class IndexedLineResult:
    indexed: bool
    duplicate: bool = False
    failure_code: str | None = None


@dataclass(frozen=True)
class ZeekPruneResult:
    connections: int
    failures: int


def _validate_safe_name(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or SAFE_NAME_RE.fullmatch(value.strip()) is None
    ):
        raise ZeekConnValidationError(
            f"{label} must be a safe identifier of at most {maximum} characters"
        )
    return value.strip()


def _required_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ZeekConnValidationError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ZeekConnValidationError(f"{label} must be finite and non-negative")
    return number


def _zeek_timestamp(value: Any) -> float:
    timestamp = _required_number(value, "ts")
    try:
        datetime.fromtimestamp(timestamp, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ZeekConnValidationError("ts is outside the supported time range") from exc
    return timestamp


def _optional_number(
    value: Any,
    label: str,
    *,
    maximum: float | None = None,
) -> float | None:
    if value is None:
        return None
    number = _required_number(value, label)
    if maximum is not None and number > maximum:
        raise ZeekConnValidationError(f"{label} exceeds the supported maximum")
    return number


def _required_port(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise ZeekConnValidationError(
            f"{label} must be an integer from 0 to 65535"
        )
    return value


def _optional_counter(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
        raise ZeekConnValidationError(
            f"{label} must be a non-negative SQLite integer"
        )
    return value


def _required_ip(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ZeekConnValidationError(f"{label} must be an IP address string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ZeekConnValidationError(f"{label} must be a valid IP address") from exc


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_OPTIONAL_TEXT_CHARS
        or PRINTABLE_TEXT_RE.fullmatch(value) is None
    ):
        raise ZeekConnValidationError(
            f"{label} must contain at most {MAX_OPTIONAL_TEXT_CHARS} printable characters"
        )
    return value


def normalize_conn_record(
    record: Mapping[str, Any],
    source_instance: str,
) -> ZeekConnection:
    """Validate and project one decoded Zeek conn.log JSON object."""

    if not isinstance(record, Mapping):
        raise ZeekConnValidationError("conn.log record must be a JSON object")
    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    uid = record.get("uid")
    if not isinstance(uid, str) or UID_RE.fullmatch(uid) is None:
        raise ZeekConnValidationError(
            f"uid must be a safe identifier of at most {MAX_UID_CHARS} characters"
        )
    ts = _zeek_timestamp(record.get("ts"))
    duration = _optional_number(
        record.get("duration"),
        "duration",
        maximum=MAX_CONNECTION_DURATION_SECONDS,
    )
    proto_value = record.get("proto")
    if not isinstance(proto_value, str):
        raise ZeekConnValidationError("proto must be tcp or udp")
    proto = proto_value.strip().upper()
    if proto not in {"TCP", "UDP"}:
        raise ZeekConnValidationError("proto must be tcp or udp")

    end_ts = ts + (duration or 0.0)
    try:
        datetime.fromtimestamp(end_ts, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ZeekConnValidationError(
            "connection end time is outside the supported range"
        ) from exc

    return ZeekConnection(
        source_instance=source_instance,
        uid=uid,
        ts=ts,
        end_ts=end_ts,
        orig_h=_required_ip(record.get("id.orig_h"), "id.orig_h"),
        orig_p=_required_port(record.get("id.orig_p"), "id.orig_p"),
        resp_h=_required_ip(record.get("id.resp_h"), "id.resp_h"),
        resp_p=_required_port(record.get("id.resp_p"), "id.resp_p"),
        proto=proto,
        service=_optional_text(record.get("service"), "service"),
        duration=duration,
        orig_bytes=_optional_counter(record.get("orig_bytes"), "orig_bytes"),
        resp_bytes=_optional_counter(record.get("resp_bytes"), "resp_bytes"),
        conn_state=_optional_text(record.get("conn_state"), "conn_state"),
        missed_bytes=_optional_counter(
            record.get("missed_bytes"),
            "missed_bytes",
        ),
        orig_pkts=_optional_counter(record.get("orig_pkts"), "orig_pkts"),
        resp_pkts=_optional_counter(record.get("resp_pkts"), "resp_pkts"),
    )


def ensure_zeek_index(conn: sqlite3.Connection) -> None:
    """Create the standalone index schema idempotently."""

    try:
        conn.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def connect_zeek_index(path: str | Path) -> sqlite3.Connection:
    """Open and initialize a dedicated Zeek context database."""

    conn = connect_database(path)
    try:
        ensure_zeek_index(conn)
        return conn
    except Exception:
        conn.close()
        raise


def load_checkpoint(
    conn: sqlite3.Connection,
    source_instance: str,
    log_name: str = "conn",
) -> ZeekLogCheckpoint | None:
    """Return one durable index cursor without inventing a missing position."""

    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    log_name = _validate_safe_name(log_name, "log_name", MAX_LOG_NAME_CHARS)
    row = conn.execute(
        """SELECT device, inode, offset, file_size
           FROM zeek_log_checkpoints
           WHERE source_instance = ? AND log_name = ?""",
        (source_instance, log_name),
    ).fetchone()
    if row is None:
        return None
    return ZeekLogCheckpoint(
        source_instance=source_instance,
        log_name=log_name,
        device=int(row[0]),
        inode=int(row[1]),
        offset=int(row[2]),
        file_size=int(row[3]),
    )


def _validate_checkpoint_transition(
    current: ZeekLogCheckpoint | None,
    expected: ZeekLogCheckpoint | None,
    next_checkpoint: ZeekLogCheckpoint,
    record_bytes: int,
) -> None:
    if current != expected:
        raise ZeekCheckpointConflict(
            "Zeek log checkpoint changed while the record was being processed"
        )
    if expected is not None and (
        expected.source_instance != next_checkpoint.source_instance
        or expected.log_name != next_checkpoint.log_name
    ):
        raise ZeekCheckpointConflict(
            "Zeek checkpoint identity cannot change source or log name"
        )
    if expected is None:
        if next_checkpoint.offset != record_bytes:
            raise ZeekCheckpointConflict(
                "the first Zeek checkpoint must equal the complete record length"
            )
        return
    same_file = (
        expected.device == next_checkpoint.device
        and expected.inode == next_checkpoint.inode
    )
    expected_offset = expected.offset + record_bytes if same_file else record_bytes
    if next_checkpoint.offset != expected_offset:
        raise ZeekCheckpointConflict(
            "Zeek checkpoint must advance by exactly one complete record"
        )
    if same_file and next_checkpoint.file_size < expected.file_size:
        raise ZeekCheckpointConflict(
            "Zeek checkpoint file size cannot shrink within the same identity"
        )


def _decode_complete_line(raw_line: bytes | str) -> tuple[bytes, str]:
    if isinstance(raw_line, str):
        raw = raw_line.encode("utf-8")
    elif isinstance(raw_line, bytes):
        raw = raw_line
    else:
        raise TypeError("raw_line must be bytes or text")
    if not raw.endswith((b"\n", b"\r")):
        raise ZeekIncompleteRecordError(
            "Zeek JSON-Lines record is incomplete and cannot be checkpointed"
        )
    if len(raw) > MAX_CONN_RECORD_BYTES:
        raise ZeekConnValidationError(
            f"conn.log record exceeds the {MAX_CONN_RECORD_BYTES}-byte limit"
        )
    try:
        text = raw.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZeekConnValidationError("conn.log record is not valid UTF-8") from exc
    return raw, text


def _parse_complete_conn_line(
    raw_line: bytes | str,
    source_instance: str,
) -> tuple[bytes, ZeekConnection | None]:
    raw, text = _decode_complete_line(raw_line)
    if not text.strip():
        return raw, None

    def reject_duplicate_keys(pairs):
        decoded = {}
        for key, value in pairs:
            if key in decoded:
                raise ZeekConnValidationError(
                    f"conn.log record contains duplicate key {key!r}"
                )
            decoded[key] = value
        return decoded

    try:
        decoded = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ZeekConnValidationError("conn.log record is not valid JSON") from exc
    return raw, normalize_conn_record(decoded, source_instance)


def _insert_connection(
    conn: sqlite3.Connection,
    record: ZeekConnection,
    indexed_at: float,
) -> str:
    cursor = conn.execute(
        """INSERT OR IGNORE INTO zeek_connections (
               source_instance, uid, ts, end_ts,
               orig_h, orig_p, resp_h, resp_p, proto,
               service, duration, orig_bytes, resp_bytes, conn_state,
               missed_bytes, orig_pkts, resp_pkts, indexed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record.source_instance,
            record.uid,
            record.ts,
            record.end_ts,
            record.orig_h,
            record.orig_p,
            record.resp_h,
            record.resp_p,
            record.proto,
            record.service,
            record.duration,
            record.orig_bytes,
            record.resp_bytes,
            record.conn_state,
            record.missed_bytes,
            record.orig_pkts,
            record.resp_pkts,
            indexed_at,
        ),
    )
    if cursor.rowcount == 1:
        return "inserted"
    stored = conn.execute(
        """SELECT ts, end_ts, orig_h, orig_p, resp_h, resp_p, proto,
                  service, duration, orig_bytes, resp_bytes, conn_state,
                  missed_bytes, orig_pkts, resp_pkts
           FROM zeek_connections
           WHERE source_instance = ? AND uid = ?""",
        (record.source_instance, record.uid),
    ).fetchone()
    expected = (
        record.ts,
        record.end_ts,
        record.orig_h,
        record.orig_p,
        record.resp_h,
        record.resp_p,
        record.proto,
        record.service,
        record.duration,
        record.orig_bytes,
        record.resp_bytes,
        record.conn_state,
        record.missed_bytes,
        record.orig_pkts,
        record.resp_pkts,
    )
    return "duplicate" if stored == expected else "uid_conflict"


def _store_failure(
    conn: sqlite3.Connection,
    raw: bytes,
    checkpoint: ZeekLogCheckpoint,
    error_code: str,
    error: str,
    recorded_at: float,
) -> None:
    conn.execute(
        """INSERT INTO zeek_ingest_failures (
               source_instance, log_name, device, inode, record_end_offset,
               record_sha256, error_code, error, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            checkpoint.source_instance,
            checkpoint.log_name,
            checkpoint.device,
            checkpoint.inode,
            checkpoint.offset,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            error_code,
            error[:MAX_FAILURE_ERROR_CHARS],
            recorded_at,
        ),
    )


def _store_checkpoint(
    conn: sqlite3.Connection,
    checkpoint: ZeekLogCheckpoint,
    updated_at: float,
) -> None:
    conn.execute(
        """INSERT INTO zeek_log_checkpoints (
               source_instance, log_name, device, inode,
               offset, file_size, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_instance, log_name) DO UPDATE SET
               device = excluded.device,
               inode = excluded.inode,
               offset = excluded.offset,
               file_size = excluded.file_size,
               updated_at = excluded.updated_at""",
        (
            checkpoint.source_instance,
            checkpoint.log_name,
            checkpoint.device,
            checkpoint.inode,
            checkpoint.offset,
            checkpoint.file_size,
            updated_at,
        ),
    )


def index_conn_line(
    conn: sqlite3.Connection,
    raw_line: bytes | str,
    next_checkpoint: ZeekLogCheckpoint,
    *,
    expected_checkpoint: ZeekLogCheckpoint | None,
    clock: Callable[[], float] = time.time,
) -> IndexedLineResult:
    """Atomically index one complete line and advance an exact durable cursor."""

    if next_checkpoint.log_name != "conn":
        raise ZeekConnValidationError(
            "conn.log records require the 'conn' checkpoint name"
        )
    raw = raw_line.encode("utf-8") if isinstance(raw_line, str) else raw_line
    record = None
    failure_code = None
    failure_message = None
    try:
        raw, record = _parse_complete_conn_line(
            raw_line,
            next_checkpoint.source_instance,
        )
    except ZeekIncompleteRecordError:
        raise
    except ZeekConnValidationError as exc:
        if not isinstance(raw, bytes):
            raise TypeError("raw_line must be bytes or text") from exc
        failure_code = "invalid_record"
        failure_message = str(exc)

    observed_at = _epoch_timestamp(clock())
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = load_checkpoint(
            conn,
            next_checkpoint.source_instance,
            next_checkpoint.log_name,
        )
        _validate_checkpoint_transition(
            current,
            expected_checkpoint,
            next_checkpoint,
            len(raw),
        )
        inserted = False
        duplicate = False
        if record is not None:
            insert_outcome = _insert_connection(conn, record, observed_at)
            inserted = insert_outcome == "inserted"
            duplicate = insert_outcome == "duplicate"
            if insert_outcome == "uid_conflict":
                failure_code = "uid_conflict"
                failure_message = (
                    "Zeek uid already exists with different normalized content"
                )
        if failure_code is not None:
            _store_failure(
                conn,
                raw,
                next_checkpoint,
                failure_code,
                failure_message or failure_code,
                observed_at,
            )
        _store_checkpoint(conn, next_checkpoint, observed_at)
        conn.commit()
        return IndexedLineResult(
            indexed=inserted,
            duplicate=duplicate,
            failure_code=failure_code,
        )
    except Exception:
        conn.rollback()
        raise


def _epoch_timestamp(value: str | datetime | int | float) -> float:
    if isinstance(value, bool):
        raise ValueError("timestamp must not be boolean")
    if isinstance(value, (int, float)):
        epoch = float(value)
        if not math.isfinite(epoch) or epoch < 0:
            raise ValueError("epoch timestamp must be finite and non-negative")
        return epoch
    return parse_utc_timestamp(value).timestamp()


def _connection_context(row: tuple[Any, ...], request: ZeekLookupRequest) -> str:
    (
        uid,
        ts,
        end_ts,
        orig_h,
        orig_p,
        resp_h,
        resp_p,
        proto,
        service,
        duration,
        orig_bytes,
        resp_bytes,
        conn_state,
        missed_bytes,
        orig_pkts,
        resp_pkts,
    ) = row
    direction = (
        "same_as_alert"
        if orig_h == request.src_ip
        and orig_p == request.src_port
        and resp_h == request.dest_ip
        and resp_p == request.dest_port
        else "reversed_from_alert"
    )
    context = {
        "schema_version": ZEEK_CONTEXT_SCHEMA_VERSION,
        "connections": [
            {
                "uid": uid,
                "ts": format_utc_timestamp(
                    datetime.fromtimestamp(ts, timezone.utc)
                ),
                "end_ts": format_utc_timestamp(
                    datetime.fromtimestamp(end_ts, timezone.utc)
                ),
                "id.orig_h": orig_h,
                "id.orig_p": orig_p,
                "id.resp_h": resp_h,
                "id.resp_p": resp_p,
                "proto": proto,
                "service": service,
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "conn_state": conn_state,
                "missed_bytes": missed_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "direction": direction,
            }
        ],
    }
    return json.dumps(context, sort_keys=True, separators=(",", ":"))


def lookup_connection(
    conn: sqlite3.Connection,
    request: ZeekLookupRequest,
    source_instance: str,
) -> ZeekLookupResult:
    """Correlate one exact tuple against connection intervals without guessing."""

    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    alert_epoch = _epoch_timestamp(request.alert_timestamp)
    rows = conn.execute(
        """SELECT uid, ts, end_ts, orig_h, orig_p, resp_h, resp_p, proto,
                  service, duration, orig_bytes, resp_bytes, conn_state,
                  missed_bytes, orig_pkts, resp_pkts
           FROM zeek_connections INDEXED BY idx_zeek_conn_tuple_time
           WHERE source_instance = ?
             AND proto = ?
             AND (
                 (orig_h = ? AND orig_p = ? AND resp_h = ? AND resp_p = ?)
                 OR
                 (orig_h = ? AND orig_p = ? AND resp_h = ? AND resp_p = ?)
             )
             AND ts <= ?
             AND end_ts >= ?
           ORDER BY ts DESC, uid
           LIMIT ?""",
        (
            source_instance,
            request.proto,
            request.src_ip,
            request.src_port,
            request.dest_ip,
            request.dest_port,
            request.dest_ip,
            request.dest_port,
            request.src_ip,
            request.src_port,
            alert_epoch + request.window_after_seconds,
            alert_epoch - request.window_before_seconds,
            request.max_records + 1,
        ),
    ).fetchall()

    if not rows:
        return ZeekLookupResult(
            status=ZeekLookupStatus.NO_MATCH,
            source_instance=source_instance,
            match_strategy="exact_tuple_interval",
        )
    if len(rows) > 1:
        return ZeekLookupResult(
            status=ZeekLookupStatus.AMBIGUOUS,
            source_instance=source_instance,
            match_strategy="exact_tuple_interval",
            candidate_count=min(len(rows), MAX_CANDIDATES),
            truncated=len(rows) > request.max_records,
        )

    context_json = _connection_context(rows[0], request)
    if len(context_json.encode("utf-8")) > request.max_context_bytes:
        return ZeekLookupResult(
            status=ZeekLookupStatus.INVALID_RESPONSE,
            source_instance=source_instance,
            match_strategy="exact_tuple_interval",
        )
    return ZeekLookupResult(
        status=ZeekLookupStatus.MATCHED,
        context_json=context_json,
        source_instance=source_instance,
        match_strategy="exact_tuple_interval",
        record_count=1,
        candidate_count=1,
    )


def prune_index(
    conn: sqlite3.Connection,
    cutoff: str | datetime | int | float,
    *,
    batch_size: int = DEFAULT_PRUNE_BATCH_SIZE,
    max_rows: int = DEFAULT_PRUNE_MAX_ROWS,
) -> ZeekPruneResult:
    """Bound deletion work for expired connections and failure metadata."""

    if type(batch_size) is not int or not 1 <= batch_size <= MAX_PRUNE_BATCH_SIZE:
        raise ValueError(
            f"batch_size must be between 1 and {MAX_PRUNE_BATCH_SIZE}"
        )
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_PRUNE_ROWS:
        raise ValueError(f"max_rows must be between 1 and {MAX_PRUNE_ROWS}")
    cutoff_epoch = _epoch_timestamp(cutoff)

    totals = {"connections": 0, "failures": 0}
    targets = (
        ("connections", "zeek_connections"),
        ("failures", "zeek_ingest_failures"),
    )
    total_deleted = 0
    for key, table in targets:
        while total_deleted < max_rows:
            current_batch = min(batch_size, max_rows - total_deleted)
            try:
                conn.execute("BEGIN IMMEDIATE")
                if table == "zeek_connections":
                    conn.execute(
                        """DELETE FROM zeek_connections
                           WHERE (source_instance, uid) IN (
                               SELECT source_instance, uid
                               FROM zeek_connections
                               WHERE end_ts < ?
                               ORDER BY end_ts, source_instance, uid
                               LIMIT ?
                           )""",
                        (cutoff_epoch, current_batch),
                    )
                else:
                    conn.execute(
                        """DELETE FROM zeek_ingest_failures
                           WHERE id IN (
                               SELECT id
                               FROM zeek_ingest_failures
                               WHERE recorded_at < ?
                               ORDER BY recorded_at, id
                               LIMIT ?
                           )""",
                        (cutoff_epoch, current_batch),
                    )
                deleted = int(conn.execute("SELECT changes()").fetchone()[0])
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            totals[key] += deleted
            total_deleted += deleted
            if deleted < current_batch:
                break

    return ZeekPruneResult(
        connections=totals["connections"],
        failures=totals["failures"],
    )
