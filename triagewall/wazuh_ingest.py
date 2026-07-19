#!/usr/bin/env python3
"""Tail Wazuh alerts.json with durable, rotation-aware checkpoints."""

from __future__ import annotations

import calendar
import gzip
import hashlib
import json
import logging
import os
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from database import connect_database
from ingest import (
    CHECKPOINT_LINE,
    PROCESSED_LINE,
    RETRY_LINE,
    ensure_db_initialized,
    insert_with_retry,
    quarantine_line,
)
from triage import MODEL, call_ollama_wazuh, get_asset_context
from wazuh_event import (
    WazuhValidationError,
    normalize_wazuh_event,
    validate_source_id,
)
from wazuh_isolation import format_wazuh_for_llm


WAZUH_ALERTS_PATH = Path(
    os.environ.get("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
)
WAZUH_POSITION_PATH = Path(
    os.environ.get(
        "WAZUH_POSITION_PATH", "/var/lib/triagewall/wazuh-position.json"
    )
)
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or str(Path(__file__).resolve().parent.parent / "triage.db")
)
WAZUH_SOURCE_ID = os.environ.get("WAZUH_SOURCE_ID", "wazuh-local")
WAZUH_MIN_LEVEL = int(os.environ.get("WAZUH_MIN_LEVEL", "8"))
WAZUH_START_MODE = os.environ.get("WAZUH_START_MODE", "end").strip().lower()
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))
MAX_RECORD_BYTES = 1024 * 1024
POSITION_VERSION = 1

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wazuh-ingest")

_stop = False


class WazuhCheckpointError(RuntimeError):
    """The stream cannot continue without risking an alert gap."""


class WazuhRotationRace(RuntimeError):
    """The live path rotated between stat and open and should be retried."""


@dataclass(frozen=True)
class StreamResult:
    scanned: int = 0
    processed: int = 0
    blocked: bool = False
    complete: bool = True


@dataclass(frozen=True)
class RecordRead:
    raw: bytes | None
    complete: bool
    oversized_size: int | None = None
    oversized_hash: str | None = None


def _handle_signal(signum, _frame):
    global _stop
    _stop = True
    log.info("Received signal %s, shutting down...", signum)


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def validate_config() -> None:
    validate_source_id(WAZUH_SOURCE_ID)
    if isinstance(WAZUH_MIN_LEVEL, bool) or not 1 <= WAZUH_MIN_LEVEL <= 16:
        raise WazuhValidationError("WAZUH_MIN_LEVEL must be from 1 to 16")
    if WAZUH_START_MODE not in {"beginning", "end"}:
        raise WazuhValidationError(
            "WAZUH_START_MODE must be either 'beginning' or 'end'"
        )
    if POLL_INTERVAL < 1:
        raise WazuhValidationError("POLL_INTERVAL must be at least one second")


def _position_document(log_date: date, offset: int, inode, size: int) -> dict:
    return {
        "version": POSITION_VERSION,
        "source_instance": WAZUH_SOURCE_ID,
        "date": log_date.isoformat(),
        "offset": offset,
        "inode": inode,
        "size": size,
    }


def save_position(state: dict) -> None:
    """Atomically replace the Wazuh checkpoint."""
    WAZUH_POSITION_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = WAZUH_POSITION_PATH.with_name(
        f".{WAZUH_POSITION_PATH.name}.{os.getpid()}.tmp"
    )
    try:
        with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, WAZUH_POSITION_PATH)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_position(state) -> dict:
    if not isinstance(state, dict) or set(state) != {
        "version", "source_instance", "date", "offset", "inode", "size"
    }:
        raise WazuhCheckpointError("Wazuh checkpoint has an invalid schema")
    if state["version"] != POSITION_VERSION:
        raise WazuhCheckpointError("unsupported Wazuh checkpoint version")
    if state["source_instance"] != WAZUH_SOURCE_ID:
        raise WazuhCheckpointError(
            "Wazuh checkpoint source does not match WAZUH_SOURCE_ID"
        )
    try:
        date.fromisoformat(state["date"])
    except (TypeError, ValueError) as exc:
        raise WazuhCheckpointError("Wazuh checkpoint date is invalid") from exc
    for field in ("offset", "size"):
        value = state[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WazuhCheckpointError(
                f"Wazuh checkpoint {field} must be a non-negative integer"
            )
    if state["inode"] is not None and (
        isinstance(state["inode"], bool) or not isinstance(state["inode"], int)
    ):
        raise WazuhCheckpointError("Wazuh checkpoint inode is invalid")
    return state


def load_position() -> dict | None:
    if not WAZUH_POSITION_PATH.exists():
        return None
    try:
        state = json.loads(WAZUH_POSITION_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WazuhCheckpointError("could not read Wazuh checkpoint") from exc
    return _validate_position(state)


def _last_complete_offset(path: Path) -> int:
    size = path.stat().st_size
    if size == 0:
        return 0
    with open(path, "rb") as handle:
        handle.seek(size - 1)
        if handle.read(1) in (b"\n", b"\r"):
            return size
        cursor = size
        while cursor:
            chunk_size = min(64 * 1024, cursor)
            cursor -= chunk_size
            handle.seek(cursor)
            chunk = handle.read(chunk_size)
            newline = chunk.rfind(b"\n")
            if newline >= 0:
                return cursor + newline + 1
    return 0


def _current_log_date(path: Path) -> date:
    modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return modified.date()


def initialize_position() -> dict:
    if not WAZUH_ALERTS_PATH.is_file():
        raise WazuhCheckpointError(
            f"configured Wazuh alerts file is missing: {WAZUH_ALERTS_PATH}"
        )
    stat = WAZUH_ALERTS_PATH.stat()
    offset = _last_complete_offset(WAZUH_ALERTS_PATH)
    if WAZUH_START_MODE == "beginning":
        offset = 0
    state = _position_document(
        _current_log_date(WAZUH_ALERTS_PATH),
        offset,
        stat.st_ino,
        stat.st_size,
    )
    save_position(state)
    return state


def _read_record(stream) -> RecordRead:
    first = stream.readline(MAX_RECORD_BYTES + 1)
    if not first:
        return RecordRead(raw=None, complete=True)
    if len(first) <= MAX_RECORD_BYTES:
        return RecordRead(
            raw=first,
            complete=first.endswith((b"\n", b"\r")),
        )

    digest = hashlib.sha256(first)
    total = len(first)
    complete = first.endswith((b"\n", b"\r"))
    while not complete:
        chunk = stream.readline(64 * 1024)
        if not chunk:
            return RecordRead(raw=None, complete=False)
        digest.update(chunk)
        total += len(chunk)
        complete = chunk.endswith((b"\n", b"\r"))
    return RecordRead(
        raw=None,
        complete=True,
        oversized_size=total,
        oversized_hash="sha256:" + digest.hexdigest(),
    )


def is_duplicate(conn, event) -> bool:
    row = conn.execute(
        """SELECT 1 FROM sensor_event_context
           WHERE source_type = 'wazuh'
             AND source_instance = ? AND source_event_id = ?
           LIMIT 1""",
        (event.sensor.instance, event.sensor.event_id),
    ).fetchone()
    return row is not None


def process_wazuh_record(conn, raw: bytes):
    try:
        text = raw.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError as exc:
        quarantine_line(
            conn,
            raw.decode("utf-8", errors="replace")[:MAX_RECORD_BYTES],
            f"invalid UTF-8: {exc}",
            source_type="wazuh",
        )
        return CHECKPOINT_LINE
    if not text.strip():
        return CHECKPOINT_LINE
    try:
        alert = json.loads(text)
    except json.JSONDecodeError as exc:
        quarantine_line(
            conn, text, f"invalid JSON: {exc}", source_type="wazuh"
        )
        return CHECKPOINT_LINE

    try:
        event = normalize_wazuh_event(alert, WAZUH_SOURCE_ID)
    except WazuhValidationError as exc:
        quarantine_line(conn, text, str(exc), source_type="wazuh")
        return CHECKPOINT_LINE

    if event.severity < WAZUH_MIN_LEVEL:
        return CHECKPOINT_LINE

    try:
        if is_duplicate(conn, event):
            return CHECKPOINT_LINE
        asset_context = get_asset_context(
            {"src_ip": event.src_ip, "dest_ip": event.dest_ip}
        )
        verdict = call_ollama_wazuh(
            event,
            format_wazuh_for_llm(alert),
            asset_context=asset_context,
        )
        if not insert_with_retry(
            conn, event, verdict, asset_context=asset_context
        ):
            return RETRY_LINE
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        try:
            if is_duplicate(conn, event):
                return CHECKPOINT_LINE
        except sqlite3.Error:
            pass
        log.error(
            "Failed to persist Wazuh rule %s: %s; checkpoint unchanged",
            event.signature_id,
            exc,
        )
        return RETRY_LINE
    except Exception as exc:
        conn.rollback()
        log.error(
            "Failed to triage Wazuh rule %s: %s: %s; checkpoint unchanged",
            event.signature_id,
            type(exc).__name__,
            exc,
        )
        return RETRY_LINE

    return PROCESSED_LINE


def _quarantine_oversized(conn, record: RecordRead):
    placeholder = json.dumps(
        {
            "oversized_record": True,
            "bytes": record.oversized_size,
            "sha256": record.oversized_hash,
        },
        sort_keys=True,
    )
    quarantine_line(
        conn,
        placeholder,
        f"Wazuh record exceeded {MAX_RECORD_BYTES} bytes; "
        f"{record.oversized_hash}",
        source_type="wazuh",
    )
    return CHECKPOINT_LINE


def _open_stream(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    return open(path, "rb")


def _process_stream(
    conn,
    path: Path,
    state: dict,
    log_date: date,
    *,
    inode=None,
    observed_size: int | None = None,
) -> StreamResult:
    scanned = 0
    processed = 0
    with _open_stream(path) as stream:
        if inode is not None and os.fstat(stream.fileno()).st_ino != inode:
            raise WazuhRotationRace(
                "Wazuh alerts path rotated between stat and open"
            )
        try:
            stream.seek(state["offset"])
        except (OSError, ValueError) as exc:
            raise WazuhCheckpointError(
                f"could not seek Wazuh stream {path.name} to checkpoint"
            ) from exc
        if stream.tell() != state["offset"]:
            raise WazuhCheckpointError(
                f"Wazuh stream {path.name} ends before the saved checkpoint"
            )
        while not _stop:
            record = _read_record(stream)
            if record.raw is None and record.oversized_size is None:
                return StreamResult(
                    scanned=scanned,
                    processed=processed,
                    complete=record.complete,
                )
            if not record.complete:
                return StreamResult(
                    scanned=scanned,
                    processed=processed,
                    complete=False,
                )

            result = (
                _quarantine_oversized(conn, record)
                if record.oversized_size is not None
                else process_wazuh_record(conn, record.raw)
            )
            if not result.checkpoint:
                return StreamResult(
                    scanned=scanned,
                    processed=processed,
                    blocked=True,
                    complete=False,
                )

            scanned += 1
            if result.processed:
                processed += 1
            state.update(
                _position_document(
                    log_date,
                    stream.tell(),
                    inode,
                    observed_size if observed_size is not None else stream.tell(),
                )
            )
            save_position(state)
    return StreamResult(scanned=scanned, processed=processed)


def _archive_path(log_date: date) -> Path | None:
    directory = (
        WAZUH_ALERTS_PATH.parent
        / str(log_date.year)
        / calendar.month_abbr[log_date.month]
    )
    basename = f"ossec-alerts-{log_date.day:02d}.json"
    for candidate in (directory / basename, directory / f"{basename}.gz"):
        if candidate.is_file():
            return candidate
    return None


def process_available(conn, state: dict) -> StreamResult:
    if not WAZUH_ALERTS_PATH.is_file():
        raise WazuhCheckpointError(
            f"configured Wazuh alerts file is missing: {WAZUH_ALERTS_PATH}"
        )
    current_date = _current_log_date(WAZUH_ALERTS_PATH)
    checkpoint_date = date.fromisoformat(state["date"])
    if checkpoint_date > current_date:
        raise WazuhCheckpointError("Wazuh checkpoint date is in the future")

    total_scanned = 0
    total_processed = 0
    while checkpoint_date < current_date:
        archive = _archive_path(checkpoint_date)
        if archive is None:
            raise WazuhCheckpointError(
                f"required Wazuh archive is missing for {checkpoint_date}"
            )
        try:
            result = _process_stream(
                conn, archive, state, checkpoint_date, inode=None
            )
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise WazuhCheckpointError(
                f"required Wazuh archive is unreadable for {checkpoint_date}"
            ) from exc
        total_scanned += result.scanned
        total_processed += result.processed
        if result.blocked:
            return StreamResult(total_scanned, total_processed, blocked=True)
        if not result.complete:
            raise WazuhCheckpointError(
                f"required Wazuh archive is incomplete for {checkpoint_date}"
            )
        checkpoint_date += timedelta(days=1)
        state.update(_position_document(checkpoint_date, 0, None, 0))
        save_position(state)

    stat = WAZUH_ALERTS_PATH.stat()
    if state["inode"] is not None and state["inode"] != stat.st_ino:
        raise WazuhCheckpointError(
            "Wazuh alerts file inode changed without a recoverable date rotation"
        )
    if stat.st_size < state["offset"]:
        raise WazuhCheckpointError(
            "Wazuh alerts file shrank behind the durable checkpoint"
        )
    result = _process_stream(
        conn,
        WAZUH_ALERTS_PATH,
        state,
        current_date,
        inode=stat.st_ino,
        observed_size=stat.st_size,
    )
    return StreamResult(
        total_scanned + result.scanned,
        total_processed + result.processed,
        blocked=result.blocked,
        complete=result.complete,
    )


def tail_wazuh() -> int:
    try:
        validate_config()
        ensure_db_initialized(DB_PATH)
        state = load_position() or initialize_position()
    except (OSError, ValueError, WazuhCheckpointError) as exc:
        log.critical("Wazuh ingest startup failed: %s", exc)
        return 1

    log.info("Starting Wazuh ingest")
    log.info("  source:   %s", WAZUH_SOURCE_ID)
    log.info("  minimum:  level %s", WAZUH_MIN_LEVEL)
    log.info("  database: %s", DB_PATH)
    log.info("  model:    %s", MODEL)
    log.info("  checkpoint date=%s offset=%s", state["date"], state["offset"])

    conn = connect_database(DB_PATH)
    try:
        while not _stop:
            try:
                result = process_available(conn, state)
            except WazuhRotationRace:
                log.info("Wazuh alerts path rotated; resolving the new stream")
                time.sleep(POLL_INTERVAL)
                continue
            except WazuhCheckpointError as exc:
                log.critical("Wazuh ingest stopped to prevent an alert gap: %s", exc)
                return 1
            except OSError as exc:
                log.critical(
                    "Wazuh ingest stopped because checkpoint I/O failed: %s", exc
                )
                return 1
            if result.scanned:
                log.info(
                    "Wazuh batch scanned=%s triaged=%s checkpoint=%s:%s",
                    result.scanned,
                    result.processed,
                    state["date"],
                    state["offset"],
                )
            time.sleep(POLL_INTERVAL)
    finally:
        conn.close()
    log.info("Wazuh ingest stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(tail_wazuh())
