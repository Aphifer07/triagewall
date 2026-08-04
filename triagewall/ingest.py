#!/usr/bin/env python3
"""
Live ingest daemon: tails OPNsense eve.json, triages alerts in real time.

Reads new lines from the synced eve.json, filters to alert events,
sends each to the triage function, writes verdict to triage.db.

Run:
    python3 src/ingest.py

Stop with Ctrl-C or systemd.
"""
import os
import sys
import spc
import time
import json
import sqlite3
import signal
import logging
import random
from dataclasses import dataclass
from pathlib import Path
from database import connect_database
from environment import parse_boolean
from migrations import verify_db_initialized
from time_utils import format_utc_timestamp, utc_now_iso

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(override: bool = False) -> None:
    """Minimal `.env` loader (stdlib-only; matches docker-compose interpolation locally)."""
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return
    try:
        for raw_line in env_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not key:
                continue
            if not override and key in os.environ:
                continue
            os.environ[key] = val
    except OSError:
        return


_load_dotenv(override=False)

# Reuse the existing triage code
sys.path.insert(0, str(Path(__file__).parent))
from triage import call_ollama, get_asset_context, insert_triage_row, MODEL
from sensor_event import (
    SuricataValidationError,
    normalize_suricata_event,
    suricata_classification_alert,
)

# --- Config ---
DEMO_MODE = parse_boolean(
    os.environ.get("DEMO_MODE", "false"),
    "DEMO_MODE",
)
EVE_PATH = Path(os.environ.get("EVE_PATH", "/var/log/suricata/eve.json"))
POSITION_PATH = Path(os.environ.get("POSITION_PATH", "/var/lib/triagewall/position.json"))
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or str(_REPO_ROOT / "triage.db")
)
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))  # seconds
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ingest")


@dataclass(frozen=True)
class LineResult:
    """Outcome of processing one complete input record."""

    processed: bool
    checkpoint: bool

    def __bool__(self):
        """Preserve the historical truthy result for successfully triaged alerts."""
        return self.processed


PROCESSED_LINE = LineResult(processed=True, checkpoint=True)
CHECKPOINT_LINE = LineResult(processed=False, checkpoint=True)
RETRY_LINE = LineResult(processed=False, checkpoint=False)

# Graceful shutdown
_stop = False
def _handle_signal(signum, frame):
    global _stop
    _stop = True
    log.info(f"Received signal {signum}, shutting down...")

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def load_position():
    """Return dict with last-read state, or empty if first run."""
    if POSITION_PATH.exists():
        try:
            return json.loads(POSITION_PATH.read_text())
        except Exception as e:
            log.warning(f"Could not read position file: {e}; starting fresh")
    return {"offset": 0, "inode": None, "size": 0}


def save_position(state):
    POSITION_PATH.parent.mkdir(parents=True, exist_ok=True)
    POSITION_PATH.write_text(json.dumps(state))


def _line_is_complete(line):
    """A JSON-Lines record is complete only after its newline is present."""
    return bool(line) and line.endswith(("\n", "\r"))


def _line_is_complete_or_wait(line):
    """Return whether a record is complete, backing off before retrying if not."""
    if _line_is_complete(line):
        return True
    log.debug("Waiting for newline to complete eve.json record")
    time.sleep(POLL_INTERVAL)
    return False


def quarantine_line(conn, line, error, source_type="suricata"):
    """Durably retain an unprocessable complete record before checkpointing."""
    conn.rollback()
    conn.execute(
        """INSERT INTO ingest_failures
           (source_type, raw_line, error, failed_at) VALUES (?, ?, ?, ?)""",
        (
            source_type,
            line.rstrip("\r\n"),
            str(error)[:1000],
            utc_now_iso(),
        ),
    )
    conn.commit()
    log.error(f"Quarantined unprocessable {source_type} record: {error}")


def is_duplicate(conn, alert):
    """Check if we've already triaged this alert (flow_id + sig_id + timestamp)."""
    flow_id = alert.get("flow_id")
    sig_id = alert.get("alert", {}).get("signature_id")
    raw_ts = alert.get("timestamp")
    if not (flow_id and sig_id and raw_ts):
        return False
    canonical_ts = format_utc_timestamp(raw_ts)
    row = conn.execute(
        """SELECT 1 FROM triage_events
           WHERE flow_id = ? AND signature_id = ? AND timestamp IN (?, ?)
           LIMIT 1""",
        (flow_id, sig_id, raw_ts, canonical_ts),
    ).fetchone()
    return row is not None


def insert_with_retry(
    conn,
    event,
    verdict,
    asset_context=None,
    max_retries=3,
    base_backoff_ms=100,
):
    """
    Insert a triage row with simple exponential backoff on SQLite 'database is locked' errors.
    Returns True on success, False if we give up after max_retries.
    """
    for attempt in range(max_retries):
        try:
            insert_triage_row(
                conn,
                event,
                verdict,
                asset_context=asset_context,
            )
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            conn.rollback()
            if "locked" in str(e).lower():
                if attempt < max_retries - 1:
                    sleep_time = (base_backoff_ms * (2**attempt)) / 1000.0
                    logging.warning(
                        f"Database locked, retrying in {sleep_time}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(sleep_time)
                else:
                    event_reference = (
                        event.get("flow_id")
                        if isinstance(event, dict)
                        else event.sensor.event_id
                    )
                    logging.error(
                        f"Failed to insert alert after {max_retries} attempts; "
                        f"will retry without checkpointing event: {event_reference}"
                    )
                    return False
            else:
                raise


def process_line(conn, line):
    """Parse one line and return whether it was processed and may be checkpointed."""
    raw_line = line.rstrip("\r\n")
    line = raw_line.strip()
    if not line:
        return CHECKPOINT_LINE
    try:
        event = json.loads(line)
    except json.JSONDecodeError as e:
        quarantine_line(conn, raw_line, f"invalid JSON: {e}")
        return CHECKPOINT_LINE

    if not isinstance(event, dict):
        quarantine_line(conn, raw_line, "top-level JSON value must be an object")
        return CHECKPOINT_LINE

    if event.get("event_type") != "alert":
        return CHECKPOINT_LINE

    if not isinstance(event.get("alert"), dict):
        quarantine_line(conn, raw_line, "alert event metadata must be an object")
        return CHECKPOINT_LINE

    try:
        format_utc_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as e:
        quarantine_line(conn, raw_line, f"invalid alert timestamp: {e}")
        return CHECKPOINT_LINE

    try:
        normalized_event = normalize_suricata_event(event)
    except SuricataValidationError as e:
        quarantine_line(conn, raw_line, f"invalid alert data: {e}")
        return CHECKPOINT_LINE

    classification_event = suricata_classification_alert(normalized_event)

    if is_duplicate(conn, event):
        log.debug(f"Skipping duplicate alert flow_id={event.get('flow_id')}")
        return CHECKPOINT_LINE

    sig = normalized_event.signature
    try:
        asset_context = get_asset_context(classification_event)
        verdict = call_ollama(
            classification_event,
            asset_context=asset_context,
        )
        if not insert_with_retry(
            conn,
            normalized_event,
            verdict,
            asset_context=asset_context,
        ):
            log.error(
                f"Failed to persist alert ({sig}); retrying without advancing checkpoint"
            )
            return RETRY_LINE
        # SPC behavioral baselining — independent observer, never fatal
        try:
            spc.observe(conn, classification_event)
            conn.commit()
        except Exception as e:
            log.warning(f"SPC observe failed (non-fatal): {type(e).__name__}: {e}")
        log.info(
            f"[{verdict['verdict']:>15}] {verdict['confidence']:.2f}  {sig[:80]}"
        )
        return PROCESSED_LINE
    except sqlite3.IntegrityError as e:
        conn.rollback()
        quarantine_line(
            conn,
            raw_line,
            f"invalid alert data: {type(e).__name__}: {e}",
        )
        return CHECKPOINT_LINE
    except Exception as e:
        conn.rollback()
        log.error(
            f"Failed to triage alert ({sig}): {type(e).__name__}: {e}; "
            "retrying without advancing checkpoint"
        )
        return RETRY_LINE


def demo_loop():
    fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures" / "diverse_alerts.json"
    if not fixtures_path.exists():
        log.error(f"Demo fixtures not found at {fixtures_path}")
        sys.exit(1)

    try:
        with open(fixtures_path, "r") as f:
            demo_lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log.error(f"Failed to load demo fixtures: {type(e).__name__}: {e}")
        sys.exit(1)

    if not demo_lines:
        log.error("Demo fixtures file is empty (expected JSON-Lines).")
        sys.exit(1)

    verify_db_initialized(DB_PATH)

    log.info(f"Demo fixtures loaded: {len(demo_lines)} alerts")
    conn = connect_database(DB_PATH)

    try:
        while not _stop:
            for line in demo_lines:
                if _stop:
                    break
                process_line(conn, line)
                time.sleep(random.uniform(2, 8))
    finally:
        conn.close()


def tail_file():
    """Main loop: poll the file, process new lines."""
    if EVE_PATH.is_dir():
        log.error(f"{EVE_PATH} is a directory, not a file.")
        log.error("Either:")
        log.error("  1. Set DEMO_MODE=true in .env to test without real Suricata data")
        log.error("  2. Set HOST_EVE_PATH in .env to your actual eve.json file path")
        log.error("  3. Make sure the file exists on the host before starting the container")
        sys.exit(1)

    verify_db_initialized(DB_PATH)

    log.info(f"Starting ingest daemon")
    log.info(f"  eve.json: {EVE_PATH}")
    log.info(f"  database: {DB_PATH}")
    log.info(f"  model:    {MODEL}")
    log.info(f"  poll:     every {POLL_INTERVAL}s")

    state = load_position()
    conn = connect_database(DB_PATH)
    last_line_seen_ts = time.time()
    last_stall_warning_ts = 0.0

    def eve_disk_stat():
        try:
            return os.stat(EVE_PATH)
        except FileNotFoundError:
            return None

    while not _stop:
        try:
            # Warn if we haven't seen new eve.json lines recently (rate-limited).
            now = time.time()
            gap = now - last_line_seen_ts
            if gap > 300 and (now - last_stall_warning_ts) > 300:
                mins = gap / 60.0
                log.warning(
                    f"Ingestion stalled. No new lines seen in eve.json for {mins:.1f} minutes."
                )
                last_stall_warning_ts = now

            disk_stat = eve_disk_stat()
            if disk_stat is None:
                log.warning(f"{EVE_PATH} doesn't exist yet, waiting...")
                time.sleep(POLL_INTERVAL)
                continue

            current_inode = disk_stat.st_ino
            current_size = disk_stat.st_size

            # Detect truncation (same path inode, but file got smaller than our saved offset)
            if current_size < state["offset"]:
                log.info(
                    f"File shrunk (size {current_size} < offset {state['offset']}), restarting from start"
                )
                state["offset"] = 0

            # If we're tracking the wrong inode on disk (rare if position.json is stale), reset.
            if state["inode"] is not None and state["inode"] != current_inode:
                log.info("Saved inode doesn't match current eve.json inode; resetting offset")
                state["offset"] = 0

            state["inode"] = current_inode

            if current_size == state["offset"]:
                # Nothing new
                time.sleep(POLL_INTERVAL)
                continue

            # Read new content using readline() so f.tell() works inside the loop.
            # Track the inode of the *open file descriptor* via os.fstat() so we can detect rotation
            # even when the path is recreated with a new inode while we're still reading the old file.
            f = open(EVE_PATH, "r")
            try:
                open_inode = os.fstat(f.fileno()).st_ino
                f.seek(state["offset"])
                new_lines = 0
                processed = 0
                while not _stop:
                    line = f.readline()
                    if not line:
                        # EOF: decide whether we're waiting for more bytes, or the file rotated.
                        disk = eve_disk_stat()
                        if disk is None:
                            # Race during rotation/rename; wait briefly and retry.
                            time.sleep(POLL_INTERVAL)
                            continue

                        if disk.st_ino != open_inode:
                            log.info(
                                "Detected eve.json rotation (inode changed); reopening new file from start"
                            )
                            state["offset"] = 0
                            state["inode"] = disk.st_ino
                            save_position(state)

                            f.close()
                            f = open(EVE_PATH, "r")
                            open_inode = os.fstat(f.fileno()).st_ino
                            f.seek(0)
                            continue

                        # Same inode, waiting for more data.
                        break

                    if not _line_is_complete_or_wait(line):
                        # An append-in-place writer may expose a partial JSON
                        # record at EOF. Leave the checkpoint unchanged so the
                        # completed record is reread on the next poll.
                        break

                    last_line_seen_ts = time.time()
                    result = process_line(conn, line)
                    if not result.checkpoint:
                        # Retryable processing failures must block later records
                        # from moving the durable checkpoint past this alert.
                        time.sleep(POLL_INTERVAL)
                        break

                    new_lines += 1
                    if result:
                        processed += 1

                    state["offset"] = f.tell()
                    state["inode"] = open_inode
                    save_position(state)
            finally:
                try:
                    f.close()
                except Exception:
                    pass

            if new_lines:
                log.info(
                    f"Read {new_lines} new lines, triaged {processed} alerts (offset now {state['offset']})"
                )

        except Exception as e:
            log.error(f"Loop error: {type(e).__name__}: {e}")
            time.sleep(POLL_INTERVAL)

    conn.close()
    log.info("Ingest daemon stopped cleanly")


def main() -> int:
    try:
        if DEMO_MODE:
            log.info("Running in DEMO MODE using local fixtures...")
            demo_loop()
        else:
            tail_file()
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        log.critical("Suricata ingest startup failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
