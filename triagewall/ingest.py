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
import time
import json
import sqlite3
import signal
import logging
from pathlib import Path
from datetime import datetime, timezone

# Reuse the existing triage code
sys.path.insert(0, str(Path(__file__).parent))
from triage import call_ollama, insert_triage_row, MODEL, DB_PATH

# --- Config ---
EVE_PATH = Path(os.getenv("EVE_PATH", "/var/log/suricata-opnsense/eve.json"))
POSITION_PATH = Path(os.getenv("POSITION_PATH", "/var/lib/triagewall/position.json"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))  # seconds
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ingest")

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


def is_duplicate(conn, alert):
    """Check if we've already triaged this alert (flow_id + sig_id + timestamp)."""
    flow_id = alert.get("flow_id")
    sig_id = alert.get("alert", {}).get("signature_id")
    ts = alert.get("timestamp")
    if not (flow_id and sig_id and ts):
        return False
    row = conn.execute(
        """SELECT 1 FROM triage_events
           WHERE flow_id = ? AND signature_id = ? AND timestamp = ?
           LIMIT 1""",
        (flow_id, sig_id, ts),
    ).fetchone()
    return row is not None


def process_line(conn, line):
    """Parse one line, triage if it's an alert, return True if we did work."""
    line = line.strip()
    if not line:
        return False
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return False

    if event.get("event_type") != "alert":
        return False

    if is_duplicate(conn, event):
        log.debug(f"Skipping duplicate alert flow_id={event.get('flow_id')}")
        return False

    sig = event.get("alert", {}).get("signature", "?")
    try:
        verdict = call_ollama(event)
        insert_triage_row(conn, event, verdict)
        log.info(
            f"[{verdict['verdict']:>15}] {verdict['confidence']:.2f}  {sig[:80]}"
        )
        return True
    except Exception as e:
        log.error(f"Failed to triage alert ({sig}): {type(e).__name__}: {e}")
        return False


def tail_file():
    """Main loop: poll the file, process new lines."""
    if not DB_PATH.exists():
        log.error(f"Database not found at {DB_PATH}")
        sys.exit(1)

    log.info(f"Starting ingest daemon")
    log.info(f"  eve.json: {EVE_PATH}")
    log.info(f"  database: {DB_PATH}")
    log.info(f"  model:    {MODEL}")
    log.info(f"  poll:     every {POLL_INTERVAL}s")

    state = load_position()
    conn = sqlite3.connect(DB_PATH, timeout=30.0)

    while not _stop:
        try:
            if not EVE_PATH.exists():
                log.warning(f"{EVE_PATH} doesn't exist yet, waiting...")
                time.sleep(POLL_INTERVAL)
                continue

            stat = EVE_PATH.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size

            # Detect truncation or rotation
            if state["inode"] is not None and current_inode != state["inode"]:
                log.info(f"File replaced (inode changed), reopening from start")
                state = {"offset": 0, "inode": current_inode, "size": 0}
            elif current_size < state["offset"]:
                log.info(f"File shrunk (size {current_size} < offset {state['offset']}), restarting from start")
                state = {"offset": 0, "inode": current_inode, "size": 0}

            state["inode"] = current_inode

            if current_size == state["offset"]:
                # Nothing new
                time.sleep(POLL_INTERVAL)
                continue

            # Read new content using readline() so f.tell() works inside the loop
            with open(EVE_PATH, "r") as f:
                f.seek(state["offset"])
                new_lines = 0
                processed = 0
                while not _stop:
                    line = f.readline()
                    if not line:
                        break
                    new_lines += 1
                    if process_line(conn, line):
                        processed += 1
                state["offset"] = f.tell()

            if new_lines:
                log.info(f"Read {new_lines} new lines, triaged {processed} alerts (offset now {state['offset']})")

            save_position(state)

        except Exception as e:
            log.error(f"Loop error: {type(e).__name__}: {e}")
            time.sleep(POLL_INTERVAL)

    conn.close()
    log.info("Ingest daemon stopped cleanly")


if __name__ == "__main__":
    tail_file()
