#!/usr/bin/env python3
"""
SPC baseline backfill.

Replays historical alerts from triage_events through spc.observe() to build a
warm behavioral baseline, so SPC is useful immediately on deploy instead of
after a 24h cold-start.

Run this ONCE on omv1, AFTER pulling the spc-baselining branch but BEFORE
rebuilding the ingest container — so the live observer isn't writing to the SPC
tables at the same time (no contention, no double-counting).

Because spc reasons in event-time, replaying historical alerts builds correct
historical baselines and ages IPs out of 'learning' based on the data's
timespan, not wall-clock.

Usage:
    python3 backfill_spc.py                 # last 14 days (default)
    python3 backfill_spc.py --days 30       # custom window
    python3 backfill_spc.py --db /path/to/triage.db
    python3 backfill_spc.py --dry-run       # count rows, don't write

Safe to re-run: spc.observe is idempotent-ish on seen_sids (INSERT OR IGNORE)
and rate buckets are keyed by (ip, bucket), but re-running WILL double-count
rate buckets for already-processed alerts. If you need to re-run cleanly, drop
the spc_* tables first (see --reset).
"""
import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

# import the spc module from the same package dir
sys.path.insert(0, str(Path(__file__).resolve().parent / "triagewall"))
try:
    import spc
except ImportError:
    # fallback if run from repo root with package layout
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from triagewall import spc


DEFAULT_DB = os.environ.get(
    "DB_PATH", "/opt/axon-agents/triage-agent/data/triage.db"
)


def main():
    ap = argparse.ArgumentParser(description="Backfill SPC baselines from history")
    ap.add_argument("--db", default=DEFAULT_DB, help="path to triage.db")
    ap.add_argument("--days", type=int, default=14, help="window of history to replay")
    ap.add_argument("--dry-run", action="store_true", help="count only, no writes")
    ap.add_argument("--reset", action="store_true",
                    help="DROP spc_* tables first (clean re-run)")
    ap.add_argument("--commit-every", type=int, default=5000,
                    help="commit interval (rows)")
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: DB not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.execute("PRAGMA busy_timeout=10000")

    if args.reset:
        print("Dropping spc_* tables for clean re-run...")
        for t in ("spc_anomalies", "spc_rate_buckets", "spc_seen_sids", "spc_ip_state"):
            conn.execute(f"DROP TABLE IF EXISTS {t}")
        conn.commit()

    spc.ensure_spc_schema(conn)

    # Pull the window of history, oldest first (chronological replay is required
    # so rolling baselines build in the right order).
    where = f"timestamp >= datetime('now', '-{int(args.days)} days')"
    total = conn.execute(
        f"SELECT COUNT(*) FROM triage_events WHERE {where} AND raw_alert IS NOT NULL"
    ).fetchone()[0]
    print(f"DB: {db_path}")
    print(f"Window: last {args.days} days")
    print(f"Rows to replay: {total:,}")

    if args.dry_run:
        print("(dry run — no writes)")
        conn.close()
        return

    if total == 0:
        print("Nothing to replay.")
        conn.close()
        return

    # Read with a separate cursor so we can stream without loading all rows.
    read_cur = conn.cursor()
    read_cur.execute(
        f"SELECT raw_alert FROM triage_events "
        f"WHERE {where} AND raw_alert IS NOT NULL ORDER BY timestamp ASC"
    )

    processed = 0
    skipped = 0
    anomalies = 0
    start = time.time()

    for (raw,) in read_cur:
        try:
            event = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            skipped += 1
            continue
        try:
            a = spc.observe(conn, event)
            if a:
                anomalies += 1
        except Exception as e:
            skipped += 1
            if skipped <= 5:
                print(f"  [warn] observe failed: {type(e).__name__}: {e}")
        processed += 1
        if processed % args.commit_every == 0:
            conn.commit()
            rate = processed / (time.time() - start)
            print(f"  {processed:,}/{total:,}  ({rate:.0f}/s)  anomalies={anomalies}")

    conn.commit()
    elapsed = time.time() - start

    # Summary of the resulting baseline state
    ip_total = conn.execute("SELECT COUNT(*) FROM spc_ip_state").fetchone()[0]
    ip_active = conn.execute(
        "SELECT COUNT(*) FROM spc_ip_state WHERE state='active'"
    ).fetchone()[0]
    ip_learning = ip_total - ip_active
    anom_rows = conn.execute("SELECT COUNT(*) FROM spc_anomalies").fetchone()[0]

    print()
    print("=== Backfill complete ===")
    print(f"  Replayed:        {processed:,} alerts in {elapsed:.0f}s")
    print(f"  Skipped:         {skipped:,}")
    print(f"  IPs baselined:   {ip_total}  (active={ip_active}, learning={ip_learning})")
    print(f"  Anomalies found: {anom_rows} (historical — expected, these are past spikes)")
    print()
    print("Top anomalies by feature:")
    for row in conn.execute(
        "SELECT feature, COUNT(*) FROM spc_anomalies GROUP BY feature ORDER BY 2 DESC"
    ):
        print(f"    {row[0]:<12} {row[1]}")

    conn.close()
    print()
    print("Baseline is warm. Now rebuild the ingest container to bring the live")
    print("SPC observer online on top of this baseline.")


if __name__ == "__main__":
    main()
