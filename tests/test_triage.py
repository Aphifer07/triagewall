#!/usr/bin/env python3
"""
Test run: triage first 20 alerts and print reasoning for each.
Same code as triage.py but limited to 20 alerts and verbose output.
"""
import sys
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

# Reuse the existing triage module
from triage import call_ollama, insert_triage_row, MODEL, DB_PATH

LIMIT = 20


def main(fixture_path: str) -> None:
    if not DB_PATH.exists():
        print(f"ERROR: {DB_PATH} not found.", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    alerts = []
    with open(fixture_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    alerts = alerts[:LIMIT]
    print(f"Triaging {len(alerts)} alerts using {MODEL}\n")
    print("=" * 80)
    counts = {"real": 0, "false_positive": 0, "uncertain": 0, "errors": 0}
    start = time.time()

    for i, alert in enumerate(alerts, 1):
        sig = alert.get("alert", {}).get("signature", "?")
        src = f"{alert.get('src_ip', '?')}:{alert.get('src_port', '?')}"
        dst = f"{alert.get('dest_ip', '?')}:{alert.get('dest_port', '?')}"
        try:
            verdict = call_ollama(alert)
            insert_triage_row(conn, alert, verdict)
            counts[verdict["verdict"]] += 1
            print(f"\n[{i:>2}/{len(alerts)}] {sig}")
            print(f"        {src} -> {dst}")
            print(f"        Verdict: {verdict['verdict']} (confidence: {verdict['confidence']:.2f})")
            print(f"        Reasoning: {verdict['reasoning']}")
        except Exception as e:
            counts["errors"] += 1
            print(f"\n[{i:>2}/{len(alerts)}] ERROR: {type(e).__name__}: {e}", file=sys.stderr)

    elapsed = time.time() - start
    print("\n" + "=" * 80)
    print(f"Done in {elapsed:.1f}s ({elapsed/max(len(alerts),1):.1f}s/alert)")
    print(f"Verdicts: real={counts['real']}  false_positive={counts['false_positive']}  "
          f"uncertain={counts['uncertain']}  errors={counts['errors']}")
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 src/triage_test.py <fixtures_file>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
