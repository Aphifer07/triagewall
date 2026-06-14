#!/usr/bin/env python3
"""
Regression tests for the SPC behavioral baselining engine (triagewall/spc.py).

Standalone and dependency-free, matching the project's test style: no pytest,
no live DB, no Ollama. Runs the engine against an in-memory SQLite DB with
synthetic events and asserts the four core behaviors. Exits 0 on pass, 1 on any
failure, so it can be run by hand or wired into CI.

    python3 tests/test_spc.py

Scenarios covered:
  1. Chatty host with a learned baseline: a rate spike fires alert_rate, and a
     never-before-seen SID fires novel_sid.
  2. Quiet-but-established host (few samples, but >= MIN_AGE_HOURS old): a new
     SID fires novel_sid even though it has no rate baseline, and its rate-state
     stays 'learning' (correct — can't baseline a rate from a couple points).
  3. Brand-new host (< MIN_AGE_HOURS old): novel SIDs are suppressed (a new host
     triggers many "novel" SIDs by definition; that's not signal).
  4. External (non-internal) source IP is ignored entirely.

Also checks: alert_rate dedups to one anomaly per (ip, bucket), not one per
alert in the spike hour.
"""
import sqlite3
import sys
from datetime import datetime, timezone, timedelta

# Import the engine under test.
from triagewall import spc


def _ev(ip, sid, base, hour, minute=0):
    """Build a minimal Suricata-shaped alert event at base + hour:minute."""
    ts = (base + timedelta(hours=hour, minutes=minute)).isoformat()
    return {"src_ip": ip, "timestamp": ts, "alert": {"signature_id": sid}}


def _fresh_conn():
    conn = sqlite3.connect(":memory:")
    spc.ensure_spc_schema(conn)
    return conn


def _anom_count(conn, feature):
    return conn.execute(
        "SELECT COUNT(*) FROM spc_anomalies WHERE feature = ?", (feature,)
    ).fetchone()[0]


# Track pass/fail across all checks.
_failures = []


def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}")
    if not condition:
        _failures.append(name)


def scenario_chatty_host_spike_and_novel():
    print("Scenario 1: chatty host — baseline, spike fires alert_rate, novel SID fires")
    conn = _fresh_conn()
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)

    # 30 hours of steady ~2/hr traffic on one SID -> builds an active baseline
    # (>= MIN_SAMPLES buckets AND >= MIN_AGE_HOURS old).
    for h in range(30):
        for m in (0, 30):
            spc.observe(conn, _ev("10.0.1.50", 1000, base, h, m))

    state = conn.execute(
        "SELECT state FROM spc_ip_state WHERE ip='10.0.1.50'"
    ).fetchone()[0]
    check("host reached 'active' after warmup", state == "active")

    # Hour 31: a 40-alert spike against the ~2/hr baseline -> alert_rate anomaly.
    spike_hit = None
    for m in range(40):
        a = spc.observe(conn, _ev("10.0.1.50", 1000, base, 31, m))
        spike_hit = a or spike_hit
    check("rate spike produced an alert_rate anomaly",
          bool(spike_hit and spike_hit["feature"] == "alert_rate"))
    check("alert_rate deduped to one anomaly for the spike hour",
          _anom_count(conn, "alert_rate") == 1)

    # Hour 32: a never-before-seen SID on the now-active host -> novel_sid.
    nov = spc.observe(conn, _ev("10.0.1.50", 9999, base, 32))
    check("never-seen SID produced a novel_sid anomaly",
          bool(nov and nov["feature"] == "novel_sid"))
    conn.close()


def scenario_quiet_established_host():
    print("Scenario 2: quiet-but-established host — novel_sid fires, rate stays learning")
    conn = _fresh_conn()
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)

    # Host appears at hour 0 and again at hour 30: only 2 buckets (far below
    # MIN_SAMPLES) but >= MIN_AGE_HOURS of age.
    spc.observe(conn, _ev("10.0.2.50", 5000, base, 0))
    spc.observe(conn, _ev("10.0.2.50", 5000, base, 30))

    # A brand-new SID at hour 31 should fire novel_sid (age gate satisfied)...
    nov = spc.observe(conn, _ev("10.0.2.50", 7777, base, 31))
    check("quiet established host fires novel_sid on new SID",
          bool(nov and nov["feature"] == "novel_sid"))

    # ...but the host should still be 'learning' for rate (too few samples).
    state = conn.execute(
        "SELECT state FROM spc_ip_state WHERE ip='10.0.2.50'"
    ).fetchone()[0]
    check("quiet host stays 'learning' for alert_rate", state == "learning")
    conn.close()


def scenario_new_host_suppressed():
    print("Scenario 3: brand-new host (< MIN_AGE_HOURS) — novel SIDs suppressed")
    conn = _fresh_conn()
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)

    # First sighting at hour 0, then a new SID 1 hour later (well under
    # MIN_AGE_HOURS). Should NOT fire — a new host trips many "novel" SIDs.
    spc.observe(conn, _ev("10.0.3.50", 8000, base, 0))
    a = spc.observe(conn, _ev("10.0.3.50", 8001, base, 1))
    check("new host's novel SID is suppressed (age gate)", a is None)
    check("no anomalies recorded for new host",
          _anom_count(conn, "novel_sid") == 0)
    conn.close()


def scenario_external_ignored():
    print("Scenario 4: external source IP is ignored")
    conn = _fresh_conn()
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    a = spc.observe(conn, {
        "src_ip": "8.8.8.8",
        "timestamp": base.isoformat(),
        "alert": {"signature_id": 1},
    })
    check("external IP returns no anomaly", a is None)
    check("external IP creates no ip_state row",
          conn.execute("SELECT COUNT(*) FROM spc_ip_state").fetchone()[0] == 0)
    conn.close()


def main():
    print(f"Running SPC engine regression tests "
          f"(MIN_SAMPLES={spc.MIN_SAMPLES}, MIN_AGE_HOURS={spc.MIN_AGE_HOURS}, "
          f"SIGMA_THRESHOLD={spc.SIGMA_THRESHOLD}, MIN_SIGMA={spc.MIN_SIGMA})\n")
    scenario_chatty_host_spike_and_novel()
    scenario_quiet_established_host()
    scenario_new_host_suppressed()
    scenario_external_ignored()

    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): " + ", ".join(_failures))
        sys.exit(1)
    print("All SPC regression tests passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
