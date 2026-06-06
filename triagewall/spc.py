"""
Behavioral baselining (SPC) — injection-immune detection layer.

Path B / thin slice: two features derived from the alert stream you already
collect (no flow logging, no extra telemetry). The feature extractor is kept
separate from the baseline engine so richer sources (Suricata flow events,
Zeek conn.log) can be added later WITHOUT touching the engine.

Features in this slice:
  - alert_rate   : alerts per hour for an internal source IP (rolling baseline,
                   3-sigma upper-bound anomaly).
  - novel_sid    : this IP triggered a signature_id it has never triggered
                   before (direct boolean trigger, not statistical).

Design rules (see spc-baselining-design.md):
  - Per internal source IP. Only baseline internal IPs (10.x ranges here).
  - Full stream: SPC sees every ingested alert, including ones the prefilter
    would call known-noise. Volume of known-noise IS a behavioral feature.
  - Cold-start: an IP is in 'learning' state until it has enough history;
    no anomalies are emitted during learning.
  - Precedence: an SPC anomaly is INDEPENDENT of the LLM verdict and is never
    suppressed by an LLM 'false_positive'. This module only records anomalies;
    surfacing logic must not let a text-verdict override spc_anomaly.

This module is intentionally dependency-free (stdlib only) and takes an open
sqlite3 connection from the caller so it shares the ingest transaction context.
"""
import ipaddress
import logging
import math
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# --- Tunables (could move to config later) ---
INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
SIGMA_THRESHOLD = 3.0          # 3-sigma upper bound for alert_rate
MIN_SIGMA = 1.0                # floor: a perfectly stable baseline (sigma=0)
                               # must still flag gross deviations. Without this,
                               # a device with very regular behavior (sigma~0,
                               # e.g. IoT beacons) could never trip 3-sigma.
MIN_SAMPLES = 24               # need >= this many hourly buckets before alerting
MIN_AGE_HOURS = 24             # and >= this much wall-clock history
RATE_BUCKET = "%Y-%m-%dT%H"    # hourly bucket key (truncate timestamp to hour)


SCHEMA = """
CREATE TABLE IF NOT EXISTS spc_ip_state (
    ip            TEXT PRIMARY KEY,
    first_seen    TEXT,
    last_seen     TEXT,
    sample_count  INTEGER DEFAULT 0,   -- number of completed hourly buckets seen
    state         TEXT DEFAULT 'learning'
);

CREATE TABLE IF NOT EXISTS spc_rate_buckets (
    ip            TEXT,
    bucket        TEXT,                -- hour key, e.g. 2026-06-05T14
    count         INTEGER DEFAULT 0,
    PRIMARY KEY (ip, bucket)
);

CREATE TABLE IF NOT EXISTS spc_seen_sids (
    ip            TEXT,
    signature_id  INTEGER,
    first_seen    TEXT,
    PRIMARY KEY (ip, signature_id)
);

CREATE TABLE IF NOT EXISTS spc_anomalies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ip             TEXT,
    feature        TEXT,
    value          REAL,
    mean           REAL,
    sigma          REAL,
    z              REAL,
    detected_at    TEXT,
    signature_id   INTEGER,
    note           TEXT
);

CREATE INDEX IF NOT EXISTS idx_spc_anom_ip ON spc_anomalies(ip);
CREATE INDEX IF NOT EXISTS idx_spc_anom_detected ON spc_anomalies(detected_at);
CREATE INDEX IF NOT EXISTS idx_spc_buckets_ip ON spc_rate_buckets(ip);
"""


def ensure_spc_schema(conn):
    conn.executescript(SCHEMA)
    conn.commit()


# --- Feature extraction (swappable; this is the AlertStreamExtractor) ---

def _is_internal(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def extract(event):
    """Map a raw Suricata alert event to the fields SPC needs.
    Returns None if the event has no internal source IP to baseline."""
    src_ip = event.get("src_ip") or event.get("alert", {}).get("source", {}).get("ip")
    if not _is_internal(src_ip):
        return None
    sig_id = event.get("alert", {}).get("signature_id")
    ts = event.get("timestamp")
    return {"ip": src_ip, "signature_id": sig_id, "timestamp": ts}


# --- helpers ---

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _bucket_key(ts_iso):
    """Truncate an ISO timestamp to the hour bucket. Falls back to now."""
    try:
        # Suricata timestamps look like 2026-06-05T14:38:55.230939+0000
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        dt = datetime.now(timezone.utc)
    return dt.strftime(RATE_BUCKET)


def _rolling_stats(conn, ip, exclude_bucket):
    """Mean and population stddev of hourly counts for an IP, excluding the
    in-progress current bucket. Welford over the stored buckets."""
    rows = conn.execute(
        "SELECT count FROM spc_rate_buckets WHERE ip = ? AND bucket != ?",
        (ip, exclude_bucket),
    ).fetchall()
    counts = [r[0] for r in rows]
    n = len(counts)
    if n == 0:
        return 0.0, 0.0, 0
    mean = sum(counts) / n
    if n == 1:
        return mean, 0.0, n
    var = sum((c - mean) ** 2 for c in counts) / n
    return mean, math.sqrt(var), n


# --- main entry point, called once per ingested alert ---

def observe(conn, event):
    """
    Update behavioral baselines for one alert and record any anomalies.
    Safe to call on EVERY ingested alert (full stream). Uses the caller's
    connection; does not commit (caller's transaction owns the commit).

    Returns a dict describing any anomaly detected, or None.
    """
    feat = extract(event)
    if feat is None:
        return None
    ip = feat["ip"]
    sig_id = feat["signature_id"]
    ts = feat["timestamp"] or _now_iso()
    bucket = _bucket_key(ts)
    # Drive all time reasoning off the EVENT timestamp, not the wall clock, so
    # SPC behaves identically on live and on replayed/backfilled data.
    now = ts

    anomalies = []

    # --- IP state / cold-start tracking ---
    row = conn.execute(
        "SELECT first_seen, sample_count, state FROM spc_ip_state WHERE ip = ?",
        (ip,),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO spc_ip_state (ip, first_seen, last_seen, sample_count, state) "
            "VALUES (?, ?, ?, 0, 'learning')",
            (ip, now, now),
        )
        first_seen, sample_count, state = now, 0, "learning"
    else:
        first_seen, sample_count, state = row
        conn.execute("UPDATE spc_ip_state SET last_seen = ? WHERE ip = ?", (now, ip))

    # --- feature: novel_sid (boolean trigger) ---
    if sig_id is not None:
        seen = conn.execute(
            "SELECT 1 FROM spc_seen_sids WHERE ip = ? AND signature_id = ?",
            (ip, sig_id),
        ).fetchone()
        if seen is None:
            conn.execute(
                "INSERT OR IGNORE INTO spc_seen_sids (ip, signature_id, first_seen) "
                "VALUES (?, ?, ?)",
                (ip, sig_id, now),
            )
            # Only an anomaly once the IP is out of learning (it has a baseline
            # of what it normally does). A brand-new IP triggers many "novel"
            # SIDs by definition; that's not signal.
            if state == "active":
                anomalies.append({
                    "ip": ip, "feature": "novel_sid", "value": float(sig_id),
                    "mean": 0.0, "sigma": 0.0, "z": 0.0,
                    "signature_id": sig_id,
                    "note": f"IP triggered signature_id {sig_id} for the first time",
                })

    # --- feature: alert_rate (3-sigma upper bound on hourly count) ---
    # Compute baseline from completed buckets BEFORE incrementing this one.
    mean, sigma, n_buckets = _rolling_stats(conn, ip, exclude_bucket=bucket)

    # increment current hourly bucket
    conn.execute(
        "INSERT INTO spc_rate_buckets (ip, bucket, count) VALUES (?, ?, 1) "
        "ON CONFLICT(ip, bucket) DO UPDATE SET count = count + 1",
        (ip, bucket),
    )
    cur_count = conn.execute(
        "SELECT count FROM spc_rate_buckets WHERE ip = ? AND bucket = ?",
        (ip, bucket),
    ).fetchone()[0]

    # cold-start gate: enough completed buckets AND enough wall-clock age
    age_ok = _age_hours(first_seen, now) >= MIN_AGE_HOURS
    samples_ok = n_buckets >= MIN_SAMPLES
    if state == "learning" and age_ok and samples_ok:
        conn.execute("UPDATE spc_ip_state SET state = 'active' WHERE ip = ?", (ip,))
        state = "active"

    if state == "active":
        eff_sigma = max(sigma, MIN_SIGMA)
        z = (cur_count - mean) / eff_sigma
        if z >= SIGMA_THRESHOLD:
            # Fire at most once per (ip, bucket): a spiking hour produces ONE
            # anomaly, not one per alert in that hour.
            already = conn.execute(
                "SELECT 1 FROM spc_anomalies "
                "WHERE ip = ? AND feature = 'alert_rate' AND note LIKE ?",
                (ip, f"%[bucket:{bucket}]%"),
            ).fetchone()
            if already is None:
                anomalies.append({
                    "ip": ip, "feature": "alert_rate", "value": float(cur_count),
                    "mean": mean, "sigma": eff_sigma, "z": z,
                    "signature_id": sig_id,
                    "note": f"alert_rate {cur_count}/hr vs baseline {mean:.1f}±{sigma:.1f} (z={z:.1f}) [bucket:{bucket}]",
                })

    # bump completed-bucket sample_count when a NEW bucket appears for this IP
    # (cheap heuristic: count distinct buckets seen)
    conn.execute(
        "UPDATE spc_ip_state SET sample_count = "
        "(SELECT COUNT(*) FROM spc_rate_buckets WHERE ip = ?) WHERE ip = ?",
        (ip, ip),
    )

    # --- record anomalies ---
    for a in anomalies:
        conn.execute(
            "INSERT INTO spc_anomalies "
            "(ip, feature, value, mean, sigma, z, detected_at, signature_id, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (a["ip"], a["feature"], a["value"], a["mean"], a["sigma"], a["z"],
             now, a["signature_id"], a["note"]),
        )
        log.info(f"[SPC anomaly] {a['note']} (ip={a['ip']})")

    return anomalies[0] if anomalies else None


def _age_hours(first_seen_iso, now_iso):
    try:
        a = datetime.fromisoformat(first_seen_iso.replace("Z", "+00:00"))
        b = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        return (b - a).total_seconds() / 3600.0
    except (ValueError, AttributeError, TypeError):
        return 0.0
