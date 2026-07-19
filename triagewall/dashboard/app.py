#!/usr/bin/env python3
"""
Triage dashboard backend.

MODE=local  → full data, feedback enabled
MODE=demo   → IPs masked, feedback disabled, read-only

Run:
    uvicorn triagewall.dashboard.app:app --host 0.0.0.0 --port 8084
"""
import os
import json
import ipaddress
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, Body, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from triagewall.dashboard.stats import get_dashboard_stats
from triagewall.database import connect_database

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_dotenv(override: bool = False) -> None:
    """Minimal `.env` loader (stdlib-only)."""
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

MODE = os.environ.get("MODE", "local").lower()
STALE_THRESHOLD_SECONDS = int(os.environ.get("STALE_THRESHOLD_SECONDS", "600"))
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or "/var/lib/triagewall/triage.db"
)
STATIC_DIR = Path(__file__).parent / "static"
TRUSTED_HOSTS = {
    host.strip().lower().rstrip(".")
    for host in os.environ.get("TRUSTED_HOSTS", "localhost").split(",")
    if host.strip()
}

app = FastAPI(title="Triage Dashboard")

# --- Helpers -----------------------------------------------------------------

def _host_is_allowed(host_header):
    """Allow localhost, IP literals, and explicitly configured DNS names."""
    if not isinstance(host_header, str) or host_header != host_header.strip():
        return False
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    if not hostname:
        return False
    hostname = hostname.lower().rstrip(".")
    if hostname in TRUSTED_HOSTS:
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


@app.middleware("http")
async def enforce_trusted_host(request: Request, call_next):
    if not _host_is_allowed(request.headers.get("host", "")):
        return PlainTextResponse("Invalid host header", status_code=400)
    return await call_next(request)


@contextmanager
def db(readonly: bool = False):
    """
    Yield a SQLite connection and always close it after the request operation.
    - readonly=True → open in read-only mode for polling endpoints
    - readonly=False → standard read-write connection (used for feedback)
    """
    conn = connect_database(DB_PATH, readonly=readonly)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def mask_ip(ip):
    """Mask the last two octets of internal IPs in demo mode."""
    if not ip or MODE != "demo":
        return ip
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address in ipaddress.ip_network("10.0.0.0/8"):
        return "10.x.x.x"
    if address in ipaddress.ip_network("192.168.0.0/16"):
        return "192.168.x.x"
    return ip


def row_to_dict(row):
    d = dict(row)
    if MODE == "demo":
        d["src_ip"] = mask_ip(d.get("src_ip"))
        d["dest_ip"] = mask_ip(d.get("dest_ip"))
        # Demo responses contain no stored alert/model/analyst free text.
        d["raw_alert"] = None
        d["reasoning"] = None
        d["human_notes"] = None
    return d


# --- API endpoints -----------------------------------------------------------

@app.get("/api/verdicts")
def list_verdicts(
    verdict: str = None,
    signature: str = None,
    model: str = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    """Return a paginated list of verdicts plus summary stats."""
    where, params = [], []
    if verdict in ("real", "false_positive", "uncertain"):
        where.append("verdict = ?")
        params.append(verdict)
    if signature:
        where.append("signature LIKE ?")
        params.append(f"%{signature}%")
    if model == "llm":
        where.append("model_used != 'prefilter'")
    elif model == "prefilter":
        where.append("model_used = 'prefilter'")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Use a read-only connection for the high-frequency polling endpoint to reduce
    # lock contention with the ingest daemon.
    with db(readonly=True) as conn:
        rows = conn.execute(
            f"""SELECT id, timestamp, src_ip, src_port, dest_ip, dest_port, proto,
                       signature_id, signature, category, severity,
                       verdict, confidence, reasoning, model_used, processed_at,
                       human_verdict, human_notes, agreed, reviewed_at
                FROM triage_events {where_sql}
                ORDER BY processed_at DESC NULLS LAST, id DESC
                LIMIT ?""",
            params + [limit],
        ).fetchall()

    # Cache the bounded 24-hour aggregate so concurrent dashboard polls share
    # one result. The query itself remains safe after cache expiry because it
    # uses idx_triage_processed to seek to the cutoff.
    _now = _time.time()
    if (
        _stats_cache["data"] is not None
        and (_now - _stats_cache["ts"]) < _STATS_TTL
    ):
        stats_dict = _stats_cache["data"]
    else:
        with db(readonly=True) as conn:
            stats_dict = get_dashboard_stats(conn)

        _stats_cache["data"] = stats_dict
        _stats_cache["ts"] = _now

    return {
        "mode": MODE,
        "stats": stats_dict,
        "verdicts": [row_to_dict(r) for r in rows],
    }


@app.post("/api/feedback/{event_id}")
def submit_feedback(event_id: int, payload: dict = Body(...)):
    """Record human feedback on a verdict. Disabled in demo mode."""
    if MODE == "demo":
        raise HTTPException(403, "Feedback disabled in demo mode")

    human_verdict = payload.get("human_verdict")
    notes = payload.get("notes", "")
    if human_verdict not in ("real", "false_positive", "uncertain"):
        raise HTTPException(400, "human_verdict must be real | false_positive | uncertain")

    with db() as conn:
        row = conn.execute(
            "SELECT verdict FROM triage_events WHERE id = ?", (event_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        agreed = 1 if row["verdict"] == human_verdict else 0
        conn.execute(
            """UPDATE triage_events
               SET human_verdict = ?, human_notes = ?, agreed = ?, reviewed_at = ?
               WHERE id = ?""",
            (human_verdict, notes, agreed, datetime.now(timezone.utc).isoformat(), event_id),
        )
        conn.commit()
    return {"ok": True, "agreed": bool(agreed)}


@app.get("/api/health")
def health():
    last_processed_at = None
    with db(readonly=True) as conn:
        try:
            row = conn.execute(
                "SELECT MAX(processed_at) AS last_processed_at FROM triage_events"
            ).fetchone()
            if row:
                last_processed_at = row["last_processed_at"]
        except sqlite3.OperationalError:
            # If schema/table doesn't exist yet, treat as stale.
            last_processed_at = None

    now = datetime.now(timezone.utc)
    age_seconds = 10**9
    if last_processed_at:
        try:
            dt = datetime.fromisoformat(str(last_processed_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_seconds = int((now - dt).total_seconds())
        except Exception:
            age_seconds = 10**9

    payload = {"last_alert_age_seconds": max(0, age_seconds)}
    if age_seconds > STALE_THRESHOLD_SECONDS:
        payload["status"] = "stale"
        return JSONResponse(payload, status_code=503)
    payload["status"] = "ok"
    return payload



# --- lightweight TTL cache for expensive polling endpoints ---------------
import time as _time
_timeline_cache = {"data": None, "ts": 0.0}
_TIMELINE_TTL = 60.0  # seconds; hourly buckets don't change faster than this
_spc_cache = {"data": None, "ts": 0.0}
_SPC_TTL = 30.0  # seconds; anomalies arrive ~1-2/day, no need to re-query often
_stats_cache = {"data": None, "ts": 0.0}
_STATS_TTL = 30.0  # seconds; share one bounded aggregate across concurrent polls

@app.get("/api/timeline")
def timeline():
    """
    Return hourly buckets for the last 24 hours. Cached for _TIMELINE_TTL
    seconds so concurrent polls from multiple clients share one query result
    instead of each re-aggregating against the live (write-busy) DB.
    """
    now = _time.time()
    if _timeline_cache["data"] is not None and (now - _timeline_cache["ts"]) < _TIMELINE_TTL:
        return _timeline_cache["data"]
    # Bucket by processed_at so the timeline matches when Triagewall classified
    # alerts (consistent with the hero stat), not when Suricata first detected them.
    with db(readonly=True) as conn:
        rows = conn.execute(
            """
            SELECT
                strftime('%Y-%m-%d %H:00:00', processed_at) AS hour_bucket,
                COUNT(*) AS total_alerts,
                COALESCE(SUM(model_used = 'prefilter'), 0) AS prefiltered_count,
                COALESCE(SUM(verdict = 'real'), 0) AS real_count
            FROM triage_events
            WHERE processed_at >= datetime('now', '-24 hours')
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            """
        ).fetchall()

    out = []
    for r in rows:
        total = int(r["total_alerts"] or 0)
        pre = int(r["prefiltered_count"] or 0)
        real = int(r["real_count"] or 0)
        pct = (pre / total * 100.0) if total else 0.0
        # Append 'Z' suffix so JavaScript Date() parses as UTC, then
        # the frontend's toLocaleTimeString() can convert to user's local time.
        hour = (r["hour_bucket"] or "").replace(" ", "T")
        if hour and not hour.endswith("Z"):
            hour = hour + "Z"
        out.append(
            {
                "timestamp": hour,
                "total_alerts": total,
                "prefiltered_count": pre,
                "prefilter_percentage": pct,
                "real_count": real,
            }
        )
    _timeline_cache["data"] = out
    _timeline_cache["ts"] = now
    return out


@app.get("/api/spc-anomalies")
def spc_anomalies():
    """
    Recent SPC behavioral-baselining anomalies — an INDEPENDENT detection signal.

    These are surfaced regardless of any LLM verdict: an SPC anomaly means a host
    deviated from its own behavioral baseline (a rate spike, or a never-before-seen
    signature), which prompt injection cannot fake by rewriting alert text. The
    panel is intentionally not joined to or filtered by the verdict list, so a
    high-confidence LLM "false positive" can never suppress a behavioral anomaly.

    Cached briefly since anomalies arrive on the order of 1-2 per day.
    """
    now = _time.time()
    if _spc_cache["data"] is not None and (now - _spc_cache["ts"]) < _SPC_TTL:
        return _spc_cache["data"]

    out = {"anomalies": [], "available": True}
    with db(readonly=True) as conn:
        # The spc_anomalies table only exists once the SPC engine has run. Guard
        # so the dashboard degrades gracefully on installs without SPC.
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='spc_anomalies'"
        ).fetchone()
        if not exists:
            out["available"] = False
            _spc_cache["data"] = out
            _spc_cache["ts"] = now
            return out

        rows = conn.execute(
            """
            SELECT detected_at, feature, ip, signature_id, z, note
            FROM spc_anomalies
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

        # Also surface a count for the last 24h, so the panel can show recency.
        last24 = conn.execute(
            "SELECT COUNT(*) FROM spc_anomalies "
            "WHERE detected_at >= datetime('now', '-24 hours')"
        ).fetchone()[0]

    for r in rows:
        dt = r["detected_at"] or ""
        # Normalize to a JS-parseable UTC timestamp like the timeline endpoint.
        ts = dt.replace(" ", "T")
        if ts and not (ts.endswith("Z") or "+" in ts):
            ts = ts + "Z"
        out["anomalies"].append({
            "detected_at": ts,
            "feature": r["feature"],
            "ip": mask_ip(r["ip"]),
            "signature_id": r["signature_id"],
            "z": r["z"],
            "note": None if MODE == "demo" else r["note"],
        })
    out["count_24h"] = int(last24 or 0)

    _spc_cache["data"] = out
    _spc_cache["ts"] = now
    return out


# --- Static files ------------------------------------------------------------

@app.get("/")
@app.head("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
