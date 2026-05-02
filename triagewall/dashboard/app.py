#!/usr/bin/env python3
"""
Triage dashboard backend.

MODE=local  → full data, feedback enabled
MODE=demo   → IPs masked, feedback disabled, read-only

Run:
    uvicorn app:app --host 0.0.0.0 --port 8084
"""
import os
import re
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

MODE = os.getenv("MODE", "local").lower()
DB_PATH = Path(os.getenv("TRIAGE_DB", "/var/lib/triagewall/triage.db"))
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Triage Dashboard")

# --- Helpers -----------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def mask_ip(ip):
    """Mask the last two octets of internal IPs in demo mode."""
    if not ip or MODE != "demo":
        return ip
    # RFC1918 ranges we care about: 10.0.0.0/8, 192.168.0.0/16
    m = re.match(r"^(10|192\.168)\.(\d+)\.(\d+)\.(\d+)$", ip)
    if m:
        prefix = m.group(1)
        return f"{prefix}.x.x.x" if prefix == "10" else f"192.168.x.x"
    return ip


def row_to_dict(row):
    d = dict(row)
    if MODE == "demo":
        d["src_ip"] = mask_ip(d.get("src_ip"))
        d["dest_ip"] = mask_ip(d.get("dest_ip"))
        # Don't leak the raw alert JSON in demo mode
        d["raw_alert"] = None
    return d


# --- API endpoints -----------------------------------------------------------

@app.get("/api/verdicts")
def list_verdicts(verdict: str = None, signature: str = None, model: str = None, limit: int = 100):
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

    with db() as conn:
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

        stats = conn.execute(
            """SELECT
                COUNT(*) AS total,
                SUM(verdict = 'real') AS real_,
                SUM(verdict = 'false_positive') AS fp,
                SUM(verdict = 'uncertain') AS unc,
                SUM(human_verdict IS NOT NULL) AS reviewed,
                SUM(agreed = 1) AS agreed,
                SUM(agreed = 0) AS disagreed
                FROM triage_events"""
        ).fetchone()

    return {
        "mode": MODE,
        "stats": dict(stats),
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
    return {"status": "ok", "mode": MODE, "db_exists": DB_PATH.exists()}


# --- Static files ------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
