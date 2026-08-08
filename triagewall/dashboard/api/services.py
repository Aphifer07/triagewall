"""Shared dashboard API query helpers used by v1 and legacy aliases."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
from datetime import timedelta
from typing import Any, Callable

from fastapi import HTTPException

from triagewall.dashboard.api.pseudonym import (
    IpPseudonymConfigError,
    pseudonymize_ip,
)
from triagewall.dashboard.stats import get_dashboard_stats
from triagewall.storage import get_storage_metrics
from triagewall.time_utils import (
    format_utc_timestamp,
    parse_utc_timestamp,
    utc_now,
    utc_now_iso,
)

STATS_TTL = 30.0
TIMELINE_TTL = 60.0
SPC_TTL = 30.0
MAX_TIMELINE_HOURS = 168
MAX_VERDICT_LIMIT = 500
DEFAULT_VERDICT_LIMIT = 100

# Bounds on free-form input. These exist so one request cannot make the
# database or the application do unbounded work: a long LIKE pattern is scanned
# against every candidate row, and an oversized cursor or note is stored and
# echoed back. The values are generous for real use and documented in
# docs/api.md.
MAX_SIGNATURE_SEARCH_LENGTH = 200
MAX_CURSOR_LENGTH = 512
MAX_FEEDBACK_NOTES_LENGTH = 2_000

_stats_cache: dict[str, Any] = {"data": None, "ts": 0.0, "generated_at": None}
_timeline_cache: dict[str, Any] = {"data": None, "ts": 0.0, "key": None}
_spc_cache: dict[str, Any] = {"data": None, "ts": 0.0}


def reset_caches() -> None:
    """Clear TTL caches (tests)."""
    _stats_cache.update(data=None, ts=0.0, generated_at=None)
    _timeline_cache.update(data=None, ts=0.0, key=None)
    _spc_cache.update(data=None, ts=0.0)


def hash_ip(ip: str | None, secret: bytes | None = None) -> str | None:
    """Pseudonymize one IP address for API output.

    Keyed with HMAC-SHA256: an unsalted digest of an IP address is reversible
    by exhaustive search, so it never provided the redaction it implied. The
    secret is validated at startup, which is why it is required here.
    """
    if not ip:
        return ip
    if not secret:
        raise IpPseudonymConfigError(
            "IP redaction is enabled but no pseudonymization secret is loaded"
        )
    return pseudonymize_ip(ip, secret)


def encode_cursor(processed_at: str | None, event_id: int) -> str:
    payload = json.dumps(
        {"p": processed_at, "i": event_id},
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[str | None, int]:
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + padding)
        payload = json.loads(raw.decode("utf-8"))
        event_id = int(payload["i"])
        processed_at = payload.get("p")
        if processed_at is not None and not isinstance(processed_at, str):
            raise ValueError("invalid processed_at")
        return processed_at, event_id
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=422, detail="invalid cursor") from exc


def build_verdict_filters(
    verdict: str | None,
    signature: str | None,
    model: str | None,
) -> tuple[list[str], list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    if verdict in ("real", "false_positive", "uncertain"):
        where.append("events.verdict = ?")
        params.append(verdict)
    if signature:
        where.append("events.signature LIKE ?")
        params.append(f"%{signature}%")
    if model == "llm":
        where.append("events.model_used != 'prefilter'")
    elif model == "prefilter":
        where.append("events.model_used = 'prefilter'")
    return where, params


_VERDICT_SELECT = """
SELECT events.id, events.timestamp, events.src_ip, events.src_port,
       events.dest_ip, events.dest_port, events.proto,
       events.signature_id, events.signature, events.category,
       events.severity, events.verdict, events.confidence,
       events.reasoning, events.model_used, events.processed_at,
       events.human_verdict, events.human_notes, events.agreed,
       events.reviewed_at,
       src_snapshot.asset_json AS src_asset_json,
       dest_snapshot.asset_json AS dest_asset_json,
       sensor.source_type AS sensor_source,
       sensor.source_instance AS sensor_instance,
       sensor.source_event_id AS sensor_event_id,
       sensor.agent_id AS sensor_agent_id,
       sensor.agent_name AS sensor_agent_name
FROM triage_events AS events
LEFT JOIN asset_snapshots AS src_snapshot
  ON src_snapshot.id = events.src_asset_snapshot_id
LEFT JOIN asset_snapshots AS dest_snapshot
  ON dest_snapshot.id = events.dest_asset_snapshot_id
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
"""


def fetch_verdicts(
    conn: sqlite3.Connection,
    *,
    verdict: str | None = None,
    signature: str | None = None,
    model: str | None = None,
    limit: int = DEFAULT_VERDICT_LIMIT,
    cursor: str | None = None,
) -> tuple[list[sqlite3.Row], str | None]:
    """Return verdict rows and an opaque next_cursor (or None)."""
    if limit < 1 or limit > MAX_VERDICT_LIMIT:
        raise HTTPException(
            status_code=422,
            detail=f"limit must be between 1 and {MAX_VERDICT_LIMIT}",
        )
    where, params = build_verdict_filters(verdict, signature, model)
    if cursor:
        processed_at, event_id = decode_cursor(cursor)
        where.append(
            """(
                (
                    ? IS NOT NULL
                    AND (
                        events.processed_at < ?
                        OR (events.processed_at = ? AND events.id < ?)
                        OR events.processed_at IS NULL
                    )
                )
                OR (
                    ? IS NULL
                    AND events.processed_at IS NULL
                    AND events.id < ?
                )
            )"""
        )
        params.extend(
            [
                processed_at,
                processed_at,
                processed_at,
                event_id,
                processed_at,
                event_id,
            ]
        )
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(
        f"""{_VERDICT_SELECT}
            {where_sql}
            ORDER BY events.processed_at DESC NULLS LAST, events.id DESC
            LIMIT ?""",
        params + [limit + 1],
    ).fetchall()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = encode_cursor(last["processed_at"], int(last["id"]))
    elif rows:
        # Exact page with no more rows.
        next_cursor = None
    return list(rows), next_cursor


def get_cached_stats(
    db_factory: Callable[..., Any],
) -> tuple[dict[str, int], str]:
    now = time.time()
    if (
        _stats_cache["data"] is not None
        and (now - _stats_cache["ts"]) < STATS_TTL
    ):
        return _stats_cache["data"], _stats_cache["generated_at"]
    with db_factory(readonly=True) as conn:
        stats = get_dashboard_stats(conn)
    generated_at = utc_now_iso()
    _stats_cache["data"] = stats
    _stats_cache["ts"] = now
    _stats_cache["generated_at"] = generated_at
    return stats, generated_at


def get_timeline(
    db_factory: Callable[..., Any],
    *,
    hours: int = 24,
    interval: str = "1h",
) -> tuple[list[dict[str, Any]], str]:
    if hours < 1 or hours > MAX_TIMELINE_HOURS:
        raise HTTPException(
            status_code=422,
            detail=f"hours must be between 1 and {MAX_TIMELINE_HOURS}",
        )
    if interval != "1h":
        raise HTTPException(
            status_code=422,
            detail="interval must be 1h",
        )
    cache_key = (hours, interval)
    now = time.time()
    if (
        _timeline_cache["data"] is not None
        and _timeline_cache["key"] == cache_key
        and (now - _timeline_cache["ts"]) < TIMELINE_TTL
    ):
        return _timeline_cache["data"]["buckets"], _timeline_cache["data"][
            "generated_at"
        ]

    cutoff = format_utc_timestamp(utc_now() - timedelta(hours=hours))
    with db_factory(readonly=True) as conn:
        rows = conn.execute(
            """
            SELECT
                strftime('%Y-%m-%dT%H:00:00.000000Z', processed_at) AS hour_bucket,
                COUNT(*) AS total_alerts,
                COALESCE(SUM(model_used = 'prefilter'), 0) AS prefiltered_count,
                COALESCE(SUM(verdict = 'real'), 0) AS real_count
            FROM triage_events
            WHERE processed_at >= ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            """,
            (cutoff,),
        ).fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        total = int(row["total_alerts"] or 0)
        pre = int(row["prefiltered_count"] or 0)
        real = int(row["real_count"] or 0)
        pct = (pre / total * 100.0) if total else 0.0
        out.append(
            {
                "timestamp": row["hour_bucket"] or "",
                "total_alerts": total,
                "prefiltered_count": pre,
                "prefilter_percentage": pct,
                "real_count": real,
            }
        )
        if len(out) >= MAX_TIMELINE_HOURS:
            break

    generated_at = utc_now_iso()
    payload = {"buckets": out, "generated_at": generated_at}
    _timeline_cache["data"] = payload
    _timeline_cache["ts"] = now
    _timeline_cache["key"] = cache_key
    return out, generated_at


def get_spc_anomalies(
    db_factory: Callable[..., Any],
    *,
    mode: str,
    mask_ip_fn: Callable[[str | None], str | None],
    redact_ips: bool,
    ip_secret: bytes | None = None,
) -> tuple[dict[str, Any], str]:
    now = time.time()
    if _spc_cache["data"] is not None and (now - _spc_cache["ts"]) < SPC_TTL:
        return _spc_cache["data"]["payload"], _spc_cache["data"]["generated_at"]

    out: dict[str, Any] = {"anomalies": [], "available": True}
    with db_factory(readonly=True) as conn:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='spc_anomalies'"
        ).fetchone()
        if not exists:
            out["available"] = False
            generated_at = utc_now_iso()
            _spc_cache["data"] = {"payload": out, "generated_at": generated_at}
            _spc_cache["ts"] = now
            return out, generated_at

        rows = conn.execute(
            """
            SELECT detected_at, feature, ip, signature_id, z, note
            FROM spc_anomalies
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()
        cutoff = format_utc_timestamp(utc_now() - timedelta(hours=24))
        last24 = conn.execute(
            "SELECT COUNT(*) FROM spc_anomalies WHERE detected_at >= ?",
            (cutoff,),
        ).fetchone()[0]

    for row in rows:
        try:
            ts = format_utc_timestamp(row["detected_at"])
        except (TypeError, ValueError):
            ts = None
        ip_value = mask_ip_fn(row["ip"]) if mode == "demo" else row["ip"]
        if redact_ips and mode != "demo":
            ip_value = hash_ip(ip_value, ip_secret)
        out["anomalies"].append(
            {
                "detected_at": ts,
                "feature": row["feature"],
                "ip": ip_value,
                "signature_id": row["signature_id"],
                "z": row["z"],
                "note": None if mode == "demo" else row["note"],
            }
        )
    out["count_24h"] = int(last24 or 0)
    generated_at = utc_now_iso()
    _spc_cache["data"] = {"payload": out, "generated_at": generated_at}
    _spc_cache["ts"] = now
    return out, generated_at


def compute_health(
    db_factory: Callable[..., Any],
    db_path: Any,
    *,
    stale_threshold_seconds: int,
    include_storage: bool,
) -> tuple[dict[str, Any], int]:
    last_processed_at = None
    storage = None
    with db_factory(readonly=True) as conn:
        try:
            row = conn.execute(
                "SELECT MAX(processed_at) AS last_processed_at FROM triage_events"
            ).fetchone()
            if row:
                last_processed_at = row["last_processed_at"]
            if include_storage:
                storage = get_storage_metrics(conn, db_path)
        except sqlite3.OperationalError:
            last_processed_at = None

    age_seconds = 10**9
    if last_processed_at:
        try:
            dt = parse_utc_timestamp(str(last_processed_at))
            age_seconds = int((utc_now() - dt).total_seconds())
        except Exception:
            age_seconds = 10**9

    payload: dict[str, Any] = {
        "last_alert_age_seconds": max(0, age_seconds),
        "generated_at": utc_now_iso(),
    }
    if include_storage:
        payload["storage"] = storage
    status_code = 200
    if age_seconds > stale_threshold_seconds:
        payload["status"] = "stale"
        status_code = 503
    else:
        payload["status"] = "ok"
    return payload, status_code


def submit_feedback(
    db_factory: Callable[..., Any],
    *,
    mode: str,
    event_id: int,
    human_verdict: str,
    notes: str,
) -> dict[str, Any]:
    if mode == "demo":
        raise HTTPException(403, "Feedback disabled in demo mode")
    if human_verdict not in ("real", "false_positive", "uncertain"):
        raise HTTPException(
            400,
            "human_verdict must be real | false_positive | uncertain",
        )
    with db_factory() as conn:
        row = conn.execute(
            "SELECT verdict FROM triage_events WHERE id = ?",
            (event_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        agreed = 1 if row["verdict"] == human_verdict else 0
        conn.execute(
            """UPDATE triage_events
               SET human_verdict = ?, human_notes = ?, agreed = ?, reviewed_at = ?
               WHERE id = ?""",
            (human_verdict, notes, agreed, utc_now_iso(), event_id),
        )
        conn.commit()
    return {"ok": True, "agreed": bool(agreed)}
