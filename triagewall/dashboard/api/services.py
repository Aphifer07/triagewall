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

# Investigation bounds.
#
# The window is capped at 24 hours rather than the 168 the timeline allows.
# src_ip and dest_ip are not indexed, so address correlation cannot be an index
# seek; it is a bounded scan, and a wider window would widen that scan without
# a production-shaped benchmark proving a query-time budget is still met.
#
# MAX_RELATED_CANDIDATE_ROWS is the second half of that bound. Every correlation
# view -- recurrence, same-rule activity and address matches -- examines at most
# this many of the newest rows in the window, selected through
# idx_triage_processed. Anything older inside the window is not examined, and
# the response says so via candidate_limit/truncated rather than implying the
# result is complete correlation across the whole window.
DEFAULT_INVESTIGATION_WINDOW_HOURS = 24
MAX_INVESTIGATION_WINDOW_HOURS = 24
MAX_RELATED_ALERTS = 10
MAX_RELATED_CANDIDATE_ROWS = 2_000

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
    source: str | None = None,
    review: str | None = None,
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
    if source == "suricata":
        # Rows created before source provenance was introduced are Suricata
        # rows: Wazuh support and sensor_event_context shipped together.
        where.append("(sensor.source_type = 'suricata' OR sensor.source_type IS NULL)")
    elif source == "wazuh":
        where.append("sensor.source_type = 'wazuh'")
    if review == "unreviewed":
        where.append("events.human_verdict IS NULL")
    elif review == "agreed":
        where.append("events.human_verdict IS NOT NULL AND events.agreed = 1")
    elif review == "corrected":
        where.append("events.human_verdict IS NOT NULL AND events.agreed = 0")
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

_VERDICT_DETAIL_SELECT = _VERDICT_SELECT.replace(
    "events.reasoning, events.model_used, events.processed_at,",
    "events.reasoning, events.raw_alert, events.model_used, events.processed_at,",
)


def fetch_verdicts(
    conn: sqlite3.Connection,
    *,
    verdict: str | None = None,
    signature: str | None = None,
    model: str | None = None,
    source: str | None = None,
    review: str | None = None,
    limit: int = DEFAULT_VERDICT_LIMIT,
    cursor: str | None = None,
) -> tuple[list[sqlite3.Row], str | None]:
    """Return verdict rows and an opaque next_cursor (or None)."""
    if limit < 1 or limit > MAX_VERDICT_LIMIT:
        raise HTTPException(
            status_code=422,
            detail=f"limit must be between 1 and {MAX_VERDICT_LIMIT}",
        )
    where, params = build_verdict_filters(
        verdict,
        signature,
        model,
        source,
        review,
    )
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


def fetch_verdict(conn: sqlite3.Connection, event_id: int) -> sqlite3.Row | None:
    """Return one complete decision, including its original sensor record."""
    return conn.execute(
        f"""{_VERDICT_DETAIL_SELECT}
            WHERE events.id = ?""",
        (event_id,),
    ).fetchone()


# --- Investigation context -------------------------------------------------
#
# Provenance is normalized the same way build_verdict_filters treats it: rows
# written before sensor_event_context existed are Suricata rows. Qualifying by
# source type is not cosmetic. Suricata stores its SID in signature_id while
# Wazuh stores rule.id there, so an unqualified group would silently merge two
# unrelated rules that happen to share an integer.
_SOURCE_TYPE_EXPR = "COALESCE(sensor.source_type, 'suricata')"

# The newest candidates in the window, ordered by the indexed column so
# idx_triage_processed drives the range. All correlation happens over this one
# bounded set; no investigation query scans a high-volume 24-hour window end to
# end or builds a new production index during deployment.
_RELATED_CANDIDATES_SQL = f"""
SELECT events.id, events.timestamp, events.processed_at,
       events.signature_id, events.signature, events.verdict,
       events.confidence, events.src_ip, events.dest_ip,
       {_SOURCE_TYPE_EXPR} AS source_type
FROM triage_events AS events
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
WHERE events.processed_at IS NOT NULL
  AND events.processed_at >= ?
ORDER BY events.processed_at DESC, events.id DESC
LIMIT ?
"""

_NEIGHBOR_SELECT = f"""
SELECT events.id, events.signature, events.verdict, events.processed_at,
       {_SOURCE_TYPE_EXPR} AS source_type
FROM triage_events AS events
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
"""

RELATIONSHIP_LABELS = {
    "same_rule": (
        "Same rule",
        "Same source type and signature id as this alert among the examined "
        "candidates. The scope below states whether the whole window was read.",
    ),
    "same_source_ip": (
        "Same source address",
        "Recorded src_ip is identical to this alert's src_ip. Shared "
        "addressing only; it does not establish a shared cause.",
    ),
    "same_destination_ip": (
        "Same destination address",
        "Recorded dest_ip is identical to this alert's dest_ip. Shared "
        "addressing only; it does not establish a shared cause.",
    ),
}


def _apply_ip_policy(
    value: str | None,
    *,
    mode: str,
    mask_ip_fn: Callable,
    redact_ips: bool,
    ip_secret: bytes | None,
) -> str | None:
    """Apply the same address-disclosure policy the verdict rows use."""
    if not value:
        return value
    if mode == "demo":
        return mask_ip_fn(value)
    if redact_ips:
        return hash_ip(value, ip_secret)
    return value


def _normalize_timestamp(value: str | None) -> str | None:
    """Re-canonicalize a stored timestamp, matching app.row_to_dict."""
    if not value:
        return None
    try:
        return format_utc_timestamp(value)
    except (TypeError, ValueError):
        return None


def _related_row_to_dict(
    row: sqlite3.Row,
    relationship: str,
    *,
    mode: str,
    mask_ip_fn: Callable,
    redact_ips: bool,
    ip_secret: bytes | None,
) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "timestamp": _normalize_timestamp(row["timestamp"]),
        "processed_at": _normalize_timestamp(row["processed_at"]),
        "signature_id": row["signature_id"],
        "signature": row["signature"],
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "src_ip": _apply_ip_policy(
            row["src_ip"],
            mode=mode,
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips,
            ip_secret=ip_secret,
        ),
        "dest_ip": _apply_ip_policy(
            row["dest_ip"],
            mode=mode,
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips,
            ip_secret=ip_secret,
        ),
        "source_type": row["source_type"],
        "relationship": relationship,
    }


def _neighbor_row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "signature": row["signature"],
        "verdict": row["verdict"],
        "processed_at": _normalize_timestamp(row["processed_at"]),
        "source_type": row["source_type"],
    }


def _fetch_neighbors(
    conn: sqlite3.Connection,
    *,
    anchor_id: int,
    anchor_processed_at: str | None,
    where: list[str],
    params: list[Any],
) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    """Return the (previous, next) rows around an anchor in queue order.

    Queue order is ``processed_at DESC NULLS LAST, id DESC``. "Next" is the row
    immediately after the anchor in that order (older); "previous" is the row
    immediately before it (newer). Filters are the caller's, so navigation stays
    inside whatever queue the analyst was looking at.
    """

    def run(extra_clauses: list[str], extra_params: list[Any], order: str):
        clauses = where + extra_clauses
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return conn.execute(
            f"""{_NEIGHBOR_SELECT}
                {where_sql}
                ORDER BY {order}
                LIMIT 1""",
            params + extra_params,
        ).fetchone()

    if anchor_processed_at is None:
        # Unprocessed rows sort last, ordered by descending id.
        next_row = run(
            ["events.processed_at IS NULL", "events.id < ?"],
            [anchor_id],
            "events.id DESC",
        )
        previous_row = run(
            ["events.processed_at IS NULL", "events.id > ?"],
            [anchor_id],
            "events.id ASC",
        )
        if previous_row is None:
            # Nothing unprocessed above it, so the neighbour is the oldest
            # processed row.
            previous_row = run(
                ["events.processed_at IS NOT NULL"],
                [],
                "events.processed_at ASC, events.id ASC",
            )
        return previous_row, next_row

    # Keep the timestamp tie and the adjacent timestamp as separate seeks.
    # Combining them with OR makes SQLite walk and order every row on the
    # newer side of an old alert before LIMIT 1 can apply. That was more than
    # five seconds on a production database even though each seek is instant.
    next_row = run(
        ["events.processed_at = ?", "events.id < ?"],
        [anchor_processed_at, anchor_id],
        "events.id DESC",
    )
    if next_row is None:
        next_row = run(
            ["events.processed_at < ?"],
            [anchor_processed_at],
            "events.processed_at DESC, events.id DESC",
        )
    if next_row is None:
        next_row = run(
            ["events.processed_at IS NULL"],
            [],
            "events.id DESC",
        )

    previous_row = run(
        ["events.processed_at = ?", "events.id > ?"],
        [anchor_processed_at, anchor_id],
        "events.id ASC",
    )
    if previous_row is None:
        previous_row = run(
            ["events.processed_at > ?"],
            [anchor_processed_at],
            "events.processed_at ASC, events.id ASC",
        )
    return previous_row, next_row


def fetch_investigation(
    conn: sqlite3.Connection,
    event_id: int,
    *,
    hours: int = DEFAULT_INVESTIGATION_WINDOW_HOURS,
    mode: str = "local",
    mask_ip_fn: Callable = lambda value: value,
    redact_ips: bool = False,
    ip_secret: bytes | None = None,
    verdict: str | None = None,
    signature: str | None = None,
    model: str | None = None,
    source: str | None = None,
    review: str | None = None,
) -> dict[str, Any] | None:
    """Return bounded recurrence, related activity and queue neighbours.

    Returns ``None`` when the anchor event does not exist, so the caller can
    answer 404 the same way the detail route does.
    """
    if hours < 1 or hours > MAX_INVESTIGATION_WINDOW_HOURS:
        raise HTTPException(
            status_code=422,
            detail=f"hours must be between 1 and {MAX_INVESTIGATION_WINDOW_HOURS}",
        )

    anchor = conn.execute(
        f"""SELECT events.id, events.processed_at, events.signature_id,
                   events.src_ip, events.dest_ip,
                   {_SOURCE_TYPE_EXPR} AS source_type
            FROM triage_events AS events
            LEFT JOIN sensor_event_context AS sensor
              ON sensor.triage_event_id = events.id
            WHERE events.id = ?""",
        (event_id,),
    ).fetchone()
    if anchor is None:
        return None

    window_start = format_utc_timestamp(utc_now() - timedelta(hours=hours))
    source_type = anchor["source_type"]
    signature_id = anchor["signature_id"]

    ip_policy = {
        "mode": mode,
        "mask_ip_fn": mask_ip_fn,
        "redact_ips": redact_ips,
        "ip_secret": ip_secret,
    }

    # Fetch one bounded candidate set for every correlation view. Over-fetch by
    # one row: exactly reaching the budget does not prove that anything was
    # omitted, while the extra row does.
    candidate_limit = MAX_RELATED_CANDIDATE_ROWS
    candidates: list[sqlite3.Row] = []
    candidates_truncated = False
    if signature_id is not None or anchor["src_ip"] or anchor["dest_ip"]:
        candidates = conn.execute(
            _RELATED_CANDIDATES_SQL,
            (window_start, candidate_limit + 1),
        ).fetchall()
        candidates_truncated = len(candidates) > candidate_limit
        if candidates_truncated:
            candidates = candidates[:candidate_limit]

    # Recurrence. A row without a signature_id has no group to belong to;
    # correlating on NULL would join every other signature-less row. Counts are
    # exact only when the candidate query proves it exhausted the whole window.
    if signature_id is None:
        recurrence = {
            "available": False,
            "signature_id": None,
            "source_type": source_type,
            "occurrences": 0,
            "first_seen": None,
            "last_seen": None,
            "real_count": 0,
            "false_positive_count": 0,
            "uncertain_count": 0,
            "unclassified_count": 0,
            "exact": False,
            "truncated": False,
            "candidate_limit": None,
            "candidates_examined": 0,
        }
    else:
        recurrence_rows = [
            candidate
            for candidate in candidates
            if candidate["signature_id"] == signature_id
            and candidate["source_type"] == source_type
        ]
        processed_values = [
            candidate["processed_at"]
            for candidate in recurrence_rows
            if candidate["processed_at"]
        ]
        recurrence = {
            "available": True,
            "signature_id": int(signature_id),
            "source_type": source_type,
            "occurrences": len(recurrence_rows),
            "first_seen": _normalize_timestamp(min(processed_values, default=None)),
            "last_seen": _normalize_timestamp(max(processed_values, default=None)),
            "real_count": sum(row["verdict"] == "real" for row in recurrence_rows),
            "false_positive_count": sum(
                row["verdict"] == "false_positive" for row in recurrence_rows
            ),
            "uncertain_count": sum(
                row["verdict"] == "uncertain" for row in recurrence_rows
            ),
            "unclassified_count": sum(
                row["verdict"] is None for row in recurrence_rows
            ),
            "exact": not candidates_truncated,
            "truncated": candidates_truncated,
            "candidate_limit": candidate_limit,
            "candidates_examined": len(candidates),
        }

    groups: list[dict[str, Any]] = []

    # Same rule uses the same bounded candidates as recurrence. This keeps one
    # frequent SID from monopolizing the dashboard and gives both panels the
    # same honest completeness boundary.
    rule_alerts: list[dict[str, Any]] = []
    if signature_id is not None:
        rule_rows = [
            candidate
            for candidate in candidates
            if int(candidate["id"]) != event_id
            and candidate["signature_id"] == signature_id
            and candidate["source_type"] == source_type
        ][:MAX_RELATED_ALERTS]
        rule_alerts = [
            _related_row_to_dict(r, "same_rule", **ip_policy) for r in rule_rows
        ]
    label, reason = RELATIONSHIP_LABELS["same_rule"]
    groups.append(
        {
            "relationship": "same_rule",
            "label": label,
            "reason": reason,
            "exact": signature_id is not None and not candidates_truncated,
            "truncated": signature_id is not None and candidates_truncated,
            "candidate_limit": candidate_limit if signature_id is not None else None,
            "candidates_examined": len(candidates) if signature_id is not None else 0,
            "alerts": rule_alerts,
        }
    )

    # Address groups are matched in application code over the same candidates.
    for relationship, column, anchor_value in (
        ("same_source_ip", "src_ip", anchor["src_ip"]),
        ("same_destination_ip", "dest_ip", anchor["dest_ip"]),
    ):
        label, reason = RELATIONSHIP_LABELS[relationship]
        alerts: list[dict[str, Any]] = []
        if anchor_value:
            for candidate in candidates:
                if len(alerts) >= MAX_RELATED_ALERTS:
                    break
                if int(candidate["id"]) == event_id:
                    continue
                if candidate[column] != anchor_value:
                    continue
                alerts.append(
                    _related_row_to_dict(candidate, relationship, **ip_policy)
                )
        groups.append(
            {
                "relationship": relationship,
                "label": label,
                "reason": reason,
                "exact": False,
                "truncated": bool(anchor_value) and candidates_truncated,
                "candidate_limit": candidate_limit,
                "candidates_examined": len(candidates) if anchor_value else 0,
                "alerts": alerts,
            }
        )

    where, params = build_verdict_filters(verdict, signature, model, source, review)
    previous_row, next_row = _fetch_neighbors(
        conn,
        anchor_id=int(anchor["id"]),
        anchor_processed_at=anchor["processed_at"],
        where=list(where),
        params=list(params),
    )

    return {
        "generated_at": utc_now_iso(),
        "event_id": int(anchor["id"]),
        "window_hours": hours,
        "window_start": window_start,
        "recurrence": recurrence,
        "related": groups,
        "neighbors": {
            "previous": _neighbor_row_to_dict(previous_row),
            "next": _neighbor_row_to_dict(next_row),
            "filters": {
                "verdict": verdict,
                "signature": signature,
                "model": model,
                "source": source,
                "review": review,
            },
        },
    }


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
