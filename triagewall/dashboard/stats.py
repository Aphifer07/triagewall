"""Bounded statistics queries for the dashboard."""

import sqlite3
from datetime import datetime, timedelta, timezone


STATS_WINDOW_HOURS = 24

WINDOW_STATS_SQL = """
SELECT
    COUNT(*) AS window_total,
    COALESCE(SUM(verdict = 'real'), 0) AS window_real,
    COALESCE(SUM(verdict = 'false_positive'), 0) AS window_fp,
    COALESCE(SUM(verdict = 'uncertain'), 0) AS window_uncertain,
    COALESCE(SUM(human_verdict IS NOT NULL), 0) AS window_reviewed,
    COALESCE(SUM(agreed = 1), 0) AS window_agreed,
    COALESCE(SUM(agreed = 0), 0) AS window_disagreed,
    COALESCE(SUM(model_used = 'prefilter'), 0) AS window_prefilter,
    COALESCE(SUM(model_used != 'prefilter'), 0) AS window_llm
FROM triage_events
WHERE processed_at >= ?
"""

LIFETIME_TOTAL_SQL = """
SELECT COALESCE(
    (
        SELECT seq
        FROM sqlite_sequence
        WHERE name = 'triage_events'
    ),
    0
) AS lifetime_total
"""


def get_dashboard_stats(conn: sqlite3.Connection) -> dict[str, int]:
    """Return 24-hour dashboard statistics and the lifetime event total."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        hours=STATS_WINDOW_HOURS
    )
    window = conn.execute(
        WINDOW_STATS_SQL,
        (cutoff.isoformat(),),
    ).fetchone()
    lifetime = conn.execute(LIFETIME_TOTAL_SQL).fetchone()

    return {
        "total": int(lifetime["lifetime_total"] or 0),
        "real_": int(window["window_real"] or 0),
        "fp": int(window["window_fp"] or 0),
        "unc": int(window["window_uncertain"] or 0),
        "reviewed": int(window["window_reviewed"] or 0),
        "agreed": int(window["window_agreed"] or 0),
        "disagreed": int(window["window_disagreed"] or 0),
        "prefilter_count": int(window["window_prefilter"] or 0),
        "llm_count": int(window["window_llm"] or 0),
        "today_total": int(window["window_total"] or 0),
        "today_prefilter": int(window["window_prefilter"] or 0),
        "today_llm": int(window["window_llm"] or 0),
    }
