#!/usr/bin/env python3
"""Regression tests for bounded dashboard statistics."""

import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from triagewall.dashboard.stats import WINDOW_STATS_SQL, get_dashboard_stats


class DashboardStatsTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

        schema_path = PROJECT_ROOT / "triagewall" / "schema.sql"
        self.conn.executescript(schema_path.read_text())

    def tearDown(self):
        self.conn.close()

    def insert_event(
        self,
        signature_id,
        verdict,
        model_used,
        age_hours,
        human_verdict=None,
        agreed=None,
    ):
        """Insert a test event at a chosen age."""
        event_time = datetime.now(timezone.utc) - timedelta(
            hours=age_hours
        )
        event_time_iso = event_time.isoformat()

        self.conn.execute(
            """
            INSERT INTO triage_events (
                timestamp,
                signature_id,
                signature,
                raw_alert,
                verdict,
                model_used,
                processed_at,
                human_verdict,
                agreed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_time_iso,
                signature_id,
                f"Test alert {signature_id}",
                "{}",
                verdict,
                model_used,
                event_time_iso,
                human_verdict,
                agreed,
            ),
        )

    def test_stats_are_bounded_to_last_24_hours(self):
        self.insert_event(1001, "real", "prefilter", 1)
        self.insert_event(
            1002,
            "false_positive",
            "test-llm",
            2,
            human_verdict="false_positive",
            agreed=1,
        )
        self.insert_event(
            1003,
            "uncertain",
            "test-llm",
            3,
            human_verdict="real",
            agreed=0,
        )

        # This event contributes to the lifetime total, but not the 24-hour data.
        self.insert_event(
            1004,
            "real",
            "prefilter",
            25,
            human_verdict="real",
            agreed=1,
        )

        stats = get_dashboard_stats(self.conn)

        self.assertEqual(
            stats,
            {
                "total": 4,
                "real": 1,
                "real_": 1,
                "fp": 1,
                "unc": 1,
                "reviewed": 2,
                "agreed": 1,
                "disagreed": 1,
                "prefilter_count": 1,
                "llm_count": 2,
                "today_total": 3,
                "today_prefilter": 1,
                "today_llm": 2,
                "model_real_count": 0,
                "model_fp_count": 1,
                "model_uncertain_count": 1,
                "unreviewed_model_count": 0,
            },
        )

    def test_empty_database_returns_zeroes(self):
        stats = get_dashboard_stats(self.conn)

        self.assertTrue(
            all(value == 0 for value in stats.values()),
            stats,
        )

    def test_lifetime_total_survives_row_deletion(self):
        self.insert_event(2001, "real", "prefilter", 1)
        self.conn.execute("DELETE FROM triage_events")

        stats = get_dashboard_stats(self.conn)

        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["today_total"], 0)

    def test_window_query_uses_processed_at_index(self):
        cutoff = datetime.now(timezone.utc).isoformat()
        plan = self.conn.execute(
            "EXPLAIN QUERY PLAN " + WINDOW_STATS_SQL,
            (cutoff,),
        ).fetchall()

        details = " ".join(row[3] for row in plan)

        self.assertIn("SEARCH triage_events", details)
        self.assertIn("idx_triage_processed", details)


if __name__ == "__main__":
    unittest.main(verbosity=2)
