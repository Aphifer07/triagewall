#!/usr/bin/env python3
"""API v1 contract, auth, pagination, and legacy-alias regressions."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from triagewall.dashboard import app as dashboard
from triagewall.dashboard.api.auth import (
    API_KEY_HEADER_NAME,
    DASHBOARD_WRITE_COOKIE,
    SCOPE_FEEDBACK_WRITE,
    SCOPE_READ,
    parse_api_keys,
)
from triagewall.dashboard.api import services
from triagewall.time_utils import format_utc_timestamp


def _sha256_hex(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class ApiV1Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "triage.db"
        conn = sqlite3.connect(self.db_path)
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        now = datetime.now(timezone.utc)
        for index in range(3):
            event_time = now - timedelta(minutes=index)
            conn.execute(
                """
                INSERT INTO triage_events (
                    timestamp, signature_id, signature, raw_alert, verdict,
                    confidence, reasoning, model_used, processed_at, src_ip, dest_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    format_utc_timestamp(event_time),
                    1000 + index,
                    f"Signature {index}",
                    "{}",
                    "real" if index == 0 else "false_positive",
                    0.9,
                    "reason",
                    "test-llm",
                    format_utc_timestamp(event_time),
                    "10.0.0.5",
                    "192.168.1.20",
                ),
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS spc_anomalies (
                id INTEGER PRIMARY KEY, detected_at TEXT, feature TEXT, ip TEXT,
                signature_id INTEGER, z REAL, note TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO spc_anomalies VALUES (1, ?, ?, ?, ?, ?, ?)",
            (
                format_utc_timestamp(now),
                "novel_sid",
                "10.0.0.5",
                1000,
                3.1,
                "note",
            ),
        )
        conn.commit()
        conn.close()

        self.old_db_path = dashboard.DB_PATH
        self.old_mode = dashboard.MODE
        self.old_redact = dashboard.API_REDACT_IPS
        self.old_keys = dashboard.auth_state.keys
        self.old_secret = dashboard.auth_state.dashboard_write_secret
        self.old_allow = dashboard.auth_state.allow_unauthenticated_reads

        dashboard.DB_PATH = self.db_path
        dashboard.MODE = "local"
        dashboard.API_REDACT_IPS = False
        dashboard.auth_state.allow_unauthenticated_reads = True
        dashboard.auth_state.dashboard_write_secret = "test-dashboard-secret"
        self.plaintext_key = "test-api-key-value"
        self.read_only_key = "read-only-key"
        dashboard.auth_state.keys = parse_api_keys(
            "operator:"
            f"{_sha256_hex(self.plaintext_key)}:"
            f"{SCOPE_READ}|{SCOPE_FEEDBACK_WRITE},"
            f"reader:{_sha256_hex(self.read_only_key)}:{SCOPE_READ}"
        )
        services.reset_caches()
        self.client = TestClient(dashboard.app)
        self.host = {"host": "localhost"}

    def tearDown(self):
        dashboard.DB_PATH = self.old_db_path
        dashboard.MODE = self.old_mode
        dashboard.API_REDACT_IPS = self.old_redact
        dashboard.auth_state.keys = self.old_keys
        dashboard.auth_state.dashboard_write_secret = self.old_secret
        dashboard.auth_state.allow_unauthenticated_reads = self.old_allow
        services.reset_caches()
        self.temp_dir.cleanup()

    def test_v1_health_has_no_storage(self):
        response = self.client.get("/api/v1/health", headers=self.host)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertIn("generated_at", payload)
        self.assertNotIn("storage", payload)

    def test_legacy_health_includes_storage(self):
        response = self.client.get("/api/health", headers=self.host)
        self.assertEqual(response.status_code, 200)
        self.assertIn("storage", response.json())
        self.assertGreater(response.json()["storage"]["database_bytes"], 0)

    def test_stats_split_from_verdicts(self):
        stats = self.client.get("/api/v1/stats", headers=self.host).json()
        verdicts = self.client.get("/api/v1/verdicts", headers=self.host).json()
        self.assertIn("stats", stats)
        self.assertEqual(stats["stats"]["real"], stats["stats"]["real_"])
        self.assertNotIn("stats", verdicts)
        self.assertIn("verdicts", verdicts)
        self.assertIn("next_cursor", verdicts)

    def test_legacy_verdicts_still_combined(self):
        payload = self.client.get("/api/verdicts", headers=self.host).json()
        self.assertIn("stats", payload)
        self.assertIn("verdicts", payload)
        self.assertEqual(payload["stats"]["real"], payload["stats"]["real_"])

    def test_feedback_requires_credential(self):
        response = self.client.post(
            "/api/v1/feedback/1",
            headers=self.host,
            json={"human_verdict": "real"},
        )
        self.assertEqual(response.status_code, 401)

    def test_feedback_with_api_key(self):
        response = self.client.post(
            "/api/v1/feedback/1",
            headers={**self.host, API_KEY_HEADER_NAME: self.plaintext_key},
            json={"human_verdict": "false_positive"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertFalse(response.json()["agreed"])

    def test_feedback_rejects_read_only_key(self):
        response = self.client.post(
            "/api/v1/feedback/1",
            headers={**self.host, API_KEY_HEADER_NAME: self.read_only_key},
            json={"human_verdict": "real"},
        )
        self.assertEqual(response.status_code, 401)

    def test_dashboard_cookie_allows_legacy_feedback(self):
        self.client.get("/", headers=self.host)
        self.assertIn(DASHBOARD_WRITE_COOKIE, self.client.cookies)
        response = self.client.post(
            "/api/feedback/1",
            headers=self.host,
            json={"human_verdict": "real"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["agreed"])

    def test_feedback_validation_failure(self):
        response = self.client.post(
            "/api/v1/feedback/1",
            headers={**self.host, API_KEY_HEADER_NAME: self.plaintext_key},
            json={"human_verdict": "not-a-verdict"},
        )
        self.assertEqual(response.status_code, 422)

    def test_verdicts_cursor_pagination(self):
        first = self.client.get(
            "/api/v1/verdicts?limit=2",
            headers=self.host,
        ).json()
        self.assertEqual(len(first["verdicts"]), 2)
        self.assertIsNotNone(first["next_cursor"])
        second = self.client.get(
            f"/api/v1/verdicts?limit=2&cursor={first['next_cursor']}",
            headers=self.host,
        ).json()
        self.assertEqual(len(second["verdicts"]), 1)
        self.assertIsNone(second["next_cursor"])
        first_ids = {row["id"] for row in first["verdicts"]}
        second_ids = {row["id"] for row in second["verdicts"]}
        self.assertTrue(first_ids.isdisjoint(second_ids))

    def test_verdicts_invalid_cursor(self):
        response = self.client.get(
            "/api/v1/verdicts?cursor=not-valid",
            headers=self.host,
        )
        self.assertEqual(response.status_code, 422)

    def test_verdicts_empty_page(self):
        response = self.client.get(
            "/api/v1/verdicts?verdict=uncertain",
            headers=self.host,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["verdicts"], [])
        self.assertIsNone(payload["next_cursor"])

    def test_timeline_parameters_and_validation(self):
        ok = self.client.get(
            "/api/v1/timeline?hours=24&interval=1h",
            headers=self.host,
        )
        self.assertEqual(ok.status_code, 200)
        body = ok.json()
        self.assertEqual(body["hours"], 24)
        self.assertEqual(body["interval"], "1h")
        self.assertIn("buckets", body)

        bad_hours = self.client.get(
            "/api/v1/timeline?hours=999",
            headers=self.host,
        )
        self.assertEqual(bad_hours.status_code, 422)

        bad_interval = self.client.get(
            "/api/v1/timeline?interval=5m",
            headers=self.host,
        )
        self.assertEqual(bad_interval.status_code, 422)

    def test_legacy_timeline_is_bare_array(self):
        payload = self.client.get("/api/timeline", headers=self.host).json()
        self.assertIsInstance(payload, list)

    def test_spc_anomalies_success(self):
        payload = self.client.get(
            "/api/v1/spc-anomalies",
            headers=self.host,
        ).json()
        self.assertTrue(payload["available"])
        self.assertEqual(payload["count_24h"], 1)
        self.assertEqual(payload["anomalies"][0]["ip"], "10.0.0.5")

    def test_unauthenticated_reads_can_be_disabled(self):
        dashboard.auth_state.allow_unauthenticated_reads = False
        denied = self.client.get("/api/v1/stats", headers=self.host)
        self.assertEqual(denied.status_code, 401)
        allowed = self.client.get(
            "/api/v1/stats",
            headers={**self.host, API_KEY_HEADER_NAME: self.read_only_key},
        )
        self.assertEqual(allowed.status_code, 200)

    def test_etag_and_cache_control_on_stats(self):
        first = self.client.get("/api/v1/stats", headers=self.host)
        self.assertEqual(first.status_code, 200)
        self.assertIn("ETag", first.headers)
        self.assertIn("private", first.headers.get("Cache-Control", ""))
        second = self.client.get(
            "/api/v1/stats",
            headers={**self.host, "if-none-match": first.headers["ETag"]},
        )
        self.assertEqual(second.status_code, 304)

    def test_ip_redaction_option(self):
        dashboard.API_REDACT_IPS = True
        services.reset_caches()
        verdict = self.client.get(
            "/api/v1/verdicts?limit=1",
            headers=self.host,
        ).json()["verdicts"][0]
        self.assertTrue(verdict["src_ip"].startswith("ip_"))
        anomaly = self.client.get(
            "/api/v1/spc-anomalies",
            headers=self.host,
        ).json()["anomalies"][0]
        self.assertTrue(anomaly["ip"].startswith("ip_"))

    def test_metrics_endpoint(self):
        response = self.client.get("/metrics", headers=self.host)
        self.assertEqual(response.status_code, 200)
        self.assertIn("triagewall_up 1", response.text)
        self.assertIn("triagewall_events_lifetime_total", response.text)

    def test_openapi_declares_api_key_scheme(self):
        schema = self.client.get("/openapi.json", headers=self.host).json()
        self.assertIn("ApiKeyAuth", schema["components"]["securitySchemes"])
        health = schema["paths"]["/api/v1/health"]["get"]
        self.assertNotIn("deprecated", health)
        legacy = schema["paths"]["/api/verdicts"]["get"]
        self.assertTrue(legacy.get("deprecated"))

    def test_parse_api_keys_rejects_bad_entries(self):
        with self.assertRaises(RuntimeError):
            parse_api_keys("bad")
        with self.assertRaises(RuntimeError):
            parse_api_keys("name:nothex:read")


if __name__ == "__main__":
    unittest.main(verbosity=2)
