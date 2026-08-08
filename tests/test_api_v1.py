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
from pydantic import ValidationError as PydanticValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from triagewall.dashboard import app as dashboard
from triagewall.dashboard.api import cache_headers
from triagewall.dashboard.api.auth import (
    API_KEY_HEADER_NAME,
    DASHBOARD_WRITE_COOKIE,
    SCOPE_FEEDBACK_WRITE,
    SCOPE_READ,
    hash_api_key,
    lookup_api_key,
    parse_api_keys,
)
from triagewall.dashboard.api.cache_headers import weak_etag_for_payload
from triagewall.dashboard.api.pseudonym import (
    PSEUDONYM_HEX_LENGTH,
    PSEUDONYM_PREFIX,
    IpPseudonymConfigError,
    load_ip_pseudonym_secret,
    pseudonymize_ip,
)
from triagewall.dashboard.api import services
from triagewall.dashboard.api.v1 import router as dashboard_v1_router
from triagewall.dashboard.api.v1.models import (
    AgentContext,
    AssetContext,
    SensorContext,
    VerdictRow,
)
from triagewall.time_utils import format_utc_timestamp


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
        self.old_ip_secret = dashboard.API_IP_HASH_SECRET
        self.old_cookie_secure = dashboard.DASHBOARD_COOKIE_SECURE
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
            f"{hash_api_key(self.plaintext_key, iterations=1000)}:"
            f"{SCOPE_READ}|{SCOPE_FEEDBACK_WRITE},"
            f"reader:{hash_api_key(self.read_only_key, iterations=1000)}:{SCOPE_READ}"
        )
        services.reset_caches()
        self.client = TestClient(dashboard.app)
        self.host = {"host": "localhost"}

    def tearDown(self):
        dashboard.DB_PATH = self.old_db_path
        dashboard.MODE = self.old_mode
        dashboard.API_REDACT_IPS = self.old_redact
        dashboard.API_IP_HASH_SECRET = self.old_ip_secret
        dashboard.DASHBOARD_COOKIE_SECURE = self.old_cookie_secure
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
        dashboard.API_IP_HASH_SECRET = b"x" * 40
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
        with self.assertRaises(RuntimeError):
            parse_api_keys(f"legacy:{'a' * 64}:{SCOPE_READ}")

    def test_pbkdf2_api_key_round_trip(self):
        stored = hash_api_key(self.plaintext_key, iterations=1000)
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        keys = parse_api_keys(f"modern:{stored}:{SCOPE_READ}")
        self.assertIsNotNone(lookup_api_key(keys, self.plaintext_key))
        self.assertIsNone(lookup_api_key(keys, "wrong-key"))

    # --- runtime response-model enforcement --------------------------------

    def _injecting_payload(self, mutate):
        """Patch the v1 validation helper so a route emits a mutated payload.

        This is the only way to prove enforcement end to end: the routes build
        their payloads internally, so the extra field has to be introduced on
        the way out, immediately before validation.
        """
        original = cache_headers.validated_json_response

        def inject(request, payload, *, model, max_age, status_code=200):
            return original(
                request,
                mutate(payload),
                model=model,
                max_age=max_age,
                status_code=status_code,
            )

        return patch.object(
            dashboard_v1_router, "validated_json_response", side_effect=inject
        )

    def test_undocumented_top_level_field_cannot_reach_a_v1_client(self):
        """A stray key must fail the contract, not leak into the response."""
        baseline = self.client.get("/api/v1/stats", headers=self.host)
        self.assertEqual(baseline.status_code, 200)
        self.assertNotIn("surprise", baseline.json())

        with self._injecting_payload(
            lambda payload: {**payload, "surprise": "must-not-ship"}
        ):
            leaked = self.client.get("/api/v1/stats", headers=self.host)

        self.assertEqual(leaked.status_code, 500)
        self.assertNotIn("must-not-ship", leaked.text)

    def test_undocumented_verdict_row_field_cannot_reach_a_v1_client(self):
        def add_row_field(payload):
            rows = [
                {**row, "operator_secret": "must-not-ship"}
                for row in payload["verdicts"]
            ]
            return {**payload, "verdicts": rows}

        with self._injecting_payload(add_row_field):
            leaked = self.client.get(
                "/api/v1/verdicts?limit=1", headers=self.host
            )

        self.assertEqual(leaked.status_code, 500)
        self.assertNotIn("must-not-ship", leaked.text)

    def test_wrongly_typed_field_cannot_reach_a_v1_client(self):
        with self._injecting_payload(
            lambda payload: {**payload, "hours": "twenty-four"}
        ):
            leaked = self.client.get("/api/v1/timeline", headers=self.host)
        self.assertEqual(leaked.status_code, 500)
        self.assertNotIn("twenty-four", leaked.text)

    def test_verdict_row_and_contexts_forbid_extra_fields(self):
        for model, payload in (
            (VerdictRow, {"id": 1, "nope": 1}),
            (SensorContext, {"source": "suricata", "nope": 1}),
            (AgentContext, {"id": "000", "nope": 1}),
            (AssetContext, {"source": None, "nope": 1}),
        ):
            with self.subTest(model=model.__name__):
                with self.assertRaises(PydanticValidationError):
                    model.model_validate(payload)

    def test_asset_context_keeps_operator_defined_fields_as_a_dict(self):
        """Inventory contents are operator-defined and must stay free-form."""
        context = AssetContext.model_validate(
            {
                "source": {"hostname": "nas", "owner": "ops", "custom": [1, 2]},
                "destination": None,
            }
        )
        self.assertEqual(context.source["custom"], [1, 2])

    def test_etag_is_derived_from_the_validated_representation(self):
        """The ETag must hash exactly the bytes that were served."""
        for path in (
            "/api/v1/verdicts?limit=1",
            "/api/v1/stats",
            "/api/v1/timeline",
            "/api/v1/spc-anomalies",
            "/api/v1/health",
        ):
            with self.subTest(path=path):
                response = self.client.get(path, headers=self.host)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.headers["ETag"],
                    weak_etag_for_payload(response.json()),
                )

    def test_304_round_trip_after_validation(self):
        # /stats and /spc-anomalies are TTL-cached, so a repeat request
        # reproduces an identical validated payload.
        for path in ("/api/v1/stats", "/api/v1/spc-anomalies"):
            with self.subTest(path=path):
                first = self.client.get(path, headers=self.host)
                self.assertEqual(first.status_code, 200)
                etag = first.headers["ETag"]
                again = self.client.get(
                    path, headers={**self.host, "if-none-match": etag}
                )
                self.assertEqual(again.status_code, 304)
                self.assertEqual(again.headers["ETag"], etag)
                self.assertIn("private", again.headers.get("Cache-Control", ""))
                self.assertEqual(again.content, b"")

    def test_health_503_survives_validation(self):
        old = dashboard.STALE_THRESHOLD_SECONDS
        dashboard.STALE_THRESHOLD_SECONDS = -1
        try:
            response = self.client.get("/api/v1/health", headers=self.host)
        finally:
            dashboard.STALE_THRESHOLD_SECONDS = old
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "stale")
        self.assertIn("ETag", response.headers)

    # --- typed filters and bounded inputs -----------------------------------

    def test_invalid_typed_filters_return_422(self):
        for query in (
            "verdict=all",
            "verdict=REAL",
            "model=everything",
            "model=Prefilter",
        ):
            with self.subTest(query=query):
                response = self.client.get(
                    f"/api/v1/verdicts?{query}", headers=self.host
                )
                self.assertEqual(response.status_code, 422, query)

    def test_valid_typed_filters_still_work(self):
        for query in (
            "verdict=real",
            "verdict=false_positive",
            "verdict=uncertain",
            "model=llm",
            "model=prefilter",
        ):
            with self.subTest(query=query):
                response = self.client.get(
                    f"/api/v1/verdicts?{query}", headers=self.host
                )
                self.assertEqual(response.status_code, 200, query)

    def test_invalid_timeline_interval_returns_422(self):
        response = self.client.get(
            "/api/v1/timeline?interval=5m", headers=self.host
        )
        self.assertEqual(response.status_code, 422)

    def test_oversized_free_form_inputs_are_rejected(self):
        long_signature = "a" * (services.MAX_SIGNATURE_SEARCH_LENGTH + 1)
        self.assertEqual(
            self.client.get(
                f"/api/v1/verdicts?signature={long_signature}",
                headers=self.host,
            ).status_code,
            422,
        )
        long_cursor = "a" * (services.MAX_CURSOR_LENGTH + 1)
        self.assertEqual(
            self.client.get(
                f"/api/v1/verdicts?cursor={long_cursor}", headers=self.host
            ).status_code,
            422,
        )
        long_notes = "n" * (services.MAX_FEEDBACK_NOTES_LENGTH + 1)
        self.assertEqual(
            self.client.post(
                "/api/v1/feedback/1",
                headers={**self.host, API_KEY_HEADER_NAME: self.plaintext_key},
                json={"human_verdict": "real", "notes": long_notes},
            ).status_code,
            422,
        )

    def test_bounded_inputs_accept_their_maximum(self):
        at_limit = "a" * services.MAX_SIGNATURE_SEARCH_LENGTH
        self.assertEqual(
            self.client.get(
                f"/api/v1/verdicts?signature={at_limit}", headers=self.host
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/feedback/1",
                headers={**self.host, API_KEY_HEADER_NAME: self.plaintext_key},
                json={
                    "human_verdict": "real",
                    "notes": "n" * services.MAX_FEEDBACK_NOTES_LENGTH,
                },
            ).status_code,
            200,
        )

    def test_verdict_limit_range_is_unchanged(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/verdicts?limit=1", headers=self.host
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/verdicts?limit=500", headers=self.host
            ).status_code,
            200,
        )
        for bad in (0, 501):
            self.assertEqual(
                self.client.get(
                    f"/api/v1/verdicts?limit={bad}", headers=self.host
                ).status_code,
                422,
            )

    # --- dashboard cookie ----------------------------------------------------

    def test_write_cookie_attributes(self):
        response = self.client.get("/", headers=self.host)
        header = response.headers["set-cookie"]
        self.assertIn("HttpOnly", header)
        self.assertIn("SameSite=strict", header.replace("samesite", "SameSite"))
        self.assertIn("Path=/", header)
        self.assertNotIn("Secure", header)

    def test_write_cookie_can_be_marked_secure(self):
        dashboard.DASHBOARD_COOKIE_SECURE = True
        response = self.client.get("/", headers=self.host)
        header = response.headers["set-cookie"]
        self.assertIn("Secure", header)
        self.assertIn("HttpOnly", header)
        self.assertIn("Path=/", header)

    # --- unchanged dashboard polling ----------------------------------------

    def test_dashboard_polling_endpoints_are_unchanged(self):
        """The built-in UI polls the legacy aliases; they must not tighten."""
        verdicts = self.client.get(
            "/api/verdicts?verdict=real&model=llm", headers=self.host
        )
        self.assertEqual(verdicts.status_code, 200)
        self.assertIn("stats", verdicts.json())
        # Legacy stays lenient about unknown filter values.
        lenient = self.client.get(
            "/api/verdicts?verdict=all&model=everything", headers=self.host
        )
        self.assertEqual(lenient.status_code, 200)
        self.assertEqual(
            self.client.get("/api/health", headers=self.host).status_code, 200
        )
        self.assertIsInstance(
            self.client.get("/api/timeline", headers=self.host).json(), list
        )
        self.assertEqual(
            self.client.get(
                "/api/spc-anomalies", headers=self.host
            ).status_code,
            200,
        )


class IpPseudonymTests(unittest.TestCase):
    """Keyed, deterministic IP pseudonymization."""

    SECRET = b"unit-test-secret-value-long-enough-x"
    OTHER = b"a-different-secret-value-long-enough"

    def test_same_ip_and_secret_produce_the_same_pseudonym(self):
        for ip in ("10.0.0.5", "2001:db8::1"):
            with self.subTest(ip=ip):
                self.assertEqual(
                    pseudonymize_ip(ip, self.SECRET),
                    pseudonymize_ip(ip, self.SECRET),
                )

    def test_different_secrets_produce_different_pseudonyms(self):
        for ip in ("10.0.0.5", "2001:db8::1"):
            with self.subTest(ip=ip):
                self.assertNotEqual(
                    pseudonymize_ip(ip, self.SECRET),
                    pseudonymize_ip(ip, self.OTHER),
                )

    def test_different_ips_produce_different_pseudonyms(self):
        self.assertNotEqual(
            pseudonymize_ip("10.0.0.5", self.SECRET),
            pseudonymize_ip("10.0.0.6", self.SECRET),
        )
        self.assertNotEqual(
            pseudonymize_ip("2001:db8::1", self.SECRET),
            pseudonymize_ip("2001:db8::2", self.SECRET),
        )

    def test_original_address_never_appears_in_the_output(self):
        for ip in ("10.0.0.5", "192.168.1.20", "2001:db8::dead:beef"):
            with self.subTest(ip=ip):
                out = pseudonymize_ip(ip, self.SECRET)
                self.assertNotIn(ip, out)
                # Nor any octet/hextet group, which would narrow the search.
                for part in ip.replace(":", ".").split("."):
                    if len(part) >= 3:
                        self.assertNotIn(part, out[3:])

    def test_output_format_is_constant(self):
        out = pseudonymize_ip("10.0.0.5", self.SECRET)
        self.assertTrue(out.startswith(PSEUDONYM_PREFIX))
        digest = out[len(PSEUDONYM_PREFIX):]
        self.assertEqual(len(digest), PSEUDONYM_HEX_LENGTH)
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_is_not_an_unsalted_digest(self):
        """Regression: the previous scheme was reversible by enumeration."""
        unsalted = hashlib.sha256(b"10.0.0.5").hexdigest()[:12]
        self.assertNotEqual(
            pseudonymize_ip("10.0.0.5", self.SECRET), f"ip_{unsalted}"
        )

    def test_empty_values_pass_through(self):
        self.assertIsNone(pseudonymize_ip(None, self.SECRET))
        self.assertEqual(pseudonymize_ip("", self.SECRET), "")


class IpPseudonymStartupTests(unittest.TestCase):
    """Enabling redaction without a usable secret must fail startup."""

    GOOD = "a-persistent-secret-value-long-enough"

    def test_disabled_redaction_needs_no_secret(self):
        self.assertIsNone(
            load_ip_pseudonym_secret(None, redact_ips=False)
        )

    def test_missing_secret_fails_startup(self):
        with self.assertRaises(IpPseudonymConfigError) as ctx:
            load_ip_pseudonym_secret(None, redact_ips=True)
        self.assertIn("TRIAGEWALL_API_IP_HASH_SECRET", str(ctx.exception))
        with self.assertRaises(IpPseudonymConfigError):
            load_ip_pseudonym_secret("   ", redact_ips=True)

    def test_short_secret_fails_startup(self):
        with self.assertRaises(IpPseudonymConfigError) as ctx:
            load_ip_pseudonym_secret("too-short", redact_ips=True)
        self.assertIn("at least", str(ctx.exception))

    def test_reusing_the_dashboard_cookie_secret_fails_startup(self):
        with self.assertRaises(IpPseudonymConfigError) as ctx:
            load_ip_pseudonym_secret(
                self.GOOD,
                redact_ips=True,
                dashboard_write_secret=self.GOOD,
            )
        self.assertIn("must differ", str(ctx.exception))

    def test_valid_secret_loads(self):
        self.assertEqual(
            load_ip_pseudonym_secret(
                self.GOOD,
                redact_ips=True,
                dashboard_write_secret="something-else-entirely-and-long",
            ),
            self.GOOD.encode("utf-8"),
        )

    def test_startup_errors_never_include_the_secret(self):
        secret = "S3CRET-value-that-must-never-be-echoed-anywhere"
        for kwargs in (
            {"redact_ips": True, "dashboard_write_secret": secret},
        ):
            with self.assertRaises(IpPseudonymConfigError) as ctx:
                load_ip_pseudonym_secret(secret, **kwargs)
            self.assertNotIn(secret, str(ctx.exception))


class IpPseudonymNonAsciiSecretTests(unittest.TestCase):
    """Non-ASCII secrets must not crash the reuse check.

    ``hmac.compare_digest`` raises ``TypeError`` when either ``str`` operand
    contains a non-ASCII character. Comparing the configured secrets as
    ``str`` therefore aborted startup with an uncaught ``TypeError`` for any
    deployment using a non-ASCII passphrase, even though the secrets were
    valid, long enough and distinct. The dashboard cookie HMAC already
    accepted such secrets, so enabling the documented redaction hardening
    could take the API down.
    """

    # Both are >= MIN_SECRET_LENGTH characters and contain non-ASCII.
    SPANISH = "Contraseña-de-producción-muy-larga-para-2026"
    RUSSIAN = "Пароль-очень-длинный-секрет-для-теста-2026"
    ASCII = "a-persistent-secret-value-long-enough"

    def test_non_ascii_dashboard_secret_does_not_break_startup(self):
        """The reported trigger: valid ASCII IP secret, non-ASCII cookie secret."""
        self.assertEqual(
            load_ip_pseudonym_secret(
                self.ASCII,
                redact_ips=True,
                dashboard_write_secret=self.SPANISH,
            ),
            self.ASCII.encode("utf-8"),
        )

    def test_non_ascii_ip_secret_does_not_break_startup(self):
        self.assertEqual(
            load_ip_pseudonym_secret(
                self.SPANISH,
                redact_ips=True,
                dashboard_write_secret=self.ASCII,
            ),
            self.SPANISH.encode("utf-8"),
        )

    def test_two_different_non_ascii_secrets_are_accepted(self):
        self.assertEqual(
            load_ip_pseudonym_secret(
                self.SPANISH,
                redact_ips=True,
                dashboard_write_secret=self.RUSSIAN,
            ),
            self.SPANISH.encode("utf-8"),
        )

    def test_identical_non_ascii_secrets_are_detected_as_reuse(self):
        """Must be IpPseudonymConfigError, never TypeError."""
        for secret in (self.SPANISH, self.RUSSIAN):
            with self.subTest(secret=secret[:8]):
                with self.assertRaises(IpPseudonymConfigError) as ctx:
                    load_ip_pseudonym_secret(
                        secret,
                        redact_ips=True,
                        dashboard_write_secret=secret,
                    )
                self.assertIn("must differ", str(ctx.exception))

    def test_reuse_is_detected_across_surrounding_whitespace(self):
        with self.assertRaises(IpPseudonymConfigError):
            load_ip_pseudonym_secret(
                f"  {self.SPANISH}  ",
                redact_ips=True,
                dashboard_write_secret=f"\t{self.SPANISH}\n",
            )

    def test_whitespace_only_dashboard_secret_is_treated_as_unset(self):
        self.assertEqual(
            load_ip_pseudonym_secret(
                self.SPANISH,
                redact_ips=True,
                dashboard_write_secret="   ",
            ),
            self.SPANISH.encode("utf-8"),
        )

    def test_non_ascii_reuse_errors_never_include_either_secret(self):
        with self.assertRaises(IpPseudonymConfigError) as ctx:
            load_ip_pseudonym_secret(
                self.SPANISH,
                redact_ips=True,
                dashboard_write_secret=self.SPANISH,
            )
        message = str(ctx.exception)
        self.assertNotIn(self.SPANISH, message)
        self.assertNotIn(self.RUSSIAN, message)

    def test_ascii_reuse_behaviour_is_unchanged(self):
        with self.assertRaises(IpPseudonymConfigError) as ctx:
            load_ip_pseudonym_secret(
                self.ASCII,
                redact_ips=True,
                dashboard_write_secret=self.ASCII,
            )
        self.assertIn("must differ", str(ctx.exception))

    def test_pseudonym_output_is_unchanged_by_the_encoding_fix(self):
        """The comparison changed; the derived pseudonym must not have."""
        loaded = load_ip_pseudonym_secret(
            self.ASCII,
            redact_ips=True,
            dashboard_write_secret=self.SPANISH,
        )
        self.assertEqual(
            pseudonymize_ip("10.0.0.5", loaded),
            pseudonymize_ip("10.0.0.5", self.ASCII.encode("utf-8")),
        )
        # Pinned so a future change to the derivation is visible here.
        self.assertEqual(
            pseudonymize_ip("10.0.0.5", loaded),
            "ip_0a020c4e94126b6a199a290d2bd675f6",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
