#!/usr/bin/env python3
"""Bounded configuration previews, guarded activation, and provenance."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from triagewall import config_repository, migrations, operator_config
from triagewall.asset_inventory import AssetInventory
from triagewall.dashboard import app as dashboard
from triagewall.dashboard.api.auth import (
    API_KEY_HEADER_NAME,
    SCOPE_CONFIG_WRITE,
    hash_api_key,
    parse_api_keys,
)
from triagewall.time_utils import utc_now_iso
from triagewall.prefilter import PrefilterPolicy
import triage
import ingest
import wazuh_ingest
from sensor_event import normalize_suricata_event


def prefilter_document(*rules):
    return {
        "version": 1,
        "internal_cidrs": ["10.0.0.0/24"],
        "auto_false_positive": list(rules),
    }


def rule(signature_id, *, protocol="tcp", scoped=True):
    value = {
        "signature_ids": [signature_id],
        "reason": f"Reviewed rule {signature_id}",
    }
    if scoped:
        value["match"] = {"protocols": [protocol]}
    return value


def asset_scoped_rule(signature_id, *, side="source", roles=("gateway",)):
    """A rule whose verdict depends on the asset inventory."""
    return {
        "signature_ids": [signature_id],
        "reason": f"Reviewed {side} asset rule {signature_id}",
        "match": {f"{side}_asset": {"roles": list(roles)}},
    }


def asset_document(*assets):
    return {"version": 1, "assets": list(assets)}


def asset(hostname, ip, *, role="gateway"):
    return {
        "hostname": hostname,
        "role": role,
        "ips": [ip],
        "criticality": "high",
        "internet_facing": True,
        "exposed_ports": [{"protocol": "tcp", "port": 443}],
    }


class ConfigPreviewActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "triage.db"
        self.packaged = self.root / "packaged.json"
        self.legacy = self.root / "legacy.json"
        self.assets = self.root / "assets.json"
        self.packaged.write_text(
            json.dumps(prefilter_document(rule(1001))), encoding="utf-8"
        )
        self.legacy.write_text(self.packaged.read_text(), encoding="utf-8")
        self.assets.write_text(
            json.dumps(asset_document(asset("router", "10.0.0.1"))),
            encoding="utf-8",
        )
        migrations.ensure_db_initialized(self.db_path)
        operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
        )

        self.old_db_path = dashboard.DB_PATH
        self.old_mode = dashboard.MODE
        self.old_writes_enabled = dashboard.CONFIG_WRITES_ENABLED
        self.old_keys = dashboard.auth_state.keys
        self.old_allow = dashboard.auth_state.allow_unauthenticated_reads
        dashboard.DB_PATH = self.db_path
        dashboard.MODE = "local"
        dashboard.CONFIG_WRITES_ENABLED = True
        dashboard.auth_state.allow_unauthenticated_reads = False
        self.key = "preview-activation-key"
        dashboard.auth_state.keys = parse_api_keys(
            "operator:"
            f"{hash_api_key(self.key, iterations=1000)}:{SCOPE_CONFIG_WRITE}"
        )
        self.headers = {
            "host": "localhost",
            API_KEY_HEADER_NAME: self.key,
            "X-Request-ID": "slice-3-test",
        }
        self.client = TestClient(dashboard.app)

    def tearDown(self):
        dashboard.DB_PATH = self.old_db_path
        dashboard.MODE = self.old_mode
        dashboard.CONFIG_WRITES_ENABLED = self.old_writes_enabled
        dashboard.auth_state.keys = self.old_keys
        dashboard.auth_state.allow_unauthenticated_reads = self.old_allow
        self.temp.cleanup()

    def summary(self):
        response = self.client.get("/api/v1/config", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def db_rows(self, sql, parameters=()):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, parameters).fetchall()
        finally:
            conn.close()

    def create_validate(self, kind, document):
        summary = self.summary()
        parent = summary["active"][kind]["id"]
        created = self.client.post(
            f"/api/v1/config/{kind}/drafts",
            headers=self.headers,
            json={
                "document": document,
                "parent_revision_id": parent,
                "expected_generation": summary["generation"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/{kind}/drafts/{draft_id}/validate",
            headers=self.headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        self.assertEqual(validated.json()["validation"]["status"], "valid")
        return draft_id, validated.json()["revision"]["id"], summary

    def add_event(
        self,
        event_id,
        signature_id,
        src_ip,
        dest_ip,
        *,
        source="suricata",
        padding=0,
        padding_char="x",
        record_size=True,
    ):
        raw = {
            "event_type": "alert",
            "timestamp": utc_now_iso(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": "TCP",
            "alert": {"signature_id": signature_id, "signature": f"SID {signature_id}"},
        }
        if padding:
            raw["payload_printable"] = padding_char * padding
        # Retained bodies are not guaranteed to be ASCII, so the fixture stores
        # multibyte content verbatim to exercise byte-versus-character counting.
        raw_alert = json.dumps(raw, ensure_ascii=False)
        # Ingestion records the body's UTF-8 length beside it. `record_size`
        # off reproduces a row retained before that column existed.
        raw_alert_bytes = len(raw_alert.encode("utf-8")) if record_size else None
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """INSERT INTO triage_events (
                       timestamp, src_ip, dest_ip, proto, signature_id,
                       signature, raw_alert, raw_alert_bytes, verdict, processed_at
                   ) VALUES (?, ?, ?, 'TCP', ?, ?, ?, ?, 'real', ?)""",
                (
                    raw["timestamp"],
                    src_ip,
                    dest_ip,
                    signature_id,
                    raw["alert"]["signature"],
                    raw_alert,
                    raw_alert_bytes,
                    utc_now_iso(),
                ),
            )
            if source is not None:
                conn.execute(
                    """INSERT INTO sensor_event_context
                       (triage_event_id, source_type) VALUES (?, ?)""",
                    (cursor.lastrowid, source),
                )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()

    def test_prefilter_preview_is_bounded_delta_only_and_audited(self):
        removed_id = self.add_event(1, 1001, "10.0.0.1", "198.51.100.1")
        added_id = self.add_event(2, 2002, "10.0.0.2", "198.51.100.2")
        self.add_event(3, 9999, "10.0.0.3", "198.51.100.3")
        candidate = prefilter_document(
            rule(2002, scoped=False),
            rule(3003),
        )
        draft_id, revision_id, summary = self.create_validate(
            "prefilter_policy", candidate
        )

        with patch.object(triage, "call_ollama") as model:
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={
                    "expected_generation": summary["generation"],
                    "hours": 24,
                    "candidate_limit": 20,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "private, no-store")
        payload = response.json()
        self.assertEqual(payload["candidate_revision_id"], revision_id)
        self.assertEqual(payload["candidates_examined"], 3)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["summary"]["counts"]["newly_suppressed"], 1)
        self.assertEqual(payload["summary"]["counts"]["no_longer_suppressed"], 1)
        self.assertEqual(
            set(payload["summary"]["affected_event_ids"]),
            {removed_id, added_id},
        )
        self.assertEqual(payload["summary"]["broad_rule_indexes"], [0])
        self.assertEqual(payload["summary"]["unmatched_rule_indexes"], [1])
        self.assertEqual(len(payload["warnings"]), 2)
        model.assert_not_called()

        bounded = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={
                "expected_generation": summary["generation"],
                "hours": 24,
                "candidate_limit": 1,
            },
        )
        self.assertEqual(bounded.status_code, 200, bounded.text)
        self.assertEqual(bounded.json()["candidates_examined"], 1)
        self.assertTrue(bounded.json()["truncated"])
        conn = sqlite3.connect(self.db_path)
        try:
            audit = conn.execute(
                """SELECT actor, auth_via, request_id, action, detail_json
                   FROM operator_config_audit ORDER BY id DESC LIMIT 1"""
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(audit[:4], ("operator", "api_key", "slice-3-test", "draft_previewed"))
        self.assertNotIn("Reviewed rule", audit[4])

    def activate_policy(self, document):
        """Make one prefilter policy the active one and return the generation."""
        summary = self.summary()
        created = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.headers,
            json={
                "document": document,
                "parent_revision_id": summary["active"]["prefilter_policy"]["id"],
                "expected_generation": summary["generation"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.headers,
            json={
                "expected_generation": summary["generation"],
                "acknowledge_broad_rules": True,
                "acknowledge_shipped_base_change": True,
            },
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        return activated.json()["generation"]

    def asset_preview(self, candidate, *, candidate_limit=20):
        draft_id, _, summary = self.create_validate("asset_inventory", candidate)
        response = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/preview",
            headers=self.headers,
            json={
                "expected_generation": summary["generation"],
                "candidate_limit": candidate_limit,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return draft_id, summary["generation"], response.json()

    def test_asset_preview_reports_newly_suppressed_source_asset_alerts(self):
        event_id = self.add_event(1, 1001, "10.0.0.5", "198.51.100.1")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))

        _, _, payload = self.asset_preview(
            asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5"))
        )

        suppression = payload["summary"]["suppression"]
        self.assertEqual(suppression["asset_dependent_rule_count"], 1)
        self.assertTrue(suppression["complete"])
        self.assertEqual(suppression["counts"]["newly_suppressed"], 1)
        self.assertEqual(suppression["counts"]["no_longer_suppressed"], 0)
        self.assertEqual(suppression["affected_event_ids"], [event_id])
        self.assertEqual(suppression["affected_signature_ids"], [1001])
        # Enrichment and suppression are reported separately.
        self.assertIn("counts", payload["summary"])
        self.assertEqual(payload["summary"]["counts"]["newly_matched_addresses"], 1)

    def test_asset_preview_reports_suppression_lost_when_an_asset_stops_matching(self):
        event_id = self.add_event(1, 1001, "10.0.0.1", "198.51.100.1")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))

        # The active inventory owns 10.0.0.1 as a gateway; the candidate makes
        # it an endpoint, so the rule stops matching.
        _, _, payload = self.asset_preview(
            asset_document(asset("router", "10.0.0.1", role="endpoint"))
        )

        suppression = payload["summary"]["suppression"]
        self.assertEqual(suppression["counts"]["no_longer_suppressed"], 1)
        self.assertEqual(suppression["counts"]["newly_suppressed"], 0)
        self.assertEqual(suppression["affected_event_ids"], [event_id])

    def test_asset_preview_reports_destination_asset_suppression(self):
        event_id = self.add_event(1, 1001, "198.51.100.9", "10.0.0.7")
        self.activate_policy(
            prefilter_document(asset_scoped_rule(1001, side="destination"))
        )

        _, _, payload = self.asset_preview(
            asset_document(asset("router", "10.0.0.1"), asset("target", "10.0.0.7"))
        )

        suppression = payload["summary"]["suppression"]
        self.assertEqual(suppression["counts"]["newly_suppressed"], 1)
        self.assertEqual(suppression["affected_event_ids"], [event_id])

    def test_asset_preview_separates_enrichment_only_changes(self):
        self.add_event(1, 1001, "10.0.0.1", "198.51.100.1")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))

        # Same role, so the rule still matches; only the hostname changed.
        _, _, payload = self.asset_preview(
            asset_document(asset("renamed", "10.0.0.1"))
        )

        suppression = payload["summary"]["suppression"]
        self.assertTrue(suppression["complete"])
        self.assertEqual(suppression["counts"]["newly_suppressed"], 0)
        self.assertEqual(suppression["counts"]["no_longer_suppressed"], 0)
        self.assertEqual(suppression["counts"]["unchanged_suppressed"], 1)
        self.assertEqual(suppression["affected_event_ids"], [])
        # The enrichment half still reports the change.
        self.assertEqual(payload["summary"]["counts"]["changed_context_addresses"], 1)

    def test_asset_preview_excludes_non_applicable_sources_from_suppression(self):
        self.add_event(1, 1001, "10.0.0.5", "198.51.100.1", source="wazuh")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))
        conn, reads = self.recorded_column_reads()
        try:
            sample = config_repository._sample_rows(
                conn,
                kind="asset_inventory",
                window_start="2000-01-01T00:00:00.000000Z",
                candidate_limit=20,
                read_alerts=True,
            )
        finally:
            conn.close()

        # The Wazuh row is compared by address, but its body is never read and
        # the policy is never evaluated against it.
        self.assertEqual(len(sample.rows), 1)
        self.assertIsNone(sample.rows[0][1])
        self.assertNotIn(("triage_events", "raw_alert"), reads)

        _, _, payload = self.asset_preview(
            asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5"))
        )
        suppression = payload["summary"]["suppression"]
        self.assertEqual(suppression["evaluated_candidates"], 0)
        self.assertEqual(suppression["counts"]["newly_suppressed"], 0)
        self.assertTrue(suppression["complete"])
        # The address change is still reported by the enrichment half.
        self.assertEqual(payload["summary"]["counts"]["newly_matched_addresses"], 1)

    def test_asset_preview_without_asset_rules_reads_no_alert_bodies(self):
        self.add_event(1, 1001, "10.0.0.5", "198.51.100.1", padding=4096)
        conn, reads = self.recorded_column_reads()
        try:
            _, _, payload = self.asset_preview(
                asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5"))
            )
        finally:
            conn.close()

        suppression = payload["summary"]["suppression"]
        # The active policy is scoped by protocol only, so no inventory edit can
        # move a decision and nothing needs reading to prove it.
        self.assertEqual(suppression["asset_dependent_rule_count"], 0)
        self.assertTrue(suppression["complete"])
        self.assertEqual(suppression["evaluated_candidates"], 0)
        self.assertNotIn(("triage_events", "raw_alert"), reads)

    def test_asset_preview_marks_a_truncated_suppression_analysis_incomplete(self):
        for index in range(3):
            self.add_event(
                index + 1, 1001, f"10.0.0.{index + 5}", "198.51.100.1", padding=2048
            )
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 3_000):
            draft_id, generation, payload = self.asset_preview(
                asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5"))
            )

        self.assertTrue(payload["truncated"])
        suppression = payload["summary"]["suppression"]
        self.assertFalse(suppression["complete"])
        self.assertIn(
            "asset preview could not evaluate every asset-dependent "
            "prefilter rule; activation requires acknowledging it",
            payload["warnings"],
        )
        detail = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'draft_previewed' ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertFalse(detail["suppression_complete"])
        self.assertEqual(detail["asset_dependent_rules"], 1)

        # Fail closed: an incomplete analysis cannot activate unacknowledged.
        blocked = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/activate",
            headers=self.headers,
            json={"expected_generation": generation},
        )
        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertIn("complete asset preview", blocked.text)
        rejection = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'revision_activation_rejected'
                   ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertEqual(rejection["reason"], "incomplete_asset_preview")

        acknowledged = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/activate",
            headers=self.headers,
            json={
                "expected_generation": generation,
                "acknowledge_incomplete_asset_preview": True,
            },
        )
        self.assertEqual(acknowledged.status_code, 200, acknowledged.text)

    def test_a_complete_asset_preview_activates_without_extra_acknowledgement(self):
        self.add_event(1, 1001, "10.0.0.5", "198.51.100.1")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))

        draft_id, generation, payload = self.asset_preview(
            asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5"))
        )
        self.assertTrue(payload["summary"]["suppression"]["complete"])

        activated = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/activate",
            headers=self.headers,
            json={"expected_generation": generation},
        )

        self.assertEqual(activated.status_code, 200, activated.text)

    def test_activating_an_asset_inventory_without_any_preview_fails_closed(self):
        self.add_event(1, 1001, "10.0.0.5", "198.51.100.1")
        self.activate_policy(prefilter_document(asset_scoped_rule(1001)))
        draft_id, _, summary = self.create_validate(
            "asset_inventory",
            asset_document(asset("router", "10.0.0.1"), asset("edge", "10.0.0.5")),
        )

        blocked = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/activate",
            headers=self.headers,
            json={"expected_generation": summary["generation"]},
        )

        self.assertEqual(blocked.status_code, 409, blocked.text)
        self.assertIn("complete asset preview", blocked.text)
        self.assertEqual(self.summary()["generation"], summary["generation"])

    def test_preview_includes_migrated_events_without_sensor_context(self):
        migrated = self.add_event(1, 1001, "10.0.0.1", "198.51.100.1", source=None)
        self.add_event(2, 1001, "10.0.0.9", "198.51.100.9", source="wazuh")
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )

        response = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": summary["generation"], "candidate_limit": 20},
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        # The migrated Suricata row is compared; the Wazuh row is still excluded.
        self.assertEqual(payload["candidates_examined"], 1)
        self.assertEqual(payload["summary"]["counts"]["no_longer_suppressed"], 1)
        self.assertEqual(payload["summary"]["affected_event_ids"], [migrated])

    def test_asset_preview_includes_migrated_events_and_reads_no_alert_bodies(self):
        migrated = self.add_event(
            1, 5001, "10.0.0.1", "10.0.0.2", source=None, padding=2048
        )
        draft_id, _, summary = self.create_validate(
            "asset_inventory",
            asset_document(asset("firewall", "10.0.0.1")),
        )

        with patch.object(
            config_repository,
            "MAX_PREVIEW_SAMPLE_BYTES",
            1,
        ):
            response = self.client.post(
                f"/api/v1/config/asset_inventory/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        # No alert body is selected for an asset preview, so the byte budget is
        # never consumed and the migrated row is still examined.
        self.assertEqual(payload["candidates_examined"], 1)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["summary"]["affected_event_ids"], [migrated])

    def test_prefilter_preview_stops_at_the_sample_byte_budget(self):
        for index in range(4):
            self.add_event(
                index + 1,
                1001,
                f"10.0.0.{index + 1}",
                "198.51.100.5",
                padding=4096,
            )
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 6_000):
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["candidates_examined"], 1)
        self.assertTrue(payload["truncated"])
        self.assertIn(
            "preview sample reached its byte budget before its row limit",
            payload["warnings"],
        )
        detail = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'draft_previewed' ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertTrue(detail["truncated_by_bytes"])
        self.assertEqual(detail["candidates_examined"], 1)

    def sampled_alert_bodies(self, evaluator):
        """Capture exactly what the preview evaluator was handed."""
        captured = []
        original = getattr(config_repository, evaluator)

        def spy(*args, **kwargs):
            captured.append(list(args[-1]))
            return original(*args, **kwargs)

        return captured, patch.object(config_repository, evaluator, spy)

    def test_a_single_oversized_alert_is_never_read_or_examined(self):
        oversized = self.add_event(
            1, 1001, "10.0.0.1", "198.51.100.1", padding=4096
        )
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        captured, spy = self.sampled_alert_bodies("_prefilter_preview")

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 16), spy:
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        # The only candidate does not fit, so nothing is examined and the result
        # says so instead of admitting one unbounded body.
        self.assertEqual(payload["candidates_examined"], 0)
        self.assertTrue(payload["truncated"])
        self.assertIn(
            "preview sample reached its byte budget before its row limit",
            payload["warnings"],
        )
        self.assertEqual(payload["summary"]["counts"]["skipped_invalid_records"], 0)
        self.assertEqual(payload["summary"]["affected_event_ids"], [])
        # The oversized body never reached the evaluator, so it was never parsed.
        self.assertEqual(captured, [[]])
        self.assertNotIn(
            "xxxx",
            json.dumps(payload),
        )
        detail = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'draft_previewed' ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertTrue(detail["truncated_by_bytes"])
        self.assertEqual(detail["candidates_examined"], 0)
        self.assertTrue(oversized)

    def test_the_evaluator_never_receives_more_than_the_byte_budget(self):
        for index in range(3):
            self.add_event(
                index + 1,
                1001,
                f"10.0.0.{index + 1}",
                "198.51.100.5",
                padding=2048,
            )
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        captured, spy = self.sampled_alert_bodies("_prefilter_preview")
        budget = 5_000

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", budget), spy:
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        rows = captured[0]
        self.assertEqual(len(rows), 2)
        self.assertEqual(response.json()["candidates_examined"], 2)
        self.assertTrue(response.json()["truncated"])
        total = sum(len(str(row[1]).encode("utf-8")) for row in rows)
        self.assertLessEqual(total, budget)

    def test_the_byte_budget_counts_utf8_bytes_not_characters(self):
        # 300 multibyte characters are 600 stored bytes: a character-count
        # budget would admit this row, a byte budget must not.
        self.add_event(
            1, 1001, "10.0.0.1", "198.51.100.1", padding=300, padding_char="é"
        )
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        captured, spy = self.sampled_alert_bodies("_prefilter_preview")

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 500), spy:
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["candidates_examined"], 0)
        self.assertTrue(response.json()["truncated"])
        self.assertEqual(captured, [[]])

    def recorded_column_reads(self):
        """Record every column SQLite reads, straight from its authorizer."""
        reads = []
        conn = sqlite3.connect(self.db_path)

        def authorizer(action, arg1, arg2, *_rest):
            if action == sqlite3.SQLITE_READ:
                reads.append((arg1, arg2))
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorizer)
        return conn, reads

    def test_sizing_pass_never_reads_the_alert_body(self):
        self.add_event(1, 1001, "10.0.0.1", "198.51.100.1", padding=4096)
        conn, reads = self.recorded_column_reads()
        try:
            with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 16):
                sample = config_repository._sample_rows(
                    conn,
                    kind="prefilter_policy",
                    window_start="2000-01-01T00:00:00.000000Z",
                    candidate_limit=20,
                )
        finally:
            conn.close()

        # The engine is never asked for the body at all, so it cannot
        # materialize one: only the recorded size is read.
        self.assertNotIn(("triage_events", "raw_alert"), reads)
        self.assertIn(("triage_events", "raw_alert_bytes"), reads)
        self.assertEqual(sample.rows, [])
        self.assertTrue(sample.truncated_by_bytes)

    def test_an_accepted_row_reads_its_body_exactly_once(self):
        self.add_event(1, 1001, "10.0.0.1", "198.51.100.1", padding=64)
        conn, reads = self.recorded_column_reads()
        try:
            sample = config_repository._sample_rows(
                conn,
                kind="prefilter_policy",
                window_start="2000-01-01T00:00:00.000000Z",
                candidate_limit=20,
            )
        finally:
            conn.close()

        self.assertEqual(len(sample.rows), 1)
        self.assertFalse(sample.truncated)
        self.assertEqual(reads.count(("triage_events", "raw_alert")), 1)

    def test_a_row_retained_before_sizes_were_recorded_stops_the_sample(self):
        self.add_event(1, 1001, "10.0.0.1", "198.51.100.1", record_size=False)
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        captured, spy = self.sampled_alert_bodies("_prefilter_preview")
        conn, reads = self.recorded_column_reads()
        try:
            sample = config_repository._sample_rows(
                conn,
                kind="prefilter_policy",
                window_start="2000-01-01T00:00:00.000000Z",
                candidate_limit=20,
            )
        finally:
            conn.close()

        # An unrecorded size is never trusted, so the body is not fetched.
        self.assertEqual(sample.rows, [])
        self.assertTrue(sample.truncated)
        self.assertTrue(sample.truncated_by_unsized)
        self.assertFalse(sample.truncated_by_bytes)
        self.assertNotIn(("triage_events", "raw_alert"), reads)

        with spy:
            response = self.client.post(
                f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["candidates_examined"], 0)
        self.assertTrue(payload["truncated"])
        self.assertIn(
            "preview sample stopped at a retained alert with no usable recorded size",
            payload["warnings"],
        )
        self.assertEqual(captured, [[]])
        detail = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'draft_previewed' ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertTrue(detail["truncated_by_unsized"])
        self.assertFalse(detail["truncated_by_bytes"])

    def test_a_negative_recorded_size_never_reads_the_alert_body(self):
        event_id = self.add_event(1, 1001, "10.0.0.1", "198.51.100.1", padding=64)
        conn = sqlite3.connect(self.db_path)
        try:
            # Only trusted database modification can produce this; the sampler
            # must still refuse to read a body it cannot bound.
            conn.execute(
                "UPDATE triage_events SET raw_alert_bytes = -1 WHERE id = ?",
                (event_id,),
            )
            conn.commit()
        finally:
            conn.close()
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        conn, reads = self.recorded_column_reads()
        try:
            sample = config_repository._sample_rows(
                conn,
                kind="prefilter_policy",
                window_start="2000-01-01T00:00:00.000000Z",
                candidate_limit=20,
            )
        finally:
            conn.close()

        self.assertNotIn(("triage_events", "raw_alert"), reads)
        self.assertEqual(sample.rows, [])
        self.assertTrue(sample.truncated_by_unsized)
        self.assertFalse(sample.truncated_by_bytes)

        response = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": summary["generation"], "candidate_limit": 20},
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["candidates_examined"], 0)
        self.assertTrue(payload["truncated"])
        self.assertIn(
            "preview sample stopped at a retained alert with no usable recorded size",
            payload["warnings"],
        )
        detail = json.loads(
            self.db_rows(
                """SELECT detail_json FROM operator_config_audit
                   WHERE action = 'draft_previewed' ORDER BY id DESC LIMIT 1"""
            )[0][0]
        )
        self.assertTrue(detail["truncated_by_unsized"])

    def test_a_recorded_size_that_is_not_a_length_is_refused(self):
        for stored in (-1, "not-a-number", 1.5):
            self.assertIsNone(config_repository._usable_recorded_size(stored))
        self.assertIsNone(config_repository._usable_recorded_size(None))
        self.assertIsNone(config_repository._usable_recorded_size(True))
        self.assertEqual(config_repository._usable_recorded_size(0), 0)
        self.assertEqual(config_repository._usable_recorded_size(1234), 1234)

    def test_asset_preview_is_unaffected_by_unrecorded_sizes(self):
        migrated = self.add_event(
            1, 5001, "10.0.0.1", "10.0.0.2", record_size=False
        )
        draft_id, _, summary = self.create_validate(
            "asset_inventory",
            asset_document(asset("firewall", "10.0.0.1")),
        )
        conn, reads = self.recorded_column_reads()
        try:
            sample = config_repository._sample_rows(
                conn,
                kind="asset_inventory",
                window_start="2000-01-01T00:00:00.000000Z",
                candidate_limit=20,
            )
        finally:
            conn.close()

        # Address comparison reads neither the body nor its size.
        self.assertNotIn(("triage_events", "raw_alert"), reads)
        self.assertNotIn(("triage_events", "raw_alert_bytes"), reads)
        self.assertEqual(len(sample.rows), 1)
        self.assertFalse(sample.truncated)

        response = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": summary["generation"], "candidate_limit": 20},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["candidates_examined"], 1)
        self.assertEqual(
            response.json()["summary"]["affected_event_ids"], [migrated]
        )

    def test_ingestion_records_the_exact_utf8_size_of_the_retained_alert(self):
        conn = sqlite3.connect(self.db_path)
        try:
            event = normalize_suricata_event(
                {
                    "event_type": "alert",
                    "timestamp": "2026-08-15T00:00:00Z",
                    "src_ip": "10.0.0.1",
                    "proto": "tcp",
                    "alert": {
                        "signature_id": 4242,
                        "signature": "Multibyte é signature",
                    },
                    "payload_printable": "é" * 100,
                }
            )
            triage.insert_triage_row(
                conn,
                event,
                {"verdict": "real", "confidence": 0.9, "reasoning": "test"},
            )
            conn.commit()
            stored, recorded = conn.execute(
                "SELECT raw_alert, raw_alert_bytes FROM triage_events"
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(recorded)
        self.assertEqual(recorded, len(stored.encode("utf-8")))
        self.assertEqual(json.loads(stored)["payload_printable"], "é" * 100)
        # The stored representation escapes non-ASCII, which is what makes the
        # character count an exact byte count.
        self.assertTrue(stored.isascii())
        self.assertIn("\\u00e9", stored)

    def test_sizing_never_allocates_a_second_copy_of_the_retained_alert(self):
        payload = "é" * 50_000
        event = normalize_suricata_event(
            {
                "event_type": "alert",
                "timestamp": "2026-08-15T00:00:00Z",
                "src_ip": "10.0.0.1",
                "proto": "tcp",
                "alert": {"signature_id": 4242, "signature": "Large multibyte"},
                "payload_printable": payload,
            }
        )
        encodes = []
        original_str_encode = str.encode

        class _TrackedStr(str):
            def encode(self, *args, **kwargs):
                encodes.append(len(self))
                return original_str_encode(self, *args, **kwargs)

        real_dumps = triage.json.dumps

        def tracking_dumps(*args, **kwargs):
            # Hand the writer a string that reports any attempt to encode it.
            return _TrackedStr(real_dumps(*args, **kwargs))

        conn = sqlite3.connect(self.db_path)
        try:
            with patch.object(triage.json, "dumps", tracking_dumps):
                triage.insert_triage_row(
                    conn,
                    event,
                    {"verdict": "real", "confidence": 0.9, "reasoning": "test"},
                )
            conn.commit()
            stored, recorded = conn.execute(
                "SELECT raw_alert, raw_alert_bytes FROM triage_events"
            ).fetchone()
        finally:
            conn.close()

        # The retained body is large, and its size was recorded without ever
        # copying it: nothing encoded a body-sized string.
        self.assertGreater(recorded, 100_000)
        self.assertEqual(recorded, len(stored.encode("utf-8")))
        self.assertEqual(json.loads(stored)["payload_printable"], payload)
        self.assertEqual(
            [size for size in encodes if size >= len(stored)],
            [],
            "the serialized body was copied to measure it",
        )

    def test_migration_adds_the_size_column_to_an_existing_database(self):
        legacy_path = self.root / "legacy.db"
        # The shipped schema with only this column removed is exactly the
        # previous release's triage_events definition.
        previous_schema = "\n".join(
            line
            for line in (
                Path(PROJECT_ROOT / "triagewall" / "schema.sql")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            if "raw_alert_bytes" not in line
        )
        conn = sqlite3.connect(legacy_path)
        try:
            conn.executescript(previous_schema)
            columns_before = {
                row[1] for row in conn.execute("PRAGMA table_info('triage_events')")
            }
            conn.execute(
                """INSERT INTO triage_events (timestamp, signature_id, signature, raw_alert)
                   VALUES ('2026-08-15T00:00:00Z', 1, 'legacy', '{}')"""
            )
            conn.commit()
        finally:
            conn.close()
        self.assertNotIn("raw_alert_bytes", columns_before)

        migrations.ensure_db_initialized(legacy_path)

        conn = sqlite3.connect(legacy_path)
        try:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info('triage_events')")
            }
            retained = conn.execute(
                "SELECT raw_alert, raw_alert_bytes FROM triage_events"
            ).fetchone()
        finally:
            conn.close()

        self.assertIn("raw_alert_bytes", columns)
        # The migration adds the column without rewriting retained rows, so the
        # historical row keeps its body and reports no size.
        self.assertEqual(retained, ("{}", None))
        self.assertIn("raw_alert_bytes", migrations.ADDED_EVENT_COLUMNS)

    def test_asset_preview_hands_the_evaluator_no_alert_bodies(self):
        self.add_event(1, 5001, "10.0.0.1", "10.0.0.2", padding=4096)
        draft_id, _, summary = self.create_validate(
            "asset_inventory",
            asset_document(asset("firewall", "10.0.0.1")),
        )
        captured, spy = self.sampled_alert_bodies("_asset_preview")

        with patch.object(config_repository, "MAX_PREVIEW_SAMPLE_BYTES", 16), spy:
            response = self.client.post(
                f"/api/v1/config/asset_inventory/drafts/{draft_id}/preview",
                headers=self.headers,
                json={"expected_generation": summary["generation"], "candidate_limit": 20},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        # Address-only comparison: the byte budget is irrelevant because no
        # alert body is selected at all.
        self.assertEqual(payload["candidates_examined"], 1)
        self.assertFalse(payload["truncated"])
        self.assertEqual([row[1] for row in captured[0]], [None])

    def test_preview_refuses_a_candidate_whose_parent_is_no_longer_active(self):
        draft_id, _, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        other_draft, _, _ = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(3003)),
        )
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{other_draft}/activate",
            headers=self.headers,
            json={"expected_generation": summary["generation"]},
        )
        self.assertEqual(activated.status_code, 200, activated.text)

        response = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": self.summary()["generation"]},
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("parent is no longer active", response.text)
        # Refused before sampling, so no preview event is recorded for it.
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_audit
                   WHERE action = 'draft_previewed' AND revision_id = ?""",
                (draft_id,),
            ),
            [(0,)],
        )
        rejection = self.db_rows(
            """SELECT revision_id, detail_json FROM operator_config_audit
               WHERE action = 'draft_preview_rejected' ORDER BY id DESC LIMIT 1"""
        )
        self.assertEqual(rejection[0][0], draft_id)
        self.assertEqual(json.loads(rejection[0][1])["reason"], "stale_parent")

    def test_asset_preview_reports_address_context_changes(self):
        changed_event = self.add_event(
            1, 5001, "10.0.0.1", "10.0.0.2", source="wazuh"
        )
        candidate = asset_document(
            asset("firewall", "10.0.0.1"),
            asset("server", "10.0.0.2", role="application"),
        )
        draft_id, _, summary = self.create_validate("asset_inventory", candidate)

        response = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": summary["generation"], "candidate_limit": 20},
        )

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["summary"]
        self.assertEqual(result["counts"]["changed_context_addresses"], 1)
        self.assertEqual(result["counts"]["newly_matched_addresses"], 1)
        self.assertEqual(result["affected_event_ids"], [changed_event])
        self.assertEqual(
            set(result["affected_addresses"]), {"10.0.0.1", "10.0.0.2"}
        )

    def test_preview_requires_validated_candidate_and_current_generation(self):
        summary = self.summary()
        parent = summary["active"]["prefilter_policy"]["id"]
        created = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.headers,
            json={
                "document": prefilter_document(rule(2002)),
                "parent_revision_id": parent,
                "expected_generation": summary["generation"],
            },
        )
        draft_id = created.json()["draft"]["id"]
        unvalidated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": summary["generation"]},
        )
        stale = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={"expected_generation": 99},
        )
        oversized = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.headers,
            json={
                "expected_generation": summary["generation"],
                "candidate_limit": config_repository.MAX_PREVIEW_CANDIDATES + 1,
            },
        )
        self.assertEqual(unvalidated.status_code, 409)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(oversized.status_code, 422)

    def test_activation_cuts_over_legacy_then_atomically_activates(self):
        draft_id, revision_id, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002, scoped=False)),
        )
        path = f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate"
        missing_ack = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": summary["generation"]},
        )
        self.assertEqual(missing_ack.status_code, 409)
        self.assertEqual(self.summary()["generation"], 1)

        activated = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": 1, "acknowledge_broad_rules": True},
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        payload = activated.json()
        self.assertEqual(payload["generation"], 2)
        self.assertTrue(payload["authority_cutover"])
        self.assertEqual(payload["revision"]["id"], revision_id)
        state = self.summary()
        self.assertEqual(state["generation"], 2)
        self.assertEqual(state["mode"], "database")
        self.assertEqual(state["active"]["prefilter_policy"]["id"], revision_id)
        self.assertEqual(payload["revision"]["state"], "active")

        stale = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": 1, "acknowledge_broad_rules": True},
        )
        self.assertEqual(stale.status_code, 409)

    def test_corrupt_candidate_rolls_back_activation(self):
        draft_id, revision_id, _ = self.create_validate(
            "asset_inventory",
            asset_document(asset("server", "10.0.0.2")),
        )
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE operator_config_revisions SET document_json = '{}' WHERE id = ?",
            (revision_id,),
        )
        conn.commit()
        before = conn.execute(
            "SELECT active_asset_revision_id, generation FROM operator_config_state"
        ).fetchone()
        conn.close()

        response = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/activate",
            headers=self.headers,
            json={"expected_generation": 1},
        )

        self.assertEqual(response.status_code, 500)
        conn = sqlite3.connect(self.db_path)
        try:
            after = conn.execute(
                "SELECT active_asset_revision_id, generation FROM operator_config_state"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(after, before)

    def test_activation_acknowledges_a_newer_shipped_baseline(self):
        draft_id, _, _ = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        self.packaged.write_text(
            json.dumps(prefilter_document(rule(3003))),
            encoding="utf-8",
        )
        discovered = operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
        )
        self.assertTrue(discovered.discovered_shipped_revision)
        self.assertEqual(discovered.generation, 1)
        path = f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate"

        missing_ack = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": 1},
        )
        self.assertEqual(missing_ack.status_code, 409)
        self.assertIn("shipped-base change", missing_ack.text)

        activated = self.client.post(
            path,
            headers=self.headers,
            json={
                "expected_generation": 1,
                "acknowledge_shipped_base_change": True,
            },
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["generation"], 2)

    def test_rollback_reactivates_superseded_revision_with_new_generation(self):
        original = self.summary()["active"]["prefilter_policy"]["id"]
        draft_id, candidate_id, _ = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002)),
        )
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.headers,
            json={"expected_generation": 1},
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["revision"]["id"], candidate_id)

        rolled_back = self.client.post(
            f"/api/v1/config/prefilter_policy/revisions/{original}/rollback",
            headers=self.headers,
            json={"expected_generation": 2},
        )

        self.assertEqual(rolled_back.status_code, 200, rolled_back.text)
        payload = rolled_back.json()
        self.assertEqual(payload["generation"], 3)
        self.assertFalse(payload["authority_cutover"])
        self.assertEqual(payload["revision"]["id"], original)
        summary = self.summary()
        self.assertEqual(summary["active"]["prefilter_policy"]["id"], original)
        self.assertEqual(summary["generation"], 3)
        audit = self.db_rows(
            """SELECT action, from_revision_id, to_revision_id
               FROM operator_config_audit ORDER BY id DESC LIMIT 1"""
        )[0]
        self.assertEqual(audit, ("revision_rolled_back", candidate_id, original))

        stale = self.client.post(
            f"/api/v1/config/prefilter_policy/revisions/{candidate_id}/rollback",
            headers=self.headers,
            json={"expected_generation": 2},
        )
        self.assertEqual(stale.status_code, 409)

    def test_runtime_bundle_loader_verifies_legacy_and_loads_database_authority(self):
        policy = PrefilterPolicy.from_document(
            json.loads(self.legacy.read_text(encoding="utf-8"))
        )
        inventory = AssetInventory.from_document(
            json.loads(self.assets.read_text(encoding="utf-8"))
        )
        conn = sqlite3.connect(self.db_path)
        try:
            bundle = operator_config.load_configuration_bundle(
                conn,
                legacy_prefilter_policy=policy,
                legacy_asset_inventory=inventory,
            )
            self.assertEqual(bundle.generation, 1)
            with self.assertRaisesRegex(
                operator_config.OperatorConfigError,
                "asset inventory",
            ):
                operator_config.load_configuration_bundle(
                    conn,
                    legacy_prefilter_policy=policy,
                    legacy_asset_inventory=AssetInventory.from_document(
                        {"version": 1, "assets": []}
                    ),
                )
            conn.execute(
                "UPDATE operator_config_state SET mode = 'database' WHERE id = 1"
            )
            conn.commit()
            database_bundle = operator_config.load_configuration_bundle(
                conn,
                legacy_prefilter_policy=PrefilterPolicy.empty(),
                legacy_asset_inventory=AssetInventory.from_document(
                    {"version": 1, "assets": []}
                ),
            )
            self.assertEqual(database_bundle.mode, "database")
            self.assertEqual(database_bundle.prefilter_policy.signature_ids, {1001})
        finally:
            conn.close()


class ConfigurationBundleProvenanceTests(unittest.TestCase):
    def test_both_ingest_adapters_size_alerts_through_the_shared_writer(self):
        # Only one writer records the size, so both adapters must reach it.
        self.assertIs(wazuh_ingest.insert_with_retry, ingest.insert_with_retry)
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
        )
        event = normalize_suricata_event(
            {
                "event_type": "alert",
                "timestamp": "2026-08-15T00:00:00Z",
                "alert": {"signature_id": 7, "signature": "shared writer"},
            }
        )
        # The Suricata adapter's bound writer is the one that records sizes, and
        # the Wazuh adapter reaches it through the same retry wrapper.
        self.assertIs(ingest.insert_triage_row, triage.insert_triage_row)
        try:
            ingest.insert_with_retry(
                conn,
                event,
                {"verdict": "real", "confidence": 0.9, "reasoning": "test"},
            )
            conn.commit()
            stored, recorded = conn.execute(
                "SELECT raw_alert, raw_alert_bytes FROM triage_events"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(recorded, len(stored.encode("utf-8")))

    def test_shared_insert_persists_exact_bundle_tuple(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            (Path(__file__).resolve().parents[1] / "triagewall" / "schema.sql").read_text()
        )
        bundle = SimpleNamespace(
            generation=7,
            prefilter_revision="sha256:" + "a" * 64,
            asset_revision="sha256:" + "b" * 64,
        )
        event = normalize_suricata_event(
            {
                "event_type": "alert",
                "timestamp": "2026-08-15T00:00:00Z",
                "alert": {"signature_id": 42, "signature": "test"},
            }
        )
        triage.insert_triage_row(
            conn,
            event,
            {"verdict": "real", "confidence": 0.9, "reasoning": "test"},
            config_bundle=bundle,
        )
        row = conn.execute(
            """SELECT config_generation, prefilter_revision, asset_revision
               FROM triage_events"""
        ).fetchone()
        conn.close()
        self.assertEqual(row, (7, bundle.prefilter_revision, bundle.asset_revision))

    def test_both_ingest_adapters_forward_the_verified_bundle(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        bundle = SimpleNamespace(
            generation=9,
            prefilter_revision="sha256:" + "c" * 64,
            asset_revision="sha256:" + "d" * 64,
        )
        verdict = {"verdict": "real", "confidence": 0.9, "reasoning": "test"}
        suricata = json.dumps(
            {
                "event_type": "alert",
                "timestamp": "2026-08-15T00:00:00Z",
                "alert": {"signature_id": 42, "signature": "test"},
            }
        )
        owner = type(
            "Owner",
            (),
            {"bundle": bundle, "maybe_reload": lambda self, conn: False},
        )()
        with patch.object(
            ingest,
            "get_asset_context",
            return_value={"source": None, "destination": None},
        ), patch.object(ingest, "call_ollama", return_value=verdict), patch.object(
            ingest, "insert_with_retry", return_value=True
        ) as suricata_insert, patch.object(
            ingest, "RUNTIME_CONFIG_OWNER", owner
        ):
            ingest.process_line(conn, suricata)
        self.assertIs(suricata_insert.call_args.kwargs["config_bundle"], bundle)

        wazuh = {
            "timestamp": "2026-08-15T00:00:00.000+0000",
            "id": "1752950123.123456",
            "rule": {"id": 87702, "level": 8, "description": "test"},
            "agent": {"id": "000", "name": "manager"},
            "manager": {"name": "manager"},
            "decoder": {"name": "json"},
            "location": "test",
        }
        with patch.object(wazuh_ingest, "WAZUH_SOURCE_ID", "test-wazuh"), patch.object(
            wazuh_ingest,
            "get_asset_context",
            return_value={"source": None, "destination": None},
        ), patch.object(
            wazuh_ingest, "call_ollama_wazuh", return_value=verdict
        ), patch.object(
            wazuh_ingest, "insert_with_retry", return_value=True
        ) as wazuh_insert, patch.object(
            wazuh_ingest, "RUNTIME_CONFIG_OWNER", owner
        ):
            wazuh_ingest.process_wazuh_record(
                conn,
                (json.dumps(wazuh) + "\n").encode(),
            )
        self.assertIs(wazuh_insert.call_args.kwargs["config_bundle"], bundle)
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
