#!/usr/bin/env python3
"""Bounded configuration previews, guarded activation, and provenance."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
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

    def add_event(self, event_id, signature_id, src_ip, dest_ip, *, source="suricata"):
        raw = {
            "event_type": "alert",
            "timestamp": utc_now_iso(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": "TCP",
            "alert": {"signature_id": signature_id, "signature": f"SID {signature_id}"},
        }
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """INSERT INTO triage_events (
                       timestamp, src_ip, dest_ip, proto, signature_id,
                       signature, raw_alert, verdict, processed_at
                   ) VALUES (?, ?, ?, 'TCP', ?, ?, ?, 'real', ?)""",
                (
                    raw["timestamp"],
                    src_ip,
                    dest_ip,
                    signature_id,
                    raw["alert"]["signature"],
                    json.dumps(raw),
                    utc_now_iso(),
                ),
            )
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

    def test_activation_refuses_legacy_then_atomically_activates_in_database_mode(self):
        draft_id, revision_id, summary = self.create_validate(
            "prefilter_policy",
            prefilter_document(rule(2002, scoped=False)),
        )
        path = f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate"
        legacy = self.client.post(
            path,
            headers=self.headers,
            json={
                "expected_generation": summary["generation"],
                "acknowledge_broad_rules": True,
            },
        )
        self.assertEqual(legacy.status_code, 409)
        self.assertEqual(self.summary()["generation"], 1)

        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE operator_config_state SET mode = 'database' WHERE id = 1")
        conn.commit()
        conn.close()
        missing_ack = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": 1},
        )
        self.assertEqual(missing_ack.status_code, 409)

        activated = self.client.post(
            path,
            headers=self.headers,
            json={"expected_generation": 1, "acknowledge_broad_rules": True},
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        payload = activated.json()
        self.assertEqual(payload["generation"], 2)
        self.assertEqual(payload["revision"]["id"], revision_id)
        state = self.summary()
        self.assertEqual(state["generation"], 2)
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
        conn.execute("UPDATE operator_config_state SET mode = 'database' WHERE id = 1")
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

    def test_runtime_bundle_loader_verifies_legacy_authority_and_refuses_cutover(self):
        policy = PrefilterPolicy.from_document(
            json.loads(self.legacy.read_text(encoding="utf-8"))
        )
        inventory = AssetInventory.from_document(
            json.loads(self.assets.read_text(encoding="utf-8"))
        )
        conn = sqlite3.connect(self.db_path)
        try:
            bundle = operator_config.load_decision_bundle(
                conn,
                effective_prefilter_document=policy.to_document(),
                effective_asset_revision=inventory.revision,
            )
            self.assertEqual(bundle.generation, 1)
            with self.assertRaisesRegex(
                operator_config.OperatorConfigError,
                "asset inventory",
            ):
                operator_config.load_decision_bundle(
                    conn,
                    effective_prefilter_document=policy.to_document(),
                    effective_asset_revision="sha256:" + "0" * 64,
                )
            conn.execute(
                "UPDATE operator_config_state SET mode = 'database' WHERE id = 1"
            )
            conn.commit()
            with self.assertRaisesRegex(
                operator_config.OperatorConfigError,
                "generation-aware consumers",
            ):
                operator_config.load_decision_bundle(
                    conn,
                    effective_prefilter_document=policy.to_document(),
                    effective_asset_revision=inventory.revision,
                )
        finally:
            conn.close()


class DecisionBundleProvenanceTests(unittest.TestCase):
    def test_shared_insert_persists_exact_bundle_tuple(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            (Path(__file__).resolve().parents[1] / "triagewall" / "schema.sql").read_text()
        )
        bundle = operator_config.DecisionBundle(
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
        bundle = operator_config.DecisionBundle(
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
        with patch.object(
            ingest,
            "get_asset_context",
            return_value={"source": None, "destination": None},
        ), patch.object(ingest, "call_ollama", return_value=verdict), patch.object(
            ingest, "insert_with_retry", return_value=True
        ) as suricata_insert, patch.object(
            ingest, "RUNTIME_CONFIG_BUNDLE", bundle
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
            wazuh_ingest, "RUNTIME_CONFIG_BUNDLE", bundle
        ):
            wazuh_ingest.process_wazuh_record(
                conn,
                (json.dumps(wazuh) + "\n").encode(),
            )
        self.assertIs(wazuh_insert.call_args.kwargs["config_bundle"], bundle)
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
