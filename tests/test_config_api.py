#!/usr/bin/env python3
"""Configuration API authorization and draft-lifecycle regressions."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]

from triagewall import config_repository, migrations, operator_config
from triagewall.dashboard import app as dashboard
from triagewall.dashboard.api.auth import (
    API_KEY_HEADER_NAME,
    SCOPE_CONFIG_WRITE,
    SCOPE_FEEDBACK_WRITE,
    SCOPE_READ,
    hash_api_key,
    parse_api_keys,
    validate_config_write_settings,
)


def prefilter_document(
    *,
    signature_id: int = 1001,
    protocol: str = "tcp",
    scoped: bool = True,
):
    rule = {
        "signature_ids": [signature_id],
        "reason": f"Reviewed rule {signature_id}",
    }
    if scoped:
        rule["match"] = {"protocols": [protocol]}
    return {
        "version": 1,
        "internal_cidrs": ["10.0.0.0/24"],
        "auto_false_positive": [rule],
    }


def asset_document(*, hostname: str = "private-router"):
    return {
        "version": 1,
        "assets": [
            {
                "hostname": hostname,
                "role": "gateway",
                "ips": ["10.0.0.1"],
                "criticality": "high",
                "internet_facing": True,
                "exposed_ports": [{"protocol": "tcp", "port": 443}],
            }
        ],
    }


class ConfigApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "triage.db"
        self.packaged = self.root / "packaged.json"
        self.legacy = self.root / "legacy.json"
        self.assets = self.root / "assets.json"
        self.write(self.packaged, prefilter_document())
        self.write(self.legacy, prefilter_document())
        self.write(self.assets, asset_document())
        migrations.ensure_db_initialized(self.db_path)
        operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
            occurred_at="2026-08-15T01:00:00.000000Z",
        )

        self.old_db_path = dashboard.DB_PATH
        self.old_mode = dashboard.MODE
        self.old_writes_enabled = dashboard.CONFIG_WRITES_ENABLED
        self.old_keys = dashboard.auth_state.keys
        self.old_secret = dashboard.auth_state.dashboard_write_secret
        self.old_allow = dashboard.auth_state.allow_unauthenticated_reads

        self.config_key = "config-key-value"
        self.read_key = "read-key-value"
        self.feedback_key = "feedback-key-value"
        dashboard.DB_PATH = self.db_path
        dashboard.MODE = "local"
        dashboard.CONFIG_WRITES_ENABLED = True
        dashboard.auth_state.dashboard_write_secret = "config-api-cookie-secret"
        dashboard.auth_state.allow_unauthenticated_reads = True
        dashboard.auth_state.keys = parse_api_keys(
            "config-operator:"
            f"{hash_api_key(self.config_key, iterations=1000)}:{SCOPE_CONFIG_WRITE},"
            f"reader:{hash_api_key(self.read_key, iterations=1000)}:{SCOPE_READ},"
            "feedback-operator:"
            f"{hash_api_key(self.feedback_key, iterations=1000)}:{SCOPE_FEEDBACK_WRITE}"
        )
        self.client = TestClient(dashboard.app)
        self.host = {"host": "localhost"}
        self.config_headers = {
            **self.host,
            API_KEY_HEADER_NAME: self.config_key,
        }

    def tearDown(self):
        dashboard.DB_PATH = self.old_db_path
        dashboard.MODE = self.old_mode
        dashboard.CONFIG_WRITES_ENABLED = self.old_writes_enabled
        dashboard.auth_state.keys = self.old_keys
        dashboard.auth_state.dashboard_write_secret = self.old_secret
        dashboard.auth_state.allow_unauthenticated_reads = self.old_allow
        self.temp.cleanup()

    @staticmethod
    def write(path: Path, document) -> None:
        path.write_text(json.dumps(document), encoding="utf-8")

    def db_rows(self, sql: str, parameters=()):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, parameters).fetchall()
        finally:
            conn.close()

    def summary(self):
        response = self.client.get(
            "/api/v1/config",
            headers=self.config_headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def create_draft(self, document, *, request_id="config-test-request"):
        summary = self.summary()
        parent = summary["active"]["prefilter_policy"]["id"]
        return self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers={**self.config_headers, "X-Request-ID": request_id},
            json={
                "document": document,
                "parent_revision_id": parent,
                "expected_generation": summary["generation"],
                "note": "Test candidate",
            },
        )

    def activate(self, document):
        """Run one full prefilter lifecycle and return the activated id."""
        summary = self.summary()
        created = self.create_draft(document)
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={
                "expected_generation": summary["generation"],
                "acknowledge_shipped_base_change": True,
            },
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        return activated.json()["revision"]["id"]

    def test_config_scope_is_api_key_only(self):
        cases = [
            ("anonymous", self.host),
            (
                "read",
                {**self.host, API_KEY_HEADER_NAME: self.read_key},
            ),
            (
                "feedback",
                {**self.host, API_KEY_HEADER_NAME: self.feedback_key},
            ),
        ]
        for label, headers in cases:
            with self.subTest(label=label):
                response = self.client.get("/api/v1/config", headers=headers)
                self.assertEqual(response.status_code, 401)

        self.client.get("/", headers=self.host)
        cookie_response = self.client.get("/api/v1/config", headers=self.host)
        self.assertEqual(cookie_response.status_code, 401)

    def test_demo_mode_denies_even_config_scoped_key(self):
        dashboard.MODE = "demo"

        response = self.client.get(
            "/api/v1/config",
            headers=self.config_headers,
        )

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("private-router", response.text)

    def test_config_summary_and_active_document_are_private_no_store(self):
        summary_response = self.client.get(
            "/api/v1/config",
            headers=self.config_headers,
        )
        asset_response = self.client.get(
            "/api/v1/config/asset_inventory",
            headers=self.config_headers,
        )

        self.assertEqual(summary_response.status_code, 200)
        self.assertEqual(summary_response.headers["cache-control"], "private, no-store")
        summary = summary_response.json()
        self.assertEqual(summary["mode"], "legacy")
        self.assertEqual(summary["generation"], 1)
        self.assertTrue(summary["writes_enabled"])
        self.assertTrue(summary["reload"]["supported"])
        self.assertEqual(summary["reload"]["consumers"], [])
        self.assertEqual(asset_response.status_code, 200)
        self.assertEqual(asset_response.headers["cache-control"], "private, no-store")
        self.assertEqual(
            asset_response.json()["document"]["assets"][0]["hostname"],
            "private-router",
        )

    def test_openapi_marks_configuration_routes_with_api_key_security(self):
        dashboard.app.openapi_schema = None
        schema = self.client.get("/openapi.json", headers=self.host).json()

        for path, method in (
            ("/api/v1/config", "get"),
            ("/api/v1/config/{kind}", "get"),
            ("/api/v1/config/{kind}/revisions", "get"),
            ("/api/v1/config/{kind}/revisions/{revision_id}", "get"),
            ("/api/v1/config/{kind}/drafts", "post"),
            ("/api/v1/config/{kind}/drafts/{draft_id}/validate", "post"),
            ("/api/v1/config/{kind}/drafts/{draft_id}/preview", "post"),
            ("/api/v1/config/{kind}/drafts/{draft_id}/activate", "post"),
            ("/api/v1/config/{kind}/revisions/{revision_id}/rollback", "post"),
            ("/api/v1/config/audit", "get"),
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    schema["paths"][path][method]["security"],
                    [{"ApiKeyAuth": []}],
                )

    def test_writes_are_default_off_independently_of_read_access(self):
        dashboard.CONFIG_WRITES_ENABLED = False
        summary = self.summary()
        parent = summary["active"]["prefilter_policy"]["id"]

        response = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.config_headers,
            json={
                "document": prefilter_document(signature_id=2002),
                "parent_revision_id": parent,
                "expected_generation": 1,
            },
        )

        self.assertFalse(summary["writes_enabled"])
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_revisions
                   WHERE source = 'operator'"""
            ),
            [(0,)],
        )

    def test_create_and_validate_normalized_draft_without_activation(self):
        created = self.create_draft(
            prefilter_document(signature_id=2002, protocol="TCP")
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.headers["cache-control"], "private, no-store")
        draft = created.json()["draft"]
        self.assertEqual(draft["state"], "draft")
        self.assertEqual(draft["created_by"], "config-operator")

        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft['id']}/validate",
            headers={**self.config_headers, "X-Request-ID": "validate-request"},
        )

        self.assertEqual(validated.status_code, 200, validated.text)
        payload = validated.json()
        self.assertEqual(payload["validation"]["status"], "valid")
        self.assertEqual(payload["revision"]["state"], "validated")
        self.assertNotEqual(payload["revision"]["id"], draft["id"])
        self.assertEqual(
            payload["revision"]["parent_revision_id"],
            draft["parent_revision_id"],
        )
        stored = self.db_rows(
            """SELECT id, state, document_json FROM operator_config_revisions
               WHERE id IN (?, ?) ORDER BY id""",
            (draft["id"], payload["revision"]["id"]),
        )
        self.assertEqual(stored[0][1], "superseded")
        self.assertIn('"TCP"', stored[0][2])
        self.assertEqual(stored[1][1], "validated")
        self.assertIn('"tcp"', stored[1][2])
        original = self.client.get(
            f"/api/v1/config/prefilter_policy/revisions/{draft['id']}",
            headers=self.config_headers,
        )
        self.assertEqual(original.status_code, 200)
        self.assertEqual(
            original.json()["document"]["auto_false_positive"][0]["match"][
                "protocols"
            ],
            ["TCP"],
        )
        active = self.summary()
        self.assertEqual(active["generation"], 1)
        self.assertEqual(
            active["active"]["prefilter_policy"]["revision"],
            operator_config.load_revision(
                operator_config.PREFILTER_KIND,
                self.packaged,
                "shipped",
            ).revision,
        )

    def test_invalid_draft_is_rejected_without_replacing_active(self):
        invalid = prefilter_document(signature_id=2002)
        invalid["auto_false_positive"][0]["signature_ids"] = []
        created = self.create_draft(invalid)
        self.assertEqual(created.status_code, 201)
        draft_id = created.json()["draft"]["id"]

        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )

        self.assertEqual(validated.status_code, 200)
        payload = validated.json()
        self.assertEqual(payload["validation"]["status"], "invalid")
        self.assertEqual(payload["revision"]["state"], "rejected")
        self.assertEqual(self.summary()["generation"], 1)

    def test_already_canonical_draft_validates_in_place(self):
        created = self.create_draft(prefilter_document(signature_id=2002))
        draft_id = created.json()["draft"]["id"]

        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )

        self.assertEqual(validated.status_code, 200)
        self.assertEqual(validated.json()["revision"]["id"], draft_id)
        self.assertEqual(validated.json()["revision"]["state"], "validated")

        listed = self.client.get(
            "/api/v1/config/prefilter_policy/revisions?state=validated",
            headers=self.config_headers,
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.headers["cache-control"], "private, no-store")
        self.assertEqual(
            [revision["id"] for revision in listed.json()["revisions"]],
            [draft_id],
        )

    def test_asset_inventory_uses_the_same_immutable_validation_lifecycle(self):
        summary = self.summary()
        created = self.client.post(
            "/api/v1/config/asset_inventory/drafts",
            headers=self.config_headers,
            json={
                "document": asset_document(hostname="private-firewall"),
                "parent_revision_id": summary["active"]["asset_inventory"]["id"],
                "expected_generation": summary["generation"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]

        validated = self.client.post(
            f"/api/v1/config/asset_inventory/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )

        self.assertEqual(validated.status_code, 200, validated.text)
        self.assertEqual(validated.json()["validation"]["asset_count"], 1)
        self.assertEqual(validated.json()["revision"]["state"], "validated")
        self.assertEqual(self.summary()["generation"], 1)

    def test_oversized_document_is_rejected_without_persistence(self):
        oversized = prefilter_document(signature_id=2002)
        oversized["auto_false_positive"][0]["reason"] = (
            "x" * config_repository.MAX_CONFIG_BYTES
        )

        response = self.create_draft(oversized)

        self.assertEqual(response.status_code, 422)
        self.assertNotIn("xxx", response.text)
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_revisions
                   WHERE source = 'operator'"""
            ),
            [(0,)],
        )

    def test_stale_generation_conflicts_and_identical_draft_resumes(self):
        summary = self.summary()
        parent = summary["active"]["prefilter_policy"]["id"]
        stale = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.config_headers,
            json={
                "document": prefilter_document(signature_id=2002),
                "parent_revision_id": parent,
                "expected_generation": 99,
            },
        )
        self.assertEqual(stale.status_code, 409)

        first = self.create_draft(prefilter_document(signature_id=2002))
        duplicate = self.create_draft(prefilter_document(signature_id=2002))
        self.assertEqual(first.status_code, 201)
        self.assertFalse(first.json()["resumed"])
        self.assertEqual(duplicate.status_code, 200)
        self.assertTrue(duplicate.json()["resumed"])
        self.assertEqual(
            duplicate.json()["draft"]["id"], first.json()["draft"]["id"]
        )
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_revisions
                   WHERE kind = 'prefilter_policy' AND source = 'operator'"""
            ),
            [(1,)],
        )

    def test_validated_revision_resumes_after_editor_state_is_lost(self):
        document = prefilter_document(signature_id=2002)
        created = self.create_draft(document)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        validated_id = validated.json()["revision"]["id"]

        # The editor lost its lifecycle state; the operator resubmits the very
        # same document, which cannot create a second row for that digest.
        resumed = self.create_draft(document)

        self.assertEqual(resumed.status_code, 200, resumed.text)
        self.assertTrue(resumed.json()["resumed"])
        self.assertEqual(resumed.json()["draft"]["id"], validated_id)
        self.assertEqual(resumed.json()["draft"]["state"], "validated")

        revalidated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{validated_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(revalidated.status_code, 200, revalidated.text)
        self.assertEqual(revalidated.json()["revision"]["id"], validated_id)

        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{validated_id}/activate",
            headers=self.config_headers,
            json={"expected_generation": 1},
        )

        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["generation"], 2)
        self.assertEqual(self.summary()["generation"], 2)
        self.assertEqual(
            self.summary()["active"]["prefilter_policy"]["id"], validated_id
        )
        self.assertIn(
            ("draft_resumed",),
            self.db_rows("SELECT action FROM operator_config_audit"),
        )

    def test_resume_is_refused_for_a_revision_off_a_different_parent(self):
        document = prefilter_document(signature_id=2002)
        created = self.create_draft(document)
        draft_id = created.json()["draft"]["id"]
        self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={"expected_generation": 1},
        )
        self.assertEqual(activated.status_code, 200, activated.text)

        # The identical content is now the active revision, raised against a
        # parent that is no longer active. It must never be resumed as a draft.
        conflict = self.create_draft(document)

        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertIn("identical configuration revision", conflict.text)
        self.assertEqual(self.summary()["generation"], 2)

    def test_canonicalized_candidate_keeps_the_submitted_draft_parent(self):
        first_id = self.summary()["active"]["prefilter_policy"]["id"]
        superseded_id = self.activate(prefilter_document(signature_id=2002))
        self.activate(prefilter_document(signature_id=3003))
        summary = self.summary()
        self.assertEqual(summary["generation"], 3)
        self.assertNotEqual(
            summary["active"]["prefilter_policy"]["id"], superseded_id
        )

        # This noncanonical draft normalizes onto the superseded SID 2002 row,
        # whose recorded parent is the long-replaced original revision.
        created = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.config_headers,
            json={
                "document": prefilter_document(signature_id=2002, protocol="TCP"),
                "parent_revision_id": summary["active"]["prefilter_policy"]["id"],
                "expected_generation": summary["generation"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )

        self.assertEqual(validated.status_code, 200, validated.text)
        payload = validated.json()
        self.assertEqual(payload["validation"]["status"], "valid")
        self.assertEqual(payload["revision"]["id"], superseded_id)
        self.assertEqual(payload["revision"]["parent_revision_id"], first_id)
        self.assertEqual(
            payload["candidate_parent_revision_id"],
            summary["active"]["prefilter_policy"]["id"],
        )

        previewed = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.config_headers,
            json={"expected_generation": summary["generation"]},
        )
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={"expected_generation": summary["generation"]},
        )

        self.assertEqual(previewed.status_code, 200, previewed.text)
        self.assertEqual(previewed.json()["candidate_revision_id"], superseded_id)
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["generation"], 4)
        self.assertEqual(activated.json()["revision"]["id"], superseded_id)
        self.assertEqual(
            self.summary()["active"]["prefilter_policy"]["id"], superseded_id
        )
        self.assertEqual(
            self.db_rows(
                "SELECT document_json FROM operator_config_revisions WHERE id = ?",
                (superseded_id,),
            ),
            [(json.dumps(
                prefilter_document(signature_id=2002),
                sort_keys=True,
                separators=(",", ":"),
            ),)],
        )

    def test_canonical_reuse_still_requires_shipped_base_acknowledgement(self):
        # Discover a newer shipped baseline, which lands as its own revision
        # carrying that new baseline.
        self.write(self.packaged, prefilter_document(signature_id=3003))
        operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
        )
        summary = self.summary()
        self.assertEqual(
            summary["active"]["prefilter_policy"]["shipped_base_revision"],
            operator_config.load_revision(
                operator_config.PREFILTER_KIND,
                self.legacy,
                "shipped",
            ).revision,
        )

        # This draft is raised against the older baseline but canonicalizes onto
        # the row that was imported with the newer one.
        created = self.create_draft(
            prefilter_document(signature_id=3003, protocol="TCP")
        )
        self.assertEqual(created.status_code, 201, created.text)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        reused = validated.json()["revision"]
        self.assertNotEqual(reused["id"], draft_id)
        self.assertNotEqual(
            reused["shipped_base_revision"],
            created.json()["draft"]["shipped_base_revision"],
        )

        missing_ack = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={"expected_generation": summary["generation"]},
        )

        self.assertEqual(missing_ack.status_code, 409, missing_ack.text)
        self.assertIn("shipped-base change", missing_ack.text)
        self.assertEqual(self.summary()["generation"], summary["generation"])
        rejected = self.db_rows(
            """SELECT detail_json FROM operator_config_audit
               WHERE action = 'revision_activation_rejected'
               ORDER BY id DESC LIMIT 1"""
        )
        self.assertEqual(
            json.loads(rejected[0][0])["reason"],
            "unacknowledged_shipped_base_change",
        )

        acknowledged = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={
                "expected_generation": summary["generation"],
                "acknowledge_shipped_base_change": True,
            },
        )
        self.assertEqual(acknowledged.status_code, 200, acknowledged.text)
        self.assertEqual(acknowledged.json()["revision"]["id"], reused["id"])

    def test_normalized_draft_resumes_after_losing_the_draft_handle(self):
        self.activate(prefilter_document(signature_id=2002))
        self.activate(prefilter_document(signature_id=3003))
        noncanonical = prefilter_document(signature_id=2002, protocol="TCP")
        created = self.create_draft(noncanonical)
        draft_id = created.json()["draft"]["id"]
        validated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(validated.status_code, 200, validated.text)
        canonical_id = validated.json()["revision"]["id"]

        # The editor loses the draft handle and the operator resubmits, first
        # the identical noncanonical document, then its canonical form.
        resumed = self.create_draft(noncanonical)
        resumed_canonical = self.create_draft(prefilter_document(signature_id=2002))

        for response in (resumed, resumed_canonical):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["resumed"])
            self.assertEqual(response.json()["draft"]["id"], draft_id)
            self.assertEqual(response.json()["validated_revision_id"], canonical_id)

        generation = self.summary()["generation"]
        revalidated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        self.assertEqual(revalidated.status_code, 200, revalidated.text)
        self.assertEqual(revalidated.json()["revision"]["id"], canonical_id)
        previewed = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/preview",
            headers=self.config_headers,
            json={"expected_generation": generation},
        )
        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={
                "expected_generation": generation,
                "acknowledge_shipped_base_change": True,
            },
        )

        self.assertEqual(previewed.status_code, 200, previewed.text)
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(activated.json()["generation"], generation + 1)
        self.assertEqual(
            self.summary()["active"]["prefilter_policy"]["id"], canonical_id
        )
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_revisions
                   WHERE kind = 'prefilter_policy' AND revision = ?""",
                (created.json()["draft"]["revision"],),
            ),
            [(1,)],
        )

    def test_normalization_input_is_not_a_rollback_target(self):
        self.activate(prefilter_document(signature_id=2002))
        created = self.create_draft(
            prefilter_document(signature_id=3003, protocol="TCP")
        )
        draft_id = created.json()["draft"]["id"]
        self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        listed = self.client.get(
            "/api/v1/config/prefilter_policy/revisions?state=superseded",
            headers=self.config_headers,
        )
        self.assertEqual(listed.status_code, 200)
        normalization_inputs = [
            revision
            for revision in listed.json()["revisions"]
            if revision["validation"].get("normalized_revision_id") is not None
        ]
        self.assertEqual([revision["id"] for revision in normalization_inputs], [draft_id])

        response = self.client.post(
            f"/api/v1/config/prefilter_policy/revisions/{draft_id}/rollback",
            headers=self.config_headers,
            json={"expected_generation": self.summary()["generation"]},
        )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("normalization input", response.text)
        self.assertEqual(
            json.loads(
                self.db_rows(
                    """SELECT detail_json FROM operator_config_audit
                       WHERE action = 'revision_rollback_rejected'
                       ORDER BY id DESC LIMIT 1"""
                )[0][0]
            )["reason"],
            "normalization_input",
        )

    def test_refused_mutations_leave_attributable_audit_evidence(self):
        summary = self.summary()
        stale = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers={**self.config_headers, "X-Request-ID": "stale-generation"},
            json={
                "document": prefilter_document(signature_id=2002),
                "parent_revision_id": summary["active"]["prefilter_policy"]["id"],
                "expected_generation": 99,
            },
        )
        self.assertEqual(stale.status_code, 409)

        created = self.create_draft(prefilter_document(signature_id=4004, scoped=False))
        draft_id = created.json()["draft"]["id"]
        self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        missing_ack = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers={**self.config_headers, "X-Request-ID": "missing-ack"},
            json={"expected_generation": summary["generation"]},
        )
        self.assertEqual(missing_ack.status_code, 409)

        rejections = self.db_rows(
            """SELECT action, actor, auth_via, request_id, detail_json
               FROM operator_config_audit
               WHERE action IN (
                   'draft_creation_rejected', 'revision_activation_rejected'
               ) ORDER BY id"""
        )
        self.assertEqual(
            [row[0] for row in rejections],
            ["draft_creation_rejected", "revision_activation_rejected"],
        )
        for row in rejections:
            self.assertEqual(row[1], "config-operator")
            self.assertEqual(row[2], "api_key")
            self.assertNotIn("Reviewed rule", row[4])
            self.assertNotIn(self.config_key, row[4])
        self.assertEqual(rejections[0][3], "stale-generation")
        self.assertEqual(rejections[1][3], "missing-ack")
        self.assertEqual(
            json.loads(rejections[0][4])["reason"], "stale_generation"
        )
        self.assertEqual(
            json.loads(rejections[1][4])["reason"], "unacknowledged_broad_rules"
        )
        # Evidence survives the rollback of the refused mutation itself.
        self.assertEqual(self.summary()["generation"], summary["generation"])
        self.assertEqual(
            self.db_rows(
                """SELECT COUNT(*) FROM operator_config_revisions
                   WHERE kind = 'prefilter_policy' AND state = 'active'"""
            ),
            [(1,)],
        )

    def test_canonicalized_candidate_off_a_stale_parent_cannot_activate(self):
        superseded_id = self.activate(prefilter_document(signature_id=2002))
        summary = self.summary()
        created = self.client.post(
            "/api/v1/config/prefilter_policy/drafts",
            headers=self.config_headers,
            json={
                "document": prefilter_document(signature_id=4004, protocol="TCP"),
                "parent_revision_id": summary["active"]["prefilter_policy"]["id"],
                "expected_generation": summary["generation"],
            },
        )
        draft_id = created.json()["draft"]["id"]
        self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers=self.config_headers,
        )
        # Another activation moves the active pointer under the candidate.
        self.activate(prefilter_document(signature_id=3003))

        activated = self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/activate",
            headers=self.config_headers,
            json={"expected_generation": self.summary()["generation"]},
        )

        self.assertEqual(activated.status_code, 409, activated.text)
        self.assertIn("parent is no longer active", activated.text)
        self.assertNotEqual(
            self.summary()["active"]["prefilter_policy"]["id"], superseded_id
        )

    def test_audit_is_attributable_bounded_and_cursor_paginated(self):
        created = self.create_draft(prefilter_document(signature_id=2002))
        draft_id = created.json()["draft"]["id"]
        self.client.post(
            f"/api/v1/config/prefilter_policy/drafts/{draft_id}/validate",
            headers={**self.config_headers, "X-Request-ID": "validation-id"},
        )

        first = self.client.get(
            "/api/v1/config/audit?limit=2",
            headers=self.config_headers,
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.headers["cache-control"], "private, no-store")
        first_payload = first.json()
        self.assertEqual(len(first_payload["entries"]), 2)
        self.assertIsNotNone(first_payload["next_cursor"])
        self.assertEqual(first_payload["entries"][0]["action"], "draft_validated")
        self.assertEqual(first_payload["entries"][0]["actor"], "config-operator")
        self.assertEqual(first_payload["entries"][0]["auth_via"], "api_key")
        self.assertEqual(first_payload["entries"][0]["request_id"], "validation-id")

        second = self.client.get(
            "/api/v1/config/audit",
            headers=self.config_headers,
            params={"limit": 2, "cursor": first_payload["next_cursor"]},
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            [entry["action"] for entry in second.json()["entries"]],
            ["bootstrap_activated"],
        )
        self.assertNotIn("private-router", first.text + second.text)

    def test_invalid_audit_cursor_and_request_id_are_rejected(self):
        audit = self.client.get(
            "/api/v1/config/audit?cursor=not-a-cursor",
            headers=self.config_headers,
        )
        created = self.create_draft(
            prefilter_document(signature_id=2002),
            request_id="x" * 129,
        )

        self.assertEqual(audit.status_code, 422)
        self.assertEqual(created.status_code, 422)


class ConfigAuthSettingsTests(unittest.TestCase):
    def test_config_scope_is_accepted(self):
        keys = parse_api_keys(
            "operator:"
            f"{hash_api_key('secret-value', iterations=1000)}:{SCOPE_CONFIG_WRITE}"
        )
        self.assertEqual(keys[0].scopes, frozenset({SCOPE_CONFIG_WRITE}))

    def test_enabled_writes_require_config_scoped_key(self):
        read_keys = parse_api_keys(
            "reader:"
            f"{hash_api_key('read-value', iterations=1000)}:{SCOPE_READ}"
        )
        with self.assertRaisesRegex(RuntimeError, "config:write"):
            validate_config_write_settings(read_keys, writes_enabled=True)

        validate_config_write_settings(read_keys, writes_enabled=False)
        config_keys = parse_api_keys(
            "operator:"
            f"{hash_api_key('config-value', iterations=1000)}:{SCOPE_CONFIG_WRITE}"
        )
        validate_config_write_settings(config_keys, writes_enabled=True)

    def test_compose_and_example_keep_configuration_mutation_default_off(self):
        compose = (PROJECT_ROOT / "docker-compose.yml").read_text()
        example = (PROJECT_ROOT / ".env.example").read_text()
        expected = (
            "TRIAGEWALL_CONFIG_WRITES_ENABLED: "
            "${TRIAGEWALL_CONFIG_WRITES_ENABLED:-false}"
        )
        self.assertIn(expected, compose)
        self.assertIn("TRIAGEWALL_API_KEYS: ${TRIAGEWALL_API_KEYS:-}", compose)
        self.assertIn("TRIAGEWALL_CONFIG_WRITES_ENABLED=false", example)


if __name__ == "__main__":
    unittest.main(verbosity=2)
