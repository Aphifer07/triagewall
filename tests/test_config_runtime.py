#!/usr/bin/env python3
"""Generation-aware configuration reload and last-known-good regressions."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import config_repository
import ingest
import migrations
import operator_config
import triage
import wazuh_ingest
from asset_inventory import AssetInventory
from database import connect_database
from prefilter import PrefilterPolicy


def prefilter_document(signature_id=1001):
    return {
        "version": 1,
        "internal_cidrs": ["10.0.0.0/24"],
        "auto_false_positive": [
            {
                "signature_ids": [signature_id],
                "reason": f"Reviewed rule {signature_id}",
                "match": {"protocols": ["tcp"]},
            }
        ],
    }


def asset_document(hostname="router"):
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


class RuntimeConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "triage.db"
        self.packaged = self.root / "packaged.json"
        self.legacy = self.root / "legacy.json"
        self.assets = self.root / "assets.json"
        self.packaged.write_text(json.dumps(prefilter_document()), encoding="utf-8")
        self.legacy.write_text(self.packaged.read_text(), encoding="utf-8")
        self.assets.write_text(json.dumps(asset_document()), encoding="utf-8")
        migrations.ensure_db_initialized(self.db_path)
        operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
        )
        self.policy = PrefilterPolicy.from_document(prefilter_document())
        self.inventory = AssetInventory.from_document(asset_document())
        self.conn = connect_database(self.db_path)

    def tearDown(self):
        triage.set_configuration_bundle_owner(None)
        self.conn.close()
        self.temp.cleanup()

    def owner(self, consumer="suricata", clock=lambda: 0.0):
        return operator_config.ConfigurationBundleOwner(
            consumer=consumer,
            legacy_prefilter_policy=self.policy,
            legacy_asset_inventory=self.inventory,
            reload_interval_seconds=5,
            clock=clock,
        )

    def active(self, kind):
        state = self.conn.execute(
            """SELECT generation, active_prefilter_revision_id,
                      active_asset_revision_id
               FROM operator_config_state"""
        ).fetchone()
        return int(state[0]), int(state[1] if kind == "prefilter_policy" else state[2])

    def activate_prefilter(self, signature_id=2002):
        generation, parent = self.active("prefilter_policy")
        created = config_repository.create_draft(
            self.conn,
            kind="prefilter_policy",
            document=prefilter_document(signature_id),
            parent_revision_id=parent,
            expected_generation=generation,
            note=None,
            actor="operator",
            auth_via="api_key",
            request_id="runtime-test",
        )
        draft_id = created["draft"]["id"]
        validated = config_repository.validate_draft(
            self.conn,
            kind="prefilter_policy",
            draft_id=draft_id,
            actor="operator",
            auth_via="api_key",
            request_id="runtime-test",
        )
        activated = config_repository.activate_draft(
            self.conn,
            kind="prefilter_policy",
            draft_id=draft_id,
            expected_generation=generation,
            acknowledge_broad_rules=False,
            acknowledge_shipped_base_change=False,
            actor="operator",
            auth_via="api_key",
            request_id="runtime-test",
        )
        return parent, validated["revision"]["id"], activated

    def test_generation_reload_publishes_complete_database_bundle(self):
        owner = self.owner()
        initial = owner.start(self.conn)
        triage.set_configuration_bundle_owner(owner)
        _, candidate_id, activated = self.activate_prefilter()

        self.assertTrue(activated["authority_cutover"])
        self.assertEqual(owner.bundle.generation, 1)
        self.assertEqual(owner.bundle.prefilter_policy.signature_ids, {1001})

        reloaded = owner.maybe_reload(self.conn, force=True)

        self.assertTrue(reloaded)
        self.assertIsNot(owner.bundle, initial)
        self.assertEqual(owner.bundle.generation, 2)
        self.assertEqual(owner.bundle.mode, "database")
        self.assertEqual(owner.bundle.prefilter_policy.signature_ids, {2002})
        self.assertEqual(owner.bundle.asset_revision, initial.asset_revision)
        self.assertEqual(
            self.conn.execute(
                """SELECT loaded_generation, desired_generation, status,
                          last_error FROM operator_config_consumers
                   WHERE consumer = 'suricata'"""
            ).fetchone(),
            (2, 2, "ok", None),
        )
        self.assertEqual(
            self.conn.execute(
                """SELECT to_revision_id FROM operator_config_audit
                   WHERE action = 'revision_activated'"""
            ).fetchone()[0],
            candidate_id,
        )

    def test_reload_failure_keeps_last_known_good_and_recovers(self):
        owner = self.owner()
        initial = owner.start(self.conn)
        active_id = self.active("prefilter_policy")[1]
        original = self.conn.execute(
            """SELECT document_json FROM operator_config_revisions
               WHERE id = ?""",
            (active_id,),
        ).fetchone()[0]
        self.conn.execute(
            "UPDATE operator_config_revisions SET document_json = '{}' WHERE id = ?",
            (active_id,),
        )
        self.conn.execute(
            """UPDATE operator_config_state
               SET mode = 'database', generation = 2 WHERE id = 1"""
        )
        self.conn.commit()

        self.assertFalse(owner.maybe_reload(self.conn, force=True))
        self.assertIs(owner.bundle, initial)
        status = self.conn.execute(
            """SELECT loaded_generation, desired_generation, status, last_error
               FROM operator_config_consumers WHERE consumer = 'suricata'"""
        ).fetchone()
        self.assertEqual(status[:3], (1, 2, "error"))
        self.assertEqual(status[3], "active configuration reload failed validation")
        health = config_repository.get_config_summary(
            self.conn,
            writes_enabled=True,
        )["reload"]
        self.assertEqual(health["desired_generation"], 2)
        self.assertEqual(len(health["consumers"]), 1)
        self.assertEqual(health["consumers"][0]["consumer"], "suricata")
        self.assertEqual(health["consumers"][0]["loaded_generation"], 1)
        self.assertEqual(health["consumers"][0]["desired_generation"], 2)
        self.assertEqual(health["consumers"][0]["status"], "error")
        self.assertGreaterEqual(health["consumers"][0]["status_age_seconds"], 0)

        self.assertFalse(owner.maybe_reload(self.conn, force=True))
        failures = self.conn.execute(
            """SELECT COUNT(*) FROM operator_config_audit
               WHERE action = 'runtime_reload_failed'"""
        ).fetchone()[0]
        self.assertEqual(failures, 1)

        self.conn.execute(
            "UPDATE operator_config_revisions SET document_json = ? WHERE id = ?",
            (original, active_id),
        )
        self.conn.commit()
        self.assertTrue(owner.maybe_reload(self.conn, force=True))
        self.assertEqual(owner.bundle.generation, 2)
        recovered = self.conn.execute(
            """SELECT status, last_error FROM operator_config_consumers
               WHERE consumer = 'suricata'"""
        ).fetchone()
        self.assertEqual(recovered, ("ok", None))

    def test_startup_database_mode_ignores_mounted_legacy_objects(self):
        first = self.owner()
        first.start(self.conn)
        self.activate_prefilter()
        incompatible_policy = PrefilterPolicy.empty()
        incompatible_assets = AssetInventory.from_document(
            {"version": 1, "assets": []}
        )
        restarted = operator_config.ConfigurationBundleOwner(
            consumer="wazuh",
            legacy_prefilter_policy=incompatible_policy,
            legacy_asset_inventory=incompatible_assets,
        )

        bundle = restarted.start(self.conn)

        self.assertEqual(bundle.mode, "database")
        self.assertEqual(bundle.generation, 2)
        self.assertEqual(bundle.prefilter_policy.signature_ids, {2002})
        self.assertEqual(bundle.asset_inventory.count, 1)

    def test_reload_interval_is_bounded_between_checks(self):
        ticks = iter([0.0, 1.0, 6.0])
        owner = self.owner(clock=lambda: next(ticks))
        owner.start(self.conn)
        self.conn.execute(
            """UPDATE operator_config_consumers
               SET status = 'error', last_error = 'stale test marker'
               WHERE consumer = 'suricata'"""
        )
        self.conn.commit()
        self.assertFalse(owner.maybe_reload(self.conn))
        self.assertFalse(owner.maybe_reload(self.conn))
        self.assertEqual(
            self.conn.execute(
                """SELECT status, last_error FROM operator_config_consumers
                   WHERE consumer = 'suricata'"""
            ).fetchone(),
            ("ok", None),
        )


class ConsumerStartupSynchronizationTests(unittest.TestCase):
    """A consumer restart must mirror valid legacy mounts before it starts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "triage.db"
        self.packaged = self.root / "packaged.json"
        self.legacy = self.root / "legacy.json"
        self.assets = self.root / "assets.json"
        self.packaged.write_text(json.dumps(prefilter_document()), encoding="utf-8")
        self.legacy.write_text(self.packaged.read_text(), encoding="utf-8")
        self.assets.write_text(json.dumps(asset_document()), encoding="utf-8")
        migrations.ensure_db_initialized(self.db_path)
        operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
        )
        self.conn = connect_database(self.db_path)

    def tearDown(self):
        triage.set_configuration_bundle_owner(None)
        self.conn.close()
        self.temp.cleanup()

    def start_consumer(self, consumer="suricata"):
        """Run the exact startup path both ingest daemons use."""
        with patch.object(
            ingest, "packaged_prefilter_path", lambda: str(self.packaged)
        ), patch.object(
            ingest, "configured_inventory_path", lambda: self.assets
        ), patch.object(
            ingest, "PREFILTER_CONFIG_PATH", self.legacy
        ):
            return ingest.start_configuration_owner(
                self.conn,
                consumer=consumer,
                db_path=self.db_path,
            )

    def durable_state(self):
        return self.conn.execute(
            """SELECT generation, mode, active_prefilter_revision_id
               FROM operator_config_state WHERE id = 1"""
        ).fetchone()

    def test_restarted_consumer_mirrors_an_edited_legacy_mount(self):
        self.legacy.write_text(
            json.dumps(prefilter_document(2002)), encoding="utf-8"
        )

        owner = self.start_consumer()

        self.assertEqual(owner.bundle.generation, 2)
        self.assertEqual(owner.bundle.mode, "legacy")
        self.assertEqual(owner.bundle.prefilter_policy.signature_ids, {2002})
        self.assertEqual(self.durable_state()[0], 2)
        self.assertEqual(
            self.conn.execute(
                """SELECT revision FROM operator_config_revisions WHERE id = ?""",
                (self.durable_state()[2],),
            ).fetchone()[0],
            owner.bundle.prefilter_revision,
        )
        self.assertEqual(
            self.conn.execute(
                """SELECT loaded_generation, status, last_error
                   FROM operator_config_consumers WHERE consumer = 'suricata'"""
            ).fetchone(),
            (2, "ok", None),
        )

    def test_both_consumers_share_one_synchronized_startup_path(self):
        self.assertIs(
            wazuh_ingest.start_configuration_owner,
            ingest.start_configuration_owner,
        )
        self.assets.write_text(
            json.dumps(asset_document("firewall")), encoding="utf-8"
        )

        owner = self.start_consumer(consumer="wazuh")

        self.assertEqual(owner.bundle.generation, 2)
        self.assertEqual(
            owner.bundle.asset_inventory.assets[0]["hostname"], "firewall"
        )
        self.assertEqual(
            self.conn.execute(
                """SELECT loaded_generation, status FROM operator_config_consumers
                   WHERE consumer = 'wazuh'"""
            ).fetchone(),
            (2, "ok"),
        )

    def test_repeated_consumer_starts_do_not_churn_the_generation(self):
        self.legacy.write_text(
            json.dumps(prefilter_document(2002)), encoding="utf-8"
        )

        first = self.start_consumer()
        second = self.start_consumer()

        self.assertEqual(first.bundle.generation, 2)
        self.assertEqual(second.bundle.generation, 2)
        self.assertEqual(self.durable_state()[0], 2)

    def test_invalid_legacy_mount_still_fails_the_consumer_closed(self):
        self.legacy.write_text("not json", encoding="utf-8")

        with self.assertRaisesRegex(
            operator_config.OperatorConfigError,
            "must be valid UTF-8 JSON",
        ):
            self.start_consumer()

        self.assertEqual(self.durable_state()[0], 1)

    def test_database_authority_consumer_start_never_reads_legacy_mounts(self):
        generation, parent = 1, self.durable_state()[2]
        created = config_repository.create_draft(
            self.conn,
            kind="prefilter_policy",
            document=prefilter_document(2002),
            parent_revision_id=parent,
            expected_generation=generation,
            note=None,
            actor="operator",
            auth_via="api_key",
            request_id="startup-test",
        )
        config_repository.validate_draft(
            self.conn,
            kind="prefilter_policy",
            draft_id=created["draft"]["id"],
            actor="operator",
            auth_via="api_key",
            request_id="startup-test",
        )
        config_repository.activate_draft(
            self.conn,
            kind="prefilter_policy",
            draft_id=created["draft"]["id"],
            expected_generation=generation,
            acknowledge_broad_rules=False,
            acknowledge_shipped_base_change=False,
            actor="operator",
            auth_via="api_key",
            request_id="startup-test",
        )
        self.legacy.unlink()
        self.assets.unlink()

        owner = self.start_consumer()

        self.assertEqual(owner.bundle.mode, "database")
        self.assertEqual(owner.bundle.generation, 2)
        self.assertEqual(owner.bundle.prefilter_policy.signature_ids, {2002})
        self.assertIsNone(owner.legacy_prefilter_policy)
        self.assertIsNone(owner.legacy_asset_inventory)

    def test_ingest_modules_import_without_reading_legacy_mounts(self):
        environment = {
            **os.environ,
            "ASSET_INVENTORY_PATH": str(self.root / "missing-assets.json"),
            "PYTHONPATH": str(PROJECT_ROOT / "triagewall"),
            "PYTHONIOENCODING": "utf-8",
        }

        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "import triage, ingest, wazuh_ingest; print('imported')",
            ],
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(PROJECT_ROOT),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("imported", completed.stdout)
        self.assertNotIn("asset inventory", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
