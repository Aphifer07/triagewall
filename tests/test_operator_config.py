#!/usr/bin/env python3
"""Regression coverage for immutable operator-configuration bootstrap."""

import json
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import migrations
import operator_config


NOW = "2026-08-15T00:00:00.000000Z"


def prefilter_document(*, signature_id=1001, protocol="tcp"):
    return {
        "version": 1,
        "internal_cidrs": ["10.0.0.0/24"],
        "auto_false_positive": [
            {
                "signature_ids": [signature_id],
                "reason": f"Reviewed rule {signature_id}",
                "match": {"protocols": [protocol]},
            }
        ],
    }


def asset_document(*, hostname="router"):
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


class OperatorConfigBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "triage.db"
        self.packaged = self.root / "packaged-prefilter.json"
        self.legacy = self.root / "legacy-prefilter.json"
        self.assets = self.root / "assets.json"
        self.write(self.packaged, prefilter_document())
        self.write(self.legacy, prefilter_document())
        self.write(self.assets, asset_document())
        migrations.ensure_db_initialized(self.db_path)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write(path, document):
        path.write_text(json.dumps(document), encoding="utf-8")

    def bootstrap(self):
        return operator_config.bootstrap_operator_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
            occurred_at=NOW,
        )

    def rows(self, sql, parameters=()):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql, parameters).fetchall()
        finally:
            conn.close()

    def execute(self, sql, parameters=()):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(sql, parameters)
            conn.commit()
        finally:
            conn.close()

    def test_migration_creates_configuration_tables_and_indexes(self):
        tables = {
            row[0]
            for row in self.rows(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in self.rows(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        self.assertTrue(
            {
                "operator_config_revisions",
                "operator_config_state",
                "operator_config_audit",
                "operator_config_consumers",
            }
            <= tables
        )
        self.assertTrue(
            {
                "idx_operator_config_revisions_kind_state",
                "idx_operator_config_one_active_kind",
                "idx_operator_config_audit_occurred",
            }
            <= indexes
        )
        state_columns = {
            row[1]
            for row in self.rows("PRAGMA table_info('operator_config_state')")
        }
        self.assertIn("mode", state_columns)
        consumer_columns = {
            row[1]
            for row in self.rows("PRAGMA table_info('operator_config_consumers')")
        }
        self.assertEqual(
            consumer_columns,
            {
                "consumer",
                "loaded_generation",
                "desired_generation",
                "status",
                "prefilter_revision",
                "asset_revision",
                "loaded_at",
                "checked_at",
                "last_error",
            },
        )

    def test_identical_legacy_policy_uses_shipped_revision(self):
        result = self.bootstrap()

        self.assertTrue(result.initialized)
        self.assertEqual(result.generation, 1)
        self.assertEqual(result.mode, "legacy")
        revisions = self.rows(
            """SELECT kind, source, state, revision
               FROM operator_config_revisions ORDER BY kind"""
        )
        self.assertEqual(len(revisions), 2)
        self.assertEqual(
            [(row[0], row[1], row[2]) for row in revisions],
            [
                ("asset_inventory", "operator_import", "active"),
                ("prefilter_policy", "shipped", "active"),
            ],
        )
        self.assertEqual(
            self.rows(
                """SELECT generation, mode FROM operator_config_state WHERE id = 1"""
            ),
            [(1, "legacy")],
        )
        self.assertEqual(
            self.rows("SELECT action FROM operator_config_audit"),
            [("bootstrap_activated",)],
        )

    def test_changed_legacy_policy_is_imported_as_active_operator_revision(self):
        self.write(self.legacy, prefilter_document(signature_id=2002))

        result = self.bootstrap()

        revisions = self.rows(
            """SELECT source, state, revision FROM operator_config_revisions
               WHERE kind = 'prefilter_policy' ORDER BY id"""
        )
        self.assertEqual(
            [(row[0], row[1]) for row in revisions],
            [("shipped", "validated"), ("operator_import", "active")],
        )
        self.assertEqual(result.active_prefilter_revision, revisions[1][2])

    def test_bootstrap_is_idempotent(self):
        first = self.bootstrap()
        second = self.bootstrap()

        self.assertTrue(first.initialized)
        self.assertFalse(second.initialized)
        self.assertFalse(second.discovered_shipped_revision)
        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_revisions"), [(2,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_audit"), [(1,)])
        self.assertEqual(self.rows("SELECT generation FROM operator_config_state"), [(1,)])

    def test_legacy_mode_synchronizes_changed_mounted_bundle(self):
        first = self.bootstrap()
        old_state = self.rows(
            """SELECT active_prefilter_revision_id, active_asset_revision_id
               FROM operator_config_state"""
        )[0]
        self.write(self.legacy, prefilter_document(signature_id=2002))
        self.write(self.assets, asset_document(hostname="firewall"))

        second = self.bootstrap()

        self.assertFalse(second.initialized)
        self.assertEqual(second.mode, "legacy")
        self.assertEqual(second.generation, 2)
        self.assertNotEqual(second.active_prefilter_revision, first.active_prefilter_revision)
        self.assertNotEqual(second.active_asset_revision, first.active_asset_revision)
        state = self.rows(
            """SELECT generation, mode, previous_prefilter_revision_id,
                      previous_asset_revision_id
               FROM operator_config_state"""
        )
        self.assertEqual(state, [(2, "legacy", old_state[0], old_state[1])])
        self.assertEqual(
            self.rows(
                """SELECT kind, state FROM operator_config_revisions
                   ORDER BY kind, id"""
            ),
            [
                ("asset_inventory", "superseded"),
                ("asset_inventory", "active"),
                ("prefilter_policy", "superseded"),
                ("prefilter_policy", "active"),
            ],
        )
        self.assertEqual(
            self.rows("SELECT action FROM operator_config_audit ORDER BY id"),
            [("bootstrap_activated",), ("legacy_sync_activated",)],
        )

    def test_synchronization_returns_the_documents_it_mirrored(self):
        self.bootstrap()
        self.write(self.legacy, prefilter_document(signature_id=2002))
        self.write(self.assets, asset_document(hostname="firewall"))

        snapshot = operator_config.synchronize_legacy_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
            occurred_at=NOW,
        )

        self.assertEqual(snapshot.mode, "legacy")
        self.assertEqual(snapshot.generation, 2)
        self.assertEqual(snapshot.prefilter_policy.signature_ids, {2002})
        self.assertEqual(snapshot.asset_inventory.assets[0]["hostname"], "firewall")
        self.assertEqual(
            snapshot.asset_inventory.revision,
            snapshot.result.active_asset_revision,
        )
        # The mirrored objects are exactly what the durable revision records,
        # so a consumer publishing them cannot mismatch its own active bundle.
        self.assertEqual(
            self.rows(
                """SELECT revision FROM operator_config_revisions
                   WHERE kind = 'prefilter_policy' AND state = 'active'"""
            ),
            [(snapshot.result.active_prefilter_revision,)],
        )

    def test_mounted_documents_are_read_inside_the_write_transaction(self):
        """Ordering proof: no authoritative read happens before the lock."""
        events = []
        real_connect = operator_config.connect_database
        real_read = operator_config._read_json_document

        def recording_connect(path, **kwargs):
            connection = real_connect(path, **kwargs)
            events.append("connect")

            def trace(statement):
                if str(statement).strip().upper().startswith("BEGIN IMMEDIATE"):
                    events.append("begin_immediate")

            connection.set_trace_callback(trace)
            return connection

        def recording_read(path, label):
            events.append(f"read:{label}")
            return real_read(path, label)

        with unittest.mock.patch.object(
            operator_config, "connect_database", recording_connect
        ), unittest.mock.patch.object(
            operator_config, "_read_json_document", recording_read
        ):
            self.bootstrap()

        self.assertIn("begin_immediate", events)
        self.assertTrue([event for event in events if event.startswith("read:")])
        first_read = min(
            index for index, event in enumerate(events) if event.startswith("read:")
        )
        self.assertLess(events.index("begin_immediate"), first_read)

    def test_a_stale_synchronizer_cannot_reactivate_an_older_mount(self):
        self.bootstrap()

        # A observes P1 and commits it, the mount becomes P2, B synchronizes it,
        # and A then resumes: A must re-read under the lock, never resurrect P1.
        first = self.bootstrap()
        self.write(self.legacy, prefilter_document(signature_id=2002))
        second = self.bootstrap()
        resumed = self.bootstrap()

        self.assertEqual(first.generation, 1)
        self.assertEqual(second.generation, 2)
        self.assertEqual(resumed.generation, 2)
        self.assertEqual(
            resumed.active_prefilter_revision,
            second.active_prefilter_revision,
        )
        active = self.rows(
            """SELECT document_json FROM operator_config_revisions
               WHERE kind = 'prefilter_policy' AND state = 'active'"""
        )
        self.assertEqual(len(active), 1)
        self.assertIn("2002", active[0][0])

    def test_database_mode_synchronization_reads_no_mounted_document(self):
        self.bootstrap()
        self.execute("UPDATE operator_config_state SET mode = 'database' WHERE id = 1")
        self.legacy.unlink()
        self.assets.unlink()

        snapshot = operator_config.synchronize_legacy_configuration(
            self.db_path,
            packaged_prefilter_path=self.packaged,
            legacy_prefilter_path=self.legacy,
            asset_inventory_path=self.assets,
            occurred_at=NOW,
        )

        self.assertEqual(snapshot.mode, "database")
        self.assertIsNone(snapshot.prefilter_policy)
        self.assertIsNone(snapshot.asset_inventory)
        self.assertEqual(self.rows("SELECT generation FROM operator_config_state"), [(1,)])

    def test_upgrade_discovers_shipped_default_without_replacing_legacy_bundle(self):
        first = self.bootstrap()
        self.write(self.packaged, prefilter_document(signature_id=3003))

        second = self.bootstrap()

        self.assertFalse(second.initialized)
        self.assertTrue(second.discovered_shipped_revision)
        self.assertEqual(second.generation, 1)
        self.assertEqual(second.active_prefilter_revision, first.active_prefilter_revision)
        revisions = self.rows(
            """SELECT revision, state FROM operator_config_revisions
               WHERE kind = 'prefilter_policy' ORDER BY id"""
        )
        self.assertEqual(len(revisions), 2)
        self.assertEqual(revisions[0], (first.active_prefilter_revision, "active"))
        self.assertEqual(revisions[1][1], "validated")
        self.assertEqual(
            self.rows("SELECT action FROM operator_config_audit ORDER BY id"),
            [("bootstrap_activated",), ("shipped_revision_discovered",)],
        )

    def test_legacy_mode_fails_closed_when_mounted_configuration_becomes_invalid(self):
        self.bootstrap()
        self.legacy.write_text("not json", encoding="utf-8")

        with self.assertRaisesRegex(
            operator_config.OperatorConfigError,
            "must be valid UTF-8 JSON",
        ):
            self.bootstrap()

        self.assertEqual(self.rows("SELECT generation FROM operator_config_state"), [(1,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_audit"), [(1,)])

    def test_database_mode_ignores_legacy_mounts_and_preserves_active_bundle(self):
        first = self.bootstrap()
        self.execute("UPDATE operator_config_state SET mode = 'database' WHERE id = 1")
        self.write(self.packaged, prefilter_document(signature_id=3003))
        self.legacy.write_text("not json", encoding="utf-8")
        self.assets.write_text("not json", encoding="utf-8")

        second = self.bootstrap()

        self.assertFalse(second.initialized)
        self.assertTrue(second.discovered_shipped_revision)
        self.assertEqual(second.mode, "database")
        self.assertEqual(second.generation, 1)
        self.assertEqual(second.active_prefilter_revision, first.active_prefilter_revision)
        self.assertEqual(second.active_asset_revision, first.active_asset_revision)
        self.assertEqual(
            self.rows("SELECT action FROM operator_config_audit ORDER BY id"),
            [("bootstrap_activated",), ("shipped_revision_discovered",)],
        )

    def test_shipped_default_matching_operator_revision_is_observed_once(self):
        self.write(self.legacy, prefilter_document(signature_id=2002))
        first = self.bootstrap()
        self.write(self.packaged, prefilter_document(signature_id=2002))

        second = self.bootstrap()
        third = self.bootstrap()

        self.assertTrue(second.discovered_shipped_revision)
        self.assertFalse(third.discovered_shipped_revision)
        self.assertEqual(second.generation, first.generation)
        self.assertEqual(
            self.rows(
                """SELECT source FROM operator_config_revisions
                   WHERE revision = ?""",
                (first.active_prefilter_revision,),
            ),
            [("operator_import",)],
        )
        self.assertEqual(
            self.rows("SELECT action FROM operator_config_audit ORDER BY id"),
            [("bootstrap_activated",), ("shipped_revision_discovered",)],
        )

    def test_invalid_initial_legacy_document_persists_nothing(self):
        self.legacy.write_text("not json", encoding="utf-8")

        with self.assertRaisesRegex(
            operator_config.OperatorConfigError,
            "must be valid UTF-8 JSON",
        ):
            self.bootstrap()

        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_revisions"), [(0,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_state"), [(0,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM operator_config_audit"), [(0,)])

    def test_corrupt_active_revision_fails_closed(self):
        self.bootstrap()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """UPDATE operator_config_revisions SET document_json = '{}'
                   WHERE kind = 'prefilter_policy' AND state = 'active'"""
            )
            conn.commit()
        finally:
            conn.close()

        with self.assertRaisesRegex(
            operator_config.OperatorConfigError,
            "stored prefilter_policy revision is invalid",
        ):
            self.bootstrap()

    def test_corrupt_inactive_revision_fails_closed_on_content_collision(self):
        self.write(self.legacy, prefilter_document(signature_id=2002))
        self.bootstrap()
        self.execute(
            """UPDATE operator_config_revisions SET document_json = '{}'
               WHERE kind = 'prefilter_policy' AND source = 'shipped'"""
        )

        with self.assertRaisesRegex(
            operator_config.OperatorConfigError,
            "content does not match its digest",
        ):
            self.bootstrap()

    def test_prefilter_revision_uses_normalized_effective_document(self):
        upper = operator_config.load_revision(
            operator_config.PREFILTER_KIND,
            self.packaged,
            "shipped",
        )
        self.write(self.packaged, prefilter_document(protocol="TCP"))
        lower = operator_config.load_revision(
            operator_config.PREFILTER_KIND,
            self.packaged,
            "shipped",
        )

        self.assertEqual(upper.revision, lower.revision)
        self.assertEqual(upper.document_json, lower.document_json)


if __name__ == "__main__":
    unittest.main(verbosity=2)
