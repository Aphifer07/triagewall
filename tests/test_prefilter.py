#!/usr/bin/env python3
"""Regression coverage for validated, context-aware prefilter policies."""

import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from prefilter import MAX_CONFIG_BYTES, PrefilterConfigError, PrefilterPolicy


def policy_document(match=None, *, internal_cidrs=None):
    rule = {"signature_ids": [1001], "reason": "Known site-specific noise."}
    if match is not None:
        rule["match"] = match
    return {
        "version": 1,
        "internal_cidrs": internal_cidrs if internal_cidrs is not None else ["10.0.0.0/24"],
        "auto_false_positive": [rule],
    }


def alert(**overrides):
    value = {
        "alert": {"signature_id": 1001},
        "src_ip": "198.51.100.20",
        "dest_ip": "10.0.0.20",
        "src_port": 443,
        "dest_port": 52000,
        "proto": "TCP",
        "direction": "to_client",
    }
    value.update(overrides)
    return value


class PolicyMatchingTests(unittest.TestCase):
    def test_legacy_sid_only_policy_remains_supported(self):
        policy = PrefilterPolicy.from_document({
            "auto_false_positive": [
                {"signature_ids": [1001], "reason": "Legacy site decision."}
            ]
        })

        self.assertEqual(policy.match_reason({"alert": {"signature_id": 1001}}),
                         "Legacy site decision.")
        self.assertIsNone(policy.match_reason({"alert": {"signature_id": 1002}}))

    def test_all_conditions_must_match_and_list_values_are_alternatives(self):
        policy = PrefilterPolicy.from_document(policy_document({
            "network_directions": ["external_to_internal"],
            "flow_directions": ["to_client"],
            "protocols": ["tcp"],
            "source_ports": [80, 443],
            "destination_cidrs": ["10.0.0.0/25"],
        }))

        self.assertEqual(policy.match_reason(alert()), "Known site-specific noise.")
        self.assertIsNone(policy.match_reason(alert(src_port=8443)))
        self.assertIsNone(policy.match_reason(alert(direction="to_server")))
        self.assertIsNone(policy.match_reason(alert(dest_ip="10.0.0.200")))

    def test_network_direction_supports_ipv4_and_ipv6(self):
        policy = PrefilterPolicy.from_document(policy_document(
            {"network_directions": ["internal_to_external"]},
            internal_cidrs=["10.0.0.0/24", "2001:db8:1::/64"],
        ))

        self.assertIsNotNone(policy.match_reason(alert(
            src_ip="2001:db8:1::5", dest_ip="2001:db8:2::5"
        )))
        self.assertIsNone(policy.match_reason(alert(
            src_ip="2001:db8:2::5", dest_ip="2001:db8:1::5"
        )))

    def test_missing_or_malformed_alert_context_does_not_suppress(self):
        policy = PrefilterPolicy.from_document(policy_document({
            "network_directions": ["external_to_internal"],
            "source_ports": [443],
        }))

        for candidate in (
            alert(src_ip=None),
            alert(dest_ip="not-an-ip"),
            alert(src_port="443"),
            {"alert": {"signature_id": "1001"}},
            None,
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(policy.match_reason(candidate))

    def test_source_and_destination_asset_selectors(self):
        policy = PrefilterPolicy.from_document(policy_document({
            "source_asset": {"matched": False},
            "destination_asset": {
                "matched": True,
                "hostnames": ["omv1"],
                "roles": ["container-host"],
                "criticalities": ["critical"],
                "internet_facing": False,
            },
        }))
        context = {
            "source": None,
            "destination": {
                "hostname": "omv1",
                "role": "container-host",
                "criticality": "critical",
                "internet_facing": False,
            },
        }

        self.assertIsNotNone(policy.match_reason(alert(), context))
        self.assertIsNone(policy.match_reason(alert(), None))
        self.assertIsNone(policy.match_reason(alert(), {"source": None}))
        self.assertIsNone(policy.match_reason(alert(), {
            **context, "destination": {**context["destination"], "criticality": "high"}
        }))
        self.assertIsNone(policy.match_reason(alert(), {
            **context, "destination": ["malformed"]
        }))

    def test_first_matching_rule_for_duplicate_sid_wins(self):
        document = policy_document()
        document["auto_false_positive"] = [
            {
                "signature_ids": [1001],
                "reason": "Only UDP.",
                "match": {"protocols": ["udp"]},
            },
            {
                "signature_ids": [1001],
                "reason": "HTTPS response.",
                "match": {"protocols": ["tcp"], "source_ports": [443]},
            },
        ]

        policy = PrefilterPolicy.from_document(document)
        self.assertEqual(policy.match_reason(alert()), "HTTPS response.")
        self.assertEqual(policy.match_reason(alert(proto="UDP")), "Only UDP.")

    def test_shipped_ssdp_and_nmap_ack_rules_are_scoped(self):
        policy = PrefilterPolicy.load(PROJECT_ROOT / "triagewall" / "config" / "prefilter.json")
        ssdp = alert(
            alert={"signature_id": 2019102}, src_ip="10.0.0.5", dest_ip="10.0.0.8",
            src_port=53000, dest_port=1900, proto="UDP", direction="to_server",
        )
        nmap_ack = alert(alert={"signature_id": 2000538})

        self.assertIsNotNone(policy.match_reason(ssdp))
        self.assertIsNone(policy.match_reason({**ssdp, "src_ip": "198.51.100.5"}))
        self.assertIsNotNone(policy.match_reason(nmap_ack))
        self.assertIsNone(policy.match_reason({**nmap_ack, "src_port": 22}))


class PolicyValidationTests(unittest.TestCase):
    def assert_invalid(self, document):
        with self.assertRaises(PrefilterConfigError):
            PrefilterPolicy.from_document(document)

    def test_rejects_unknown_fields_and_invalid_version(self):
        self.assert_invalid({**policy_document(), "unexpected": True})
        self.assert_invalid({**policy_document(), "version": 2})
        self.assert_invalid({"auto_false_positive": [], "internal_cidrs": []})

    def test_rejects_bad_rule_values(self):
        invalid_rules = [
            {"signature_ids": [], "reason": "x"},
            {"signature_ids": [True], "reason": "x"},
            {"signature_ids": [1, 1], "reason": "x"},
            {"signature_ids": [1], "reason": ""},
            {"signature_ids": [1], "reason": "x", "extra": 1},
        ]
        for invalid_rule in invalid_rules:
            document = policy_document()
            document["auto_false_positive"] = [invalid_rule]
            with self.subTest(rule=invalid_rule):
                self.assert_invalid(document)

    def test_rejects_invalid_match_conditions(self):
        invalid_matches = [
            {},
            {"unexpected": ["value"]},
            {"network_directions": ["sideways"]},
            {"flow_directions": ["both"]},
            {"protocols": ["sctp"]},
            {"source_ports": [0]},
            {"destination_ports": [65536]},
            {"source_cidrs": ["10.0.0.1/24"]},
            {"source_asset": {}},
            {"source_asset": {"roles": ["unsafe role"]}},
            {"source_asset": {"matched": False, "roles": ["server"]}},
            {"destination_asset": {"internet_facing": "false"}},
        ]
        for invalid_match in invalid_matches:
            with self.subTest(match=invalid_match):
                self.assert_invalid(policy_document(invalid_match))

        self.assert_invalid(policy_document(
            {"network_directions": ["internal_to_internal"]}, internal_cidrs=[]
        ))

    def test_rejects_invalid_json_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "prefilter.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(PrefilterConfigError):
                PrefilterPolicy.load(path)

            path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
            with self.assertRaisesRegex(PrefilterConfigError, "1 MiB"):
                PrefilterPolicy.load(path)

    def test_empty_versioned_policy_is_valid(self):
        policy = PrefilterPolicy.from_document({
            "version": 1, "internal_cidrs": [], "auto_false_positive": []
        })
        self.assertEqual(policy.signature_ids, frozenset())
        self.assertIsNone(policy.match_reason(alert()))


if __name__ == "__main__":
    unittest.main()
