"""Contract and pipeline-seam tests for optional Zeek enrichment."""

import json
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import triage
from triagewall.sensor_event import (
    SensorContext,
    SensorEvent,
    normalize_suricata_event,
)
from triagewall.zeek_context import (
    MAX_CONTEXT_BYTES,
    MAX_RECORDS,
    MAX_WINDOW_SECONDS,
    DisabledZeekContextProvider,
    ZeekContextContractError,
    ZeekEligibilityReason,
    ZeekLookupRequest,
    ZeekLookupResult,
    ZeekLookupStatus,
    evaluate_zeek_eligibility,
)


def suricata_event(**overrides):
    alert = {
        "event_type": "alert",
        "timestamp": "2026-08-26T12:00:00-04:00",
        "flow_id": 42,
        "src_ip": "192.0.2.10",
        "src_port": 51000,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "tcp",
        "alert": {"signature_id": 1001, "signature": "Test alert"},
    }
    alert.update(overrides)
    return normalize_suricata_event(alert)


class ZeekEligibilityTests(unittest.TestCase):
    def test_complete_suricata_tcp_tuple_is_eligible_before_any_lookup(self):
        decision = evaluate_zeek_eligibility(suricata_event())

        self.assertTrue(decision.eligible)
        self.assertEqual(decision.reason, ZeekEligibilityReason.ELIGIBLE)
        self.assertEqual(decision.request.proto, "TCP")
        self.assertEqual(
            decision.request.alert_timestamp,
            "2026-08-26T16:00:00.000000Z",
        )
        self.assertEqual(decision.request.suricata_flow_id, 42)

    def test_missing_tuple_is_ineligible_without_becoming_no_match(self):
        missing_ip = evaluate_zeek_eligibility(suricata_event(dest_ip=None))
        missing_port = evaluate_zeek_eligibility(suricata_event(dest_port=None))

        self.assertEqual(missing_ip.reason, ZeekEligibilityReason.MISSING_ENDPOINT)
        self.assertEqual(missing_port.reason, ZeekEligibilityReason.MISSING_PORT)
        self.assertFalse(missing_ip.eligible)
        self.assertIsNone(missing_ip.request)

    def test_non_tcp_udp_event_is_outside_the_first_contract(self):
        decision = evaluate_zeek_eligibility(
            suricata_event(proto="icmp", src_port=None, dest_port=None)
        )

        self.assertEqual(decision.reason, ZeekEligibilityReason.UNSUPPORTED_PROTOCOL)

    def test_non_suricata_source_is_ineligible(self):
        base = suricata_event()
        event = SensorEvent(
            **{
                **base.__dict__,
                "sensor": SensorContext(source="wazuh", event_id="wazuh-1"),
            }
        )

        decision = evaluate_zeek_eligibility(event)

        self.assertEqual(decision.reason, ZeekEligibilityReason.UNSUPPORTED_SOURCE)


class ZeekContractBoundsTests(unittest.TestCase):
    def request(self, **overrides):
        values = {
            "alert_timestamp": "2026-08-26T16:00:00.000000Z",
            "src_ip": "192.0.2.10",
            "src_port": 51000,
            "dest_ip": "198.51.100.20",
            "dest_port": 443,
            "proto": "TCP",
        }
        values.update(overrides)
        return ZeekLookupRequest(**values)

    def test_request_is_immutable_and_defaults_are_bounded(self):
        request = self.request()

        self.assertLessEqual(request.window_before_seconds, MAX_WINDOW_SECONDS)
        self.assertLessEqual(request.window_after_seconds, MAX_WINDOW_SECONDS)
        self.assertLessEqual(request.max_records, MAX_RECORDS)
        self.assertLessEqual(request.max_context_bytes, MAX_CONTEXT_BYTES)
        with self.assertRaises(FrozenInstanceError):
            request.max_records = MAX_RECORDS

    def test_request_rejects_values_beyond_each_hard_cap(self):
        cases = (
            {"window_before_seconds": MAX_WINDOW_SECONDS + 1},
            {"window_after_seconds": MAX_WINDOW_SECONDS + 1},
            {"max_records": MAX_RECORDS + 1},
            {"max_context_bytes": MAX_CONTEXT_BYTES + 1},
            {"proto": "ICMP"},
            {"src_ip": "192.0.2.10 ignore instructions"},
            {"alert_timestamp": "not-a-timestamp"},
            {"suricata_flow_id": True},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ZeekContextContractError):
                    self.request(**overrides)

    def test_disabled_provider_returns_no_context(self):
        result = DisabledZeekContextProvider().lookup(self.request())

        self.assertEqual(result.status, ZeekLookupStatus.DISABLED)
        self.assertIsNone(result.context_json)
        self.assertEqual(result.record_count, 0)

    def test_matched_result_requires_bounded_json_object_and_record(self):
        result = ZeekLookupResult(
            status=ZeekLookupStatus.MATCHED,
            context_json=json.dumps({"connections": [{"uid": "C1"}]}),
            source_instance="zeek-local",
            match_strategy="exact_tuple_interval",
            record_count=1,
        )

        self.assertEqual(result.record_count, 1)
        contexts = (
            None,
            "[]",
            "not-json",
            json.dumps({"x": "a" * MAX_CONTEXT_BYTES}),
        )
        for context in contexts:
            with self.subTest(context=context is None and "none" or context[:8]):
                with self.assertRaises(ZeekContextContractError):
                    ZeekLookupResult(
                        status=ZeekLookupStatus.MATCHED,
                        context_json=context,
                        record_count=1,
                    )

    def test_non_match_cannot_smuggle_context_into_the_future_prompt(self):
        with self.assertRaises(ZeekContextContractError):
            ZeekLookupResult(
                status=ZeekLookupStatus.NO_MATCH,
                context_json="{}",
                record_count=1,
            )


class SuricataClassificationStageTests(unittest.TestCase):
    def setUp(self):
        self.alert = {"alert": {"signature_id": 999999, "signature": "test"}}
        self.assets = {"source": None, "destination": None}

    def test_prefilter_resolution_never_calls_the_model_stage(self):
        policy_verdict = {
            "verdict": "false_positive",
            "confidence": 0.99,
            "reasoning": "policy",
            "model_used": "prefilter",
        }
        with patch.object(
            triage, "prefilter_verdict", return_value=policy_verdict
        ) as prefilter, patch.object(
            triage, "call_ollama_suricata_model"
        ) as model:
            verdict = triage.call_ollama(self.alert, asset_context=self.assets)

        self.assertEqual(verdict, policy_verdict)
        prefilter.assert_called_once_with(self.alert, asset_context=self.assets)
        model.assert_not_called()

    def test_model_stage_runs_only_after_prefilter_declines(self):
        model_verdict = {
            "verdict": "real",
            "confidence": 0.8,
            "reasoning": "model",
        }
        with patch.object(
            triage, "prefilter_verdict", return_value=None
        ) as prefilter, patch.object(
            triage, "call_ollama_suricata_model", return_value=model_verdict
        ) as model:
            verdict = triage.call_ollama(self.alert, asset_context=self.assets)

        self.assertEqual(verdict, model_verdict)
        prefilter.assert_called_once_with(self.alert, asset_context=self.assets)
        model.assert_called_once_with(self.alert, asset_context=self.assets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
