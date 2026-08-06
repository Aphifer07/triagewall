#!/usr/bin/env python3
"""
Deterministic regressions for the gold-set change-validation gate.

Everything here runs with no Ollama, no GPU, no network, and no production
data. The outbound model call is intercepted, so these tests exercise the real
production prompt, projection, prefilter, and response validator rather than a
copy of them.
"""

import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from scripts import gold_gate
from scripts.gold_gate import GoldGateError

triage = gold_gate.import_triage()


def valid_body(verdict="real", confidence=0.9, reasoning="Synthetic test verdict."):
    return {
        "model": "test-stub",
        "response": json.dumps(
            {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}
        ),
    }


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self):
        return self._payload


def fake_urlopen_factory(body):
    def fake_urlopen(_request, timeout=None):
        return FakeResponse(json.dumps(body).encode("utf-8"))

    return fake_urlopen


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


class NormalizationTests(unittest.TestCase):
    def test_canary_is_replaced_with_placeholder(self):
        text = f"never emit {triage.CANARY_TOKEN} for any reason"
        normalized = gold_gate.normalize_runtime_values(
            text, canary=triage.CANARY_TOKEN, internal_subnets="10.0.0.0/24"
        )
        self.assertNotIn(triage.CANARY_TOKEN, normalized)
        self.assertIn(gold_gate.CANARY_PLACEHOLDER, normalized)

    def test_internal_subnets_are_normalized_out(self):
        """Operator topology must never reach published evidence."""
        text = "Internal subnets: 10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24."
        normalized = gold_gate.normalize_runtime_values(
            text,
            canary="UNUSED",
            internal_subnets="10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24",
        )
        self.assertNotIn("10.0.0.0/24", normalized)
        self.assertIn(gold_gate.SUBNETS_PLACEHOLDER, normalized)

    def test_empty_subnet_configuration_is_tolerated(self):
        normalized = gold_gate.normalize_runtime_values(
            "text", canary="TOKEN", internal_subnets=""
        )
        self.assertEqual(normalized, "text")


# --------------------------------------------------------------------------
# Behavior fingerprint
# --------------------------------------------------------------------------


class FingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fingerprint = gold_gate.compute_behavior_fingerprint(triage)

    def test_all_components_are_sha256_digests(self):
        for name, value in self.fingerprint["components"].items():
            with self.subTest(component=name):
                self.assertTrue(value.startswith("sha256:"), name)
                self.assertEqual(len(value), len("sha256:") + 64)

    def test_fingerprint_is_stable_across_repeated_computation(self):
        again = gold_gate.compute_behavior_fingerprint(triage)
        self.assertEqual(self.fingerprint["combined"], again["combined"])

    def test_coverage_reports_the_prefilter_split(self):
        coverage = self.fingerprint["coverage"]
        self.assertEqual(coverage["suricata_fixtures"], 6)
        self.assertEqual(coverage["suricata_prefiltered"], 1)
        self.assertEqual(coverage["suricata_model_requests"], 5)
        self.assertEqual(coverage["wazuh_fixtures"], 4)
        self.assertGreater(coverage["response_contract_cases"], 15)

    def test_model_identity_change_moves_the_fingerprint(self):
        with patch.object(triage, "MODEL", "some-other-model:latest"):
            changed = gold_gate.compute_behavior_fingerprint(triage)
        self.assertNotEqual(self.fingerprint["combined"], changed["combined"])
        self.assertNotEqual(
            self.fingerprint["components"]["model_identity"],
            changed["components"]["model_identity"],
        )

    def test_system_prompt_change_moves_the_fingerprint(self):
        """
        The prompt is captured from the outbound request, so any edit that
        actually reaches the model moves the fingerprint. Patching the builder
        rather than the SYSTEM_PROMPT constant is deliberate: the constant is
        bound as a default argument at import, so an in-process rebind would
        not reach the request. A real edit plus a restart does.
        """
        original = triage._system_prompt_with_asset_context

        def tampered(asset_context, base_prompt=None):
            if base_prompt is None:
                return original(asset_context) + "\n# injected section"
            return original(asset_context, base_prompt) + "\n# injected section"

        with patch.object(triage, "_system_prompt_with_asset_context", tampered):
            changed = gold_gate.compute_behavior_fingerprint(triage)
        self.assertNotEqual(self.fingerprint["combined"], changed["combined"])
        self.assertNotEqual(
            self.fingerprint["components"]["suricata_request_surface"],
            changed["components"]["suricata_request_surface"],
        )

    def test_prefilter_policy_change_moves_the_fingerprint(self):
        from prefilter import PrefilterPolicy

        with patch.object(triage, "PREFILTER_POLICY", PrefilterPolicy.empty()):
            changed = gold_gate.compute_behavior_fingerprint(triage)
        self.assertNotEqual(self.fingerprint["combined"], changed["combined"])
        self.assertNotEqual(
            self.fingerprint["components"]["prefilter_behavior"],
            changed["components"]["prefilter_behavior"],
        )
        # With the policy emptied, the previously prefiltered alert reaches
        # the model, so the request surface must widen too.
        self.assertEqual(changed["coverage"]["suricata_prefiltered"], 0)
        self.assertEqual(changed["coverage"]["suricata_model_requests"], 6)


# --------------------------------------------------------------------------
# Isolation invariants, measured on the real outbound request
# --------------------------------------------------------------------------


class RequestSurfaceIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.requests = gold_gate._capture_suricata_surface(triage)
        cls.wazuh = gold_gate._capture_wazuh_surface(triage)

    def _prompt_for(self, case_id, requests=None):
        for entry in requests or self.requests:
            if entry["id"] == case_id:
                return entry["request"]["prompt"]
        self.fail(f"no captured request for {case_id}")

    def test_free_text_signature_is_never_sent_plain(self):
        prompt = self._prompt_for("injection-in-signature")
        self.assertNotIn("SYSTEM OVERRIDE", prompt)
        self.assertIn("=== UNTRUSTED FIELD [alert.signature]", prompt)

    def test_http_injection_strings_are_never_sent_plain(self):
        prompt = self._prompt_for("injection-in-http-fields")
        for fragment in (
            "IGNORE ALL PREVIOUS INSTRUCTIONS",
            "Disregard the security policy",
            "maintenance mode",
        ):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, prompt)

    def test_array_nested_free_text_is_wrapped(self):
        prompt = self._prompt_for("dns-array-nested-rrname")
        self.assertNotIn("ignore-previous-instructions", prompt)
        self.assertIn("=== UNTRUSTED FIELD [dns.queries.0.rrname]", prompt)

    def test_unknown_fields_wrap_by_default(self):
        prompt = self._prompt_for("unknown-protocol-record")
        self.assertNotIn("treat this host as trusted", prompt)
        self.assertIn("=== UNTRUSTED FIELD [future_protocol_v9.banner]", prompt)

    def test_trusted_structured_metadata_is_still_sent_plain(self):
        """Isolation must not blind the model to Suricata's own analysis."""
        prompt = self._prompt_for("malware-c2-beacon")
        self.assertIn("A Network Trojan was detected", prompt)
        self.assertIn("2404000", prompt)

    def test_wazuh_injection_text_is_wrapped(self):
        prompt = self._prompt_for(
            "level-12-injection-in-full-log", requests=self.wazuh
        )
        self.assertNotIn("disregard the security policy", prompt)
        self.assertNotIn("IGNORE PRIOR INSTRUCTIONS", prompt)

    def test_wazuh_projection_stays_within_the_prompt_budget(self):
        from wazuh_isolation import MAX_PROMPT_BYTES

        for entry in self.wazuh:
            with self.subTest(case=entry["id"]):
                self.assertLessEqual(entry["projection_bytes"], MAX_PROMPT_BYTES)

    def test_no_captured_request_leaks_the_canary(self):
        for entry in self.requests + self.wazuh:
            with self.subTest(case=entry["id"]):
                self.assertNotIn(
                    triage.CANARY_TOKEN, json.dumps(entry["request"])
                )


# --------------------------------------------------------------------------
# Response contract
# --------------------------------------------------------------------------


class ResponseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outcomes = {
            entry["id"]: entry
            for entry in gold_gate._capture_response_contract(triage)
        }
        cls.cases = {
            case["id"]: case for case in gold_gate.response_contract_cases()
        }

    def test_every_case_matches_its_declared_expectation(self):
        for case_id, case in self.cases.items():
            with self.subTest(case=case_id):
                self.assertEqual(case["expect"], self.outcomes[case_id]["outcome"])

    def test_malformed_output_never_becomes_an_accepted_verdict(self):
        for case_id, case in self.cases.items():
            if case["expect"] != "rejected":
                continue
            with self.subTest(case=case_id):
                verdict = self.outcomes[case_id]["verdict"]
                self.assertEqual(verdict["verdict"], "uncertain")
                self.assertEqual(verdict["confidence"], 0.0)

    def test_canary_reflection_fails_closed_to_real(self):
        for case_id, case in self.cases.items():
            if case["expect"] != "injection":
                continue
            with self.subTest(case=case_id):
                verdict = self.outcomes[case_id]["verdict"]
                self.assertEqual(verdict["verdict"], "real")
                self.assertGreaterEqual(verdict["confidence"], 0.8)

    def test_json_escaped_canary_is_still_detected(self):
        """A token hidden behind JSON escapes must not slip past the scan."""
        self.assertEqual(self.outcomes["canary-json-escaped"]["outcome"], "injection")

    def test_recorded_verdicts_never_contain_the_live_canary(self):
        self.assertNotIn(triage.CANARY_TOKEN, json.dumps(self.outcomes))


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


class MetricsTests(unittest.TestCase):
    def test_perfect_agreement_is_one(self):
        confusion = {"real": {"real": 10}, "false_positive": {"false_positive": 10}}
        self.assertAlmostEqual(gold_gate.cohens_kappa(confusion), 1.0)

    def test_chance_agreement_is_zero(self):
        confusion = {
            "real": {"real": 25, "false_positive": 25},
            "false_positive": {"real": 25, "false_positive": 25},
        }
        self.assertAlmostEqual(gold_gate.cohens_kappa(confusion), 0.0)

    def test_known_kappa_value(self):
        # po = 0.85, pe = 0.5 * 0.6 + 0.5 * 0.4 = 0.5, kappa = 0.7
        confusion = {
            "real": {"real": 45, "false_positive": 5},
            "false_positive": {"real": 10, "false_positive": 40},
        }
        self.assertAlmostEqual(gold_gate.cohens_kappa(confusion), 0.7, places=6)

    def test_empty_confusion_is_zero_not_an_error(self):
        self.assertEqual(gold_gate.cohens_kappa({}), 0.0)

    def test_single_class_perfect_agreement_is_not_credited(self):
        """All-one-class agreement carries no information; kappa must be 0."""
        self.assertEqual(gold_gate.cohens_kappa({"real": {"real": 50}}), 0.0)

    def test_per_class_metrics(self):
        confusion = {
            "real": {"real": 8, "false_positive": 2},
            "false_positive": {"real": 4, "false_positive": 16},
        }
        metrics = gold_gate.per_class_metrics(confusion)
        self.assertAlmostEqual(metrics["real"]["recall"], 0.8)
        self.assertAlmostEqual(metrics["real"]["precision"], 8 / 12)
        self.assertEqual(metrics["real"]["support"], 10)
        self.assertAlmostEqual(metrics["false_positive"]["recall"], 0.8)

    def test_summarize_exposes_true_positive_recall(self):
        confusion = {
            "real": {"real": 8, "false_positive": 2},
            "false_positive": {"false_positive": 20},
        }
        summary = gold_gate.summarize(confusion)
        self.assertAlmostEqual(summary["true_positive_recall"], 0.8)
        self.assertEqual(summary["scored"], 30)

    def test_summarize_without_real_class_reports_zero_recall(self):
        summary = gold_gate.summarize({"false_positive": {"false_positive": 5}})
        self.assertEqual(summary["true_positive_recall"], 0.0)


# --------------------------------------------------------------------------
# Manifest schema
# --------------------------------------------------------------------------


# Confusion matrices used to build consistent evidence. Scalar metrics are
# derived from these rather than written by hand, because validation now
# recomputes them and rejects any disagreement.
BASELINE_CONFUSION = {
    "real": {"real": 80, "false_positive": 20},
    "false_positive": {"false_positive": 200},
}
SLIGHTLY_WORSE_CONFUSION = {
    "real": {"real": 78, "false_positive": 22},
    "false_positive": {"false_positive": 200},
}
MUCH_WORSE_CONFUSION = {
    "real": {"real": 40, "false_positive": 60},
    "false_positive": {"false_positive": 200},
}
BETTER_CONFUSION = {
    "real": {"real": 95, "false_positive": 5},
    "false_positive": {"false_positive": 200},
}


def fingerprint_block(components=None):
    """Build an internally consistent fingerprint block."""
    components = components or {"model_identity": "sha256:" + "1" * 64}
    return {
        "combined": gold_gate.digest(components),
        "components": components,
        "coverage": {},
    }


def sample_evidence(pipeline=None, model_only=None, **overrides):
    pipeline_metrics = gold_gate.summarize(
        copy.deepcopy(pipeline or BASELINE_CONFUSION)
    )
    model_only_metrics = gold_gate.summarize(
        copy.deepcopy(model_only or pipeline or BASELINE_CONFUSION)
    )
    evidence = {
        "manifest_version": 1,
        "kind": gold_gate.EVIDENCE_KIND,
        "generated_at": "2026-08-04T00:00:00+00:00",
        "commit": "a7bb499",
        "behavior_fingerprint": fingerprint_block(),
        "asset_inventory": {"revision": "sha256:" + "2" * 64, "count": 1},
        "dataset": {
            "revision": "sha256:" + "3" * 64,
            "total": 320,
            "class_counts": {"real": 100, "false_positive": 220},
            "source_counts": {"suricata": 300, "wazuh": 20},
        },
        "run": {
            "completed": True,
            "scored": pipeline_metrics["scored"],
            "prefilter_resolved": 40,
            "errors": {"transport": 0, "unexpected": 0},
            "invalid_output": 0,
        },
        "metrics": {"pipeline": pipeline_metrics, "model_only": model_only_metrics},
    }
    evidence.update(overrides)
    return evidence


def approved_baseline(evidence=None, **threshold_overrides):
    thresholds = {
        "max_kappa_decrease": 0.05,
        "max_true_positive_recall_decrease": 0.05,
        "max_invalid_output": 0,
        "require_complete_run": True,
        "require_matching_class_counts": True,
    }
    thresholds.update(threshold_overrides)
    return {
        "manifest_version": 1,
        "kind": gold_gate.BASELINE_KIND,
        "status": "approved",
        "notes": [],
        "thresholds": thresholds,
        "evidence": evidence or sample_evidence(),
    }


class EvidenceSchemaTests(unittest.TestCase):
    def test_valid_evidence_passes(self):
        self.assertIsNotNone(gold_gate.validate_evidence(sample_evidence()))

    def test_unknown_top_level_key_is_rejected(self):
        evidence = sample_evidence()
        evidence["extra"] = True
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_missing_top_level_key_is_rejected(self):
        evidence = sample_evidence()
        del evidence["metrics"]
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_wrong_manifest_version_is_rejected(self):
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(sample_evidence(manifest_version=99))

    def test_wrong_kind_is_rejected(self):
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(sample_evidence(kind="something.else"))

    def test_non_digest_fingerprint_is_rejected(self):
        evidence = sample_evidence()
        evidence["behavior_fingerprint"]["combined"] = "not-a-digest"
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_empty_fingerprint_components_are_rejected(self):
        evidence = sample_evidence()
        evidence["behavior_fingerprint"]["components"] = {}
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_unknown_confusion_label_is_rejected(self):
        evidence = sample_evidence()
        evidence["metrics"]["pipeline"]["confusion"]["benign"] = {"real": 1}
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_negative_class_count_is_rejected(self):
        evidence = sample_evidence()
        evidence["dataset"]["class_counts"]["real"] = -1
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_boolean_is_not_accepted_as_a_metric_number(self):
        evidence = sample_evidence()
        evidence["metrics"]["pipeline"]["kappa"] = True
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_non_boolean_completed_flag_is_rejected(self):
        evidence = sample_evidence()
        evidence["run"]["completed"] = "yes"
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_edited_combined_digest_is_rejected(self):
        """
        The combined digest decides whether evidence is current, so it must be
        recomputed. Pointing it at the live fingerprint while leaving stale
        components behind must not make the gate look satisfied.
        """
        evidence = sample_evidence()
        evidence["behavior_fingerprint"]["combined"] = "sha256:" + "a" * 64
        with self.assertRaises(GoldGateError) as ctx:
            gold_gate.validate_evidence(evidence)
        self.assertIn("does not match its components", str(ctx.exception))

    def test_edited_kappa_inconsistent_with_confusion_is_rejected(self):
        """A degraded matrix must not be shipped under approved scalars."""
        evidence = sample_evidence(pipeline=MUCH_WORSE_CONFUSION)
        approved = gold_gate.summarize(BASELINE_CONFUSION)
        evidence["metrics"]["pipeline"]["kappa"] = approved["kappa"]
        with self.assertRaises(GoldGateError) as ctx:
            gold_gate.validate_evidence(evidence)
        self.assertIn("does not match the recorded confusion matrix", str(ctx.exception))

    def test_edited_true_positive_recall_is_rejected(self):
        evidence = sample_evidence()
        evidence["metrics"]["pipeline"]["true_positive_recall"] = 0.99
        with self.assertRaises(GoldGateError):
            gold_gate.validate_evidence(evidence)

    def test_edited_per_class_metrics_are_rejected(self):
        evidence = sample_evidence()
        evidence["metrics"]["pipeline"]["classes"]["real"]["recall"] = 0.99
        with self.assertRaises(GoldGateError) as ctx:
            gold_gate.validate_evidence(evidence)
        self.assertIn("classes does not match", str(ctx.exception))

    def test_run_scored_must_agree_with_pipeline_metrics(self):
        evidence = sample_evidence()
        evidence["run"]["scored"] = evidence["run"]["scored"] + 5
        with self.assertRaises(GoldGateError) as ctx:
            gold_gate.validate_evidence(evidence)
        self.assertIn("run.scored disagrees", str(ctx.exception))

    def test_consistent_evidence_from_a_real_evaluation_validates(self):
        """The recomputation must accept genuine output, not just reject edits."""
        self.assertIsNotNone(
            gold_gate.validate_evidence(sample_evidence(pipeline=BETTER_CONFUSION))
        )


class BaselineSchemaTests(unittest.TestCase):
    def test_committed_baseline_validates(self):
        self.assertIsNotNone(gold_gate.load_baseline())

    def test_uncalibrated_baseline_may_not_carry_evidence(self):
        document = {
            "manifest_version": 1,
            "kind": gold_gate.BASELINE_KIND,
            "status": "uncalibrated",
            "notes": [],
            "thresholds": None,
            "evidence": sample_evidence(),
        }
        with self.assertRaises(GoldGateError):
            gold_gate.validate_baseline(document)

    def test_approved_baseline_requires_evidence(self):
        document = approved_baseline()
        document["evidence"] = None
        with self.assertRaises(GoldGateError):
            gold_gate.validate_baseline(document)

    def test_approved_baseline_requires_every_threshold(self):
        document = approved_baseline()
        del document["thresholds"]["max_kappa_decrease"]
        with self.assertRaises(GoldGateError):
            gold_gate.validate_baseline(document)

    def test_unknown_status_is_rejected(self):
        document = approved_baseline()
        document["status"] = "provisional"
        with self.assertRaises(GoldGateError):
            gold_gate.validate_baseline(document)

    def test_missing_baseline_file_is_an_error_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(GoldGateError):
                gold_gate.load_baseline(Path(tmp) / "absent.json")


# --------------------------------------------------------------------------
# Gate decisions
# --------------------------------------------------------------------------


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.fingerprint = gold_gate.compute_behavior_fingerprint(triage)

    def test_uncalibrated_baseline_passes_ordinary_ci(self):
        baseline = gold_gate.load_baseline()
        self.assertEqual(baseline["status"], "uncalibrated")
        self.assertEqual(gold_gate.verify_baseline(baseline, self.fingerprint), [])

    def test_uncalibrated_baseline_fails_when_calibration_is_required(self):
        baseline = gold_gate.load_baseline()
        failures = gold_gate.verify_baseline(
            baseline, self.fingerprint, require_calibrated=True
        )
        self.assertEqual(len(failures), 1)
        self.assertIn("uncalibrated", failures[0])

    def test_approved_baseline_with_current_fingerprint_passes(self):
        evidence = sample_evidence()
        evidence["behavior_fingerprint"] = self.fingerprint
        baseline = approved_baseline(evidence)
        self.assertEqual(gold_gate.verify_baseline(baseline, self.fingerprint), [])

    def test_stale_evidence_is_rejected_and_names_the_changed_component(self):
        """
        Evidence recorded before a model change: internally consistent, so it
        passes schema validation, but no longer describes the live pipeline.
        """
        evidence = sample_evidence()
        stale = copy.deepcopy(self.fingerprint)
        stale["components"]["model_identity"] = "sha256:" + "f" * 64
        stale["combined"] = gold_gate.digest(stale["components"])
        evidence["behavior_fingerprint"] = stale
        gold_gate.validate_evidence(evidence)  # consistent, just out of date
        failures = gold_gate.verify_baseline(approved_baseline(evidence), self.fingerprint)
        self.assertEqual(len(failures), 1)
        self.assertIn("guarded production inputs changed", failures[0])
        self.assertIn("model_identity", failures[0])

    def test_approved_evidence_from_an_incomplete_run_is_rejected(self):
        evidence = sample_evidence()
        evidence["behavior_fingerprint"] = self.fingerprint
        evidence["run"]["completed"] = False
        failures = gold_gate.verify_baseline(approved_baseline(evidence), self.fingerprint)
        self.assertTrue(any("incomplete run" in f for f in failures))


class CompareTests(unittest.TestCase):
    def test_identical_evidence_passes(self):
        self.assertEqual(
            gold_gate.compare_evidence(approved_baseline(), sample_evidence()), []
        )

    def test_small_degradation_within_tolerance_passes(self):
        candidate = sample_evidence(pipeline=SLIGHTLY_WORSE_CONFUSION)
        self.assertEqual(
            gold_gate.compare_evidence(approved_baseline(), candidate), []
        )

    def test_kappa_drop_beyond_tolerance_fails(self):
        candidate = sample_evidence(pipeline=MUCH_WORSE_CONFUSION)
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("Cohen's kappa fell" in f for f in failures))

    def test_improvement_never_fails(self):
        candidate = sample_evidence(pipeline=BETTER_CONFUSION)
        self.assertEqual(
            gold_gate.compare_evidence(approved_baseline(), candidate), []
        )

    def test_true_positive_recall_drop_fails(self):
        candidate = sample_evidence(pipeline=MUCH_WORSE_CONFUSION)
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("true-positive recall fell" in f for f in failures))

    def test_model_only_regression_is_caught_even_if_pipeline_holds(self):
        """The prefilter can mask a model regression; both scopes are gated."""
        candidate = sample_evidence(
            pipeline=BASELINE_CONFUSION, model_only=MUCH_WORSE_CONFUSION
        )
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("model_only" in f for f in failures))
        self.assertFalse(any("pipeline" in f for f in failures))

    def test_incomplete_candidate_run_fails(self):
        candidate = sample_evidence()
        candidate["run"]["completed"] = False
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("did not complete" in f for f in failures))

    def test_invalid_output_beyond_limit_fails(self):
        candidate = sample_evidence()
        candidate["run"]["invalid_output"] = 3
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("invalid model outputs" in f for f in failures))

    def test_class_count_mismatch_fails(self):
        candidate = sample_evidence()
        candidate["dataset"]["class_counts"] = {"real": 11, "false_positive": 19}
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("class counts differ" in f for f in failures))

    def test_dataset_revision_mismatch_fails(self):
        candidate = sample_evidence()
        candidate["dataset"]["revision"] = "sha256:" + "9" * 64
        failures = gold_gate.compare_evidence(approved_baseline(), candidate)
        self.assertTrue(any("dataset revision differs" in f for f in failures))

    def test_uncalibrated_baseline_cannot_be_compared_against(self):
        failures = gold_gate.compare_evidence(
            gold_gate.load_baseline(), sample_evidence()
        )
        self.assertTrue(any("uncalibrated baseline" in f for f in failures))

    def test_malformed_candidate_is_rejected_rather_than_passed(self):
        candidate = sample_evidence()
        del candidate["run"]
        with self.assertRaises(GoldGateError):
            gold_gate.compare_evidence(approved_baseline(), candidate)


# --------------------------------------------------------------------------
# Operator evaluation
# --------------------------------------------------------------------------


def build_labeled_database(path):
    """Create a temporary database holding synthetic labeled rows."""
    schema = (PROJECT_ROOT / "triagewall" / "schema.sql").read_text(encoding="utf-8")
    cases = {case["id"]: case["alert"] for case in gold_gate.suricata_cases()}
    rows = [
        ("malware-c2-beacon", "real", "suricata"),
        ("injection-in-http-fields", "real", "suricata"),
        ("prefilter-stun-binding", "false_positive", "suricata"),
        ("dns-array-nested-rrname", "false_positive", "suricata"),
        ("unknown-protocol-record", "real", "wazuh"),
    ]
    conn = sqlite3.connect(path)
    try:
        conn.executescript(schema)
        for index, (case_id, human_verdict, source_type) in enumerate(rows, 1):
            alert = cases[case_id]
            cursor = conn.execute(
                """INSERT INTO triage_events
                   (id, timestamp, signature_id, signature, raw_alert, human_verdict)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    index,
                    alert["timestamp"],
                    alert["alert"]["signature_id"],
                    alert["alert"]["signature"],
                    json.dumps(alert),
                    human_verdict,
                ),
            )
            conn.execute(
                """INSERT INTO sensor_event_context
                   (triage_event_id, source_type, source_instance, source_event_id)
                   VALUES (?, ?, ?, ?)""",
                (cursor.lastrowid, source_type, "test", f"event-{index}"),
            )
        conn.commit()
    finally:
        conn.close()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = Path(self._tmp.name) / "labeled.db"
        build_labeled_database(self.db_path)

    def test_labeled_rows_are_loaded_with_source_provenance(self):
        rows = gold_gate.load_labeled_rows(self.db_path)
        self.assertEqual(len(rows), 5)
        self.assertEqual(
            [row["source_type"] for row in rows],
            ["suricata", "suricata", "suricata", "suricata", "wazuh"],
        )

    def test_evaluation_never_writes_to_the_database(self):
        before = file_digest(self.db_path)
        with patch("urllib.request.urlopen", fake_urlopen_factory(valid_body("real"))):
            gold_gate.evaluate(self.db_path, commit="test")
        self.assertEqual(file_digest(self.db_path), before)
        self.assertFalse(Path(str(self.db_path) + "-wal").exists())

    def test_evaluation_produces_valid_evidence_and_splits_the_prefilter(self):
        with patch("urllib.request.urlopen", fake_urlopen_factory(valid_body("real"))):
            manifest = gold_gate.evaluate(self.db_path, commit="test")

        gold_gate.validate_evidence(manifest)
        self.assertTrue(manifest["run"]["completed"])
        self.assertEqual(manifest["run"]["scored"], 4)
        self.assertEqual(manifest["run"]["prefilter_resolved"], 1)
        self.assertEqual(manifest["run"]["invalid_output"], 0)

        # Wazuh rows are counted but not scored: no human Wazuh labels exist yet.
        self.assertEqual(
            manifest["dataset"]["source_counts"], {"suricata": 4, "wazuh": 1}
        )
        self.assertEqual(manifest["dataset"]["total"], 5)

        pipeline = manifest["metrics"]["pipeline"]["confusion"]
        self.assertEqual(pipeline["real"], {"real": 2})
        self.assertEqual(pipeline["false_positive"], {"false_positive": 1, "real": 1})

        # The prefiltered row is excluded from the model-only scope.
        model_only = manifest["metrics"]["model_only"]["confusion"]
        self.assertEqual(model_only["real"], {"real": 2})
        self.assertEqual(model_only["false_positive"], {"real": 1})

    def test_transport_failures_mark_the_run_incomplete(self):
        """
        An unreachable model must never yield passable evidence.

        Only the three non-prefiltered rows attempt a model call, so the
        prefiltered row is still scored -- the prefilter keeps working when
        Ollama is down. Partial success like that is exactly what must not be
        mistaken for a complete run.
        """

        def failing(_request, timeout=None):
            raise urllib.error.URLError("ollama unreachable")

        with patch("urllib.request.urlopen", failing):
            manifest = gold_gate.evaluate(self.db_path, commit="test")

        self.assertFalse(manifest["run"]["completed"])
        self.assertEqual(manifest["run"]["errors"]["transport"], 3)
        self.assertEqual(manifest["run"]["scored"], 1)
        self.assertEqual(manifest["run"]["prefilter_resolved"], 1)

    def test_invalid_model_output_is_counted_not_scored_as_agreement(self):
        garbage = {"model": "test-stub", "response": "not json at all"}
        with patch("urllib.request.urlopen", fake_urlopen_factory(garbage)):
            manifest = gold_gate.evaluate(self.db_path, commit="test")
        # Three non-prefiltered rows all fail closed to uncertain.
        self.assertEqual(manifest["run"]["invalid_output"], 3)

    def test_empty_labeled_set_refuses_to_emit_evidence(self):
        empty = Path(self._tmp.name) / "empty.db"
        conn = sqlite3.connect(empty)
        conn.executescript(
            (PROJECT_ROOT / "triagewall" / "schema.sql").read_text(encoding="utf-8")
        )
        conn.close()
        with self.assertRaises(GoldGateError):
            gold_gate.evaluate(empty)

    def test_evidence_contains_no_raw_alert_content(self):
        with patch("urllib.request.urlopen", fake_urlopen_factory(valid_body("real"))):
            manifest = gold_gate.evaluate(self.db_path, commit="test")
        rendered = json.dumps(manifest)
        for secret in (
            "203.0.113.20",
            "10.0.0.11",
            "cnc.example.invalid",
            "ET MALWARE",
            "IGNORE ALL PREVIOUS INSTRUCTIONS",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)

    def test_evidence_carries_only_the_aggregate_dataset_revision(self):
        """Per-row alert digests must never reach committed evidence.

        An individual alert hash lets anyone holding a candidate alert confirm
        whether that exact host, address or signature is in the labeled set.
        """
        rows = gold_gate.load_labeled_rows(self.db_path)
        with patch("urllib.request.urlopen", fake_urlopen_factory(valid_body("real"))):
            manifest = gold_gate.evaluate(self.db_path, commit="test")
        rendered = json.dumps(manifest)

        for row in rows:
            per_row = gold_gate.digest(row["alert"])
            with self.subTest(row=row["id"]):
                self.assertNotIn(per_row, rendered)
            # Nor the full alert JSON, in either key ordering.
            self.assertNotIn(gold_gate.canonical_json(row["alert"]), rendered)

        self.assertEqual(
            manifest["dataset"]["revision"], gold_gate.dataset_revision(rows)
        )
        self.assertEqual(
            set(manifest["dataset"]),
            {"revision", "total", "class_counts", "source_counts"},
        )

    def test_reported_dataset_revision_matches_the_helper(self):
        rows = gold_gate.load_labeled_rows(self.db_path)
        with patch("urllib.request.urlopen", fake_urlopen_factory(valid_body("real"))):
            manifest = gold_gate.evaluate(self.db_path, commit="test")
        self.assertEqual(
            manifest["dataset"]["revision"], gold_gate.dataset_revision(rows)
        )
        self.assertTrue(manifest["dataset"]["revision"].startswith("sha256:"))


class DatasetRevisionTests(unittest.TestCase):
    """The revision must track what the gate is actually measuring."""

    @staticmethod
    def _rows():
        return [
            {
                "id": 1,
                "alert": {
                    "timestamp": "2026-08-06T00:00:00+00:00",
                    "src_ip": "10.0.0.11",
                    "alert": {"signature_id": 2000001, "signature": "ET MALWARE"},
                },
                "human_verdict": "real",
                "source_type": "suricata",
            },
            {
                "id": 2,
                "alert": {
                    "timestamp": "2026-08-06T00:01:00+00:00",
                    "src_ip": "10.0.0.12",
                    "alert": {"signature_id": 2000002, "signature": "ET INFO"},
                },
                "human_verdict": "false_positive",
                "source_type": "suricata",
            },
        ]

    def test_changing_alert_content_changes_the_revision(self):
        """Same id, same label, same source -- different alert."""
        baseline = self._rows()
        mutated = self._rows()
        mutated[0]["alert"]["src_ip"] = "10.0.0.99"

        self.assertEqual(mutated[0]["id"], baseline[0]["id"])
        self.assertEqual(
            mutated[0]["human_verdict"], baseline[0]["human_verdict"]
        )
        self.assertEqual(mutated[0]["source_type"], baseline[0]["source_type"])
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(mutated),
        )

    def test_nested_alert_content_change_changes_the_revision(self):
        baseline = self._rows()
        mutated = self._rows()
        mutated[1]["alert"]["alert"]["signature"] = "ET INFO (edited)"
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(mutated),
        )

    def test_reordering_json_keys_does_not_change_the_revision(self):
        baseline = self._rows()
        reordered = self._rows()
        original = reordered[0]["alert"]
        reordered[0]["alert"] = {
            "alert": {
                "signature": original["alert"]["signature"],
                "signature_id": original["alert"]["signature_id"],
            },
            "src_ip": original["src_ip"],
            "timestamp": original["timestamp"],
        }
        self.assertNotEqual(
            list(baseline[0]["alert"]), list(reordered[0]["alert"])
        )
        self.assertEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(reordered),
        )

    def test_changing_a_human_label_changes_the_revision(self):
        baseline = self._rows()
        relabeled = self._rows()
        relabeled[0]["human_verdict"] = "false_positive"
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(relabeled),
        )

    def test_changing_source_type_changes_the_revision(self):
        baseline = self._rows()
        resourced = self._rows()
        resourced[1]["source_type"] = "wazuh"
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(resourced),
        )

    def test_changing_row_identity_changes_the_revision(self):
        baseline = self._rows()
        renumbered = self._rows()
        renumbered[1]["id"] = 99
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(renumbered),
        )

    def test_changing_the_evaluation_population_changes_the_revision(self):
        baseline = self._rows()
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(baseline[:1]),
        )
        extended = self._rows()
        extended.append(
            {
                "id": 3,
                "alert": {"timestamp": "2026-08-06T00:02:00+00:00"},
                "human_verdict": "uncertain",
                "source_type": "suricata",
            }
        )
        self.assertNotEqual(
            gold_gate.dataset_revision(baseline),
            gold_gate.dataset_revision(extended),
        )

    def test_revision_is_stable_across_repeated_computation(self):
        rows = self._rows()
        self.assertEqual(
            gold_gate.dataset_revision(rows),
            gold_gate.dataset_revision(self._rows()),
        )

    def test_revision_is_a_prefixed_sha256_digest(self):
        revision = gold_gate.dataset_revision(self._rows())
        self.assertTrue(revision.startswith("sha256:"))
        self.assertEqual(len(revision), len("sha256:") + 64)

    def test_revision_differs_from_the_identity_only_scheme(self):
        """Regression: the old revision ignored alert content entirely."""
        rows = self._rows()
        identity_only = gold_gate.digest(
            [
                [row["id"], row["human_verdict"], row["source_type"]]
                for row in rows
            ]
        )
        self.assertNotEqual(gold_gate.dataset_revision(rows), identity_only)


if __name__ == "__main__":
    unittest.main()
