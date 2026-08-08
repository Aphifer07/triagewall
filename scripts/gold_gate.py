#!/usr/bin/env python3
"""
Gold-set change-validation gate.

The gate has two layers, and they are deliberately separated:

Layer 1 -- deterministic verification (GitHub CI).
    Runs with no model, no GPU, no network, and no production data. It
    recomputes a *behavior fingerprint* of everything the model can see and
    compares it to the fingerprint recorded in the committed evidence
    manifest. If a guarded production input changed, the committed evidence is
    stale by definition and the gate fails until a fresh operator run replaces
    it. It also asserts the response contract fails closed.

Layer 2 -- operator evaluation (maintainer host with Ollama).
    Reads the private labeled database read-only, classifies each labeled
    alert through the *real* production path (`triage.call_ollama`, prefilter
    included), and emits a sanitized evidence manifest containing metrics and
    hashes only -- never raw alerts, reasoning, addresses, or agent names.

Why a behavior fingerprint instead of hashing guarded files:
    Hashing file bytes fails on comment and refactor churn while still missing
    behavior changes that live in configuration. The fingerprint here is taken
    from the actual request payloads production would send to Ollama, captured
    by intercepting the HTTP call. That covers the system prompt, the field
    isolation projection, asset-context injection, the model id, and the
    inference options in one measurement, with no prompt duplicated anywhere.

`scripts/benchmark_quants.py` is NOT this gate and must not be used as one:
    it carries a stale copy of the v0.2 prompt, sends raw unisolated alerts,
    skips the prefilter, and coerces invalid model output into `uncertain`.

Usage:
    python3 scripts/gold_gate.py fingerprint
    python3 scripts/gold_gate.py verify [--require-calibrated]
    python3 scripts/gold_gate.py evaluate --out evidence.json
    python3 scripts/gold_gate.py compare --candidate evidence.json
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT / "triagewall") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "gold_gate"
BASELINE_PATH = PROJECT_ROOT / "evidence" / "gold-set" / "baseline.json"

MANIFEST_VERSION = 1
EVIDENCE_KIND = "triagewall.gold_gate.evidence"
BASELINE_KIND = "triagewall.gold_gate.baseline"

CANARY_PLACEHOLDER = "<CANARY_TOKEN>"
SUBNETS_PLACEHOLDER = "<INTERNAL_SUBNETS>"

VERDICT_LABELS = ("real", "false_positive", "uncertain")


class GoldGateError(RuntimeError):
    """Raised when the gate cannot produce or verify trustworthy evidence."""


# --------------------------------------------------------------------------
# Hashing and normalization
# --------------------------------------------------------------------------


def canonical_json(value) -> str:
    """Canonical JSON used for every hash in this module."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    """Return a prefixed sha256 over the canonical JSON form of `value`."""
    return "sha256:" + hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def normalize_runtime_values(text: str, *, canary: str, internal_subnets: str) -> str:
    """
    Replace per-process and per-operator values with stable placeholders.

    The canary is regenerated every process start, so it can never appear in a
    reproducible fingerprint. The internal subnet list is operator deployment
    configuration rather than code; normalizing it keeps the fingerprint
    portable across deployments and keeps network topology out of published
    evidence. Both substitutions are recorded in the docs as deliberate.
    """
    normalized = text.replace(canary, CANARY_PLACEHOLDER)
    if internal_subnets:
        normalized = normalized.replace(internal_subnets, SUBNETS_PLACEHOLDER)
    return normalized


# --------------------------------------------------------------------------
# Fixture loading
# --------------------------------------------------------------------------


def _load_fixture(name: str) -> list[dict]:
    path = FIXTURE_DIR / name
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GoldGateError(f"missing gold-gate fixture: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GoldGateError(f"unparseable gold-gate fixture {path}: {exc}") from exc
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise GoldGateError(f"gold-gate fixture {path} has no cases")
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise GoldGateError(f"gold-gate fixture {path} has a malformed case")
    return cases


def suricata_cases() -> list[dict]:
    return _load_fixture("suricata_surface.json")


def wazuh_cases() -> list[dict]:
    return _load_fixture("wazuh_surface.json")


def response_contract_cases() -> list[dict]:
    return _load_fixture("response_contract.json")


# --------------------------------------------------------------------------
# Ollama interception
# --------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self) -> bytes:
        return self._payload


def _valid_response_body() -> dict:
    return {
        "model": "fingerprint-stub",
        "response": json.dumps(
            {
                "verdict": "uncertain",
                "confidence": 0.5,
                "reasoning": "Fingerprint capture stub.",
            }
        ),
    }


@contextlib.contextmanager
def intercept_ollama(response_for):
    """
    Replace the outbound Ollama call and record every request payload.

    `response_for(index)` returns the raw Ollama envelope dict to hand back for
    the nth intercepted call. Nothing leaves the process while this is active,
    which is what lets Layer 1 run in CI with no model and no network.
    """
    captured: list[dict] = []

    def fake_urlopen(request, timeout=None):  # noqa: ARG001 - signature parity
        try:
            payload = json.loads(request.data.decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GoldGateError(f"could not decode outbound request: {exc}") from exc
        captured.append({"url": request.full_url, "payload": payload})
        return _FakeResponse(
            json.dumps(response_for(len(captured) - 1)).encode("utf-8")
        )

    with patch("urllib.request.urlopen", fake_urlopen):
        yield captured


# --------------------------------------------------------------------------
# Behavior fingerprint
# --------------------------------------------------------------------------


def _normalized_request(payload: dict, triage_module) -> dict:
    """Strip per-process and per-operator values from a captured request."""
    rendered = canonical_json(payload)
    rendered = normalize_runtime_values(
        rendered,
        canary=triage_module.CANARY_TOKEN,
        internal_subnets=triage_module.INTERNAL_SUBNETS,
    )
    return json.loads(rendered)


def _capture_suricata_surface(triage_module) -> tuple[list[dict], list[dict]]:
    """Return (prefilter decisions, normalized model requests) for fixtures."""
    prefilter_decisions = []
    requests = []
    for case in suricata_cases():
        alert = case["alert"]
        asset_context = triage_module.get_asset_context(alert)
        reason = triage_module.PREFILTER_POLICY.match_reason(alert, asset_context)
        prefilter_decisions.append(
            {
                "id": case["id"],
                "prefiltered": reason is not None,
                "reason": reason,
            }
        )
        with intercept_ollama(lambda _index: _valid_response_body()) as captured:
            triage_module.call_ollama(alert, asset_context=asset_context)
        if reason is not None:
            if captured:
                raise GoldGateError(
                    f"prefilter-resolved fixture {case['id']} still called the model"
                )
            continue
        if len(captured) != 1:
            raise GoldGateError(
                f"fixture {case['id']} produced {len(captured)} model calls, expected 1"
            )
        requests.append(
            {
                "id": case["id"],
                "request": _normalized_request(captured[0]["payload"], triage_module),
            }
        )
    return prefilter_decisions, requests


def _capture_wazuh_surface(triage_module) -> list[dict]:
    """Reproduce the production Wazuh call path exactly as wazuh_ingest does."""
    from wazuh_event import normalize_wazuh_event
    from wazuh_isolation import format_wazuh_for_llm

    requests = []
    for case in wazuh_cases():
        alert = case["alert"]
        event = normalize_wazuh_event(alert, "gold-gate-fixture")
        asset_context = triage_module.get_asset_context(
            {"src_ip": event.src_ip, "dest_ip": event.dest_ip}
        )
        isolated = format_wazuh_for_llm(alert)
        with intercept_ollama(lambda _index: _valid_response_body()) as captured:
            triage_module.call_ollama_wazuh(
                event, isolated, asset_context=asset_context
            )
        if len(captured) != 1:
            raise GoldGateError(
                f"wazuh fixture {case['id']} produced {len(captured)} model calls"
            )
        requests.append(
            {
                "id": case["id"],
                "projection_bytes": len(isolated.encode("utf-8")),
                "request": _normalized_request(captured[0]["payload"], triage_module),
            }
        )
    return requests


def _classify_contract_outcome(verdict: dict) -> str:
    """
    Classify a validator result structurally, without copying production text.

    Recording the full normalized verdict in the digest means any change to the
    rejection wording still moves the fingerprint, so nothing silently drifts.
    """
    reasoning = verdict.get("reasoning", "")
    if isinstance(reasoning, str) and reasoning.startswith("SECURITY:"):
        return "injection"
    if verdict.get("verdict") == "uncertain" and verdict.get("confidence") == 0.0:
        return "rejected"
    return "accepted"


def _capture_response_contract(triage_module) -> list[dict]:
    """Drive canned model output through the production validator."""
    cases = response_contract_cases()
    canary = triage_module.CANARY_TOKEN
    alert = suricata_cases()[1]["alert"]  # a fixture the prefilter does not resolve

    outcomes = []
    for case in cases:
        raw = case.get("response")
        if not isinstance(raw, str):
            raise GoldGateError(f"response contract case {case['id']} has no response")
        raw = raw.replace("{{CANARY}}", canary)
        if case.get("transform") == "escape_json_unicode":
            raw = raw.replace(canary, canary.replace("_", "\\u005f"))

        with intercept_ollama(
            lambda _index, body=raw: {"model": "contract-stub", "response": body}
        ):
            verdict = triage_module.call_ollama(
                alert, asset_context={"source": None, "destination": None}
            )

        normalized = json.loads(
            normalize_runtime_values(
                canonical_json(verdict),
                canary=canary,
                internal_subnets=triage_module.INTERNAL_SUBNETS,
            )
        )
        normalized.pop("model_used", None)  # env-configurable; fingerprinted separately
        outcome = _classify_contract_outcome(normalized)
        if case.get("expect") not in (None, outcome):
            raise GoldGateError(
                f"response contract case {case['id']} expected {case['expect']} "
                f"but the production validator returned {outcome}"
            )
        outcomes.append({"id": case["id"], "outcome": outcome, "verdict": normalized})
    return outcomes


def import_triage():
    """
    Import the production triage module with its startup chatter on stderr.

    `triage` prints prefilter and inventory banners at import and prints a
    `[SECURITY]` line whenever it detects canary reflection. Those belong in
    the log, not interleaved with this tool's machine-readable stdout.
    """
    with contextlib.redirect_stdout(sys.stderr):
        import triage  # noqa: PLC0415 - deferred until sys.path is prepared

    return triage


def compute_behavior_fingerprint(triage_module=None) -> dict:
    """
    Fingerprint every input that can change what the model sees or accepts.

    Deterministic and side-effect free: safe to run in CI on every pull
    request. It never contacts Ollama and never touches the production
    database or the operator asset inventory beyond the configured startup
    load already performed by `triage`.
    """
    if triage_module is None:
        triage_module = import_triage()

    with contextlib.redirect_stdout(sys.stderr):
        prefilter_decisions, suricata_requests = _capture_suricata_surface(triage_module)
        wazuh_requests = _capture_wazuh_surface(triage_module)
        contract = _capture_response_contract(triage_module)

    prefilter_document = json.loads(
        triage_module.PREFILTER_CONFIG_PATH.read_text(encoding="utf-8")
    )

    components = {
        "suricata_request_surface": digest(suricata_requests),
        "wazuh_request_surface": digest(
            [{"id": r["id"], "request": r["request"]} for r in wazuh_requests]
        ),
        "prefilter_behavior": digest(prefilter_decisions),
        "prefilter_policy": digest(prefilter_document),
        "response_contract": digest(contract),
        "model_identity": digest({"model": triage_module.MODEL}),
    }
    return {
        "combined": digest(components),
        "components": components,
        "coverage": {
            "suricata_fixtures": len(suricata_cases()),
            "suricata_model_requests": len(suricata_requests),
            "suricata_prefiltered": sum(
                1 for d in prefilter_decisions if d["prefiltered"]
            ),
            "wazuh_fixtures": len(wazuh_requests),
            "wazuh_max_projection_bytes": max(
                (r["projection_bytes"] for r in wazuh_requests), default=0
            ),
            "response_contract_cases": len(contract),
        },
    }


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


def cohens_kappa(confusion: dict) -> float:
    """
    Cohen's kappa from confusion[true_label][predicted_label] = count.

    When only one label is present, expected agreement is 1.0 and kappa is
    mathematically undefined (0/0). This returns 0.0 rather than the 1.0 that
    `scripts/benchmark_quants.py` reports for the same case: in a release gate
    a metric that cannot distinguish anything must never read as a perfect
    score. A degenerate scope therefore shows 0.0 and invites inspection
    instead of silently certifying a broken run.
    """
    labels = sorted(
        set(confusion) | {p for row in confusion.values() for p in row}
    )
    total = sum(count for row in confusion.values() for count in row.values())
    if total == 0:
        return 0.0
    observed = sum(confusion.get(l, {}).get(l, 0) for l in labels) / total
    expected = 0.0
    for label in labels:
        row_sum = sum(confusion.get(label, {}).values())
        col_sum = sum(confusion.get(other, {}).get(label, 0) for other in labels)
        expected += (row_sum * col_sum) / (total * total)
    if expected >= 1.0:
        return 0.0
    return (observed - expected) / (1.0 - expected)


def per_class_metrics(confusion: dict) -> dict:
    """Precision, recall, F1 and support for each label."""
    labels = sorted(
        set(confusion) | {p for row in confusion.values() for p in row}
    )
    metrics = {}
    for label in labels:
        tp = confusion.get(label, {}).get(label, 0)
        fn = sum(v for k, v in confusion.get(label, {}).items() if k != label)
        fp = sum(
            confusion.get(other, {}).get(label, 0)
            for other in labels
            if other != label
        )
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        metrics[label] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": tp + fn,
        }
    return metrics


def summarize(confusion: dict) -> dict:
    """Bundle the metrics recorded in evidence for one scored population."""
    total = sum(count for row in confusion.values() for count in row.values())
    correct = sum(confusion.get(l, {}).get(l, 0) for l in confusion)
    classes = per_class_metrics(confusion)
    return {
        "scored": total,
        "accuracy": correct / total if total else 0.0,
        "kappa": cohens_kappa(confusion),
        "true_positive_recall": classes.get("real", {}).get("recall", 0.0),
        "classes": classes,
        "confusion": confusion,
    }


# --------------------------------------------------------------------------
# Manifest schema
# --------------------------------------------------------------------------


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GoldGateError(f"invalid evidence manifest: {message}")


def _require_keys(value, expected: set[str], location: str) -> None:
    _require(isinstance(value, dict), f"{location} must be an object")
    missing = expected - set(value)
    unknown = set(value) - expected
    _require(not missing, f"{location} is missing {sorted(missing)}")
    _require(not unknown, f"{location} has unknown keys {sorted(unknown)}")


def _round_floats(value, places: int = 9):
    """
    Round nested floats so recomputed metrics compare stably.

    Derived metrics are recomputed from the confusion matrix and compared
    against the recorded values. Rounding keeps that comparison robust to
    float formatting across platforms while staying far tighter than any
    change that could hide a real regression.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return round(value, places)
    if isinstance(value, dict):
        return {key: _round_floats(item, places) for key, item in value.items()}
    if isinstance(value, list):
        return [_round_floats(item, places) for item in value]
    return value


def _require_number(value, location: str) -> None:
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{location} must be a number",
    )


def _require_counts(value, location: str) -> None:
    _require(isinstance(value, dict), f"{location} must be an object")
    for key, count in value.items():
        _require(isinstance(key, str), f"{location} keys must be strings")
        _require(
            isinstance(count, int) and not isinstance(count, bool) and count >= 0,
            f"{location}.{key} must be a non-negative integer",
        )


def _validate_metrics(value, location: str) -> None:
    _require_keys(
        value,
        {
            "scored",
            "accuracy",
            "kappa",
            "true_positive_recall",
            "classes",
            "confusion",
        },
        location,
    )
    _require(
        isinstance(value["scored"], int) and not isinstance(value["scored"], bool),
        f"{location}.scored must be an integer",
    )
    for key in ("accuracy", "kappa", "true_positive_recall"):
        _require_number(value[key], f"{location}.{key}")
    _require(isinstance(value["classes"], dict), f"{location}.classes must be an object")
    _require(
        isinstance(value["confusion"], dict),
        f"{location}.confusion must be an object",
    )
    for label, row in value["confusion"].items():
        _require(
            label in VERDICT_LABELS, f"{location}.confusion has unknown label {label!r}"
        )
        _require_counts(row, f"{location}.confusion.{label}")

    # Every scalar here is a function of the confusion matrix, so trusting the
    # recorded values would let a stale or hand-edited manifest report approved
    # numbers over degraded results. Derive them again and reject any
    # disagreement.
    derived = summarize(value["confusion"])
    for key in ("scored", "accuracy", "kappa", "true_positive_recall"):
        _require(
            _round_floats(value[key]) == _round_floats(derived[key]),
            f"{location}.{key} does not match the recorded confusion matrix "
            f"(recorded {value[key]!r}, derived {derived[key]!r})",
        )
    _require(
        _round_floats(value["classes"]) == _round_floats(derived["classes"]),
        f"{location}.classes does not match the recorded confusion matrix",
    )


def validate_evidence(manifest) -> dict:
    """Validate an evidence manifest strictly. Unknown or missing keys fail."""
    _require_keys(
        manifest,
        {
            "manifest_version",
            "kind",
            "generated_at",
            "commit",
            "behavior_fingerprint",
            "asset_inventory",
            "dataset",
            "run",
            "metrics",
        },
        "manifest",
    )
    _require(
        manifest["manifest_version"] == MANIFEST_VERSION,
        f"manifest_version must be {MANIFEST_VERSION}",
    )
    _require(manifest["kind"] == EVIDENCE_KIND, f"kind must be {EVIDENCE_KIND!r}")
    _require(isinstance(manifest["generated_at"], str), "generated_at must be a string")
    _require(isinstance(manifest["commit"], str), "commit must be a string")

    fingerprint = manifest["behavior_fingerprint"]
    _require_keys(fingerprint, {"combined", "components", "coverage"}, "behavior_fingerprint")
    _require(
        isinstance(fingerprint["combined"], str)
        and fingerprint["combined"].startswith("sha256:"),
        "behavior_fingerprint.combined must be a sha256 digest",
    )
    _require(
        isinstance(fingerprint["components"], dict) and fingerprint["components"],
        "behavior_fingerprint.components must be a non-empty object",
    )
    for name, value in fingerprint["components"].items():
        _require(
            isinstance(value, str) and value.startswith("sha256:"),
            f"behavior_fingerprint.components.{name} must be a sha256 digest",
        )
    # `verify_baseline` decides whether evidence is current from `combined`
    # alone. Recompute it from the components so the digest cannot be edited
    # to look current while the components and metrics stay stale.
    _require(
        digest(fingerprint["components"]) == fingerprint["combined"],
        "behavior_fingerprint.combined does not match its components; "
        "evidence cannot be edited to appear current without a fresh "
        "operator evaluation",
    )

    _require_keys(manifest["asset_inventory"], {"revision", "count"}, "asset_inventory")
    _require_keys(
        manifest["dataset"],
        {"revision", "total", "class_counts", "source_counts"},
        "dataset",
    )
    _require_counts(manifest["dataset"]["class_counts"], "dataset.class_counts")
    _require_counts(manifest["dataset"]["source_counts"], "dataset.source_counts")

    _require_keys(
        manifest["run"],
        {"completed", "scored", "prefilter_resolved", "errors", "invalid_output"},
        "run",
    )
    _require(
        isinstance(manifest["run"]["completed"], bool), "run.completed must be a boolean"
    )
    _require_counts(manifest["run"]["errors"], "run.errors")

    _require_keys(manifest["metrics"], {"pipeline", "model_only"}, "metrics")
    _validate_metrics(manifest["metrics"]["pipeline"], "metrics.pipeline")
    _validate_metrics(manifest["metrics"]["model_only"], "metrics.model_only")

    # An evaluation scores exactly the rows in the pipeline confusion matrix,
    # so a run block claiming a different total has been edited or truncated.
    _require(
        manifest["run"]["scored"] == manifest["metrics"]["pipeline"]["scored"],
        "run.scored disagrees with metrics.pipeline.scored "
        f"({manifest['run']['scored']} vs "
        f"{manifest['metrics']['pipeline']['scored']})",
    )
    return manifest


def validate_baseline(document) -> dict:
    """Validate the committed baseline, including the uncalibrated state."""
    _require_keys(
        document,
        {"manifest_version", "kind", "status", "notes", "thresholds", "evidence"},
        "baseline",
    )
    _require(
        document["manifest_version"] == MANIFEST_VERSION,
        f"manifest_version must be {MANIFEST_VERSION}",
    )
    _require(document["kind"] == BASELINE_KIND, f"kind must be {BASELINE_KIND!r}")
    _require(
        document["status"] in ("uncalibrated", "approved"),
        "status must be 'uncalibrated' or 'approved'",
    )
    if document["status"] == "uncalibrated":
        _require(
            document["evidence"] is None and document["thresholds"] is None,
            "an uncalibrated baseline must carry no evidence and no thresholds",
        )
        return document

    _require(document["evidence"] is not None, "an approved baseline requires evidence")
    validate_evidence(document["evidence"])
    thresholds = document["thresholds"]
    _require_keys(
        thresholds,
        {
            "max_kappa_decrease",
            "max_true_positive_recall_decrease",
            "max_invalid_output",
            "require_complete_run",
            "require_matching_class_counts",
        },
        "thresholds",
    )
    _require_number(thresholds["max_kappa_decrease"], "thresholds.max_kappa_decrease")
    _require_number(
        thresholds["max_true_positive_recall_decrease"],
        "thresholds.max_true_positive_recall_decrease",
    )
    _require(
        isinstance(thresholds["max_invalid_output"], int)
        and not isinstance(thresholds["max_invalid_output"], bool),
        "thresholds.max_invalid_output must be an integer",
    )
    for key in ("require_complete_run", "require_matching_class_counts"):
        _require(isinstance(thresholds[key], bool), f"thresholds.{key} must be a boolean")
    return document


def load_baseline(path: Path = BASELINE_PATH) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GoldGateError(f"missing gold-set baseline: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GoldGateError(f"unparseable gold-set baseline {path}: {exc}") from exc
    return validate_baseline(document)


# --------------------------------------------------------------------------
# Gate decisions
# --------------------------------------------------------------------------


def verify_baseline(
    baseline: dict,
    fingerprint: dict,
    *,
    require_calibrated: bool = False,
    asset_inventory: dict | None = None,
) -> list[str]:
    """
    Return a list of failures. An empty list means the gate passes.

    An uncalibrated baseline passes ordinary CI so the machinery can merge
    before the first real-model run exists, but `require_calibrated` makes it
    a hard failure -- that flag is what release evidence collection uses, so
    an uncalibrated gate can never be mistaken for an approved one.
    """
    failures = []
    if baseline["status"] == "uncalibrated":
        if require_calibrated:
            failures.append(
                "gold-set baseline is uncalibrated: run "
                "'gold_gate.py evaluate' on the operator host and record "
                "approved thresholds before tagging a release"
            )
        return failures

    recorded = baseline["evidence"]["behavior_fingerprint"]
    if recorded["combined"] != fingerprint["combined"]:
        changed = sorted(
            name
            for name, value in fingerprint["components"].items()
            if recorded["components"].get(name) != value
        )
        missing = sorted(set(recorded["components"]) - set(fingerprint["components"]))
        failures.append(
            "guarded production inputs changed since the approved gold-set "
            f"evidence was recorded (changed: {changed or 'none'}; "
            f"missing: {missing or 'none'}). Re-run the operator evaluation "
            "and record fresh evidence."
        )
    if require_calibrated:
        recorded_inventory = baseline["evidence"]["asset_inventory"]
        if asset_inventory is None:
            failures.append(
                "current asset inventory was not supplied for calibrated "
                "verification; release evidence cannot be declared current"
            )
        elif asset_inventory != recorded_inventory:
            failures.append(
                "asset inventory changed since the approved gold-set evidence "
                "was recorded "
                f"(revision {recorded_inventory['revision']} -> "
                f"{asset_inventory.get('revision', 'missing')}, count "
                f"{recorded_inventory['count']} -> "
                f"{asset_inventory.get('count', 'missing')}). Re-run the "
                "operator evaluation and record fresh evidence."
            )
    if not baseline["evidence"]["run"]["completed"]:
        failures.append("approved gold-set evidence records an incomplete run")
    return failures


def compare_evidence(baseline: dict, candidate: dict) -> list[str]:
    """Compare a fresh operator run against the approved baseline."""
    failures = []
    if baseline["status"] != "approved":
        return [
            "cannot compare against an uncalibrated baseline: approve a "
            "calibration run first"
        ]
    validate_evidence(candidate)
    thresholds = baseline["thresholds"]
    approved = baseline["evidence"]

    if thresholds["require_complete_run"] and not candidate["run"]["completed"]:
        failures.append(
            "candidate run did not complete; partial runs never satisfy the gate"
        )
    invalid = candidate["run"]["invalid_output"]
    if invalid > thresholds["max_invalid_output"]:
        failures.append(
            f"candidate produced {invalid} invalid model outputs, "
            f"limit is {thresholds['max_invalid_output']}"
        )
    if candidate["asset_inventory"] != approved["asset_inventory"]:
        failures.append(
            "candidate asset inventory differs from the approved calibration; "
            "re-approve after inventory changes before comparing metrics"
        )
    # Dataset revision is an identity check, not a class-count policy. It must
    # always run: otherwise require_matching_class_counts=false would let a
    # candidate measured on a different labeled set reuse approved thresholds.
    if candidate["dataset"]["revision"] != approved["dataset"]["revision"]:
        failures.append(
            "candidate dataset revision differs from the approved set; "
            "re-approve the evaluation set before comparing"
        )
    if thresholds["require_matching_class_counts"]:
        if candidate["dataset"]["class_counts"] != approved["dataset"]["class_counts"]:
            failures.append(
                "candidate dataset class counts differ from the approved set; "
                "metrics are not comparable"
            )

    for scope in ("pipeline", "model_only"):
        base_metrics = approved["metrics"][scope]
        new_metrics = candidate["metrics"][scope]
        kappa_drop = base_metrics["kappa"] - new_metrics["kappa"]
        if kappa_drop > thresholds["max_kappa_decrease"]:
            failures.append(
                f"{scope} Cohen's kappa fell {kappa_drop:.4f} "
                f"({base_metrics['kappa']:.4f} -> {new_metrics['kappa']:.4f}), "
                f"limit is {thresholds['max_kappa_decrease']:.4f}"
            )
        recall_drop = (
            base_metrics["true_positive_recall"] - new_metrics["true_positive_recall"]
        )
        if recall_drop > thresholds["max_true_positive_recall_decrease"]:
            failures.append(
                f"{scope} true-positive recall fell {recall_drop:.4f} "
                f"({base_metrics['true_positive_recall']:.4f} -> "
                f"{new_metrics['true_positive_recall']:.4f}), limit is "
                f"{thresholds['max_true_positive_recall_decrease']:.4f}"
            )
    return failures


# --------------------------------------------------------------------------
# Operator evaluation
# --------------------------------------------------------------------------


LABELED_QUERY = """
    SELECT te.id AS id,
           te.raw_alert AS raw_alert,
           te.human_verdict AS human_verdict,
           COALESCE(sec.source_type, 'suricata') AS source_type
    FROM triage_events AS te
    LEFT JOIN sensor_event_context AS sec ON sec.triage_event_id = te.id
    WHERE te.human_verdict IS NOT NULL
      AND te.raw_alert IS NOT NULL
    ORDER BY te.id
"""


def load_labeled_rows(db_path, limit=None) -> list[dict]:
    """Read the labeled set read-only. This never writes to the database."""
    uri = f"file:{Path(db_path).as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        query = LABELED_QUERY
        if limit is not None:
            query += f" LIMIT {int(limit)}"
        rows = []
        unparseable = 0
        for row in conn.execute(query):
            if row["human_verdict"] not in VERDICT_LABELS:
                continue
            try:
                alert = json.loads(row["raw_alert"])
            except (json.JSONDecodeError, TypeError):
                unparseable += 1
                continue
            if not isinstance(alert, dict):
                unparseable += 1
                continue
            rows.append(
                {
                    "id": row["id"],
                    "alert": alert,
                    "human_verdict": row["human_verdict"],
                    "source_type": row["source_type"],
                }
            )
    finally:
        conn.close()
    if unparseable:
        print(
            f"[gold-gate] {unparseable} labeled rows had unparseable raw_alert "
            "and were excluded",
            file=sys.stderr,
        )
    return rows


# Bumped whenever the dataset-revision construction changes, so a revision
# computed under an older scheme can never be mistaken for a current one.
DATASET_REVISION_SCHEME = "gold-set-dataset-revision-v2"


def dataset_revision(rows) -> str:
    """Bind the dataset revision to the labeled alert *content*.

    Row identity, human label and source type do not change when an alert is
    edited in place, so a silently mutated gold set could keep reusing approved
    evidence: the gate would compare new behaviour against a baseline measured
    on different alerts and call it unchanged. Each row therefore also
    contributes a digest of its canonicalized alert.

    Canonical JSON sorts keys recursively, so the revision is stable across
    irrelevant JSON key ordering while still moving for any content change.

    Only the aggregate is ever emitted. Per-row digests stay local: publishing
    them would let anyone holding a candidate alert confirm whether that exact
    alert -- and therefore the host, address or signature in it -- is part of
    the labeled set.
    """
    contributions = [
        [
            row["id"],
            row["human_verdict"],
            row["source_type"],
            digest(row["alert"]),
        ]
        for row in rows
    ]
    return digest([DATASET_REVISION_SCHEME, contributions])


def evaluate(db_path, *, limit=None, commit="unknown") -> dict:
    """
    Run the labeled set through the real production classification path.

    Only Suricata rows are scored: Wazuh shipped in v0.3, so the labeled set
    does not yet contain human-labeled Wazuh events. Wazuh coverage in this
    release is structural (projection, bounds, isolation, fail-closed
    validation) and is fingerprinted rather than scored. The Wazuh label count
    is reported so a genuine multi-source gold set can be built when it exists.
    """
    triage = import_triage()

    rows = load_labeled_rows(db_path, limit=limit)
    if not rows:
        raise GoldGateError("no labeled rows found; refusing to emit empty evidence")

    class_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for row in rows:
        class_counts[row["human_verdict"]] = class_counts.get(row["human_verdict"], 0) + 1
        source_counts[row["source_type"]] = source_counts.get(row["source_type"], 0) + 1

    scorable = [row for row in rows if row["source_type"] == "suricata"]
    if not scorable:
        raise GoldGateError("labeled set contains no Suricata rows to score")

    pipeline_confusion: dict[str, dict[str, int]] = {}
    model_only_confusion: dict[str, dict[str, int]] = {}
    errors = {"transport": 0, "unexpected": 0}
    prefilter_resolved = 0
    invalid_output = 0

    for index, row in enumerate(scorable, 1):
        try:
            asset_context = triage.get_asset_context(row["alert"])
            verdict = triage.call_ollama(row["alert"], asset_context=asset_context)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            errors["transport"] += 1
            print(f"[gold-gate] transport error on row {row['id']}: {exc}", file=sys.stderr)
            continue
        except Exception as exc:  # noqa: BLE001 - any failure invalidates the run
            errors["unexpected"] += 1
            print(
                f"[gold-gate] {type(exc).__name__} on row {row['id']}: {exc}",
                file=sys.stderr,
            )
            continue

        predicted = verdict["verdict"]
        from_prefilter = verdict.get("model_used") == "prefilter"
        if from_prefilter:
            prefilter_resolved += 1
        elif _classify_contract_outcome(verdict) == "rejected":
            invalid_output += 1

        truth = row["human_verdict"]
        pipeline_confusion.setdefault(truth, {}).setdefault(predicted, 0)
        pipeline_confusion[truth][predicted] += 1
        if not from_prefilter:
            model_only_confusion.setdefault(truth, {}).setdefault(predicted, 0)
            model_only_confusion[truth][predicted] += 1

        if index % 25 == 0 or index == len(scorable):
            print(f"[gold-gate] scored {index}/{len(scorable)}", flush=True)

    total_errors = sum(errors.values())
    scored = sum(c for row in pipeline_confusion.values() for c in row.values())

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "kind": EVIDENCE_KIND,
        "generated_at": _utc_now(),
        "commit": commit,
        "behavior_fingerprint": compute_behavior_fingerprint(triage),
        "asset_inventory": {
            "revision": triage.ASSET_INVENTORY.revision,
            "count": triage.ASSET_INVENTORY.count,
        },
        "dataset": {
            "revision": dataset_revision(rows),
            "total": len(rows),
            "class_counts": class_counts,
            "source_counts": source_counts,
        },
        "run": {
            "completed": total_errors == 0 and scored == len(scorable),
            "scored": scored,
            "prefilter_resolved": prefilter_resolved,
            "errors": errors,
            "invalid_output": invalid_output,
        },
        "metrics": {
            "pipeline": summarize(pipeline_confusion),
            "model_only": summarize(model_only_confusion),
        },
    }
    return validate_evidence(manifest)


def _utc_now() -> str:
    from time_utils import utc_now_iso  # noqa: PLC0415 - production helper

    return utc_now_iso()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _print_failures(failures: list[str]) -> int:
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("fingerprint", help="Print the current behavior fingerprint")

    verify = sub.add_parser("verify", help="Verify committed evidence is current")
    verify.add_argument("--baseline", default=str(BASELINE_PATH))
    verify.add_argument(
        "--require-calibrated",
        action="store_true",
        help="Fail if the baseline has no approved real-model evidence",
    )

    run = sub.add_parser("evaluate", help="Operator run against the labeled database")
    run.add_argument(
        "--db",
        default=os.environ.get("DB_PATH")
        or os.environ.get("TRIAGE_DB")
        or "/opt/axon-agents/triage-agent/data/triage.db",
    )
    run.add_argument("--out", required=True, help="Path for the evidence manifest")
    run.add_argument("--limit", type=int, default=None, help="Smoke-test row limit")
    run.add_argument("--commit", default="unknown", help="Commit SHA under evaluation")

    compare = sub.add_parser("compare", help="Compare a fresh run to the baseline")
    compare.add_argument("--baseline", default=str(BASELINE_PATH))
    compare.add_argument("--candidate", required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "fingerprint":
            print(json.dumps(compute_behavior_fingerprint(), indent=2, sort_keys=True))
            return 0

        if args.command == "verify":
            baseline = load_baseline(Path(args.baseline))
            triage = import_triage()
            fingerprint = compute_behavior_fingerprint(triage)
            asset_inventory = {
                "revision": triage.ASSET_INVENTORY.revision,
                "count": triage.ASSET_INVENTORY.count,
            }
            failures = verify_baseline(
                baseline,
                fingerprint,
                require_calibrated=args.require_calibrated,
                asset_inventory=asset_inventory,
            )
            if failures:
                return _print_failures(failures)
            if baseline["status"] == "uncalibrated":
                print(
                    "gold-set gate: deterministic checks passed. Baseline is "
                    "UNCALIBRATED, so no performance threshold is enforced yet."
                )
            else:
                print(
                    "gold-set gate: deterministic checks passed and approved "
                    f"evidence is current ({fingerprint['combined']})."
                )
            return 0

        if args.command == "evaluate":
            manifest = evaluate(args.db, limit=args.limit, commit=args.commit)
            Path(args.out).write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            metrics = manifest["metrics"]
            print(f"\nEvidence written to {args.out}")
            print(f"  complete run:  {manifest['run']['completed']}")
            print(f"  scored:        {manifest['run']['scored']}")
            print(f"  prefiltered:   {manifest['run']['prefilter_resolved']}")
            print(f"  invalid output:{manifest['run']['invalid_output']}")
            for scope in ("pipeline", "model_only"):
                print(
                    f"  {scope:<11} kappa={metrics[scope]['kappa']:.4f} "
                    f"tp_recall={metrics[scope]['true_positive_recall']:.4f} "
                    f"n={metrics[scope]['scored']}"
                )
            return 0 if manifest["run"]["completed"] else 1

        if args.command == "compare":
            baseline = load_baseline(Path(args.baseline))
            candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
            failures = compare_evidence(baseline, candidate)
            if failures:
                return _print_failures(failures)
            print("gold-set gate: candidate evidence meets the approved thresholds.")
            return 0
    except GoldGateError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
