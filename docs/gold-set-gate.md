# Gold-set change-validation gate

The gate blocks prompt, policy, model, or configuration changes that regress
labeled detection performance, and it reports rather than silently promotes.
It is deliberately split into a layer that can run anywhere and a layer that
needs a real model.

| | Layer 1 — verification | Layer 2 — evaluation |
|---|---|---|
| Runs on | GitHub CI, every pull request | Operator host with Ollama |
| Needs a model | No | Yes |
| Needs production data | No | Yes, read-only |
| Network | None | Local Ollama only |
| Answers | "Is the committed evidence still current, and does the pipeline still fail closed?" | "What is the measured performance of the pipeline as it ships?" |

## Why not just run the existing benchmark in CI

`scripts/benchmark_quants.py` compares candidate models. It does not measure
the shipping pipeline: it carries a stale copy of the v0.2 prompt, sends raw
unisolated alerts, skips the prefilter, and coerces invalid model output into
`uncertain` instead of failing closed. Its published figures (Cohen's kappa
0.687, 83% true-positive recall on 265 alerts) describe the v0.2 pipeline.
They are not a valid baseline for v0.3 and are not used as one.

GitHub CI also has no GPU and no Ollama, so a real-model run cannot be a
required check. That constraint is what the two-layer split exists to handle.

## The behavior fingerprint

Layer 1 hashes what the model can actually see, not the bytes of the files
that produce it. The fingerprint is taken by intercepting the outbound Ollama
call and capturing the real request payload, so one measurement covers the
system prompt, the field-isolation projection, asset-context injection, the
model id, and the inference options — with no prompt duplicated anywhere.

Components:

| Component | Covers |
|---|---|
| `suricata_request_surface` | Rendered system prompt, isolated alert projection, asset context, inference options, for every Suricata fixture that reaches a model |
| `wazuh_request_surface` | The same for the Wazuh prompt and bounded Wazuh projection |
| `prefilter_behavior` | Which fixtures the prefilter resolves, and the reason given |
| `prefilter_policy` | Canonical form of `triagewall/config/prefilter.json` |
| `response_contract` | What the production validator returns for valid, malformed, schema-violating, and canary-reflecting model output |
| `model_identity` | The configured model id |

Two values are normalized out before hashing:

- **The canary token** is regenerated every process start, so it can never
  appear in a reproducible fingerprint.
- **`INTERNAL_SUBNETS`** is operator deployment configuration rather than
  code. Normalizing it keeps the fingerprint portable across deployments and
  keeps network topology out of published evidence.

Everything else that changes what the model sees moves the fingerprint. A
comment or refactor that does not change the request does not.

## Running it

Print the current fingerprint:

```bash
python3 scripts/gold_gate.py fingerprint
```

Verify committed evidence is current (what CI runs):

```bash
python3 scripts/gold_gate.py verify
```

Fail unless an approved real-model baseline exists (use when collecting
release evidence):

```bash
python3 scripts/gold_gate.py verify --require-calibrated
```

Operator run against the labeled database:

```bash
python3 scripts/gold_gate.py evaluate --db /opt/axon-agents/triage-agent/data/triage.db --out gold-evidence.json --commit "$(git rev-parse HEAD)"
```

Compare a fresh run against the approved baseline:

```bash
python3 scripts/gold_gate.py compare --candidate gold-evidence.json
```

## Current state: uncalibrated

`evidence/gold-set/baseline.json` ships with `status: "uncalibrated"`. No
approved real-model baseline exists for the v0.3 pipeline yet, because none
has been measured — the v0.2 figures do not describe it.

In this state:

- Layer 1 deterministic checks run on every pull request and can fail the build.
- No performance threshold is enforced.
- `verify --require-calibrated` fails, so release-evidence collection cannot
  mistake an uncalibrated gate for an approved one.

To calibrate: run `evaluate` on the operator host, review the measured
pipeline and model-only metrics, then set thresholds and flip `status` to
`approved` in a separate reviewed change. Thresholds are a human decision and
this tool never sets them.

## Two metric scopes

Every run reports metrics twice:

- **`pipeline`** — the end-to-end verdict a user actually receives, including
  alerts the prefilter resolves without consulting a model.
- **`model_only`** — the subset that reached the model.

Both are gated. A prefilter that resolves a large share of traffic can hold
pipeline metrics steady while the model silently regresses underneath it;
scoring only the end-to-end result would hide that.

## Wazuh coverage

Wazuh shipped in v0.3, so the labeled set does not yet contain human-labeled
Wazuh events. Wazuh coverage here is structural: the bounded projection, its
size limits, prompt isolation, and fail-closed validation are fingerprinted
and regression-tested, but no Wazuh performance number is claimed.

Ground truth stays human-labeled. The model does not label its own test set.
Each run reports Wazuh label counts so a genuine multi-source gold set can be
built once those labels exist.

## What the evidence contains

Evidence carries metrics, counts, and hashes. It does not carry raw alerts,
model reasoning, addresses, hostnames, agent names, or inventory contents. The
asset inventory appears only as its revision hash and asset count, both of
which are already non-disclosing. A regression test asserts that alert content
from the labeled set never appears in an emitted manifest.

## When the gate fails

**"guarded production inputs changed"** — a change moved the behavior
fingerprint, so the committed evidence describes a different pipeline. The
failure names the components that moved. Re-run `evaluate` on the operator
host and commit the fresh evidence with the change.

**"candidate run did not complete"** — transport errors, timeouts, or
unexpected exceptions left rows unscored. Partial runs never satisfy the gate;
fix the run rather than lowering the threshold.

**A metric regression** — the gate reports it and blocks. It does not roll
back, retune, or promote anything. A human decides what changes production.
