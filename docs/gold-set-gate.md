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

## This gate is not an adversarial probe suite

The gold-set gate is a **deterministic behaviour and performance gate** over a
human-labeled set. It is not a Garak implementation and does not claim Garak
coverage. The full-pipeline Garak injection gate remains an open roadmap item
and is tracked separately; keeping the two apart matters because a deterministic
regression gate and an adversarial probe suite fail for different reasons and
need different review.

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

### First v0.3 calibration candidate

A complete operator run was recorded on 2026-08-08 for commit `89e24fb`:

| Scope | Rows | Accuracy | Cohen's kappa | True-positive recall |
| --- | ---: | ---: | ---: | ---: |
| End-to-end pipeline | 266 | 0.9962 | 0.9317 | 1.0000 |
| Model only | 66 | 0.9848 | 0.9263 | 1.0000 |

The run completed all 266 rows, resolved 200 through the production prefilter,
and produced zero invalid outputs, transport errors, or unexpected errors. One
human-labeled false positive was classified conservatively as `uncertain`; all
six human-labeled real alerts were classified `real`.

This result is a **calibration candidate, not an approved baseline**. The set is
highly imbalanced (259 false positives, six real alerts, and one uncertain
alert), and every labeled row is currently Suricata. Wazuh behavior is covered
structurally but does not yet have a measured performance claim. A separate
reviewed change must decide regression tolerances and approve the exact
evidence before `verify --require-calibrated` can pass.

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

## What the dataset revision protects

`dataset.revision` answers one question: *is this evidence still describing the
same evaluation?* Comparison refuses to run when a candidate's revision differs
from the approved baseline's, because metrics measured on a different set of
alerts are not comparable.

For that to mean anything, the revision has to move whenever the evaluation
changes. It is a digest over, for every labeled row in `id` order:

- the row identity,
- the human label,
- the source type, and
- **a digest of the canonicalized alert content**.

The last item matters. Identity, label and source type all stay the same when
an alert is edited in place — a corrected address, a re-encoded field, a
tampered signature — so a revision built from those alone would let a silently
mutated gold set keep reusing approved evidence. The gate would then compare
new behaviour against a baseline measured on different alerts and report no
change.

So the revision changes when any of these change:

| Change | Revision moves |
| --- | --- |
| Alert content (including nested fields) | yes |
| Row identity | yes |
| Human label | yes |
| Source type | yes |
| The selected evaluation population (rows added, removed, or limited) | yes |
| JSON key ordering within an alert | **no** — canonical JSON sorts keys recursively |

It does **not** protect against a reviewer approving a bad label, and it is not
an integrity check on the database itself. It only guarantees that a change to
what is being measured is visible as a change in the evidence.

## What the evidence contains

Evidence carries metrics, counts, and hashes. It does not carry raw alerts,
model reasoning, addresses, hostnames, agent names, or inventory contents. The
asset inventory appears only as its revision hash and asset count, both of
which are already non-disclosing. A regression test asserts that alert content
from the labeled set never appears in an emitted manifest.

Only the **final aggregate** `dataset.revision` is committed. The per-row alert
digests that feed it are computed locally and discarded. Publishing them would
create an avoidable correlation risk: anyone holding a candidate alert could
hash it and confirm whether that exact alert — and therefore the host, address
or signature inside it — is part of the labeled set. A regression test asserts
no per-row digest appears in an emitted manifest.

## Evidence integrity

Approving a baseline means committing a JSON file by hand, so the gate does
not trust any field it can derive:

- `behavior_fingerprint.combined` is recomputed from `components`. It cannot
  be edited to the live digest while stale components sit underneath it.
- `kappa`, `accuracy`, `true_positive_recall`, `scored`, and the per-class
  metrics are recomputed from the recorded `confusion` matrix in both scopes.
  A degraded matrix cannot be shipped under approved scalars.
- `run.scored` must agree with `metrics.pipeline.scored`.

Any disagreement fails validation rather than being reported as a metric
regression, because an inconsistent manifest means the numbers cannot be
trusted at all.

What a human *is* meant to edit: `status`, `thresholds`, and `notes`. Those
are decisions, not measurements. Everything else should be pasted from
`evaluate` output unmodified.

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
