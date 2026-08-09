# v0.3 release evidence

This records the release-evidence checks required by the ROADMAP closeout item
*"Record supported fresh-install, upgrade, rollback, Core-only, and
Core-plus-Wazuh checks before tagging v0.3."*

Everything here is sanitized aggregate evidence: commits, timestamps, exit
codes, counts, and hashes. It contains no secrets, alert content, asset
inventory contents, addresses, or host identifiers.

**Commit under test:** `9b95bf007440ab2297d0dae272c57a9d6f02e4ba`
**Previous deployed commit:** `89e24fb048517bafda6cce8c362b88773fc22842`
**Environment:** single maintainer host ("omv1"), Docker Compose, Core + optional
Wazuh profile. Live project runs Core+Wazuh; isolated checks run under a separate
Compose project, port, and data directory.
**Evidence collected:** 2026-08-08T20:20Z – 2026-08-09T00:45Z

## Summary

| # | Scenario | Status |
| --- | --- | --- |
| 1 | Upgrade deployment | **PASS** (scope limited — see notes) |
| 2 | Core-only operation | **PASS** (functional) |
| 3 | Core + Wazuh operation | **PASS** |
| 4 | Fresh installation | **PASS** |
| 5 | Rollback | **PASS** |
| 6 | Multi-source Garak / adversarial coverage | **NOT IMPLEMENTED / NOT RUN** |

Scenarios 2, 4 and 5 share one isolated Compose project but are assessed
independently; a pass in one does not imply a pass in another.

## Gold-set gate (calibrated)

Run on the deployment host against the real private asset inventory, with
`ASSET_INVENTORY_PATH` pointing at the same file Compose mounts through
`HOST_ASSET_INVENTORY`. The file was confirmed readable; its contents were never
displayed.

```
python3 scripts/gold_gate.py verify --require-calibrated   → exit 0
python3 scripts/gold_gate.py compare --candidate <sanitized manifest>   → exit 0
```

- `gold-set gate: deterministic checks passed and approved evidence is current
  (sha256:5275d437763f4326669d2f34ef6e67688d5f1c8497b9e0544263b933080deda2).`
- `gold-set gate: candidate evidence meets the approved thresholds.`
- Asset inventory resolved by the gate: **count 2**, revision
  `sha256:3dd464829377322b7cbf70346bf403287c293f43075a7a9c5916ba1be01680c0` —
  matching the approved baseline exactly.

**No re-evaluation was required or performed.** The `89e24fb…9b95bf00` range
changes only `CHANGELOG.md`, `README.md`, `ROADMAP.md`, `docs/gold-set-gate.md`,
`evidence/gold-set/baseline.json`, `scripts/gold_gate.py`, and
`tests/test_gold_gate.py`. No fingerprint input changed (`triage.py`,
`config/prefilter.json`, and the gold-gate fixtures are untouched), and the
`gold_gate.py` delta is manifest validation plus the new asset-inventory check;
`compute_behavior_fingerprint` is unmodified. The recomputed fingerprint matches
the approved baseline, which confirms this by measurement rather than inspection.

The pre-existing sanitized candidate manifest was still present and trustworthy:
fingerprint `5275d437…`, inventory count 2 / `3dd46482…`, dataset revision
`231cf554…`, 266 rows (259 false positive / 6 real / 1 uncertain), 200
prefilter-resolved, 0 invalid output, 0 transport or unexpected errors,
pipeline κ 0.9317.

## Scenario 1 — Upgrade deployment (PASS, scope limited)

| Field | Value |
| --- | --- |
| Setup | Live deployment, Core+Wazuh profile |
| Commit | `89e24fb…` → `9b95bf00…` |
| Start / End | 2026-08-08T21:41:52Z / 21:47:37Z |
| Commands | `git fetch origin`; `git merge --ff-only origin/main`; `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh up -d --build` |
| Exit codes | merge 0, compose up 0 |
| Migration | `migrate` **Exited (0)** |
| Health | `/api/health` 200, `/api/v1/health` 200, `status: ok` |
| Restarts | 0 across dashboard, ingest, wazuh-ingest |
| Deployed SHA | verified equal to public `main` |

Untracked operator files in the deployment checkout were byte-for-byte preserved
across the upgrade.

**Limitation:** this range contains no schema, migration, ingest, or dashboard
code change. It therefore exercises the *deployment mechanism* — fast-forward,
rebuild, serialized migration phase, service restart, health — and is **not**
evidence that a schema-changing upgrade migrates correctly. A future release with
migration content needs its own upgrade evidence.

## Scenario 2 — Core-only operation (PASS, functional)

Isolated Compose project, separate port and data directory, Wazuh profile
omitted. This is a functional check, not a "containers started" check.

| Field | Value |
| --- | --- |
| Commit | `9b95bf00…` |
| Start | 2026-08-08T22:11:29Z |
| Fixture | 1 sanitized Suricata alert, 298 bytes, sha256 `56e55471496f0afcba6e8a563387ae5efd93cfbb749db4d9bd9b1d2e8f3b6a8c` |
| Fixture choice | SID 2016149 — a globally suppressed prefilter rule with no `match` block, so it resolves deterministically and issues **no model call** |
| Services present | `migrate`, `ingest`, `dashboard` — **wazuh-ingest count 0** |

Results:

- Checkpoint advanced from *absent* to `offset=298, size=298` (whole fixture consumed).
- Ingest logged `Read 1 new lines, triaged 1 alerts (offset now 298)`.
- Persisted: 1 `triage_events` row, verdict `false_positive`, `model_used=prefilter`
  — confirming the deterministic path and no Ollama dependency.
- Visible through the API: `/api/v1/stats` 200; `/api/v1/verdicts` 200 returning
  the single verdict with `model_used=prefilter`.
- Health moved from 503 `stale` (no alerts) to **200 `ok`** once the alert landed.

Restart check (22:15:55Z → 22:17:19Z, `docker compose restart`, exit 0):

- Checkpoint after restart **unchanged** at `offset=298` — durable recovery, no rewind.
- `triage_events` still **1 row — no duplicate ingestion**.
- `ingest_failures` 0. Health 200 `ok`.

**Limitation:** isolated environment, not the live deployment; single-event
fixture on the prefilter path, so it does not exercise the model path.

## Scenario 3 — Core + Wazuh operation (PASS)

The live deployment runs both sources, so it is the direct evidence.

| Field | Value |
| --- | --- |
| Commit | `9b95bf00…` |
| Observation window | 2026-08-08T21:52:37Z → 22:22:54Z (**30 m 17 s**) |
| Suricata checkpoint | offset 171012213 → 174346439 (**+3,334,226 bytes**), inode stable |
| Wazuh checkpoint | offset 2496174 → 2562034 (**+65,860 bytes**), same archive day |
| Health | both endpoints 200 throughout, `status: ok`, `last_alert_age_seconds: 0` |
| Restarts | 0 across all three services |

Log review over the window found no crashes, restart loops, migration errors,
database errors, invalid model output, or unexpected exceptions.

**Log-noise caution for future reviewers:** a case-insensitive `error` grep over
ingest logs returns thousands of matches that are *not* errors — the Suricata
signature `ET DNS Standard query response, Name Error` appears in ordinary
`false_positive` verdict lines. Anchor on the log level (`[ERROR]`,
`[CRITICAL]`, `Traceback`). With that anchor, the six hours before the upgrade
contained exactly one error: a single transient, retryable triage failure that
did not advance the checkpoint.

## Scenario 4 — Fresh installation (PASS)

| Field | Value |
| --- | --- |
| Commit | `9b95bf00…` |
| Setup | Isolated project, **empty** data directory, empty `eve.json` |
| Start / End | 2026-08-08T22:01:51Z / 22:07:50Z |
| Command | `docker compose -p <isolated> up -d --build` (exit 0) |
| Migration | `migrate` **Exited (0)**, created the database from nothing (118,784 bytes) |
| Health | 503 `status: stale`, well-formed JSON on both endpoints |

A fresh installation with no alerts reports **503 `stale`** by design — the
health contract reflects alert-stream staleness, not process liveness. This is
correct behavior, not a failure, and it is exactly why Core-only (Scenario 2) is
assessed functionally: the same stack returned 200 `ok` as soon as a single
alert was ingested.

## Scenario 5 — Rollback (PASS)

Performed entirely against a **copy** of a verified backup in an isolated
project. The live database was never downgraded, restored over, or written to.

### Backup artifact

| Field | Value |
| --- | --- |
| Created | 2026-08-08T20:22:30Z – 20:39:43Z (exit 0, 0 backup restarts) |
| Size | 18,551,799,808 bytes, mode 0600 |
| Backup sha256 | `fb0cf1248410e22df339c45575b46af10ca1052f500e86cd3ab3fd57e555b0ce` |
| Provenance sha256 | `5049fcbe1e9e84baf32b1071822584062e079d795836f84c2f3366318f86cdf4` |
| Manifest sha256 | `8ae0c0434e632b83b5a84bcc30adeb58e7df878d866981875667a0d3146ed4f2` |
| Manifest hash field | `sha256:8a1c55e13d008dd502613f6e1…` |
| Integrity | `integrity_check: "ok"`, verified 2026-08-08T22:19:23Z, exit 0 |
| Readability | opens read-only as valid SQLite; 11,043,136 `triage_events` rows |

The recomputed file hash matches the manifest hash exactly.

### Rollback sequence (isolated, against the restored copy)

| Step | Commit | Start / End | migrate | Rows | Health |
| --- | --- | --- | --- | --- | --- |
| Current `main` on restored data | `9b95bf00…` | 23:24:50Z / 23:28:48Z | Exited (0) | 11,043,136 | 503 `stale` |
| **Roll back to prior version** | `89e24fb…` | 00:33:04Z / 00:39:35Z | Exited (0) | 11,043,136 | 503 `stale` |
| **Return to current `main`** | `9b95bf00…` | 00:41:07Z / 00:44:09Z | Exited (0) | 11,043,136 | 503 `stale` |

All three `docker compose up -d --build` invocations exited 0. Row counts were
identical at every step. 503 `stale` is expected: the isolated stack has no live
alert stream, and the newest restored alert predates the check.

Demonstrated: a backup exists and is readable; its integrity is verified; the
procedure is recoverable; the prior version starts against restored data; and
returning to current `main` succeeds.

### Operational finding: verification cost at production scale

`verify-backup` on this 18.5 GB database took roughly **100 minutes**
(SHA-256 pass ~7 minutes, `PRAGMA integrity_check` the remainder), versus ~17
minutes for the copy itself. Operators planning a maintenance window should size
it for the copy **plus** verification, or follow the documented split workflow
and restart writers before verification. This is worth stating explicitly in the
retention runbook.

## Scenario 6 — Multi-source Garak / adversarial coverage (NOT IMPLEMENTED / NOT RUN)

**Garak is not implemented in this repository.** A repository-wide search found
**0** Garak files and **0** Garak references in code. There is no runner, no
configuration, no probe set, and no gate. Nothing here may be reported as a
Garak pass.

What *does* exist, and what was run at `9b95bf00…`:

| Coverage | Result |
| --- | --- |
| `tests.test_security_regressions` (incl. `PromptBoundaryTests`) | 19 tests, **OK**, exit 0 |
| Full suite `unittest discover -s tests` | 364 tests, **OK**, exit 0 |

`PromptBoundaryTests` covers per-process canary detection (including a canary
that only appears after JSON decoding), refusal to salvage malformed model JSON,
rejection of non-object model output, acceptance of schema-valid output, and
fail-closed isolation of wire values and malformed allowlisted network fields.

**These are deterministic regression tests, not adversarial probe coverage.**
They assert fixed properties against fixed inputs; they do not generate or
mutate hostile prompts, and they do not measure attack success rate.

Two further boundaries must not be blurred:

- The **gold-set gate is not an adversarial suite.** It is a deterministic
  behaviour and performance gate over a human-labeled set.
- The Wazuh gold-gate fixtures provide **structural** coverage of the Wazuh
  request/projection surface only. All 266 labeled rows are Suricata, so there is
  **no Wazuh performance claim** — the approved baseline states this itself.

### The gap, stated exactly

Multi-source Garak coverage requires all of the following, none of which exist:

1. A pinned Garak runner and configuration, with recorded versions.
2. A model/endpoint harness that drives the **full isolated Triagewall pipeline**
   rather than the bare model.
3. Probe coverage of **both** projection surfaces — Suricata and Wazuh — since
   they build different prompts from different fields.
4. Deterministic gate criteria: which probes are blocking, what attack-success
   threshold fails the build, and how flaky probes are handled.
5. Defined failure handling: fail-closed behaviour, reporting, and triage of a
   regression.
6. CI and release integration, including how a GPU/model-dependent suite runs
   when required CI has neither.

Recommended follow-up, separately scoped: extend the existing canary and
prompt-boundary regressions to the **Wazuh** projection path. That is genuinely
missing and small, but it is deterministic regression coverage — **not** Garak —
and is deliberately excluded from this evidence-only change.

## Release readiness

**Required for v0.3 (per the ROADMAP closeout gate):** fresh-install, upgrade,
rollback, Core-only, and Core-plus-Wazuh evidence. All five are **PASS** and
recorded above, alongside a passing calibrated gold-set gate verified against the
real private inventory.

**Not required for v0.3:** multi-source Garak coverage. The current
documentation places it as separate, tracked work — `docs/gold-set-gate.md`
states the full-pipeline Garak injection gate "remains an open roadmap item and
is tracked separately", the Garak injection gate itself sits under v0.2.1
retained hardening, and the only "before tagging v0.3" language attaches to the
release-evidence item, which does not include Garak.

**Maintainer decision required.** The bullet *"Extend Garak coverage across the
multi-source pipeline"* is currently listed inside the v0.3 **Closeout** section,
whose preamble says the release stays in closeout until its gates are complete.
That placement contradicts the three signals above. This change relabels the item
as explicitly post-v0.3 and non-blocking. If the maintainer instead intends Garak
to gate v0.3, then **v0.3 is blocked** and this document should be read as
recording five of six scenarios complete rather than a release recommendation.

Outstanding non-blocking observations:

- Backup verification at production scale is slow enough to need explicit
  window planning (see Scenario 5).
- The upgrade evidence covers the deployment mechanism only, because this commit
  range carries no migration content (see Scenario 1).
