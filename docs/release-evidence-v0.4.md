# v0.4 release evidence

**Release status: APPROVED FOR PUBLICATION.** This document records the
operational evidence collected for the v0.4 candidate and accepted before the
release marking. The `v0.4` tag and GitHub release are bound to the final release
commit on `main`; the operational evidence remains bound to the candidate SHA
recorded below.

| Field | Value |
|---|---|
| Initial operational candidate SHA | `980615be0e2021dbf0b4b09cfff94491d4c82fa8` |
| **Final operational candidate SHA** | **`fd479ab0582499e2bfffe2fd1184fb761a080120`** |
| Previous deployed SHA | `436c259d17fcda0bb74ddd565bc884e70d2bfab4` |
| Target branch | `v0.4-stabilization` |
| Collection window (UTC) | 2026-08-18T17:52Z – 2026-08-19T12:30Z |
| Production observation window (UTC) | 2026-08-18T17:54:17Z – 2026-08-18T17:59:17Z (initial candidate) |
| Post-review observation window (UTC) | 2026-08-19T12:24:28Z – 2026-08-19T12:29:28Z (final candidate) |
| Environment | Single operator host, Docker Compose project `triage-agent` |
| Topology | Core plus Wazuh — `docker-compose.yml` + `docker-compose.wazuh.yml`, `wazuh` profile |
| Services | `dashboard`, `ingest` (Suricata), `wazuh-ingest`, plus one-shot `migrate` and `config-bootstrap` |
| Database scale at collection | 5,321,827 pages @ 4096 B (~21.8 GB) |

## Privacy statement

This document contains **no** secrets, API keys, plaintext credentials, IP
addresses, hostnames, alert bodies, search terms, asset-inventory contents, or
configuration documents. Search inputs were selected from real retained events
at runtime, held in memory, and compared by assertion only. The opaque search
window token was compared for equality in memory and never recorded. The asset
inventory appears only as its revision hash and asset count, both of which the
[gold-set methodology](gold-set-gate.md) defines as non-sensitive.

## Summary

| Area | Result |
|---|---|
| Target and tree-equivalence proof | PASS |
| CI on candidate SHA | PASS |
| Deployment to production host | PASS (no rollback) |
| Backup decision | No new backup required — justified below |
| Five-minute health and checkpoint observation | PASS (6/6 samples) |
| Source-specific persisted verdicts (Suricata and Wazuh) | PASS |
| Bounded log review | PASS (all counters zero) |
| Bounded-search behaviour | PASS |
| Investigation / navigation window stability | PASS |
| Configuration authorization | PASS |
| Isolated configuration-lifecycle matrix | PASS |
| Calibrated gold-set gate | PASS |
| Complete project gates | PASS |
| Post-review runtime fixes (redaction handoff, deprecated alias) | PASS |
| Readiness | Ready for the final release-marking commit |

## Deployment and tree-equivalence proof

PR #72 ("Refresh TriageWall presentation for v0.4") was squash-merged into
`v0.4-stabilization` at 2026-08-18T17:28:27Z. `origin/v0.4-stabilization`
resolves to exactly `980615be0e2021dbf0b4b09cfff94491d4c82fa8`, whose single
parent is `436c259d17fcda0bb74ddd565bc884e70d2bfab4` — the previously deployed
revision. The deployment was therefore a clean fast-forward with no intervening
commits.

CI on the candidate SHA: `Regression suite: completed/success`.

The incremental diff `436c259d…980615be…` is 25 files, +912/−584, confined to:

- **Documentation** — `README.md`, `ROADMAP.md`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `docs/operations.md` (new),
  `docs/api.md`, `docs/THREAT_MODEL.md`, `docs/wazuh-integration.md`,
  `docs/core-lab-product-boundary.md`, `docs/operator-configuration-foundation.md`,
  `docs/release-evidence-v0.3.md`, two experiment notes
- **Community files** — `.github/ISSUE_TEMPLATE/*`, `.github/PULL_REQUEST_TEMPLATE.md`,
  `.github/FUNDING.yml`
- **Presentation assets** — three new files under `docs/assets/`
- **Tests** — `tests/test_release_docs.py` (new)
- **Dashboard presentation** — `triagewall/dashboard/static/index.html`

The only file touched inside the application tree is `index.html`, and its
change is purely the capitalization of the product name (`Triagewall` →
`TriageWall`) in the `<title>`, the `meta description`, one `aria-label`, and
the brand text. Verified explicitly: **no** file matching schema, migration,
retention, ingestion, storage, `.sql`, Dockerfile, Compose, or environment
patterns is present in the diff, and no DDL/DML was added anywhere under
`triagewall/`.

### Deployment procedure

```
git fetch origin
git checkout --detach 980615be0e2021dbf0b4b09cfff94491d4c82fa8
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh build dashboard
docker compose … --profile wazuh up -d --no-deps --force-recreate dashboard
```

The image was built **before** any service disruption. Post-deployment
verification: host checkout is exactly `980615be…`; tracked worktree clean;
seven untracked operator files preserved; `.env` unchanged (compared by digest
before and after); credentials, backups, and mounts untouched.

**Dashboard recreate window: 18 seconds. Monitoring interruption: none** — the
Suricata and Wazuh consumers were not stopped or recreated.

### Declared deviation — dashboard-only deployment

A full `docker compose up -d` was **not** run, and `migrate` was not re-executed.
This is a deliberate, justified deviation: the verified diff contains no schema,
ingestion, or Compose change, so recreating the ingest consumers would have
produced an avoidable monitoring gap with no functional benefit. The consequence
is that `ingest` and `wazuh-ingest` continue to run images built at an earlier
revision; none of the code they load differs across `12a25d1 → 87fcfa2 →
436c259 → 980615be`, so they are functionally identical but not bit-identical to
a fresh build. Reconciling that is a scheduling decision, not a correctness one.

## Backup decision and rollback readiness

**No new database backup was taken, and none is required.** The evidence:

- The candidate diff changes no persistent-data behaviour. It touches no
  schema, migration, retention, ingestion-writer, storage, or database-format
  path, and introduces no DDL or DML.
- The single application-tree change is presentation text in `index.html`.
- The existing verified backup was re-confirmed present and intact by reading
  its manifest.

Taking another ~21.8 GB copy would have required roughly 36 minutes of
monitoring downtime (measured during the v0.4 foundation deployment) in exchange
for zero risk reduction.

| Rollback artifact | State |
|---|---|
| Prior code revision `436c259d…` | Present in the production host object store |
| Backup file | `triage-pre-v04-20260817T113637Z.db` |
| Size | 21,798,203,392 bytes (5,321,827 pages @ 4096 B) |
| SHA-256 prefix | `94cf8e7a` |
| `integrity_check` | `ok` |
| Verified at | 2026-08-17T14:12:35Z |
| Manifest / provenance | Both present alongside the backup |

Code rollback is a build-and-recreate of the dashboard alone and would not touch
the database, checkpoints, or the ingest consumers. **Rollback was not needed.**

## Five-minute health and checkpoint observation

Six samples over five minutes on the deployed candidate. Checkpoint values are
opaque monotonic positions; no addresses, hostnames, or alert content appear.

| Sample | UTC | Suricata checkpoint | Wazuh checkpoint | `/api/health` | Restarts d/i/w |
|---|---|---:|---:|---|---|
| 1 | 2026-08-18T17:54:17Z | 1787075651 | 1787075645 | 200 | 0/0/0 |
| 2 | 2026-08-18T17:55:17Z | 1787075707 | 1787075705 | 200 | 0/0/0 |
| 3 | 2026-08-18T17:56:17Z | 1787075762 | 1787075765 | 200 | 0/0/0 |
| 4 | 2026-08-18T17:57:17Z | 1787075823 | 1787075825 | 200 | 0/0/0 |
| 5 | 2026-08-18T17:58:17Z | 1787075888 | 1787075885 | 200 | 0/0/0 |
| 6 | 2026-08-18T17:59:17Z | 1787075944 | 1787075945 | 200 | 0/0/0 |

Both consumers advanced **monotonically on every sample**. Restart counts
remained zero for all three services throughout.

Endpoint checks on the deployed candidate: `/` 200, `/triage` 200,
`/configuration` 200, `/api/health` 200, `/metrics` 200.

### Source-specific persisted verdicts

Checkpoint advancement alone does not prove a sensor path is producing work.
Both ingesters deliberately advance their durable checkpoint for records that
never become a verdict: the Suricata reader returns a checkpoint-only result for
empty lines, undecodable JSON, non-object events, `event_type != "alert"`,
malformed alert objects, and duplicates, and the Wazuh reader counts `scanned`
records separately from triaged ones. `/api/health` is also a single global
aggregate (`MAX(processed_at)` over `triage_events`, with no source predicate),
so one healthy source can satisfy it while the other persists nothing.

The evidence below therefore counts **persisted verdicts per authoritative
source**, independently of checkpoints and aggregate health.

| Source | Persisted verdicts | First processed (UTC) | Latest processed (UTC) |
| --- | ---: | --- | --- |
| Suricata | 1,325,568 | 2026-08-18T17:54:10.580947Z | 2026-08-19T03:00:02.587064Z |
| Wazuh | 11 | 2026-08-18T19:09:19.526048Z | 2026-08-19T02:47:23.164576Z |

- **Query window start:** 2026-08-18T17:54:04Z — candidate `980615be…`
  deployment completion, so every counted row was persisted *after* the
  candidate was running.
- **Query window end:** 2026-08-19T03:00:53Z.
- The query was **read-only** (SQLite opened with `mode=ro`; a write probe in
  the same connection was rejected as read-only) and made no database writes.
- Rows were grouped by **authoritative source provenance** —
  `triage_events` inner-joined to `sensor_event_context` on
  `triage_event_id`, grouped by `source_type`. The inner join means legacy rows
  without provenance cannot contribute to either count, and source is never
  inferred from alert contents.
- Both counts are **newly persisted rows after candidate deployment**, and both
  are greater than zero.
- **Checkpoint advancement and aggregate health were not used as substitutes**
  for this proof; they are reported separately above.
- Only the aggregate count and the boundary timestamps were retrieved. **No**
  event identifiers, signatures, verdict text, confidence values, addresses,
  hostnames, raw alerts, or asset data were selected or recorded.

The exact query shape contains no sensitive values:

```sql
SELECT c.source_type,
       COUNT(*)            AS persisted_verdicts,
       MIN(e.processed_at) AS first_processed,
       MAX(e.processed_at) AS latest_processed
FROM triage_events AS e
JOIN sensor_event_context AS c ON c.triage_event_id = e.id
WHERE e.processed_at >= :window_start
GROUP BY c.source_type
ORDER BY c.source_type;
```

**Scope of this claim.** This proves that both production sensor paths
persisted verdicts while the candidate was deployed. It does **not** claim
continuous per-source availability outside the observed window, and it does not
claim both sources persisted verdicts within the five-minute sampling window
specifically — the first Wazuh verdict in this query window landed at
2026-08-18T19:09:19Z, after that sampling window had closed. Wazuh volume is
expected to be orders of magnitude lower than
Suricata volume on this deployment; the material assertion is that the count is
positive and attributable, not that the two rates are comparable.

During this collection window both consumers remained running with **zero
restarts**, both checkpoints continued advancing, `/api/health` remained **200**,
and bounded log review found **no** ingestion or database errors in either
consumer.

### Bounded log review

Bounded to the most recent 500 lines / 45 minutes per service.

| Service | Tracebacks | DB/lock errors | Reload failures | Search timeouts | Fatals |
|---|---:|---:|---:|---:|---:|
| `dashboard` | 0 | 0 | 0 | 0 | 0 |
| `ingest` | 0 | 0 | 0 | 0 | 0 |
| `wazuh-ingest` | 0 | 0 | 0 | 0 | 0 |

Dashboard 5xx responses in the bounded access log: **0**.

### Storage

| Volume | Size | Free | Used |
|---|---:|---:|---:|
| Root | 433 G | 77 G | 82% |
| Data | 1.8 T | 1.4 T | 22% |

## Bounded-search evidence

The bounded-search implementation was delivered by PR #71 and is byte-identical
in the candidate: the `436c259d…980615be…` diff touches no search code path.
The measurements below were therefore **collected against `436c259d…`** and
remain applicable because no later commit changed a search code path.
Provenance was verified by re-inspecting each diff rather than assumed. The
delta from `980615be…` to the final candidate `fd479ab…` does change dashboard
runtime code, but only the redaction handoff guard and the deprecated-alias
bounding recorded in "Post-review runtime fixes" below; the v1 bounded-search
implementation is untouched.

| Check | Status | Rows | Elapsed |
|---|---|---:|---:|
| Unfiltered queue | 200 | 200 | ~0.030 s |
| Signature search — only matching rows returned | 200 | 20 | 0.039 s |
| Exact-IP search — expected row present | 200 | 200 | 0.049 s |
| Historical asset-hostname search — expected row present | 200 | 200 | 0.092 s |
| **Absent term (3 s budget)** | **200** | **0** | **0.042 s** |

The absent-term result is the material one. Before PR #71, an absent term
traversed the full retained database and did not complete within 16 minutes of
observation. It now returns an empty result in ~0.042 s, comfortably inside the
three-second fail-safe.

### Disclosed bounded scope and window stability

| Assertion | Result |
|---|---|
| `search_scope` present with exactly `candidate_limit`, `candidates_in_scope`, `truncated` | PASS |
| Disclosed scope on a matching search | `candidate_limit=10000`, `candidates_in_scope=10000`, `truncated=true` |
| `search_window` present and opaque | PASS |
| Pagination preserves window identity across pages | PASS |
| Pagination preserves scope and returns no overlapping rows | PASS (20 distinct rows across two pages) |
| Whitespace-only `signature` treated as unfiltered — no scope, no window | PASS |

## Investigation and navigation evidence

| Assertion | Result | Elapsed |
|---|---|---:|
| Investigation with the queue's window token returns the same window identity | PASS | 0.062 s |
| Bounded neighbours confined to the active search | PASS | — |
| Direct searched investigation without a token captures a new window | PASS | 0.068 s |
| Reusing that returned token keeps the window stable | PASS | 0.059 s |

Re-confirmed on the deployed candidate `980615be…`: queue loads (200, 0.019 s),
searched queue returns disclosed scope and window (200, 0.052 s), and
investigation navigation reuses the same window identity (200, 0.065 s).

## Configuration authorization evidence

| Check | Result |
|---|---|
| `/api/v1/config` with the existing `config:write` key | 200 |
| `/api/v1/config` without a credential | 401 |
| Production configuration generation | Unchanged |
| Production active revisions | Unchanged (`prefilter_policy` active 1, `asset_inventory` active 1) |

No production configuration was drafted, validated, previewed, activated, or
rolled back. No key was created, rotated, or replaced. `.env` was not edited.

## Isolated configuration-lifecycle evidence

The v0.4 configuration lifecycle was proved using the project's **existing
automated integration matrix**, which is the authoritative supported mechanism.
Every test constructs its own temporary SQLite database and configuration state
in an isolated temp directory; none touches the production database, and no
manual production mutation was invented to satisfy this section.

This is both stronger and safer than mutating production: it exercises failure
and denial branches that cannot be produced safely against a live 21.8 GB
database (stale-parent activation, corrupt-candidate rollback, invalid reload,
demo mode, writes-disabled startup), it is deterministic and re-runnable in CI,
and it covers both a freshly created database and an upgraded prior-release
database in the same run.

**Targeted run:** `python -m unittest tests.test_config_api tests.test_config_runtime
tests.test_config_preview_activation tests.test_operator_config` →
**95 tests, OK.**

| Lifecycle requirement | Representative test(s) | Result |
|---|---|---|
| Draft + validate (both kinds) | `test_create_and_validate_normalized_draft_without_activation`; `test_asset_inventory_uses_the_same_immutable_validation_lifecycle` | PASS |
| Invalid draft rejected without replacing active | `test_invalid_draft_is_rejected_without_replacing_active` | PASS |
| Bounded preview (prefilter) | `test_prefilter_preview_is_bounded_delta_only_and_audited`; `test_prefilter_preview_stops_at_the_sample_byte_budget` | PASS |
| Bounded preview (asset inventory) | `test_asset_preview_hands_the_evaluator_no_alert_bodies`; `test_asset_preview_marks_a_truncated_suppression_analysis_incomplete` | PASS |
| Explicit activation | `test_activation_cuts_over_legacy_then_atomically_activates`; `test_activating_an_asset_inventory_without_any_preview_fails_closed` | PASS |
| Consumer convergence | `test_both_consumers_share_one_synchronized_startup_path`; `test_peer_commit_between_synchronization_and_start_converges`; `test_generation_reload_publishes_complete_database_bundle` | PASS |
| Explicit rollback | `test_rollback_reactivates_superseded_revision_with_new_generation`; `test_asset_rollback_requires_the_incomplete_preview_acknowledgement` | PASS |
| Generation locking | `test_stale_generation_conflicts_and_identical_draft_resumes`; `test_preview_requires_validated_candidate_and_current_generation` | PASS |
| Parent locking | `test_preview_refuses_a_candidate_whose_parent_is_no_longer_active`; `test_canonicalized_candidate_off_a_stale_parent_cannot_activate`; `test_resume_is_refused_for_a_revision_off_a_different_parent` | PASS |
| Last-known-good retained after invalid reload | `test_reload_failure_keeps_last_known_good_and_recovers` | PASS |
| Fresh database | `test_migration_creates_configuration_tables_and_indexes` | PASS |
| Upgraded prior-release database | `test_upgrade_discovers_shipped_default_without_replacing_legacy_bundle`; `test_migration_adds_the_size_column_to_an_existing_database` | PASS |

### Denial matrix

| Denied caller | Test | Result |
|---|---|---|
| No credential (anonymous) | `test_config_scope_is_api_key_only` (subtest `anonymous`) → 401 | PASS |
| Wrong scope (`read`) | `test_config_scope_is_api_key_only` (subtest `read`) → 401 | PASS |
| Wrong scope (`feedback:write`) | `test_config_scope_is_api_key_only` (subtest `feedback`) → 401 | PASS |
| Dashboard feedback cookie | `test_config_scope_is_api_key_only` (cookie case) → 401 | PASS |
| Demo mode, even with a `config:write` key | `test_demo_mode_denies_even_config_scoped_key` | PASS |
| Writes disabled | `test_writes_are_default_off_independently_of_read_access`; `test_enabled_writes_require_config_scoped_key`; `test_compose_and_example_keep_configuration_mutation_default_off` | PASS |
| Refused mutations still leave audit evidence | `test_refused_mutations_leave_attributable_audit_evidence` | PASS |

## Calibrated gold-set result

Run against the production asset inventory using the documented environment
(`ASSET_INVENTORY_PATH` set to the same private file Compose mounts through
`HOST_ASSET_INVENTORY`).

| Field | Value |
|---|---|
| Command class | `gold_gate.py verify --require-calibrated` |
| Exit status | `0` |
| Outcome | Deterministic checks passed; approved evidence current |
| Approved evidence fingerprint | `sha256:5275d437763f4326669d2f34ef6e67688d5f1c8497b9e0544263b933080deda2` |
| Live inventory revision | `sha256:3dd464829377322b7cbf70346bf403287c293f43075a7a9c5916ba1be01680c0` |
| Live inventory asset count | 2 |
| Matches approved baseline | Yes |

Inventory contents were never displayed. The revision hash and asset count are
the non-sensitive identity fields the gold-set methodology defines for this
purpose.

## CI and complete project gates

CI on `980615be…`: `Regression suite: completed/success`.

All gates required by `AGENTS.md`, run on the evidence branch:

| Gate | Result |
|---|---|
| `git diff --check` | PASS |
| `python -m unittest discover -s tests` | PASS — 545 tests, OK (16 skipped) |
| `node --test tests/test_configuration_editor.js tests/test_dashboard_polling.js` | PASS — 136 pass, 0 fail |
| `python scripts/gold_gate.py verify` | PASS |
| `PYTHONPATH=. python tests/test_spc.py` | PASS — all SPC regression tests |
| `python -m compileall -q triagewall tests scripts` | PASS |
| YAML validation (workflows, issue templates, both Compose files) | PASS — 9 files, 0 failures |
| HTML well-formedness (`dashboard/static/*.html`) | PASS |
| Compose config validation (both files, `wazuh` profile) | PASS — resolved on the production host |

## Deviations and limitations

1. **Dashboard-only deployment** (declared above). The ingest consumers run
   images built at an earlier revision; the code they load is identical.
2. **Reused search measurements.** The bounded-search timings were collected
   against `436c259d…`, not re-timed on `980615be…`. Justified because the
   intervening diff touches no search code; provenance was verified by
   re-inspecting the diff, and a functional re-confirmation (queue, searched
   queue with disclosed scope and window, investigation navigation) was run on
   the deployed candidate.
3. **Compose validation ran on the production host**, not in the local gate
   environment, because Docker is not installed locally.
4. **Configuration lifecycle proved by the isolated automated matrix**, not by
   mutating live production configuration. This is intentional; see the
   rationale above.
5. **`/metrics` cold-path latency.** The endpoint costs roughly 0.36 s on a cold
   cache and ~2 ms warm, occasionally longer under heavy concurrent disk I/O.
   Pre-existing, unrelated to this candidate, and it returns 200 throughout.
6. **Single-host evidence.** All production observations come from one operator
   deployment with one Suricata source and one Wazuh source. Results are not a
   guarantee for other networks, hardware, or models.
7. **Window pagination detail.** Supplying a cursor without an explicit
   `search_window` returned the same window rather than issuing a new one,
   i.e. window identity appears recoverable from the cursor. This is stable and
   non-breaking, and is recorded as an observation for maintainer confirmation
   rather than a defect.

## Post-review runtime fixes (final operational candidate)

Two review findings on PR #75 were validated and fixed after the initial
operational candidate `980615be…`. Because these are **runtime** changes, the
earlier claim that every post-candidate change was documentation-only does not
hold, and this section records the re-verification. The final operational
candidate is `fd479ab0582499e2bfffe2fd1184fb761a080120`.

### What changed, and why

| File | Change | Why |
|---|---|---|
| `triagewall/dashboard/static/dashboard.js` | Recognize the documented redacted-address format; suppress source/destination asset actions for a pseudonym; refuse the handoff in `openConfigurationFromAlert` | Under IP redaction the API returns a pseudonym and withholds asset context, so an asset candidate seeded from one cannot validate |
| `triagewall/dashboard/static/configuration.js` | Refuse a redacted asset handoff at the exported `seedFromAlert`, before any editor state changes | That entry point is reachable without the dashboard guard; a hidden button is only an affordance |
| `triagewall/dashboard/api/legacy.py` | Deprecated `GET /api/verdicts` gains the v1 input cap and bounded search work | Reachable under default unauthenticated reads; an absent or rare term previously scanned the complete retained table |
| `docs/api.md` | Clarify the alias contract | The frozen shape claim alone would have been misleading once an over-long term returns 422 |

No schema, migration, ingestion-writer, retention, storage, Compose, or
environment file is touched, and no DDL or DML is added anywhere under
`triagewall/`. The change is dashboard-only and read-only.

### Backup decision

**No new backup was taken.** The inspection above confirms the delta cannot
alter persistent data behaviour, so the existing verified backup
`triage-pre-v04-20260817T113637Z.db` (SHA-256 prefix `94cf8e7a`,
`integrity_check: ok`) and prior code revision remain a sufficient rollback
point. A further ~21.8 GB copy would have cost roughly 36 minutes of monitoring
downtime for zero risk reduction.

### Focused deployment

Built before disruption, then only the dashboard was recreated; the Suricata and
Wazuh consumers were never stopped. `.env`, credentials, backups, operator
files, and the separate legacy stack were untouched and `.env` was confirmed
unchanged by digest.

- Deployment window: 2026-08-19T12:20:49Z – 2026-08-19T12:22:40Z
- **Dashboard downtime: 19 seconds. Monitoring interruption: none.**
- Host checkout is exactly `fd479ab…`; tracked worktree clean; seven untracked
  operator files preserved.

### Post-review five-minute observation

| Sample | UTC | Suricata checkpoint | Wazuh checkpoint | `/api/health` | Restarts d/i/w |
|---|---|---:|---:|---|---|
| 1 | 2026-08-19T12:24:28Z | 1787142243 | 1787142245 | 200 | 0/0/0 |
| 2 | 2026-08-19T12:25:28Z | 1787142304 | 1787142305 | 200 | 0/0/0 |
| 3 | 2026-08-19T12:26:28Z | 1787142363 | 1787142365 | 200 | 0/0/0 |
| 4 | 2026-08-19T12:27:28Z | 1787142423 | 1787142425 | 200 | 0/0/0 |
| 5 | 2026-08-19T12:28:28Z | 1787142484 | 1787142485 | 200 | 0/0/0 |
| 6 | 2026-08-19T12:29:28Z | 1787142544 | 1787142545 | 200 | 0/0/0 |

Both consumers advanced monotonically on every sample; restart counts stayed
zero. Endpoints: `/` 200, `/triage` 200, `/configuration` 200, `/api/health`
200, `/metrics` 200.

Bounded log review (500 lines / 40 minutes per service) across dashboard,
Suricata ingest, and Wazuh ingest: **0** tracebacks, **0** database or lock
errors, **0** reload failures, **0** search timeouts, **0** fatals, and **0**
dashboard 5xx responses. Storage: root 85 G free (80% used), data volume 1.4 T
free (23%).

### Deprecated-alias bounded search, in production

Exercised without an API key, matching production's configured read policy. The
probe term was an opaque token generated in memory, never an address or
hostname, and was never printed or written.

| Probe | Result |
|---|---|
| Absent term | **200**, **0 rows**, **2.292 s** — inside the three-second budget |
| Response shape | `{mode, stats, verdicts}` — frozen legacy contract intact |
| Over-200-character term | **422** in 0.002 s |
| Unsearched legacy read | **200** in 0.003 s, shape intact |

No returned rows, addresses, hostnames, identifiers, or terms were recorded. The
2.292 s figure is the bounded worst case on the production-scale database; before
this fix the same class of query was unbounded.

### Redaction handoff evidence

Production IP redaction was **not** enabled and no production environment
variable was changed for evidence; the dashboard still runs with
`TRIAGEWALL_API_REDACT_IPS=false`. The authoritative proof is the automated
redaction matrix, which exercises the pseudonym paths deterministically:

| Invariant | Coverage |
|---|---|
| Redacted source pseudonym hides the source asset action | `tests/test_dashboard_polling.js` |
| Redacted destination pseudonym hides the destination asset action | `tests/test_dashboard_polling.js` |
| Real address with no asset context still offers the action | `tests/test_dashboard_polling.js` |
| Prefilter handoff survives redaction | `tests/test_dashboard_polling.js`, `tests/test_configuration_editor.js` |
| Direct handoff on a redacted address seeds nothing, navigates nowhere, replaces no form, changes no editor state (both sides) | `tests/test_dashboard_polling.js`, `tests/test_configuration_editor.js` |
| Only the complete documented pseudonym format counts as redacted | both suites |

In production only a normal dashboard and `/configuration` smoke check was
performed, and no production configuration was mutated.

### Relationship to the evidence commit

This document is committed after `fd479ab…`. The evidence commit differs from
the final operational runtime candidate only by this evidence document; it
changes no application behaviour.

## Readiness recommendation

The v0.4 candidate `980615be0e2021dbf0b4b09cfff94491d4c82fa8` is deployed and
healthy in production, every gate and CI check passes, the bounded-search defect
found during the PR #70 milestone is fixed and verified in production, the
configuration lifecycle is proved end to end in isolation for both configuration
kinds including the full denial matrix, and the calibrated gold-set gate matches
its approved baseline.

**Release decision: the evidence supports v0.4 publication.** Tagging and
publishing occur only after the reviewed release marking is integrated into
`main`, so the release tag identifies the final public tree rather than the
stabilization or operational-candidate commit.
