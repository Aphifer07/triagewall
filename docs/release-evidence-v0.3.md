# v0.3 release evidence

This records the release-evidence checks required by the ROADMAP closeout item
*"Record supported fresh-install, upgrade, rollback, Core-only, and
Core-plus-Wazuh checks before tagging v0.3."*

Everything here is sanitized aggregate evidence: commits, timestamps, exit
codes, counts, and hashes. It contains no secrets, alert content, asset
inventory contents, addresses, or host identifiers.

**Commit under test:** `9b95bf007440ab2297d0dae272c57a9d6f02e4ba`
**Previous deployed commit:** `89e24fb048517bafda6cce8c362b88773fc22842`
**Environment:** single maintainer host, Docker Compose, Core + optional Wazuh
profile. Live project runs Core+Wazuh; isolated checks run under a separate
Compose project, port, and data directory.
**Evidence collected:** 2026-08-08T20:20Z – 2026-08-09T01:57Z

## Summary

| # | Scenario | Status |
| --- | --- | --- |
| 1 | Upgrade deployment | **PASS** — released `v0.2` → v0.3 candidate |
| 2 | Core-only operation | **PASS** (functional) |
| 3 | Core + Wazuh operation | **PASS** |
| 4 | Fresh installation | **PASS** |
| 5 | Rollback | **PASS** — target is released `v0.2`; backup-restore is the authoritative path |
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

## Scenario 1 — Upgrade from the supported prior release (PASS)

**Primary evidence: released `v0.2` → v0.3 candidate**, across the real release
boundary, with a v0.2-origin database and v0.2-compatible configuration.

| Field | Value |
| --- | --- |
| From | annotated tag `v0.2`, peeled `2ec506c9689b66de52141720ecec9f56131f55b0` |
| To | `9b95bf007440ab2297d0dae272c57a9d6f02e4ba` |
| Setup | Isolated Compose project, dedicated port, per-phase data and EVE dirs, generated test config |
| Start / End | 2026-08-09T03:44:55Z / 03:48:42Z |
| Migration | `migrate` **Exited (0)**, "completed in **0.7s**" |
| Services | `migrate` 0, `ingest` running (**0 restarts**), `dashboard`, `wazuh-ingest` up |
| Health | `/api/v1/health` **200 `ok`**, `/api/health` **200** |

**v0.2 starting state** (built and run from the authentic tag; v0.2 created the
database itself from `schema.sql`):

- schema before upgrade: tables `sqlite_sequence`, `triage_events` only;
  `triage_events` = **25 columns**
- one seeded alert via a globally prefiltered SID → 1 row,
  `verdict=false_positive`, `model_used=prefilter` (**no model call**)
- v0.2's own contract verified: `GET /api/health` → **200
  `{"last_alert_age_seconds":35,"status":"ok"}`** (no `Host` header; v0.2 has no
  TrustedHost middleware). v0.2's dashboard image built and served correctly
  despite its unpinned dependencies.

**Migration outcome — data preserved, schema advanced:**

| Check | Result |
| --- | --- |
| v0.2-origin row preserved | yes (1 `model_used=prefilter` row) |
| Row count | 1 → 3 (never decreased) |
| `triage_events` columns | 25 → **27**; `src_asset_snapshot_id`, `dest_asset_snapshot_id` present |
| New tables | `ingest_failures`, `asset_snapshots`, `sensor_event_context` present (+ SPC tables) |
| New indexes | `idx_triage_src_asset_snapshot`, `idx_triage_dest_asset_snapshot` present |
| `PRAGMA integrity_check` | `ok` |

**Post-upgrade function:** a second Suricata fixture advanced the checkpoint
302 → **604** (inode unchanged) and persisted; a qualifying Wazuh fixture
(`rule.level = 8`) produced `Wazuh batch scanned=1 triaged=1` and a row with
`sensor_event_context.source_type='wazuh'` (**one real model call**). Restart:
checkpoint unchanged at 604, rows still 3, **0 restarts, no duplicate ingestion**.

### Configuration migration required (names only)

| Change | Names |
| --- | --- |
| Added | `HOST_ASSET_INVENTORY`, `HOST_BACKUP_DIR`, `TRUSTED_HOSTS` |
| Added (Wazuh profile) | `WAZUH_LOGS_VOLUME`, `WAZUH_LOGS_GID`, `WAZUH_POSITION_PATH`, `WAZUH_SOURCE_ID`, `WAZUH_MIN_LEVEL`, `WAZUH_START_MODE`, `WAZUH_POLL_INTERVAL` |
| Topology | new one-shot `migrate` service; new `maintenance` profile |
| Default changed | `MODE` default `local` → empty |

No v0.3 variable is mandatory — all carry Compose defaults.

### Supplementary: maintainer-host redeployment (not the release boundary)

The earlier live `89e24fb… → 9b95bf00…` run is retained **only** as supplementary
evidence that the deployment/rebuild mechanism works on the maintainer host:
2026-08-08T21:41:52Z → 21:47:37Z, merge 0, compose up 0, `migrate` Exited (0),
both health endpoints 200, 0 restarts, untracked operator files preserved. That
range changes only documentation, gold-set evidence and its validation script, so
it is **not** a release-boundary upgrade and is not the Scenario 1 pass.

### Limitations

- Isolated environment, not the live deployment; sanitized public fixtures only.
- v0.2 starting topology is Core-only, because Wazuh support is introduced by v0.3.
- Wazuh input came from an isolated Docker volume selected through the shipped
  `WAZUH_LOGS_VOLUME` variable — a **test-harness deviation** from the live
  manager's volume. No Compose file was modified to achieve it.
- v0.2's dashboard dependencies are unpinned, so its image resolves to current
  FastAPI/uvicorn. It worked here; that is not a guarantee for future rebuilds.

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

### Source-specific Wazuh evidence (required — checkpoints alone are insufficient)

Checkpoint movement on its own does **not** show that any Wazuh alert was
triaged. `process_wazuh_record()` checkpoints every below-threshold event
without triaging it, and the health endpoint derives staleness from
`MAX(processed_at)` across **all** sources — so an active Suricata stream plus
nothing but filtered Wazuh records would produce advancing checkpoints and a
green status even if the Wazuh verdict path were broken.

A read-only aggregate query was therefore run against the live database, joining
`triage_events` to `sensor_event_context` on
`sensor_event_context.triage_event_id = triage_events.id` and filtering
`source_type = 'wazuh'`. Counts and timestamps only; no alert fields were
selected.

| Period (UTC) | Persisted Wazuh rows | First `processed_at` | Last `processed_at` |
| --- | --- | --- | --- |
| Observation window 21:52:37Z – 22:22:54Z | **3** | 2026-08-08T22:10:44.128847Z | 2026-08-08T22:20:34.509099Z |
| Full post-deploy 2026-08-08T21:41:52Z – 2026-08-09T01:57:25Z | **6** | 2026-08-08T22:10:44.128847Z | 2026-08-09T01:05:15.467981Z |

All six carry `verdict = false_positive` and `model_used` = the configured
production model — **not** `prefilter` — so these records were normalized,
admitted by the level threshold, sent through the model, and persisted with
`source_type = 'wazuh'` provenance.

The two signals prove different things and are both required:

- **Persisted source-specific rows** prove the Wazuh normalization, triage,
  verdict and persistence path executed end to end during the window.
- **Checkpoint movement** separately proves stream consumption and rotation
  continuity, including records the level threshold correctly filtered out and
  checkpointed without triage.

Lifetime Wazuh-attributed rows in this deployment: 436.

### Follow-up observation: Wazuh archive-day rollover

Wazuh names its daily `ossec-alerts-DD` archives by the manager's local calendar
day, so a day boundary is a checkpoint transition rather than a simple offset
advance.

The ingest container's timezone was checked directly during evidence collection
rather than inferred:

```
$ date '+%Z %z'      # inside the running wazuh-ingest container
UTC +0000
```

The container **reported UTC +0000**, so its archive day equals the UTC day for
this deployment. This is an observed value, not a deduction from an unset `TZ`.

| Observation (UTC) | Wazuh checkpoint |
| --- | --- |
| 2026-08-08T22:22:54Z (end of window above) | day `2026-08-08`, offset 2,562,034 |
| 2026-08-09T01:46:24Z | day `2026-08-09`, offset 202,991 |
| 2026-08-09T01:57:25Z | day `2026-08-09`, offset 223,204 |

The checkpoint followed the archive rotation onto the new day and continued
advancing within it (+20,213 bytes across the final ~11 minutes). Health stayed
200 `ok` and restart counts stayed at 0 throughout; no fail-closed rotation error
was raised.

**Precision about what was observed:** the rollover *result* was observed, not
the transition instant. The transition falls somewhere in the
22:22:54Z–01:46:24Z gap, which is consistent with the UTC day boundary at
2026-08-09T00:00:00Z given the container's reported timezone. This is
single-deployment evidence that the day-rotation path works in a UTC
deployment; it is **not** evidence for a non-UTC manager timezone, where the
boundary shifts and `TZ` must be set to match the Wazuh manager.

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
| Integrity | `integrity_check: "ok"`, exit 0; manifest `verified_at` 2026-08-08T22:19:23.467400Z |
| Readability | opens read-only as valid SQLite; 11,043,136 `triage_events` rows |

The recomputed file hash matches the manifest hash exactly.

### Rollback target: released `v0.2` (`2ec506c9…`)

Rollback is evidenced against the **supported prior release**, not a
runtime-equivalent development commit. Two paths were tested on **separate
database copies**, after immutable snapshots of both the pre-upgrade v0.2 state
and the pristine v0.3-migrated state were taken and verified read-only.

#### A. Direct downgrade — v0.2 on the v0.3-migrated database (**works**)

| Check | Result |
| --- | --- |
| v0.2 starts | yes — `ingest` + `dashboard` up, **0 restarts** |
| v0.2 health (`/api/health`) | **200 `{"status":"ok"}`** |
| Original v0.2 row readable | yes |
| v0.3-origin rows readable | yes — v0.2's legacy `/api/verdicts` returned all 3 rows, including the Wazuh-origin row |
| Schema/config incompatibility | none observed; v0.3's additions are additive |
| `PRAGMA integrity_check` | `ok` |

**v0.2 write test** (fixture #3 through the authentic v0.2 ingest path): the
insert **succeeded** — checkpoint 604 → **906**, rows 3 → **4**.
`sensor_event_context` stayed at 2, so the row v0.2 wrote has **no provenance
entry**: v0.2 cannot populate a table it does not know about. Two of four rows
therefore lack provenance (the v0.2 seed row and the v0.2-written row).

**Ambiguous legacy display, recorded not resolved:** v0.2 has no source concept,
so the Wazuh-origin alert is listed as an ordinary alert, indistinguishable from
a Suricata one. v0.2 is not required to understand Wazuh provenance; it ignored
the provenance table safely rather than failing.

#### B. Backup-restore rollback — the authoritative safe path (**PASS**)

Restored the exact pre-upgrade v0.2 set (database **+ checkpoint + matching
`eve.json`**) from its immutable snapshot and ran the released `v0.2` tag:

| Check | Result |
| --- | --- |
| Restored contents | 1 row; tables `sqlite_sequence`, `triage_events` only |
| Integrity | `ok` |
| v0.2 services | started, **0 restarts** |
| Data after start | still 1 row — **no duplication** |
| Health | 503 `stale`, well-formed (restored data ≈10.6 h old — correct behaviour) |

**Checkpoint recovery detail:** a restore necessarily produces a **new inode**
for `eve.json` (57805483 → 57805538). v0.2 adopted the new inode, kept
`offset=302`, and logged `Read 1 new lines, triaged 0 alerts` — it re-read the
file but `is_duplicate` suppressed the row. The protection here came from
duplicate detection, **not** from the checkpoint; with later events in the file
those would have been replayed.

#### Cross-version finding: restore changes file identity

v0.3's fail-closed rotation recovery treats that same inode change as
unprovable continuity and **refuses to continue**:

```
Suricata ingest stopped to prevent an alert gap: the eve.json checkpoint
points at inode 57805483 (offset 906) but no regular file with that inode
remains in /var/log/suricata
```

Reproduced twice (once on a restored upgrade copy, once on a restored return
copy): `migrate` exits 0, dashboard and `wazuh-ingest` run, but Suricata
`ingest` exits 1 and `restart: unless-stopped` restart-loops. **This is correct
by design** — v0.3 refuses to skip possibly-unread alerts — but it is
operationally significant: **restoring a database/checkpoint backup next to a
copied `eve.json` requires an operator decision before v0.3 Suricata ingest will
resume.** v0.2 is lenient where v0.3 fails closed. When file identity is
preserved (same-host code switch), v0.3 resumes with 0 restarts and no rewind.

#### C. Return to v0.3 after rollback

Run on a copy of the **write-tested** database (the one v0.2 had written to), so
the return path is evaluated with an older-release row present. The pristine
v0.3-migrated snapshot was retained untouched for comparison.

| Check | Result |
| --- | --- |
| Migration | `migrate` **Exited (0)** ("completed in 0.0s" — already migrated) |
| Services | all up; `ingest` **0 restarts** (file identity preserved) |
| Rows | **4 preserved**; checkpoint 906 unchanged — no rewind, no duplicate |
| Integrity | `ok` |
| Context-less row written by v0.2 | **not backfilled** by v0.3, and **not repaired by hand** |
| API | `/api/v1/verdicts` returned **all 4 rows**, including the 2 without provenance |
| Health | 503 `stale` — correct; the isolated stack has no live alert stream |

v0.3 therefore serves rows written by the older release without error and without
inventing provenance for them.

Demonstrated overall: a verified backup exists and is readable; the procedure is
recoverable; the **released prior version** starts against restored data; and
returning to the v0.3 candidate succeeds.

### Deviation: writer-stop overran and was converted mid-run

The backup was **intended** to run as a full freeze — writers stopped for the
copy *and* the integrity verification — so the retained artifact would be
produced without competing live I/O. That is not what happened, and the actual
sequence is recorded here in full:

| Event | Time (UTC) |
| --- | --- |
| Writers stopped (ingest, wazuh-ingest, dashboard) | 2026-08-08T20:22:04Z |
| Backup copy completed, exit 0, 0 backup restarts (~17 min) | 20:39:43Z |
| Integrity verification started, **writers still stopped** | 20:39:43Z |
| Writers restarted — **verification still running** | 21:15:12Z |
| Verification completed, exit 0, `integrity_check: "ok"` (shell-observed exit) | 22:19:41Z |

The two verification timestamps in this document measure different events and
are both correct:

- **22:19:23.467400Z** — the `verified_at` value **recorded by `verify-backup`
  inside the manifest** when it wrote the integrity result.
- **22:19:41Z** — the **shell-observed exit**, logged by the wrapper script
  immediately after the `docker compose run` invocation returned.

The ~18 s difference is the manifest write plus container exit and teardown.

**Total writer-stop: 53 m 08 s.** The copy finished after roughly 17 minutes;
verification then continued inside the freeze for a further ~35 minutes and was
still running when the freeze was ended deliberately to stop extending a live
monitoring outage. Verification completed later, with writers live.

This was therefore a **full-freeze attempt converted mid-run to split
verification** — it was *not* the planned minimal-freeze workflow, and it should
not be read as one. The estimate that preceded it (3–10 minutes) was wrong by
roughly an order of magnitude because it accounted for the copy only.

Consequences, stated plainly:

- Suricata and Wazuh ingest were stopped for the full 53 m 08 s, so triage of
  live alerts was delayed by that interval.
- No data was lost. `eve.json` grows in place and no rotation occurred during
  the window, so nothing aged out from under the checkpoint.
- On restart, ingest resumed from its durable checkpoint with **no rewind** and
  caught up: the Suricata offset advanced from 162,004,527 (pre-freeze) to
  167,080,750 shortly after restart and continued advancing thereafter.
- The resulting backup is valid and verified; the artifact hashes above were
  recomputed afterwards and match the manifest.

### Operational finding: verification cost at production scale

`verify-backup` on this 18.5 GB database took roughly **100 minutes** end to end
(SHA-256 pass ~7 minutes, `PRAGMA integrity_check` the remainder), versus ~17
minutes for the copy. A maintenance window sized for the copy alone will
overrun. Operators should either size the window for copy **plus** verification,
or deliberately follow the documented split workflow — restart writers after the
copy and verify with writers live — and record that choice up front rather than
discovering it mid-freeze.

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

**Not required for v0.3: Garak — explicit maintainer scope decision.**

Garak does not block v0.3. **Both** the initial full-pipeline Garak injection
gate and its multi-source extension are post-v0.3 work, and **v0.3 makes no
Garak or adversarial-probe claim of any kind.** Scenario 6 above stands as
`NOT IMPLEMENTED / NOT RUN`.

This is a deliberate scope decision recorded by the maintainer, not an
unresolved ambiguity and not an accidental waiver of a check that was attempted
and skipped. It resolves a genuine conflict in the previous documentation: the
full-pipeline Garak gate was listed under v0.2.1 as due "before releases", while
`docs/gold-set-gate.md` described it as separately tracked roadmap work and the
only "before tagging v0.3" language attached to the release-evidence item, which
does not mention Garak. Both Garak items now sit in a single post-v0.3 section
in the roadmap, and the v0.2.1 entry no longer asserts a v0.3 prerequisite.

Once implemented, the gate should run periodically **and before applicable
future releases** — especially any release changing the model, prompts, field
isolation, or source projections. The concrete implementation requirements are
retained in the roadmap.

Outstanding non-blocking observations:

- The backup writer-stop overran its estimate and was converted mid-run to split
  verification, stopping live ingest for 53 m 08 s. No data was lost and the
  checkpoint resumed without rewind, but the maintenance-window guidance needs
  to account for verification cost explicitly (see Scenario 5).
- **Restoring a backup changes `eve.json`'s file identity, and v0.3 fails closed
  on that.** Restore procedures should state explicitly that the Suricata
  checkpoint and the `eve.json` it refers to must be restored as a matching pair,
  or that an operator must record the gap before ingest will resume. v0.2 was
  lenient here; v0.3 is not (see Scenario 5, cross-version finding).
- Two of the four rows in the lifecycle database carry no source provenance
  (written by v0.2). v0.3 serves them correctly and does not backfill them.
