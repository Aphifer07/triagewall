# Triagewall Roadmap

Triagewall started as a way to make a homelab IDS usable again: reduce
thousands of Suricata alerts to the handful worth reviewing. The longer-term
goal is a local-first **homelab security awareness platform** that surfaces
what matters across sensors without requiring the operator to remember to
check several dashboards.

The product strategy remains consistent:

- **Integrate, do not reinvent.** Suricata, Wazuh, Zeek, Pi-hole, OpenVAS, and
  Garak provide detection, collection, scanning, and adversarial probes.
  Triagewall adds local reasoning, prioritization, correlation, and release
  evidence.
- **Keep operational triage independent.** Triagewall Core must remain useful
  without optional evaluation or awareness components.
- **Require human approval for behavior changes.** Automation may test and
  report a prompt, policy, model, or threshold change; it does not silently
  promote, roll back, or tune production behavior.

Release dates below are the existing targets, not commitments. Current status,
prerequisites, and evidence determine delivery order.

---

## Shipped

### v0.1 — May 2026

Initial public release.

- [x] Two-tier classification: tunable prefilter plus a local Ollama model
- [x] Live Suricata `eve.json` ingest with durable checkpoints
- [x] Dashboard with real-time verdicts, trends, health, and feedback
- [x] Demo mode and Docker Compose deployment
- [x] Configurable Ollama backend
- Posted to r/homelab and listed on
  [satta/awesome-suricata](https://github.com/satta/awesome-suricata).

### v0.2-alpha — May 22, 2026

- [x] Foundation-Sec-8B-Instruct as the production model
- [x] Evidence-driven system-prompt revision
- [x] Reproducible benchmark harness and labeled gold set
- Revising the prompt moved Foundation-Sec Q5_K_M from κ=0.210 to κ=0.687
  and from 0% to 83% true-positive recall on that set.

### v0.2 — May 25, 2026

Prompt-injection and operational hardening.

- [x] Per-process canary detection and strict response-schema validation
- [x] Fail-closed field isolation: only typed, allowlisted sensor metadata is
  trusted; unknown and free-text evidence is isolated by default
- [x] SQLite WAL mode, bounded automatic checkpointing, and busy timeouts
- [x] Mounted, validated prefilter configuration

---

## Current and planned

### Post-v0.2 hardening in the current tree

- [x] Durable quarantine for malformed and failed ingest records
- [x] Checkpoint advancement only after a durable process or intentional skip
- [x] Trusted-host validation and complete demo-mode redaction
- [x] Required regression CI, CodeQL, and Dependabot

### v0.2.1 — June 2026

Hardening work retained from the original roadmap.

- [ ] **Garak injection gate.** Exercise the full isolated Triagewall pipeline
  periodically and before releases. A regression is blocked and reported for
  human review.
- [ ] Improve the URL-injection verdict from a conservative `uncertain` result
  to an explicit `real` verdict with the injection attempt identified.
- [ ] Refresh the architecture diagram for Foundation-Sec, scoped prefiltering,
  multi-source isolation, asset context, and the Core/Lab boundary.

### v0.3 — July–August 2026

Multi-sensor Core is implemented and deployed in the maintainer environment.
The release remains in closeout until its operational and release gates are
complete.

#### Implemented

- [x] **Exact-IP asset inventory enrichment** with validated private mounts,
  trusted prompt context, immutable revisioned snapshots, and API redaction
- [x] **Scoped Suricata prefilter policy** using direction, CIDR, protocol,
  ports, and asset context
- [x] **Multi-source event and persistence contract** with transactional source
  provenance and duplicate protection
- [x] **Optional Wazuh integration** through a read-only local alert volume,
  level-based admission, source-aware isolation, durable checkpoints, and
  compressed-rotation recovery
- [x] **Source-aware dashboard and API** for Suricata and Wazuh verdicts
- [x] **Versioned authenticated API** with scoped keys, bounded pagination,
  runtime-validated response contracts, caching, metrics, and optional keyed IP
  pseudonymization
- [x] **Reliability closeout** for incomplete records, retryable model/database
  failures, UTC timestamps, atomic checkpoints, fail-closed Suricata rotation,
  bounded dashboard queries, startup indexes, explicit WAL policy, and locked
  dashboard dependencies

#### Closeout

- [x] **Retention policy and storage visibility.** Define a safe hot-data
  window, archive or prune workflow, operator controls, and database-size
  reporting. Do not apply an unbounded delete to a live database.
- [x] **Serialized migration phase.** Ensure one startup owner performs schema
  work before Suricata and optional Wazuh ingest begin, avoiding lock races on
  large databases.
- [ ] **Release evidence.** Record supported fresh-install, upgrade, rollback,
  Core-only, and Core-plus-Wazuh checks before tagging v0.3.
- [x] **Gold-set change-validation implementation.** Fingerprint production
  behavior deterministically, evaluate the real pipeline against human labels,
  validate evidence integrity, and compare both pipeline and model-only metrics.
- [ ] **Gold-set calibration.** Review a complete operator evaluation, approve
  thresholds in a separate change, and require the calibrated baseline for
  release evidence. The first complete v0.3 candidate has been recorded; until
  it is reviewed and approved, deterministic checks run but no performance
  threshold is enforced.
- [ ] Extend Garak coverage across the multi-source pipeline.

#### Operational usability and provenance

- [ ] **Bounded alert detail.** Show the complete stored evidence projection,
  sensor and agent provenance, asset snapshots, policy outcome, model identity,
  validation result, and related context without scanning unbounded history.
- [ ] **Investigation controls.** Add source, time, IP, subnet, and asset
  filters, then saved views and structured JSON/CSV export.
- [ ] **Portable event-bundle v1.** Define and validate a sanitized,
  integrity-protected contract that can reproduce a decision without direct
  access to the production database or sensor logs.
- [ ] **Bounded asynchronous LLM queue.** Decouple checkpointed intake from
  model latency only after overload, retry, ordering, and recovery semantics
  are explicit.

### Triagewall Core and Lab — accepted product direction

Triagewall will mature as one product family with two independently runnable
applications. See
[Core and Lab product boundary](docs/core-lab-product-boundary.md).

- [x] **Product boundary accepted.** Core remains the production-supported
  operational application. Lab is the replay, evaluation, and release-
  validation application.
- [x] **One professional finished product.** There will be one public
  repository, documentation site, issue tracker, and coordinated release
  experience after Lab graduates.
- [ ] **Complete Core provenance and event-bundle v1** before Lab development
  depends on the contract.
- [ ] **Add operator-confirmed sanitized export** from Core. Lab never mounts
  Core's database, sensor logs, inventory, or checkpoints.
- [ ] **Incubate Lab privately** while its interfaces, upload handling, and
  threat model are experimental. Unfinished Lab code does not ship to Core
  users.
- [ ] **Ship a standalone Lab interface** that can evaluate compatible bundles,
  bounded offline Suricata or Wazuh fixtures, and sanitized scenarios without
  running Core.
- [ ] **Prove all three installation modes:** Core only by default, Lab only,
  and an explicitly enabled combined suite.
- [ ] **Graduate Lab into this repository** only after hostile-input,
  separation, CI, upgrade, rollback, backup, removal, and user-documentation
  gates pass. Archive the private incubation repository after import.

### v0.4 — September–October 2026

The awareness layer turns disconnected sensor findings into a concise
explanation of what changed and what deserves attention.

- [ ] **Daily digest** of material events, changes, and trends
- [ ] **Coverage-gap detection** between known assets and enrolled sensors
- [ ] **Cross-sensor correlation** for related IPs, domains, agents, and time
  windows
- [ ] **Assisted prefilter suggestions** requiring explicit human approval
- [ ] **Constrained MITRE ATT&CK mapping** backed by controlled references
- [ ] Operator-controlled webhooks for selected high-confidence findings

### v0.5 — Late 2026

Vulnerability prioritization.

- [ ] Ingest Wazuh vulnerability findings and optionally OpenVAS results
- [ ] Explain CVEs, prioritize by asset exposure and criticality, and provide
  plain-language remediation
- Triagewall reasons on top of mature scanners; it does not become a
  vulnerability scanner.

### v1.0 — Early 2027

Package the proven Core pipeline, optional graduated Lab, and awareness layer
into a stable, explainable homelab security product with documented install,
upgrade, rollback, backup, retention, observability, and security guarantees.

---

## Backlog without commitment

- Theme and branding customization
- Additional mobile-responsive dashboard work
- Authenticated multi-user deployments
- Multi-tenant deployments

---

## Design principles

- **Local-first.** No cloud LLMs or product telemetry.
- **Integrate, do not reinvent.** Mature tools provide detection and ground
  truth.
- **License-compatible.** Planned integrations must remain compatible with
  AGPL-3.0.
- **The human stays in the loop.** Test automation removes toil but does not
  make unsupervised production decisions.
- **Fail closed across trust boundaries.** Unknown configuration, bundle
  versions, identity conflicts, and unsafe evidence must stop or remain
  untrusted rather than silently broaden access or suppress detection.
- **Experimental work does not ship as production.** Lab remains privately
  incubated until its graduation gates pass.

---

## Out of scope

- **Auto-blocking or active response.** Use Wazuh Active Response or firewall
  policy. Triagewall is decision support.
- **Cloud LLM integration.** It conflicts with the local-first telemetry
  boundary.
- **Endpoint-agent functionality.** Use Wazuh agents.
- **Building another SIEM or vulnerability scanner.** Triagewall reasons over
  existing sensors and scanners.
- **Unsupervised self-tuning or auto-rollback.** Regressions are blocked and
  reported; a human decides what changes production.
- **Background detection-rule updates.** Updates may be proposed but are never
  silently applied.
- **Lab access to live production state.** Lab does not mount or mutate Core
  data and cannot promote changes automatically.

---

## Contributing

Roadmap items are open to community contributions. Open an issue or Discussion
before starting significant work, and see [CONTRIBUTING.md](CONTRIBUTING.md).
