# Core and Lab product boundary

Status: Accepted product direction  
Lab availability: Not shipped

## Decision

TriageWall will mature as one product family with two independently runnable
applications:

- **TriageWall Core** is the production-supported operational application. It
  ingests sensor alerts, applies trusted policy and context, obtains local-model
  verdicts, persists decision history, and serves the operator dashboard.
- **TriageWall Lab** is the future replay, evaluation, and release-validation
  application. It compares models, prompts, and policies; runs injection and
  gold-set regressions; and reports evidence for a human release decision.

Lab will be incubated in a private repository while its interfaces and threat
model are experimental. Core's public repository will continue to contain only
production-ready functionality. After Lab satisfies the graduation criteria
below, it will be imported into this repository as an optional application.
The incubation repository will then be archived.

The finished product will use one public repository, one documentation site,
one issue tracker, and one coordinated release experience. No permanent third
"suite" repository is planned.

## Supported installation modes

The graduated product must support:

1. **Core only**, which remains the default installation.
2. **Lab only**, without installing or starting Core services.
3. **Core and Lab**, enabled explicitly as a local suite.

Core must remain fully useful when Lab is absent or stopped. Lab must be able to
evaluate compatible event bundles, bounded offline Suricata or Wazuh fixtures,
and shipped sanitized scenarios without a live Core deployment.

## Runtime boundary

Core and Lab remain separate services even after sharing a repository:

- separate containers, dependency locks, databases, networks, temporary
  directories, and persistent volumes;
- no Lab mount of Core's database, sensor logs, private asset inventory, or
  checkpoints;
- no Docker socket;
- no Lab dependency in the default Core Compose path;
- no Lab ability to change Core prompts, policies, thresholds, models,
  checkpoints, or verdicts;
- no automatic promotion, rollback, tuning, or production action.

Lab binds to localhost by default. Authentication is required before LAN
exposure can be recommended.

## Integration contract

Core and Lab communicate through a sanitized, versioned event-bundle contract,
not through production SQLite tables or internal ingest APIs.

Core owns bundle creation because redaction and decision auditability are
production responsibilities. Event-bundle v1 is expected to carry enough
bounded information to reproduce and compare a decision:

- normalized sensor event and schema version;
- source, event, and agent provenance;
- explicitly untrusted evidence;
- trusted asset snapshots and inventory revisions;
- prefilter outcome and policy revision;
- prompt-template and evidence-projection revisions;
- model identity, immutable digest when available, and inference settings;
- original bounded model response, validation outcome, and final verdict;
- operator feedback only when explicitly included;
- redaction manifest and integrity hashes.

Bundles never contain the live process canary. Unknown bundle versions fail
closed. Uploaded alert content cannot select filesystem paths, network
destinations, models, or other Lab configuration.

The first combined workflow may use a sanitized bundle download from Core and
manual upload to Lab. Any later local handoff API must be authenticated,
bounded, auditable, and explicitly initiated by the operator.

## Graduation criteria

Lab can join the public repository only when:

- event-bundle v1 is stable and documented;
- its threat model and security review are complete;
- hostile uploads and evidence limits are enforced;
- Core-only, Lab-only, and combined installations pass regression and security
  CI;
- Lab cannot access or affect production state;
- install, upgrade, rollback, backup, removal, and version compatibility are
  tested;
- the interface clearly distinguishes experimental results from operational
  verdicts;
- user and operator documentation is complete.

## Non-goals

Lab is not a generic model-benchmarking platform, a second SIEM, a live sensor
ingest service, or an autonomous deployment controller. It evaluates the
TriageWall decision pipeline and produces evidence for a human decision.
