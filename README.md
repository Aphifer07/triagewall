# Triagewall

**Local-first AI triage for Suricata and Wazuh alerts.** Reduce security-alert
noise without sending telemetry to a cloud model. Runs entirely on your
hardware. No telemetry. AGPL-3.0.

> **TL;DR** — Point Triagewall at Suricata `eve.json` and, optionally, a
> same-host Wazuh `alerts.json` stream. It applies validated deterministic
> filtering where appropriate, sends the remaining evidence through an
> isolated local-LLM pipeline, and shows source-aware verdicts in one dashboard.
> Core remains local, read-only with respect to sensors, and independently
> useful without optional components.

![Triagewall dashboard](https://raw.githubusercontent.com/aaronphifer/triagewall-site/main/dashboard.png)

---

## Why this exists

If you run Suricata in a homelab, you know the problem. The ET Open ruleset generates thousands of alerts a day, the vast majority of which are noise — TLS SNI matches, DNS lookups for normal CDNs, your own scanning, your kid's gaming traffic. The signal is in there, but you're not going to find it by reading every alert at 11 PM.

Commercial XDR products solve this with cloud-based ML and a $500/month bill. The open-source SIEM stack (Wazuh, TheHive, Cortex) gives you the data but no triage layer. Triagewall is the missing layer, designed for people who already self-host their security stack and want to keep it that way.

## What it does

- **Reads Suricata `eve.json`** in real time, tracks position across restarts and log rotations
- **Optionally reads Wazuh `alerts.json`** from a local read-only Docker volume, admitting configurable security-relevant levels through the same private LLM pipeline
- **Pre-filters known-benign rules** with a tunable JSON config (the "I already know what STUN traffic is, stop telling me" filter) — microsecond lookups, zero LLM cost
- **Triages residual alerts** with a local LLM via Ollama (default: `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M` as of v0.2-alpha, see [Performance & accuracy](#performance--accuracy) for VRAM-based model selection)
- **Preserves sensor provenance** so Suricata and Wazuh verdicts retain their source, event identity, and Wazuh agent context
- **Enriches exact IP matches** with a private, validated asset inventory while preserving the context revision used for each verdict
- **Records your feedback** — every verdict has Agree / Mark Different buttons in the dashboard, building a labeled dataset and a measurable agreement rate
- **Surfaces what matters** in a clean web dashboard with hourly traffic trends

### Current status: v0.3 pending release

The v0.3 implementation now provides one source-aware triage pipeline for
Suricata network alerts and actionable Wazuh alerts. The multi-source
foundation, Wazuh adapter, least-privilege optional Compose integration, exact-IP
asset context, scoped prefilter policy, durable checkpoints, migration
hardening, fail-closed Suricata rotation recovery, bounded retention, a
versioned authenticated API, deterministic gold-set change validation, runtime
dependency locks, regression CI, and CodeQL coverage are implemented.

v0.3 is not yet tagged. The current multi-sensor build has been exercised
against live Suricata and Wazuh streams; bounded backup-first retention and a
single-owner startup migration phase are implemented. The v0.3 real-model
gold-set baseline is approved from a complete 266-alert operator evaluation,
with regression thresholds enforced for both end-to-end and model-only metrics,
and the calibrated gate passes against the maintainer host's real asset
inventory.

All five required release-evidence scenarios — fresh install, upgrade,
rollback, Core-only, and Core-plus-Wazuh — are recorded in
[docs/release-evidence-v0.3.md](docs/release-evidence-v0.3.md), with upgrade and
rollback exercised across the real release boundary from the released `v0.2` tag
and back. Garak
adversarial probing remains **unimplemented** and is explicitly post-v0.3 work;
v0.3 makes no Garak or adversarial-probe claim. What remains before tagging is
ordinary review, merge, and release mechanics rather than additional runtime
scope. The existing Core installation remains the supported operational product
throughout.

### Foundation from v0.2

- **Production model swap** from Mistral 7B to Cisco's [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct), a security-domain-tuned model. Validated against a human-labeled gold set: revising the prompt moved Foundation-Sec Q5_K_M from Cohen's κ=0.210 to κ=0.687 and from 0% to 83% true-positive recall, beating Mistral 7B (κ=0.480) on the same gold set — the model's security specialization was latent and the prompt had to elicit it.
- **Revised system prompt** with explicit category priors (ET DROP, ET EXPLOIT_KIT, ET MALWARE), threat-intel context (Spamhaus, geographic priors), and operational context (smart TV ad-tech, cloud IP ranges). Required to unlock Foundation-Sec's specialized training — see [the experiment writeup](docs/experiments/2026-05-22-prompt-revision.md) for the full methodology.
- **Prompt injection hardening (Phase 1)** — canary token detection and strict response schema validation.
- **Operational improvements** — SQLite WAL mode (prevents dashboard lock contention), prefilter as mounted config volume (no rebuild required for SID changes), benchmark harness for reproducible model evaluation.

See [docs/experiments/](docs/experiments/) for full evaluation methodology and results.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for trust boundaries, what's defended, and known limitations.

---

## Prerequisites

- **Docker Engine 20.10+** ([install guide](https://docs.docker.com/engine/install/))
- **Docker Compose v2** (the `docker compose` plugin, not the deprecated `docker-compose` v1). On Ubuntu/Debian/Pop!_OS:
```bash
  sudo apt-get install docker-compose-plugin
```
  This requires Docker's official apt repo. If the package isn't found, follow the [Docker install guide](https://docs.docker.com/engine/install/ubuntu/) to add the repo first.

  > **Note:** The older `docker-compose` (v1.x) bundled with some Linux distros crashes with `KeyError: 'ContainerConfig'` against modern Docker Engine. If you hit that error, you're on v1 — install the v2 plugin instead.

- **Ollama** running locally or on another reachable network host ([install](https://ollama.com/download))
- **At least one Ollama model:** `ollama pull hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M` (production default, ~5.7 GB) or `ollama pull mistral:7b` (lighter, ~4 GB, lower accuracy)
- **A GPU with 8+ GB VRAM** for the LLM (the prefilter works without one, but the residual long tail won't classify in reasonable time on CPU)

## Quick start

```bash
git clone https://github.com/aaronphifer/triagewall.git
cd triagewall
cp .env.example .env

# Try it without real data first:
# Set DEMO_MODE=true in .env, then:
docker compose up -d        # Docker Compose v2+

# Open http://localhost:8084 to see the dashboard with sample alerts.

# For production: edit .env to set:
#   - DEMO_MODE=false
#   - HOST_DATA_DIR=./data (or wherever you want runtime files stored)
#   - HOST_EVE_DIR=/var/log/suricata (directory containing your eve.json)
#   - OLLAMA_HOST=http://your-ollama-instance:11434
#   - OLLAMA_MODEL=hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M
#   - INTERNAL_SUBNETS=10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24
#     (your internal network ranges, used for traffic-direction context in the LLM prompt)
#   - HOST_ASSET_INVENTORY=./data/assets.json
#     (optional private exact-IP inventory; the tracked default is valid and empty)
# Then `docker compose up -d` again.
```

You'll need [Ollama](https://ollama.com) running somewhere reachable on your network, with at least one compatible model pulled. The Ollama instance can be on the same host or a separate GPU node.

### Serialized database startup

Docker Compose runs a one-shot `migrate` service before dashboard, Suricata
ingest, or optional Wazuh ingest can start. It is the only startup process that
creates tables, adds columns, or builds indexes. The consumers perform a
read-only schema check and fail closed if the migration did not complete.
Docker Compose v2 is required because startup uses
`service_completed_successfully` dependency conditions.

On a fresh installation, `docker compose up -d` creates the database through
this migration phase automatically. On an existing large database, index work
may take several minutes; do not interrupt the migration just because its log
output is quiet. Inspect it with:

```bash
docker compose ps -a migrate
docker compose logs migrate
```

A migration failure blocks the dependent services instead of allowing them to
race or run against a partial schema. Correct the reported storage, permission,
or database problem, then run `docker compose up -d` again. Direct, non-Compose
ingest use must run `python3 triagewall/migrate.py` once before starting either
ingest process.

The asset inventory follows the versioned contract in
[`triagewall/config/assets.example.json`](triagewall/config/assets.example.json).
Keep populated copies outside Git and mount one with `HOST_ASSET_INVENTORY`.
Inventory changes are validated and loaded when the ingest container starts;
missing, malformed, oversized, or ambiguous inventories fail startup.
`HOST_ASSET_INVENTORY` is the Compose mount source. Direct Python operator
tools do not read it automatically; set `ASSET_INVENTORY_PATH` to that same
host file before running gold-set release verification or evaluation.
Each asset is limited to 64 IP addresses and 64 exposed ports, and validation
keeps the complete two-sided asset context within 2 KiB so trusted context
cannot exhaust the model prompt budget.

### Optional Wazuh connection

The opt-in `docker-compose.wazuh.yml` file provides a `wazuh` profile that tails
a same-host Wazuh manager's local `alerts.json` without API credentials or
Docker-socket access. The base Compose project has no Wazuh volume dependency.
The recommended level-8 admission gate keeps routine Wazuh events in Wazuh
while sending security-relevant alerts through Triagewall. Source, event, and
agent identity are persisted with each verdict, and the checkpoint can recover
through Wazuh's compressed daily archives.

See [Wazuh alerts.json integration](docs/wazuh-integration.md) for Docker
requirements, private `.env` settings, startup verification, archive-gap
recovery, and rollback.

## Performance & accuracy

Triagewall has been running on a homelab production network for multi-day continuous operation against live OPNsense Suricata data. Measured numbers:

| Metric | Value |
|---|---|
| Source rate (typical) | 6,000–13,000 alerts/hour |
| Prefilter ratio | 99%+ (after tuning ~30 SIDs) |
| LLM latency | 7–10 seconds per call (Foundation-Sec-8B Q5_K_M on RTX 4060) |
| End-to-end lag | under 2 minutes at steady state with healthy prefilter |
| Daemon RAM footprint (excluding Ollama) | ~17 MB |
| Database growth | Workload-dependent; one long-running deployment reached ~14.7 GB. Bounded, backup-first retention is available through the maintenance profile. |
| Classifier accuracy (v0.2, 265-alert gold set) | Cohen's κ = 0.687, true-positive recall = 83% |

Throughput scales primarily with prefilter ratio. The two-tier design means prefiltered alerts are processed in microseconds; only LLM-classified alerts (typically 0.3–3% after tuning) are bound by Ollama latency.

### Retention and storage visibility

The dashboard header reports the SQLite database, WAL, and shared-memory files
currently allocated on disk, plus space inside the database that SQLite can
reuse. Reusable space is not the same as filesystem free space: with the
default `auto_vacuum=none` policy, deleted pages are reused by future writes but
the main database file does not shrink automatically.

Use a controlled maintenance cycle. SQLite online backup can fail to converge
under sustained ingest writes, so the production workflow briefly stops all
SQLite writers for the copy. It restarts monitoring before the longer integrity
check, then uses short, automatically recovered deletion pauses.

1. Inspect allocation and history bounds (read-only):

```bash
docker compose --profile maintenance run --rm maintenance status
```

With optional Wazuh enabled, include both Compose files and profiles so Compose
does not treat Wazuh services as orphans:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.wazuh.yml \
  --profile wazuh \
  --profile maintenance \
  run --rm maintenance status
```

2. Dry-preview a 60-day hot-data window (default; no writes):

```bash
docker compose --profile maintenance run --rm maintenance \
  prune --keep-days 60
```

### Automated production cycle

`scripts/retention-cycle.sh` is the recommended production entry point. It:

- acquires a host lock so two cycles cannot overlap;
- captures one fixed UTC cutoff for safe resume;
- stops dashboard, Suricata ingest, and optional Wazuh ingest;
- creates a bounded, exclusive mode-0600 backup copy and provenance record;
- restores and health-checks monitoring before verifying that backup;
- writes a mode-0600 manifest bound to the backup and source database;
- bounds planning, authorization, deletion, and reporting to 15 minutes per pause;
- restores and health-checks services after every pause and on failure;
- schedules another bounded pause when orphan cleanup was deferred;
- waits 30 minutes with monitoring live before another pause if needed; and
- retains the backup, manifest, and JSON results for operator review.

Recovery requires every selected Compose service to be running and the
dashboard health endpoint to be reachable. HTTP 503 with Triagewall's normal
`stale` status is accepted because a quiet sensor may legitimately have no
recent verdict after a long pause; connection failures and other status codes
still fail the cycle. Each request has separate connection and total-transfer
timeouts so a stalled endpoint cannot block the unattended recovery loop.
Transient Compose startup failures are retried for the same bounded recovery
window. Monitoring is marked restored only after every selected service and
the dashboard database health check succeed; exhausted recovery exits with
status 75 and a critical operator message. Compose start, status, and stop
commands also have host-side deadlines so a stalled Docker client cannot hold
the recovery path indefinitely.

Run it as an SSH-independent transient systemd service. The backup directory
must already exist on the intended backup filesystem, be owned by the account
running the cycle, and not be group- or world-writable:

```bash
sudo systemd-run \
  --unit=triagewall-retention-cycle \
  --collect \
  --property=Type=exec \
  --property=WorkingDirectory=/opt/triagewall \
  /opt/triagewall/scripts/retention-cycle.sh \
  --backup-dir /mnt/triagewall-backups \
  --keep-days 60 \
  --batch-size 500 \
  --wazuh
```

Replace both example paths with the actual deployment and backup locations.
Omit `--wazuh` when the optional connector is disabled. A Wi-Fi or SSH
disconnect does not stop the systemd service.

The host runner defaults to 500 rows per delete transaction. Operators may set
`--batch-size` from 1 through 10,000 after benchmarking a disposable database
copy on the deployment storage. Larger batches can reduce repeated query work,
but increase each transaction's WAL use and rollback unit; do not copy a tuning
value from another installation without measuring it locally.

Large or sustained installations should place `HOST_DATA_DIR` on SSD-class
storage. Bounded deletion remains safe on rotational disks, but indexed delete
work can be substantially slower even when the SQLite file is not fragmented.
Keep verified backups on a different failure domain from the active database.

```bash
systemctl status triagewall-retention-cycle
journalctl -fu triagewall-retention-cycle
```

The exit trap attempts to restart every selected service after an ordinary
error, signal, or failed maintenance command. Container restart policies cover
a host reboot. The maintenance container never receives the Docker socket;
only this host-side script controls Compose.

### Manual split workflow

The CLI also exposes the three phases independently:

1. With writers stopped, use `maintenance backup --output PATH
   --confirm-writers-stopped`. This also creates
   `PATH.provenance.json`; retain both files.
2. Restart writers, then use `maintenance verify-backup --backup PATH
   --manifest PATH`.
3. Stop writers again and use `maintenance prune --apply
   --confirm-writers-stopped --verified-backup-manifest PATH
   --max-runtime-seconds 900`.

Applied prune still requires an explicit writer-stopped acknowledgement. The
backup and manifest are fresh for 24 hours by default. Verification records
the backup's SHA-256 and integrity result. Prune validates the manifest's
canonical hash, creation-time provenance, exact file identities, source
database identity, and SQLite sequence relationship. It also refuses to
delete eligible rows inserted after the backup was created. When
`--include-reviewed` is selected, authorization also rejects eligible feedback
written after backup creation. These checks avoid rereading the entire backup
while monitoring is stopped.

The original one-command `prune --backup PATH` workflow remains available for
small databases, but it cannot be combined with `--max-runtime-seconds`; use
the split workflow when a full-command maintenance deadline is required.
Applying without a backup requires `--no-backup`; it is not used by the
automated cycle.

Human-reviewed verdicts remain protected unless `--include-reviewed` is
supplied. Retain the verified backup. Do not run `VACUUM` as part of this
workflow:
rebuilding a large live database can require substantial temporary disk space
and should only be planned as a separate maintenance operation with all writers
stopped and adequate free space verified.

Applied pruning uses short indexed transactions, pauses between batches, and
uses SQLite progress interruption plus remaining-time lock waits to enforce one
deadline across database connection, planning, backup authorization, deletion,
cleanup, checkpointing, and storage reporting.
The JSON result reports when orphan cleanup was deferred; storage-after metrics
are `null` when the deadline is already exhausted. This control applies to
verdict history; it does not reset SPC baselines or remove ingest-failure
quarantine records.

### Recommended models by VRAM

Triagewall has been benchmarked on Foundation-Sec-8B-Instruct across multiple quantizations against a 265-alert human-labeled gold set. Full methodology and results in [docs/experiments/](docs/experiments/).

| GPU VRAM | Recommended model | Cohen's κ | TP recall | Notes |
|---|---|---|---|---|
| 8 GB (RTX 4060, 3060 Ti) | `Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | 0.574 | 83% | Minimum — fits with headroom |
| 8 GB (RTX 4060, 3060 Ti) | **`Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`** ⭐ | **0.687** | **83%** | **Production default — Pareto sweet spot** |
| 10 GB+ (RTX 3080, 4070 Ti) | `Foundation-Sec-8B-Instruct-GGUF:Q6_K` | 0.734 | 83% | Best on this hardware tier |
| 16 GB+ (RTX 4080, A5000) | `Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest` | n/a* | n/a* | Theoretically best; not benchmarked here |

*Q8_0 does not fit on 8 GB VRAM. Attempted runs produced ~25% JSON parse failures due to CPU offload. Avoid unless you have ≥16 GB headroom.*

**Mistral 7B** (the v0.1 default) achieved Cohen's κ = 0.480 with 16.7% (1/6) true-positive recall on the same gold set with the same prompt. Foundation-Sec's security-domain training meaningfully outperforms general-purpose models on this task once given an appropriately tuned prompt.

Avoid models that exceed your VRAM. CPU partial-offload causes 10x slower, highly variable inference latency. Verify your model fits with `ollama ps` showing `100% GPU` after warmup. **Also avoid running other GPU-heavy applications (LM Studio, browser GPU acceleration, gaming) concurrently** — VRAM contention silently drops Ollama to CPU and degrades classification latency without obvious indicators.

How tuning works

The first day of running Triagewall on a new network is mostly about populating `prefilter.json` with site-specific noise. The dashboard surfaces which signatures dominate your LLM workload; adding carefully scoped rules to the prefilter reduces repeat model work while retaining documented reasoning. Triagewall validates and loads this file once at ingest startup, so restart ingest after changing it. Invalid configuration fails startup instead of silently widening a suppression.

The versioned policy declares the networks considered internal and supports optional match conditions for network direction, Suricata flow direction, protocol, source/destination ports, source/destination CIDRs, and source/destination asset inventory fields. Every condition in `match` must pass; multiple values within one condition are alternatives. If required alert or asset context is missing or malformed, the rule does not suppress the alert and normal LLM triage continues.

Example scoped entries:

```json
{
  "version": 1,
  "internal_cidrs": ["10.0.0.0/24", "10.0.1.0/24"],
  "auto_false_positive": [
    {
      "signature_ids": [2019102],
      "reason": "Internal UDP discovery to port 1900 is normal SSDP/UPnP traffic.",
      "match": {
        "network_directions": ["internal_to_internal"],
        "flow_directions": ["to_server"],
        "protocols": ["udp"],
        "destination_ports": [1900]
      }
    },
    {
      "signature_ids": [2000538],
      "reason": "Inbound HTTPS response traffic to an internal client.",
      "match": {
        "network_directions": ["external_to_internal"],
        "flow_directions": ["to_client"],
        "protocols": ["tcp"],
        "source_ports": [443],
        "destination_asset": {
          "matched": true,
          "criticalities": ["low", "medium", "high", "critical"]
        }
      }
    }
  ]
}
```

Asset selectors support `matched`, `hostnames`, `roles`, `criticalities`, and `internet_facing`. The shipped NMAP-ACK rule does not require an inventory match so a validated empty inventory remains usable; the asset selector above illustrates how an operator can make it stricter. Rules without `match` remain supported for backward compatibility and still suppress globally by SID, so migrate them deliberately as you gather reliable context. Reason strings double as documentation of *why* a rule is suppressed on your network.

## Network visibility (be honest about what your IDS sees)

Triagewall is only as useful as the alerts Suricata feeds it, and Suricata at a typical home perimeter deployment has structural blind spots worth understanding before relying on this for full network visibility.

**What Suricata sees with the typical OPNsense/pfSense deployment:**
- All traffic crossing your router (north-south WAN traffic)
- DNS queries that traverse the router (most, unless using DNS-over-HTTPS direct)
- Inbound port-forwarded traffic
- Traffic crossing between VLANs

**What Suricata does NOT see:**
- East-west traffic within a single VLAN (devices on the same L2 segment talking to each other never reach the router)
- Container-to-container chatter on Docker bridge networks (unless explicitly bridged through monitored interfaces)
- Encrypted DNS over HTTPS to non-monitored resolvers
- Anything happening on segments not configured for IDS monitoring

This is the default deployment model and isn't a Triagewall limitation specifically — it's an IDS architecture reality. In enterprise environments, SPAN/mirror ports on switches give Suricata visibility into east-west traffic. Most homelabs don't have the spare NIC budget for that.

**Practical implication for homelab users:** Suricata provides strong perimeter
visibility but cannot observe every same-segment interaction. Triagewall can
now add actionable Wazuh alerts from enrolled endpoints to the same
source-aware triage view. This improves context; it does not turn Triagewall
into an endpoint agent or replace either sensor.

## What it does not do

- It does not block traffic. Triagewall is read-only — it triages, it doesn't act. If you want auto-blocking, that's Wazuh Active Response or your firewall, not this.
- It does not replace a SOC analyst. It reduces thousands of daily alerts down to a handful for review. Those alerts are still your job.
- It does not call out to OpenAI, Anthropic, or any cloud LLM. Ever. By design.
- It does not work without a GPU. Ollama runs models on CPU but inference is too slow to keep up with most networks' alert rates.

## Product architecture: Core and Lab

Triagewall is evolving as one product family with two independently runnable
applications:

- **Triagewall Core** is the production-supported alert-ingest, triage, and
  operator dashboard shipped by this repository today.
- **Triagewall Lab** is a future replay, evaluation, and release-validation
  application. It will compare prompts and models, run injection and gold-set
  regressions, and produce evidence for a human release decision. It will not
  participate in live ingest or modify Core.

Lab will be incubated privately while its interfaces and security model are
experimental. After it meets documented graduation criteria, it will join this
public repository as an optional application. The finished product will support
Core-only, Lab-only, and explicitly enabled combined installations without
making Lab a dependency of the default Core path.

Core and Lab will exchange sanitized, versioned event bundles rather than share
the production database, sensor logs, asset inventory, or checkpoints. See
[Core and Lab product boundary](docs/core-lab-product-boundary.md) for the
runtime boundary and graduation path. Lab is a product direction, not a
currently shipped component.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. Highlights:

**Core v0.3:** the production release unifying Suricata and actionable Wazuh
alerts with source provenance, trusted asset context, hostile-field isolation,
durable recovery, and source-aware dashboard output. Gold-set validation is
calibrated and passing, and all five required release-evidence scenarios are
recorded; v0.3 is pending review, merge, and tagging rather than further runtime
scope. Garak adversarial probing is unimplemented and explicitly post-v0.3.

**Core operational usability:** add a bounded alert-detail view, source and
time filtering, IP and asset filtering, saved views, and structured JSON
export.

**Decision provenance and portable event bundles:** make every verdict
traceable through its sensor identity, policy, prompt, model, validation, and
operator feedback. Export sanitized, versioned bundles without requiring
access to the production database or sensor logs.

**Triagewall Lab:** specify the portable event-bundle boundary, add sanitized
Core export, incubate the Lab privately, and graduate it only after standalone,
combined, security, upgrade, and removal paths are proven.

**Awareness:** build cross-sensor correlation, daily narratives, coverage-gap
reporting, assisted tuning suggestions, and operator-controlled notifications
on top of the operational and provenance foundations.

The strategy remains: integrate battle-tested tools rather than reinvent them.
Suricata, Wazuh, and future sensors provide detection and ground truth;
Triagewall provides safe local reasoning, prioritization, correlation, and
operator awareness.

## Contributing

Contributions are welcome but please open an issue to discuss before submitting a large PR.

- Bug reports → [Issues](https://github.com/aaronphifer/triagewall/issues)
- Feature ideas → [Discussions](https://github.com/aaronphifer/triagewall/discussions)
- Security disclosures → security@triagewall.io
- General contact → hello@triagewall.io

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

AGPL-3.0. See [LICENSE](LICENSE).

Commercial licenses available for organizations that need to ship Triagewall without AGPL §13 compliance — email licensing@triagewall.io.

## Acknowledgments

Built on the shoulders of [Suricata](https://suricata.io), [Ollama](https://ollama.com), [FastAPI](https://fastapi.tiangolo.com), and the broader self-hosted security community. Inspired by [SOCFortress CoPilot](https://github.com/socfortress/CoPilot) and various Wazuh+Suricata triage experiments published by community members — all of which solved adjacent pieces of this problem and shaped how Triagewall approached it.
