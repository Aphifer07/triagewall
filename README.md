# Triagewall

**Local-LLM Suricata alert triage for homelabs.** Reduce alert noise without sending data to the cloud. Runs entirely on your hardware. No telemetry. AGPL-3.0.

> **TL;DR** — `docker compose up`, point it at your Suricata `eve.json`, and Triagewall pre-filters known noise out of the box. The remaining alerts get classified by a local LLM, with a dashboard showing what to investigate. Designed for homelabs and small SOCs running Suricata on OPNsense, pfSense, or any sensor that writes Suricata-format `eve.json`.

![Triagewall dashboard](https://raw.githubusercontent.com/aaronphifer/triagewall-site/main/dashboard.png)

---

## Why this exists

If you run Suricata in a homelab, you know the problem. The ET Open ruleset generates thousands of alerts a day, the vast majority of which are noise — TLS SNI matches, DNS lookups for normal CDNs, your own scanning, your kid's gaming traffic. The signal is in there, but you're not going to find it by reading every alert at 11 PM.

Commercial XDR products solve this with cloud-based ML and a $500/month bill. The open-source SIEM stack (Wazuh, TheHive, Cortex) gives you the data but no triage layer. Triagewall is the missing layer, designed for people who already self-host their security stack and want to keep it that way.

## What it does

- **Reads Suricata `eve.json`** in real time, tracks position across restarts and log rotations
- **Pre-filters known-benign rules** with a tunable JSON config (the "I already know what STUN traffic is, stop telling me" filter) — microsecond lookups, zero LLM cost
- **Triages residual alerts** with a local LLM via Ollama (default: `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M` as of v0.2-alpha, see [Performance & accuracy](#performance--accuracy) for VRAM-based model selection)
- **Records your feedback** — every verdict has Agree / Mark Different buttons in the dashboard, building a labeled dataset and a measurable agreement rate
- **Surfaces what matters** in a clean web dashboard with hourly traffic trends

### New in v0.2-alpha (2026-05)

- **Production model swap** from Mistral 7B to Cisco's [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct), a security-domain-tuned model. Validated against a 265-alert human-labeled gold set: Cohen's κ improved 0.480 → 0.687, true-positive recall improved 17% → 83%.
- **Revised system prompt** with explicit category priors (ET DROP, ET EXPLOIT_KIT, ET MALWARE), threat-intel context (Spamhaus, geographic priors), and operational context (smart TV ad-tech, cloud IP ranges). Required to unlock Foundation-Sec's specialized training — see [the experiment writeup](docs/experiments/2026-05-22-prompt-revision.md) for the full methodology.
- **Prompt injection hardening (Phase 1)** — canary token detection and strict response schema validation. Phase 2 (field isolation) tracked for v0.2.1.
- **Operational improvements** — SQLite WAL mode (prevents dashboard lock contention), prefilter as mounted config volume (no rebuild required for SID changes), benchmark harness for reproducible model evaluation.

See [docs/experiments/](docs/experiments/) for full evaluation methodology and results.

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
# OR
docker-compose up -d        # Older Docker / Compose v1

# Open http://localhost:8084 to see the dashboard with sample alerts.

# For production: edit .env to set:
#   - DEMO_MODE=false
#   - HOST_DATA_DIR=./data (or wherever you want runtime files stored)
#   - HOST_EVE_DIR=/var/log/suricata (directory containing your eve.json)
#   - OLLAMA_HOST=http://your-ollama-instance:11434
#   - OLLAMA_MODEL=hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M
#   - INTERNAL_SUBNETS=10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24
#     (your internal network ranges, used for traffic-direction context in the LLM prompt)
# Then `docker compose up -d` again.
```

You'll need [Ollama](https://ollama.com) running somewhere reachable on your network, with at least one compatible model pulled. The Ollama instance can be on the same host or a separate GPU node.

## Performance & accuracy

Triagewall has been running on a homelab production network for multi-day continuous operation against live OPNsense Suricata data. Measured numbers:

| Metric | Value |
|---|---|
| Source rate (typical) | 6,000–13,000 alerts/hour |
| Prefilter ratio | 99%+ (after tuning ~30 SIDs) |
| LLM latency | 7–10 seconds per call (Foundation-Sec-8B Q5_K_M on RTX 4060) |
| End-to-end lag | under 2 minutes at steady state with healthy prefilter |
| Daemon RAM footprint (excluding Ollama) | ~17 MB |
| Database growth | ~1.5 GB after 7 days |
| Classifier accuracy (v0.2, 265-alert gold set) | Cohen's κ = 0.687, true-positive recall = 83% |

Throughput scales primarily with prefilter ratio. The two-tier design means prefiltered alerts are processed in microseconds; only LLM-classified alerts (typically 0.3–3% after tuning) are bound by Ollama latency.

### Recommended models by VRAM

Triagewall has been benchmarked on Foundation-Sec-8B-Instruct across multiple quantizations against a 265-alert human-labeled gold set. Full methodology and results in [docs/experiments/](docs/experiments/).

| GPU VRAM | Recommended model | Cohen's κ | TP recall | Notes |
|---|---|---|---|---|
| 8 GB (RTX 4060, 3060 Ti) | `Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | 0.574 | 83% | Minimum — fits with headroom |
| 8 GB (RTX 4060, 3060 Ti) | **`Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`** ⭐ | **0.687** | **83%** | **Production default — Pareto sweet spot** |
| 10 GB+ (RTX 3080, 4070 Ti) | `Foundation-Sec-8B-Instruct-GGUF:Q6_K` | 0.734 | 83% | Best on this hardware tier |
| 16 GB+ (RTX 4080, A5000) | `Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest` | n/a* | n/a* | Theoretically best; not benchmarked here |

*Q8_0 does not fit on 8 GB VRAM. Attempted runs produced ~25% JSON parse failures due to CPU offload. Avoid unless you have ≥16 GB headroom.*

**Mistral 7B** (the v0.1 default) achieved Cohen's κ = 0.556 with 50% true-positive recall on the same gold set with the same prompt. Foundation-Sec's security-domain training meaningfully outperforms general-purpose models on this task once given an appropriately tuned prompt.

Avoid models that exceed your VRAM. CPU partial-offload causes 10x slower, highly variable inference latency. Verify your model fits with `ollama ps` showing `100% GPU` after warmup. **Also avoid running other GPU-heavy applications (LM Studio, browser GPU acceleration, gaming) concurrently** — VRAM contention silently drops Ollama to CPU and degrades classification latency without obvious indicators.

How tuning works

The first day of running Triagewall on a new network is mostly about populating `prefilter.json` with site-specific noise. The dashboard surfaces which signatures dominate your LLM workload; adding them to the prefilter takes seconds and gives a permanent classification with documented reasoning. After initial tuning, the LLM handles only the long tail of genuinely novel signatures.

Example prefilter entry from this repo's production config:

```
{
  "signature_ids": [2009205, 2009206, 2009207, 2009208],
  "reason": "Legacy ET MALWARE Conficker/KEYPLUG P2P UDP signatures (2009-era) match modern STUN traffic to Microsoft Azure STUN servers (20.202.0.0/16:3478) used by Teams, Xbox Live, Skype, and Tailscale DERP relays. Confirmed false positive — same UDP packet shape, different intent. Empirically validated: 149 alerts processed without prefilter, v0.2 Foundation-Sec misclassified 100% as 'real' due to ET MALWARE category prior. The LLM lacks per-signature historical context that this signature now fires on modern legitimate STUN traffic. Resolved via prefilter pending v0.3 RAG layer."
}
```

These reason strings double as documentation of *why* a SID is suppressed on your network — useful when reviewing the prefilter months later, or when sharing tuning notes with others.

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

**Practical implication for homelab users:** Triagewall covers the perimeter well. For internal lateral-movement detection, pair it with endpoint agents (Wazuh) on hosts you control. Multi-sensor integration is planned for v0.3.

## What it does not do

- It does not block traffic. Triagewall is read-only — it triages, it doesn't act. If you want auto-blocking, that's Wazuh Active Response or your firewall, not this.
- It does not replace a SOC analyst. It reduces thousands of daily alerts down to a handful for review. Those alerts are still your job.
- It does not call out to OpenAI, Anthropic, or any cloud LLM. Ever. By design.
- It does not work without a GPU. Ollama runs models on CPU but inference is too slow to keep up with most networks' alert rates.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. Highlights:

**v0.2-alpha (shipped):** Prompt revision, Foundation-Sec-8B model swap, benchmark harness, 265-alert gold set, prompt injection hardening Phase 1, SQLite WAL mode, mounted prefilter volume.

**v0.2 (next, June 2026):** Prompt injection hardening Phase 2 (field isolation), documentation polish, architecture diagram, SQLite busy-timeout patches.

**v0.3 (Jul–Aug 2026):** Wazuh integration — pull Wazuh alerts through the same LLM triage pipeline. Multi-sensor pattern proven.

**v0.4 (Sep–Oct 2026):** Awareness layer — daily digest, coverage gap detection ("you have 12 active devices but only 3 running endpoint agents"), cross-sensor narrative correlation, asset criticality tagging.

**v0.5:** Vulnerability summarization layer wrapping Wazuh vulnerability detection and/or OpenVAS with LLM-driven prioritization and remediation guidance.

**v1.0 (early 2027):** Positioned as a homelab security awareness platform — the tool that fights the "out of sight, out of mind" problem by surfacing what matters across all your sensors without requiring you to remember to check dashboards.

Strategy: integrate battle-tested tools (Suricata, Wazuh, Zeek, Pi-hole, OpenVAS), don't reinvent. The LLM provides reasoning and prioritization; the underlying tools provide the data.

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
