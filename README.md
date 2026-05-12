# Triagewall

**Local-LLM Suricata alert triage for homelabs.** Reduce alert noise without sending data to the cloud. Runs entirely on your hardware. No telemetry. AGPL-3.0.

> **TL;DR** — `docker compose up`, point it at your Suricata `eve.json`, and Triagewall pre-filters known noise out of the box. The remaining alerts get classified by a local LLM, with a dashboard showing what to investigate. Designed for homelabs and small SOCs running Suricata on OPNsense, pfSense, or any sensor that writes Suricata-format `eve.json`.

![Triagewall dashboard](https://raw.githubusercontent.com/Aphifer07/triagewall-site/main/dashboard.png)

---

## Why this exists

If you run Suricata in a homelab, you know the problem. The ET Open ruleset generates thousands of alerts a day, the vast majority of which are noise — TLS SNI matches, DNS lookups for normal CDNs, your own scanning, your kid's gaming traffic. The signal is in there, but you're not going to find it by reading every alert at 11 PM.

Commercial XDR products solve this with cloud-based ML and a $500/month bill. The open-source SIEM stack (Wazuh, TheHive, Cortex) gives you the data but no triage layer. Triagewall is the missing layer, designed for people who already self-host their security stack and want to keep it that way.

## What it does

- **Reads Suricata `eve.json`** in real time, tracks position across restarts and log rotations
- **Pre-filters known-benign rules** with a tunable JSON config (the "I already know what STUN traffic is, stop telling me" filter) — microsecond lookups, zero LLM cost
- **Triages residual alerts** with a local LLM via Ollama (default: `mistral:7b`, see [Performance & accuracy](#performance--accuracy) for VRAM-based model selection)
- **Records your feedback** — every verdict has Agree / Mark Different buttons in the dashboard, building a labeled dataset and a measurable agreement rate
- **Surfaces what matters** in a clean web dashboard with hourly traffic trends

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
- **At least one Ollama model:** `ollama pull mistral:7b`
- **A GPU with 8+ GB VRAM** for the LLM (the prefilter works without one, but the residual long tail won't classify in reasonable time on CPU)

## Quick start

```bash
git clone https://github.com/Aphifer07/triagewall.git
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
#   - OLLAMA_MODEL=mistral:7b
# Then `docker compose up -d` again.
```

You'll need [Ollama](https://ollama.com) running somewhere reachable on your network, with at least one model pulled (`ollama pull mistral:7b`). The Ollama instance can be on the same host or a separate GPU node.

## Performance & accuracy

Triagewall has been running on a homelab production network for multi-day continuous operation against live OPNsense Suricata data. Measured numbers:

| Metric | Value |
|---|---|
| Source rate (typical) | 6,000–13,000 alerts/hour |
| Prefilter ratio | 99%+ (after tuning ~20 SIDs) |
| LLM latency | 1–3 seconds per call (Mistral 7B Q4 on RTX 4060) |
| End-to-end lag | under 2 minutes at steady state |
| Daemon RAM footprint (excluding Ollama) | ~17 MB |
| Database growth | ~1.5 GB after 7 days |

Throughput scales primarily with prefilter ratio. The two-tier design means prefiltered alerts are processed in microseconds; only LLM-classified alerts (typically 0.3–3% after tuning) are bound by Ollama latency.

### Recommended models by VRAM

| GPU VRAM | Recommended model | Reasoning quality |
|---|---|---|
| 8 GB (RTX 4060, 3060 Ti) | `mistral:7b` at `num_ctx=4096` | Good — handles long tail well |
| 12 GB (RTX 3060, 4070) | `mistral:7b` or `llama3.1:8b` at full context | Better |
| 24 GB+ (RTX 3090, 4090) | `gemma3:12b`, `llama3.1:70b-q4` | Best |

Avoid models that exceed your VRAM. CPU partial-offload causes 10x slower, highly variable inference latency. Verify your model fits with `ollama ps` showing `100% GPU` after warmup.

### How tuning works

The first day of running Triagewall on a new network is mostly about populating `prefilter.json` with site-specific noise. The dashboard surfaces which signatures dominate your LLM workload; adding them to the prefilter takes seconds and gives a permanent classification with documented reasoning. After initial tuning, the LLM handles only the long tail of genuinely novel signatures.

Example prefilter entry from this repo's production config:

```json
{
  "signature_ids": [2009205, 2009206, 2009207, 2009208],
  "reason": "Legacy ET MALWARE Conficker/KEYPLUG P2P UDP signatures (2009-era) match modern STUN traffic to Microsoft Azure STUN servers (20.202.0.0/16:3478) used by Teams, Xbox Live, Skype. Confirmed false positive — same UDP packet shape, different intent. The LLM consistently misclassifies these because the signature description biases toward 'malware' without port-aware context."
}
```

These reason strings double as documentation of *why* a SID is suppressed on your network — useful when reviewing the prefilter months later, or when sharing tuning notes with others.

## What it does not do

- It does not block traffic. Triagewall is read-only — it triages, it doesn't act. If you want auto-blocking, that's Wazuh Active Response or your firewall, not this.
- It does not replace a SOC analyst. It reduces thousands of daily alerts down to a handful for review. Those alerts are still your job.
- It does not call out to OpenAI, Anthropic, or any cloud LLM. Ever. By design.
- It does not work without a GPU. Ollama runs models on CPU but inference is too slow to keep up with most networks' alert rates.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan. Highlights:

**v0.2 (next):**
- Verdict feedback loop — auto-suggest prefilter additions when the user consistently overrides the LLM on a SID
- Asset tagging — name internal hosts and include in the LLM prompt for context-aware classification
- Time range and IP filtering on the dashboard
- Wazuh API integration as a second alert source
- Async LLM pipeline for higher throughput

**v0.3 and beyond:** webhook notifications, CSV/JSON export, daily/weekly digests, multi-source dashboards.

## Contributing

Contributions are welcome but please open an issue to discuss before submitting a large PR.

- Bug reports → [Issues](https://github.com/Aphifer07/triagewall/issues)
- Feature ideas → [Discussions](https://github.com/Aphifer07/triagewall/discussions)
- Security disclosures → security@triagewall.io
- General contact → hello@triagewall.io

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

AGPL-3.0. See [LICENSE](LICENSE).

Commercial licenses available for organizations that need to ship Triagewall without AGPL §13 compliance — email licensing@triagewall.io.

## Acknowledgments

Built on the shoulders of [Suricata](https://suricata.io), [Ollama](https://ollama.com), [FastAPI](https://fastapi.tiangolo.com), and the broader self-hosted security community. Inspired by [SOCFortress CoPilot](https://github.com/socfortress/CoPilot) and various Wazuh+Suricata triage experiments published by community members — all of which solved adjacent pieces of this problem and shaped how Triagewall approached it.
