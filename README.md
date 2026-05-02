# Triagewall

> ⚠️ **Pre-release.** Triagewall is actively building toward v0.1. Not yet ready for general use. **Star the repo to be notified when v0.1 ships.** First public release expected mid-2026.

**Local-LLM alert triage for self-hosted SOCs.** Point it at your Suricata `eve.json` and Wazuh API, stop drowning in alerts. Runs entirely on your hardware. No telemetry. No cloud. AGPL-3.0.

> **TL;DR** — `docker compose up`, point it at your alert sources, give feedback on the first 50 alerts, and Triagewall starts pre-filtering the noise. Designed for homelabs and small SOCs running Wazuh + Suricata on OPNsense, pfSense, or any sensor that writes Suricata-format `eve.json`.

---

## Why this exists

If you run Suricata in a homelab, you know the problem. The ET Open ruleset generates hundreds of alerts a day, the vast majority of which are noise — TLS SNI matches, DNS lookups for normal CDNs, your own scanning, your kid's gaming traffic. The signal is in there, but you're not going to find it by reading every alert at 11 PM.

Commercial XDR products solve this with cloud-based ML and a $500/month bill. The open-source SIEM stack (Wazuh, TheHive, Cortex) gives you the data but no triage layer. Triagewall is the missing layer, designed for people who already self-host their security stack and want to keep it that way.

## What it does

- **Reads Suricata `eve.json`** in real time
- **Reads Wazuh alerts** via the Wazuh API (optional)
- **Triages each alert** with a local LLM (Ollama, default model: `gemma4:e4b`)
- **Pre-filters known-benign rules** with a curated SID allowlist (the "I already know what STUN traffic is, stop telling me" filter)
- **Learns from your verdicts** — mark an alert as a false positive once, similar alerts get pre-filtered automatically
- **Surfaces what matters** in a clean web dashboard
- **Sends a daily digest** to Discord, Slack, ntfy, or email (planned)

## What it does not do

- It does not block traffic. Triagewall is read-only — it triages, it doesn't act. If you want auto-blocking, that's Wazuh Active Response or your firewall, not this.
- It does not replace a SOC analyst. It reduces a 200-alert day to a 5-alert day. The 5 alerts are still your job.
- It does not call out to OpenAI, Anthropic, or any cloud LLM by default. If you want a cloud-burst tier for hard cases, it's an opt-in toggle — off until you flip it.

## Quick start (planned for v0.1)

> Not yet available. Star the repo to be notified.

```bash
git clone https://github.com/Aphifer07/triagewall.git
cd triagewall
cp .env.example .env
# edit .env: set OLLAMA_HOST and EVE_PATH
docker compose up -d
```

## Performance & accuracy

Measured on a homelab running OPNsense → Suricata (ET Open ruleset, alert-only) → Triagewall.

| Metric | Value |
|---|---|
| Alerts ingested per day | ~62,000–80,000 |
| Pre-filtered (zero LLM cost) | ~90% |
| LLM-classified | ~10% |
| Average LLM latency per alert | ~2–10 seconds |
| Daemon RAM footprint (excluding Ollama) | ~13 MB |

These are real numbers from the development environment. Yours will vary based on your network, your Suricata ruleset, and your prefilter tuning.

## Roadmap

- [x] Suricata `eve.json` ingestion
- [x] Wazuh API integration
- [x] LLM triage with feedback loop
- [x] Web dashboard (basic)
- [x] Curated prefilter for known-benign signatures
- [ ] Docker compose packaging (v0.1)
- [ ] Demo mode with anonymized sample data (v0.1)
- [ ] Configuration via `.env` only (no code edits) (v0.1)
- [ ] Health endpoint with stale-data detection (v0.1)
- [ ] Discord webhook digest (v0.1)
- [ ] Investigation agent — correlates flagged alerts across sources (v0.2)
- [ ] Pi-hole DNS correlation (v0.2)
- [ ] Multi-host cluster mode (Team tier)

## Free vs. hosted

Triagewall is **free forever for self-hosted single-node use**. AGPL-3.0.

If you don't want to operate a Triagewall node yourself, **Triagewall Cloud** ($15/mo, planned for late 2026) hosts it for you — same code, runs in a region of your choice, no telemetry from the application itself. Designed for homelab folks who want the alerts without the maintenance.

For teams, multi-host clustering, SSO, and shared verdict databases will be available in **Triagewall Team** ($49/mo). Single-tenant on-prem licenses for cleared environments and air-gapped networks are available — contact licensing@triagewall.io.

## Contributing

Triagewall is pre-release and the codebase is changing rapidly. Contributions are welcome but please open an issue to discuss before submitting a large PR.

- Bug reports → [Issues](https://github.com/Aphifer07/triagewall/issues)
- Feature ideas → [Discussions](https://github.com/Aphifer07/triagewall/discussions)
- Security disclosures → security@triagewall.io
- General contact → hello@triagewall.io

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## License

AGPL-3.0. See [LICENSE](LICENSE).

Commercial licenses available for organizations that need to ship Triagewall without AGPL §13 compliance — email licensing@triagewall.io.

## Acknowledgments

Built on the shoulders of [Wazuh](https://wazuh.com), [Suricata](https://suricata.io), [Ollama](https://ollama.com), [FastAPI](https://fastapi.tiangolo.com), and the broader self-hosted security community. Inspired by [SOCFortress CoPilot](https://github.com/socfortress/CoPilot) and various Wazuh+Suricata triage experiments published by community members — all of which solved adjacent pieces of this problem and shaped how Triagewall approached it.
