# Triagewall Roadmap

Triagewall ships in incremental versions, with each version adding capabilities
empirically validated against production homelab traffic.

## v0.1 (current release)

- [x] Two-tier classification: tunable prefilter + local LLM
- [x] Web dashboard with real-time alert feed and hourly trend chart
- [x] Tunable prefilter via prefilter.json with rationale strings
- [x] Demo mode for evaluation without real Suricata data
- [x] Docker Compose deployment with one-command setup
- [x] Verdict feedback API (Agree / Mark different) with database persistence
- [x] Health endpoint with stale-alert detection
- [x] Configurable LLM backend via Ollama (any model)

## v0.2 (next)

- [ ] Verdict feedback loop — auto-suggest prefilter additions when user
      consistently overrides the LLM on a SID
- [ ] Asset tagging — name internal hosts ("windows-desktop", "pi-hole")
      and include in the LLM prompt for context-aware classification
- [ ] Time range filtering — last N hours, custom date range, "around event"
- [ ] IP filtering — by source IP, destination IP, subnet, or asset tag
- [ ] Alert detail view — full Suricata payload, whois enrichment, related flows
- [ ] Theming — dark/light toggle, primary color customization
- [ ] Wazuh API integration — pull alerts from Wazuh manager as a source
- [ ] Async LLM pipeline — bounded queue, decouples LLM latency from
      ingestion throughput, scales beyond ~50K alerts/hour

## v0.3 (later)

- [ ] Saved views and named filters
- [ ] CSV/JSON export of filtered alert sets
- [ ] Webhooks (Discord, Slack, generic) for high-confidence "real" verdicts
- [ ] Daily/weekly digest reports via email or Discord
- [ ] Multiple eve.json sources (multi-Suricata-instance support)
- [ ] Per-source dashboards

## Backlog (no commitment)

- Branded deployments (logo upload, custom title text)
- Mobile-responsive dashboard tweaks
- API authentication for multi-user deployments
- Multi-tenant deployments

## Contributing

Roadmap items are open to community contributions. If you want to work on
something, open an issue first to discuss approach.
