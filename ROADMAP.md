# Triagewall Roadmap

Triagewall started as a way to make a homelab IDS usable again — to get from
thousands of Suricata alerts an hour down to the handful actually worth a look.
The longer-term goal is broader: a local-first **homelab security awareness
platform** that surfaces what matters across all your sensors without requiring
you to remember to check dashboards.

The strategy is consistent across every release: **integrate battle-tested
tools, don't reinvent them.** Suricata, Wazuh, Zeek, Pi-hole, OpenVAS, and Garak
do the detection, data collection, and adversarial testing. Triagewall adds a
reasoning and prioritization layer on top. The LLM provides judgment; the
underlying tools provide ground truth. Everything runs locally, with no cloud
dependencies.

Each version adds capabilities empirically validated against production homelab
traffic. For the design philosophy behind the project, see the
[writeups](https://triagewall.io/posts).

---

## Shipped

### v0.1 — May 2026
Initial public release.

- [x] Two-tier classification: tunable prefilter + local LLM (Mistral 7B via Ollama)
- [x] Web dashboard with real-time alert feed and hourly trend chart
- [x] Tunable prefilter via `prefilter.json` with rationale strings
- [x] Demo mode for evaluation without real Suricata data
- [x] Docker Compose deployment with one-command setup
- [x] Verdict feedback API (Agree / Mark Different) with database persistence
- [x] Health endpoint with stale-alert detection
- [x] Configurable LLM backend via Ollama (any model)
- Posted to r/homelab; listed on
  [satta/awesome-suricata](https://github.com/satta/awesome-suricata).

### v0.2-alpha — May 22, 2026
- [x] Model swap to Foundation-Sec-8B-Instruct (Q5_K_M)
- [x] Revised system prompt with explicit category priors
- [x] Reproducible benchmark harness and a labeled gold set
- Revising the prompt moved Foundation-Sec Q5_K_M from κ=0.210 to κ=0.687 and
  from 0% to 83% true-positive recall against the gold set — the model's
  security specialization was latent and the prompt had to elicit it.

### v0.2 — May 25, 2026
Two-phase prompt injection hardening, plus operational hardening.

- [x] **Phase 1:** per-process canary token detection and strict
  response-schema validation
- [x] **Phase 2:** field isolation — 16 attacker-controlled alert fields are
  base64-encapsulated with explicit boundary markers so injected text can't be
  read as instructions. Closed a URL-injection vulnerability that defeated
  Phase 1. Writeup and test results in [docs/experiments](docs/experiments) and
  on the [blog](https://triagewall.io/posts/prompt-injection-phase-2).
- [x] SQLite WAL mode and `busy_timeout` on all connections (no more dashboard
  lock contention)
- [x] Prefilter mounted as a volume (edit SIDs without rebuilding the image)

---

## Planned

Dates are targets, not commitments. This is a side project built around a day
job.

### v0.2.1 — June 2026
Polish and test infrastructure deferred from v0.2.

- [ ] **Garak injection gate.** Integrate
  [NVIDIA Garak](https://github.com/NVIDIA/garak) as a pre-release adversarial
  scanner. An adapter wraps Garak's probes so they exercise the full Triagewall
  pipeline (with field isolation active), not just the raw model. Run as a
  periodic / pre-release gate rather than per-commit, since each probe is an LLM
  call against a local 8B model. A change that increases injection success
  versus baseline does not merge.
- [ ] Prompt iteration so URL injection produces an explicit "real + injection
  attempt flagged" verdict rather than the current "uncertain." Security outcome
  is already met; this improves fidelity.
- [ ] Architecture diagram refresh covering Foundation-Sec, the mounted
  prefilter, and the hardening layer.

### v0.3 — July–August 2026
Multi-sensor triage and the quality-of-life features the dashboard still needs.

- [ ] **Wazuh integration** — pull Wazuh alerts through the same LLM triage
  pipeline as Suricata, with source-aware prompts, a Wazuh-specific prefilter,
  and a schema update to support multiple sources.
- [ ] **Change validation against the gold set.** Before any prompt, rule, or
  config change takes effect, it is validated against the labeled gold set and
  the benchmark harness. A change that regresses detection is **blocked and
  reported** — staged for review, not silently applied. (See *Out of scope* for
  why this is assisted, not autonomous.)
- [ ] Garak runs extended to cover the multi-sensor pipeline.
- [ ] **Async LLM pipeline** — bounded queue decouples LLM latency from
  ingestion throughput, scales beyond ~50K alerts/hour.
- [ ] **Alert detail view** — full Suricata payload, whois enrichment, related
  flows.
- [ ] **Time range filtering** — last N hours, custom date range, "around event."
- [ ] **IP filtering** — by source IP, destination IP, subnet, or asset tag.
- [ ] Saved views and named filters.
- [ ] CSV / JSON export of filtered alert sets.
- [ ] Per-source dashboards.

### v0.4 — September–October 2026
The awareness layer. This is the actual answer to the
out-of-sight-out-of-mind problem.

- [ ] **Daily digest** in plain English: what happened in the last 24 hours that
  mattered, what changed since yesterday, what's trending.
- [ ] **Coverage gap detection:** e.g. "12 active devices on the network, only 3
  running endpoint agents."
- [ ] **Cross-sensor correlation:** an IP or domain appearing across Suricata,
  Wazuh, and Pi-hole inside a time window gets surfaced as one narrative rather
  than three disconnected alerts.
- [ ] **Assisted prefilter suggestions.** The tool proposes additions — "SID
  2009205 fired 1,400 times this week, all classified false_positive; add to
  prefilter?" — and you approve with one click. Removes the tuning toil while
  keeping you the decision-maker.
- [ ] **Asset criticality tagging:** name internal hosts ("windows-desktop",
  "pi-hole"), include in the LLM prompt for context-aware classification, and
  weight alerts on important hosts higher.
- [ ] Webhooks (Discord, Slack, generic) for high-confidence "real" verdicts.

### v0.5 — Late 2026
Vulnerability summarization.

- [ ] Wraps Wazuh's vulnerability detection module (and optionally OpenVAS).
- [ ] Plain-English explanation of CVE findings, remediation guidance, and
  prioritization based on which hosts carry which exposures.
- Does **not** perform vulnerability scanning itself — it reasons on top of
  battle-tested scanners.

### v1.0 — Early 2027
Positioned as a homelab **security awareness platform**: the tool that solves
the out-of-sight-out-of-mind problem by surfacing what matters across all your
sensors without requiring you to remember to check dashboards.

---

## Backlog (no commitment)

- Theming — dark/light toggle, primary color customization
- Branded deployments (logo upload, custom title text)
- Mobile-responsive dashboard tweaks
- API authentication for multi-user deployments
- Multi-tenant deployments

---

## Design principles

- **Local-first.** No cloud LLMs, no telemetry. Network security data stays on
  the network.
- **Integrate, don't reinvent.** Detection and scanning come from mature,
  battle-tested tools. Triagewall adds reasoning, correlation, and
  prioritization.
- **License-compatible.** All planned integrations are compatible with
  AGPL-3.0.
- **The human stays in the loop on behavior changes.** Automation removes
  *toil* (testing, tuning suggestions, reporting). It does not make
  unsupervised decisions about what the system detects. A security tool you
  can't reason about is a security tool you can't trust.

---

## Out of scope

These are deliberate non-goals. Some were suggested during research and
rejected for the reasons given, so the reasoning is recorded here for anyone
(including future me) who revisits them.

- **Auto-blocking / active response.** Use Wazuh Active Response or firewall
  rules. Triagewall triages; it does not take action on the network.
- **Cloud LLM integration.** Defeats the local-first design and sends security
  telemetry off-network.
- **Endpoint agent functionality.** Use Wazuh agents.
- **Vulnerability scanning.** Use Wazuh, OpenVAS, or Nuclei. Triagewall
  summarizes their output (v0.5), it doesn't scan.
- **LLM self-tuning its own confidence thresholds.** The model has no
  independent ground truth for whether its confidence is calibrated, so
  self-tuning is a feedback loop that drifts. Thresholds are tuned against
  labeled data (the gold set and Agree / Mark Different feedback), not against
  the model's opinion of itself.
- **Auto-rollback of changes based on a test signal.** A noisy probe result
  silently reverting a real improvement is worse than the regression it's
  guarding against. Regressions block the change and notify; a human decides.
- **Background auto-updating of detection rules.** Ruleset updates are exactly
  what undoes careful tuning (see the v0.1 writeup). Updates are proposed for
  one-click approval, never applied silently.
- **Hiding rule/validation errors from the user.** The goal is to catch broken
  changes before production via a staging step — not to suppress error
  visibility. In a security tool, silent error suppression means silent
  detection gaps.

---

## Contributing

Roadmap items are open to community contributions — especially if you can break
the injection hardening. If you want to work on something, open an issue first
to discuss approach. See the [README](README.md) to get started.
