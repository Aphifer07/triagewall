# Threat Model

This document states what Triagewall protects against, what it doesn't, and the
trust assumptions it makes. It exists because a security tool you can't reason
about is a security tool you can't trust — and because being explicit about
limitations is more useful than implying there are none.

Triagewall is a homelab tool. It is built for a single operator running it on
their own network, not for multi-tenant or enterprise deployment. The threat
model reflects that.

---

## What Triagewall is

A two-tier triage layer that sits between a Suricata IDS alert stream and a
human. A prefilter classifies known-noise signatures by ID; everything else
goes to a local LLM that returns a verdict (`real`, `false_positive`,
`uncertain`) with a confidence score and reasoning. Results land in SQLite and
surface on a local web dashboard.

It triages alerts. It does **not** block traffic, modify firewall rules, or take
any action on the network. It is a decision-support tool, not an enforcement
point.

---

## Data flow and trust boundaries

```
[ Suricata on OPNsense ]  --(eve.json, rsync/SSH or mount)-->  [ ingest daemon ]
                                                                      |
                                                  prefilter (trusted SID lookup)
                                                                      |
                                                       (miss) --> [ local Ollama LLM ]
                                                                      |
                                                                  [ SQLite ]
                                                                      |
                                                          [ FastAPI dashboard ]
```

Three trust boundaries matter:

1. **Suricata → ingest.** Alert *metadata* (signature ID, category, IPs, ports)
   is trusted: it is Suricata's own analysis. Alert *content* (URLs, hostnames,
   user-agents, payloads, TLS/DNS fields) is **untrusted** — it is
   attacker-controllable network data. This distinction is the foundation of
   the injection hardening (see below).

2. **ingest → Ollama.** Assumed to be a trusted network segment. Traffic to the
   LLM is unencrypted HTTP by default. See *Assumptions* and *Known gaps*.

3. **dashboard → operator.** The dashboard is unauthenticated by default and
   intended to be reachable only from the operator's own network. It is not
   built to be exposed to the internet.

---

## Attacker model

The primary adversary Triagewall defends against is an attacker who can
**influence the content of a Suricata alert** — by sending crafted traffic that
Suricata logs (a malicious URL, a hostile user-agent, a payload containing
attacker text). Because that content flows into an LLM prompt, the attacker's
goal is **prompt injection**: manipulating the LLM into returning an
attacker-chosen verdict (e.g. forcing a real attack to be classified
`false_positive` so it never surfaces to the human).

This is a real, demonstrated threat. v0.2 closed a vulnerability where an
attacker who controlled a URL field could dictate both the verdict and the
confidence score. See
[the writeup](https://triagewall.io/posts/prompt-injection-phase-2) and
[docs/experiments](experiments) for the attack and the fix.

**Out of the attacker model:** an adversary who already has code execution on
the host running Triagewall, or who is already on the trusted LAN segment
between ingest and Ollama, or who controls Suricata's ruleset or the prefilter
config. Those are pre-compromise scenarios that this tool does not defend
against and is not positioned to.

---

## What is defended

**Prompt injection via attacker-controlled alert fields.** Sixteen field paths
(URLs, hostnames, user-agents, HTTP bodies, DNS names, TLS cert fields, SSH
banners, payloads) are base64-encapsulated with explicit boundary markers before
reaching the LLM, so injected text cannot be parsed as instructions. Trusted
Suricata metadata stays plain. (Phase 2.)

**Prompt/system-prompt leakage.** A per-process canary token is embedded in the
system prompt; if it appears in model output, the response is rejected and the
alert is flagged. (Phase 1.)

**Malformed or manipulated model output.** Strict response-schema validation
rejects responses with unexpected keys, enforces the verdict enum, clamps
confidence to `[0, 1]`, and caps reasoning length. An attacker cannot smuggle
extra structure or oversized output through the verdict path. (Phase 1.)

The defense is empirically tested — see the Phase 1 / Phase 2 experiment docs
and the test scenarios in the repo.

---

## What is NOT defended (limitations)

These are honest gaps, stated so operators can make informed decisions.

**Injection hardening is a friction layer, not a guarantee.** Base64
encapsulation removes the obvious attack — plain-English imperatives in alert
fields — and was validated against the known attacks. It is not a proof. A
sufficiently clever adversary may find inputs that survive encoding. The right
mental model is "raised the bar and keep iterating," not "solved." Breaking it
is explicitly invited; that is how the next hardening phase gets written.

**The prefilter is a deliberate detection gap.** Signatures in
`prefilter.json` are auto-classified as `false_positive` and never reach the
LLM. This is what makes the volume manageable (99%+ of alerts), but it means an
attacker who knows which SIDs are prefiltered (the config is in the public repo)
could craft traffic that fires *only* prefiltered signatures to avoid LLM
review. The prefilter trades detection coverage for volume reduction; this is an
accepted tradeoff for a homelab, not a hidden flaw. Tune your own prefilter
accordingly and don't prefilter SIDs you actually care about.

**False negatives are expected.** The LLM misses things. On the v0.2-alpha gold
set, true-positive recall was 5/6 — one real threat in six was misclassified.
Triagewall reduces the alerts you have to read; it does not guarantee you'll
catch every real one. It is a triage aid, not a replacement for an analyst or
for the underlying IDS.

**The ingest→Ollama path is unencrypted and unauthenticated by default.** Alert
content (including payloads) crosses the LAN in cleartext to the Ollama
endpoint, and anything on that segment can query the model. This is acceptable
only if you trust that network segment. On a flatter or shared network, put
Ollama behind localhost + a tunnel, or a reverse proxy with a token.

**The dashboard is unauthenticated.** It assumes a trusted local network and is
not hardened for internet exposure. Do not port-forward it. If you need remote
access, use a VPN or an authenticated reverse proxy.

**No protection against a compromised host or LAN.** If the box running
Triagewall is compromised, or the trusted segment between components is hostile,
the tool offers no defense. It assumes its own execution environment is trusted.

**Resource exhaustion via oversized fields is not yet bounded.** A crafted alert
with a very large untrusted field (e.g. a multi-megabyte payload) is currently
wrapped and sent to the model as-is, which could exhaust the context window or
stall the LLM tier. Field-size capping is planned for v0.2.1.

---

## Assumptions

- The host running Triagewall is trusted and not already compromised.
- The network segment between ingest, Ollama, SQLite, and the dashboard is
  trusted.
- Suricata's ruleset, the prefilter config, and the mounted asset inventory are
  trusted inputs controlled by the operator. Asset context is supplied only in
  the LLM system prompt, and demo API responses redact it on both traffic sides.
- The operator is a single trusted user; there is no multi-user authorization
  model.
- The deployment is not exposed to the public internet.

---

## A note on example data

The benchmark results and experiment docs in this repo contain real RFC 1918
private IP addresses (10.x and 192.168.x) from the development network, visible
in model reasoning text. These are non-routable, reveal nothing reachable from
outside the LAN, and are retained because the unedited reasoning is useful
evidence for the benchmark. Masking them is tracked as a v0.2.1 cleanup item.

---

## Reporting

Found a way to break the injection hardening, or another security issue? That's
genuinely welcome — open an issue, or see [SECURITY.md](../SECURITY.md) for
responsible disclosure. Breaking Phase 2 is how Phase 3 gets designed.
