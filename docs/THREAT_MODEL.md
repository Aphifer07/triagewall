# Threat model

This document describes the trust assumptions and known limitations of the
currently shipped **Triagewall Core** application. Triagewall Lab is a future
component with a separate threat model and graduation gate; see
[Core and Lab product boundary](core-lab-product-boundary.md).

Triagewall targets a single trusted operator running services on a private
homelab network. It is not a multi-tenant or internet-facing application.

## What Core does

Core is a decision-support layer between Suricata and, optionally, Wazuh alert
streams and a human operator. It:

- applies validated deterministic policy to eligible Suricata alerts;
- sends remaining Suricata alerts and admitted Wazuh alerts to a local Ollama
  model through source-specific isolated prompts;
- attaches exact-IP matches from a private trusted asset inventory;
- stores verdicts, source provenance, asset snapshots, failures, checkpoints,
  and operator feedback in local persistent storage;
- serves a local dashboard and JSON API.

Core does not block traffic, change sensor rules, invoke Wazuh Active Response,
or take autonomous action.

## Data flow and trust boundaries

```text
[ Suricata eve.json ] --> [ Suricata adapter ] --+
                                                  |
[ Wazuh alerts.json ] --> [ Wazuh adapter ] -----+--> [ normalized event ]
                                                           |
                                     [ trusted asset and policy config ]
                                                           |
                              Suricata scoped prefilter or local Ollama
                                                           |
                                                        [ SQLite ]
                                                           |
                                                   [ local dashboard ]
```

The important boundaries are:

1. **Sensors to adapters.** Records are untrusted input. Suricata validates its
   required timestamp and rule identity plus every optional flow, IP, port,
   protocol, severity, and bounded rule-text field it consumes. Wazuh validates
   its required timestamp, event identity, rule identity, and level, and
   normalizes valid optional network fields. Free text, unknown fields, agent
   names, descriptions, URLs, hostnames, payloads, TLS/DNS data, and Wazuh
   `data.*` values remain attacker- or environment-controlled evidence.
2. **Operator configuration to Core.** The mounted prefilter and asset
   inventory are trusted operator inputs, but they are still schema-, size-,
   type-, and ambiguity-validated. Invalid configured files fail startup.
3. **Core to Ollama.** Only source identity, typed severity guidance, prompt
   policy, and validated asset context enter trusted system context. Sensor
   evidence stays in the isolated user evidence block. Ollama traffic is
   unencrypted HTTP unless the operator adds a protected transport.
4. **Writers to SQLite.** Verdict, asset snapshots, and source provenance are
   committed together. Retryable model or persistence failures do not advance
   the relevant checkpoint.
5. **Dashboard to operator.** The dashboard validates configured Host values
   and is intended for a trusted private network. The JSON API may require
   API keys (and always requires a credential for writes); the HTML UI uses a
   same-origin write cookie rather than multi-user login.

## Attacker model

The primary adversary can influence sensor evidence by sending crafted network
traffic or generating endpoint activity that appears in Suricata or Wazuh
alerts. Their goals may include:

- prompt injection that forces a benign verdict or attacker-selected output;
- malformed or oversized records that cause gaps, retries, or resource
  exhaustion;
- duplicate or conflicting event identity;
- hostile strings that become HTML, logs, CSV formulas, or model instructions;
- discovery of private asset or agent context through demo responses.

An adversary with code execution on the Triagewall host, control of operator
configuration, control of the trusted network between Core and Ollama, or
control of the sensor ruleset is outside this threat model.

## Defenses

### Prompt and response isolation

Suricata uses a fail-closed typed allowlist: only explicitly trusted structured
sensor fields remain plain; unknown and free-text fields are base64-wrapped with
explicit untrusted-data boundaries. Allowlisted Suricata IP addresses, ports,
protocols, and signature IDs also require valid values before they remain
plain. Wazuh uses a source-specific projection in which free text, descriptions,
agent identity, location, groups, decoder data, `full_log`, and nested `data`
strings are isolated as untrusted evidence.

A per-process canary is included in the system prompt. Raw and decoded model
output is checked for that canary. A leaked canary causes a conservative
security verdict rather than accepting the requested output.

The complete model response must be one JSON object with exactly the expected
keys and valid types. Truncated, salvaged, extra-key, or otherwise malformed
responses fail closed.

### Input and configuration bounds

- Wazuh records are limited to 1 MiB and its model-evidence projection to
  32 KiB. Oversized complete records are hashed, quarantined with bounded
  diagnostics, and checkpointed without reaching Ollama.
- Wazuh descriptions and agent fields have explicit length limits.
- Suricata signature and rule-text fields have explicit length limits; invalid
  rule identity, network tuple, protocol, severity, and flow identity values
  are durably quarantined before model or database use.
- Asset inventory and prefilter files are each limited to 1 MiB and have
  bounded collection and text fields.
- Two-sided trusted asset prompt context is limited to 2 KiB.
- Wazuh source identity, rule fields, IP addresses, ports, protocols, and
  checkpoint documents are validated before use.

### Persistence and recovery

- Incomplete append-in-place records remain uncheckpointed and use the normal
  polling backoff.
- Retryable Ollama and SQLite failures block later records and leave the failed
  record uncheckpointed.
- Intentional skips, duplicates, and durably quarantined malformed input may
  advance the checkpoint.
- Wazuh checkpoints are written atomically and bind to the configured source
  instance. Missing or corrupt required rotation archives fail closed rather
  than silently skipping a gap.
- New Wazuh identities are deduplicated by source type, source instance, and
  source event ID. Instance-less identities use a separate unique constraint.

### Operator-facing output

- Dashboard values are HTML-escaped.
- Demo mode masks private network addresses and removes model reasoning, asset
  inventory data, agent identity, event identity, SPC notes, and other private
  context.
- Benchmark CSV output neutralizes formula-capable cells.
- Application logs avoid raw Wazuh alerts and private agent data.

## Known limitations

**Isolation reduces risk; it does not prove model safety.** Encapsulation,
canary detection, and schema validation raise the cost of prompt injection but
do not make an LLM a security boundary. Adversarial regression work remains
required.

**The prefilter deliberately trades coverage for volume.** A matching rule is
auto-classified without Ollama review. Contextual conditions reduce the blast
radius, and missing required context does not match, but legacy global SID
rules remain supported. Operators must review suppressions conservatively.

**False negatives are expected.** The local model is fallible. Triagewall
reduces review volume; it does not replace the underlying sensor or a human
analyst.

**Suricata record size is not globally bounded yet.** Wazuh has record and
projection limits, but an unusually large complete Suricata JSONL record can
still consume memory and model context. Adding a bounded Suricata reader and
prompt projection remains hardening work.

**Ollama transport is unencrypted and unauthenticated by default.** Use
localhost, a tunnel, a private segmented network, or an authenticated proxy
when the network between Core and Ollama is not fully trusted.

**The dashboard UI is not multi-user SSO.** Host validation is not user
authentication. Do not port-forward the dashboard; use a VPN or authenticated
reverse proxy for remote access. The JSON API supports optional API-key auth
(`X-API-Key`, hashed keys, scopes `read` / `feedback:write`) and a same-origin
HttpOnly write cookie for the built-in UI. Writes always require a credential.
Unauthenticated reads remain available only when
`TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true` (default). See
[docs/api.md](api.md).

**Retention remains an operator-controlled maintenance action.** The bounded,
backup-first host runner restores monitoring between short deletion pauses and
fails closed when its safety evidence is missing. It does not choose a site's
retention window, delete reviewed verdicts by default, shrink the database
file, or replace off-host backup policy. High-volume installations should use
SSD-class active storage and keep verified backups on a separate failure
domain.

**Startup serialization depends on the Compose boundary.** The one-shot
`migrate` service is the sole schema owner and all shipped consumers wait for
its successful completion. Directly launching an ingest script outside
Compose requires the operator to run `triagewall/migrate.py` first; consumers
then verify the schema read-only and fail closed rather than repairing it.

## Assumptions

- The Triagewall host and operator-controlled configuration are trusted.
- Suricata and Wazuh remain the authoritative detection and alert stores.
- The network between Core components and Ollama is private and trusted unless
  the operator adds transport protection.
- Core is not exposed directly to the public internet.
- There is one trusted operator and no multi-user authorization model.

## Example and demo data

Tracked fixtures and experiment material are intended to be synthetic or
sanitized. Demo API responses apply additional redaction at runtime. Do not
commit production alerts, private inventories, checkpoints, packet captures,
or populated databases.

## Reporting

Report security issues according to [SECURITY.md](../SECURITY.md). Prompt-
injection bypasses, checkpoint gaps, identity collisions, cross-source context
leaks, and unsafe configuration behavior are all in scope.
