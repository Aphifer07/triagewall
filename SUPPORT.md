# TriageWall support

TriageWall is an open-source project maintained in public. Support is
best-effort and prioritizes reproducible bugs, security issues, and documented
release behavior.

## Where to ask

- **Questions and setup help:** use
  [GitHub Discussions](https://github.com/aaronphifer/triagewall/discussions).
- **Reproducible bugs:** use the structured
  [bug-report form](https://github.com/aaronphifer/triagewall/issues/new/choose).
- **Focused feature requests:** check the [roadmap](ROADMAP.md), then use the
  feature-request form.
- **Security vulnerabilities:** follow [SECURITY.md](SECURITY.md) and report
  privately. Never include vulnerabilities or sensitive alert evidence in a
  public issue.
- **Commercial licensing:** contact `licensing@triagewall.io`.

## What to include

Provide the release tag or commit SHA, deployment mode, OS and Docker Compose
versions, browser details for UI issues, Ollama version/model when relevant,
minimal reproduction steps, expected behavior, and sanitized bounded logs.

Do not post API keys, raw production alerts, private asset inventories, internal
hostnames, complete environment files, or other identifying telemetry.

## Support boundary

The latest released version receives priority. The current release supports the
documented Docker Compose v2 Core deployment and the optional same-host Wazuh
profile. Custom reverse proxies, identity providers, orchestration platforms,
models, and modified schemas can be discussed, but are not guaranteed support
targets unless the problem reproduces on the documented configuration.

Upstream Suricata, Wazuh, Ollama, Docker, operating-system, firewall, and model
issues should be reported to those projects. TriageWall is decision support; it
does not provide emergency monitoring or incident-response services.
