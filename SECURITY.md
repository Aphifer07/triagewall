# Security Policy

For the full threat model — trust assumptions, attacker model, and known limitations — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

If you've discovered a security issue in Triagewall, please report it privately rather than opening a public issue.

**Email:** security@triagewall.io

Please include:
- A description of the issue
- Steps to reproduce
- The version of Triagewall affected (or commit hash if you're on `main`)
- Any mitigations you've identified

I aim to acknowledge reports within 72 hours and provide a remediation timeline within 7 days.

## Supported versions

During pre-release (current), only the latest commit on `main` is supported. Once v0.1 ships, supported versions will be documented here.

## Scope

In scope:
- Bugs in Triagewall's ingestion, triage, or dashboard code
- Vulnerabilities in the prefilter logic
- Authentication or authorization issues in the HTTP API (API keys, scopes,
  dashboard write cookie) and related configuration
- Data leakage or information exposure

Out of scope (please report to the upstream project):
- Vulnerabilities in Wazuh, Suricata, OPNsense, or Ollama themselves
- Issues in third-party Python dependencies (use [PyPI security reporting](https://pypi.org/security/))
