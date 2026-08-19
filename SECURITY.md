# Security Policy

For the full threat model — trust assumptions, attacker model, and known limitations — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

If you've discovered a security issue in TriageWall, please report it privately rather than opening a public issue.

**Email:** security@triagewall.io

Please include:
- A description of the issue
- Steps to reproduce
- The version of TriageWall affected (or commit hash if you're on `main`)
- Any mitigations you've identified

I aim to acknowledge reports within 72 hours and provide a remediation timeline within 7 days.

## Supported versions

Security fixes target the latest published release and the current development
branch. Older minor releases may receive a coordinated fix when the issue can
be backported safely, but they are not guaranteed ongoing support.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Current development branch | Yes |
| Older releases | Best effort |

## Deployment expectations

TriageWall assumes a single trusted operator on a private network. Two points
are frequently misread:

- **The dashboard write cookie is not user authentication.** It provides
  same-origin CSRF resistance for the built-in UI — it proves a write came from
  a page TriageWall served, not who sent it. There is no multi-user login or
  SSO. Remote access requires a VPN or an authenticated reverse proxy. Set
  `TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true` for any HTTPS deployment.
- **API IP redaction requires a secret.** With
  `TRIAGEWALL_API_REDACT_IPS=true`, addresses are replaced by an HMAC-SHA256
  pseudonym keyed with `TRIAGEWALL_API_IP_HASH_SECRET`. An unkeyed digest of an
  IP address is reversible by exhaustive search over the address space, so
  enabling redaction without a valid secret fails startup rather than implying
  protection that is not there. The secret must differ from
  `TRIAGEWALL_DASHBOARD_WRITE_SECRET` and is never logged.

See [docs/api.md](docs/api.md) for the recommended production settings.

## Scope

In scope:
- Bugs in TriageWall's ingestion, triage, or dashboard code
- Vulnerabilities in the prefilter logic
- Authentication or authorization issues in the HTTP API (API keys, scopes,
  dashboard write cookie) and related configuration
- Data leakage or information exposure

Out of scope (please report to the upstream project):
- Vulnerabilities in Wazuh, Suricata, OPNsense, or Ollama themselves
- Issues in third-party Python dependencies (use [PyPI security reporting](https://pypi.org/security/))
