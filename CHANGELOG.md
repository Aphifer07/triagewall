# Changelog

All notable changes to Triagewall are documented in this file.

## Unreleased

### Added

- Versioned HTTP API under `/api/v1` with Pydantic response models, OpenAPI
  `ApiKeyAuth` scheme, cursor pagination on verdicts, parameterised timeline
  (`hours`, `interval`), dedicated `/api/v1/stats`, liveness-only
  `/api/v1/health`, and Prometheus `/metrics` (stdlib text format).
- API-key authentication (`X-API-Key`) with hashed key storage and scopes
  `read` / `feedback:write`. Writes always require a credential. Optional
  `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS` (default `true`) for read BC.
- Same-origin HttpOnly dashboard write cookie so the built-in UI can POST
  feedback without JavaScript changes.
- `TRIAGEWALL_API_REDACT_IPS` to hash IPs for non-local consumers (default
  `false` — real IPs remain visible on trusted LAN deployments).
- `Cache-Control` / weak `ETag` / `If-None-Match` on poll-friendly reads, plus
  `generated_at` on v1 payloads.
- Operator docs: [docs/api.md](docs/api.md).

### Changed

- Stats include canonical field `real` while retaining deprecated `real_`
  through **2026-12-31**.
- Unversioned `/api/*` routes remain as thin deprecated aliases for the
  existing dashboard (including `/api/health` storage metrics and the
  combined `/api/verdicts` shape). Removal target: **2026-12-31**.

### Migration notes

1. Prefer `/api/v1/stats` for kiosk percentage cards; do not transfer verdict
   rows solely to read counters.
2. Prefer `/api/v1/verdicts` with `cursor` / `limit` for listing.
3. Configure `TRIAGEWALL_API_KEYS` (SHA-256 hex of plaintext) before exposing
   the API beyond a trusted host. Set
   `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=false` when keys are required
   for reads.
4. Set a stable `TRIAGEWALL_DASHBOARD_WRITE_SECRET` in production so dashboard
   write cookies survive process restarts.
5. Clients using `real_` should switch to `real` before 2026-12-31.
