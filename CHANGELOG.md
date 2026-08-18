# Changelog

All notable changes to Triagewall are documented in this file.

## Unreleased

### Added

- Queue search now accepts an exact source or destination IP address and a
  historical source or destination asset hostname, while preserving signature
  search and saved `signature` query URLs. It examines a disclosed window of
  the newest 10,000 retained alerts and has a three-second query fail-safe, so
  an absent term cannot traverse the complete retained database. Search
  cursors keep that initial candidate window stable while new alerts arrive.
- A guided, standard-library-only API-key generator now produces an
  attributable `config:write` key and a Compose-safe hash-only `.env` entry for
  the configuration workspace.

## [v0.3](https://github.com/aaronphifer/triagewall/releases/tag/v0.3) - 2026-08-09

### Added

- Versioned HTTP API under `/api/v1` with Pydantic response models, OpenAPI
  `ApiKeyAuth` scheme, cursor pagination on verdicts, parameterised timeline
  (`hours`, `interval`), dedicated `/api/v1/stats`, liveness-only
  `/api/v1/health`, and Prometheus `/metrics` (stdlib text format).
- API-key authentication (`X-API-Key`) with PBKDF2-HMAC-SHA256 hashed key
  storage and scopes `read` / `feedback:write`. Writes always require a
  credential. Optional `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS`
  (default `true`) for read BC.
- Same-origin HttpOnly dashboard write cookie so the built-in UI can POST
  feedback without JavaScript changes.
- `TRIAGEWALL_API_REDACT_IPS` to produce deployment-keyed HMAC pseudonyms for
  non-local consumers. It defaults to `false`, so real IPs remain visible on
  trusted LAN deployments.
- `Cache-Control` / weak `ETag` / `If-None-Match` on poll-friendly reads, plus
  `generated_at` on v1 payloads.
- Operator docs: [docs/api.md](docs/api.md).
- A two-layer gold-set change-validation gate: deterministic production
  behavior fingerprints in CI and sanitized operator-side evaluation of both
  end-to-end and model-only metrics against human labels. The v0.3 baseline is
  approved from a complete 266-alert run and fails closed on guarded behavior,
  dataset, asset-inventory, invalid-output, kappa, or recall regressions.

### Changed

- Stats include canonical field `real` while retaining deprecated `real_`
  through **2026-12-31**.
- Unversioned `/api/*` routes remain as thin deprecated aliases for the
  existing dashboard (including `/api/health` storage metrics and the
  combined `/api/verdicts` shape). Removal target: **2026-12-31**.
- `/api/v1/*` payloads are validated against their declared response models at
  runtime before ETag calculation or serialization. Unknown typed filters now
  return 422, and free-form query and feedback inputs have explicit bounds.

### Fixed

- Suricata checkpoint writes are atomic. Corrupt, invalid, or unwritable
  checkpoints terminate ingest instead of silently rewinding or continuing
  with an undurable cursor.
- Suricata rotation recovery drains the checkpointed inode through a stable
  EOF, handles late appends and repeated rotation, bounds archive discovery,
  rejects partial scans and compressed successors, and fails closed whenever
  continuity cannot be proven.
- Reviewed-row retention authorization compares the exact feedback state in
  the verified backup through a bounded, cleanup-safe query.
- Gold-set evidence recomputes derived fingerprints and metrics, and the
  dataset revision now binds canonicalized alert content without emitting
  per-alert digests.
- Wazuh archive-day regressions now run portably across UTC-negative,
  UTC-positive, named-zone, and daylight-saving cases while retaining Linux
  coverage of the process-timezone path.

### Migration notes

1. Prefer `/api/v1/stats` for kiosk percentage cards; do not transfer verdict
   rows solely to read counters.
2. Prefer `/api/v1/verdicts` with `cursor` / `limit` for listing.
3. Configure `TRIAGEWALL_API_KEYS` with PBKDF2 digests from
   `triagewall.dashboard.api.auth.hash_api_key` before exposing the API beyond
   a trusted host. Set `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=false` when
   keys are required for reads.
4. Set a stable `TRIAGEWALL_DASHBOARD_WRITE_SECRET` in production so dashboard
   write cookies survive process restarts.
5. Clients using `real_` should switch to `real` before 2026-12-31.
6. Enabling `TRIAGEWALL_API_REDACT_IPS=true` now requires a persistent
   `TRIAGEWALL_API_IP_HASH_SECRET` of at least 32 characters. It must differ
   from the dashboard write secret.
7. Set `TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true` when the dashboard is served
   over HTTPS.
