# Triagewall HTTP API

Stable contract for clients that consume Triagewall outside the built-in
dashboard (kiosks, scrapers, automations). The dashboard process serves both
the HTML UI and this JSON API.

**Deprecation:** unversioned `/api/*` aliases and the stats field `real_` are
scheduled for removal on **2026-12-31**. Prefer `/api/v1/*` and the field
`real`.

## Authentication

| Concern | Mechanism |
|---------|-----------|
| Header | `X-API-Key: <plaintext>` |
| Storage | Keys are configured as **PBKDF2-HMAC-SHA256** digests only
  (`TRIAGEWALL_API_KEYS`). Plaintext keys are never stored or logged. |
| Scopes | `read`, `feedback:write` |
| Reads | Allowed without a key when `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true` (**default**). Set to `false` to require a key with `read` (or `feedback:write`) for read endpoints and `/metrics`. |
| Writes | **Always** require a credential: an API key with `feedback:write`, or the same-origin dashboard write cookie. |
| Dashboard cookie | Serving `GET /` sets HttpOnly `SameSite=Strict` cookie `tw_dash_write` derived from `TRIAGEWALL_DASHBOARD_WRITE_SECRET`. The built-in UI does not need JS changes. External clients must use `X-API-Key`. |
| Health | `GET /api/v1/health` is always unauthenticated and omits storage metrics. |

### Configuring a key

```bash
# Generate a plaintext key and a PBKDF2 digest (store only the digest in env):
python -c "from triagewall.dashboard.api.auth import hash_api_key; import secrets; k=secrets.token_urlsafe(32); print(k); print(hash_api_key(k))"
```

```env
TRIAGEWALL_API_KEYS=kiosk:pbkdf2_sha256$210000$<salt>$<digest>:read,operator:pbkdf2_sha256$210000$<salt>$<digest>:read|feedback:write
TRIAGEWALL_DASHBOARD_WRITE_SECRET=<long-random-string>
TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true
```
## IP exposure

Responses may include internal `src_ip` / `dest_ip` values and SPC `ip`
fields. Default: **no redaction** (`TRIAGEWALL_API_REDACT_IPS=false`) so
on-LAN operators see real addresses. Set `TRIAGEWALL_API_REDACT_IPS=true` to
replace IPs with truncated SHA-256 digests (`ip_<12 hex chars>`). Demo mode
continues to apply its stricter masking independently.

## Endpoints

### `GET /api/v1/health`

Liveness only. No auth. Returns `{status, last_alert_age_seconds, generated_at}`.
HTTP 503 when the newest alert is older than `STALE_THRESHOLD_SECONDS`.

```bash
curl -sS -H 'Host: localhost' http://127.0.0.1:8084/api/v1/health
```

### `GET /api/v1/stats`

Summary counters for the rolling 24h window plus lifetime total. Includes
canonical `real` and deprecated `real_`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/stats
```

### `GET /api/v1/verdicts`

Verdict rows only (no stats). Query params: `verdict`, `signature`, `model`
(`llm`|`prefilter`), `limit` (1–500, default 100), `cursor` (opaque).

Response: `{generated_at, mode, verdicts, next_cursor}`. Pass `next_cursor`
as `cursor` for the next page. Cursor is opaque over `(processed_at, id)`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/verdicts?limit=50&model=llm'
```

### `POST /api/v1/feedback/{event_id}`

Body: `{"human_verdict":"real"|"false_positive"|"uncertain","notes":""}`.
Requires `feedback:write` (or dashboard cookie). Disabled in demo mode.

```bash
curl -sS -X POST -H 'Host: localhost' -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"human_verdict":"false_positive"}' \
  http://127.0.0.1:8084/api/v1/feedback/1
```

### `GET /api/v1/timeline`

Hourly buckets. Query: `hours` (1–168, default 24), `interval` (`1h` only in
v1). Response wraps buckets with `generated_at`, `hours`, and `interval`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/timeline?hours=24&interval=1h'
```

### `GET /api/v1/spc-anomalies`

Recent SPC anomalies plus `count_24h` when the table exists.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/spc-anomalies
```

### `GET /metrics`

Prometheus text exposition. Auth follows the unauthenticated-reads toggle.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/metrics
```

## Caching

Read endpoints that are safe to poll emit `Cache-Control: private, max-age=…`
and a weak `ETag`. Send `If-None-Match` to receive HTTP 304 when unchanged.
Stats/timeline/SPC results also use short in-process TTL caches. Payloads
include `generated_at` (UTC).

## Deprecated aliases

| Alias | Behavior |
|-------|----------|
| `GET /api/health` | Like v1 health **plus** `storage` metrics (dashboard UI depends on this). |
| `GET /api/verdicts` | Combined `{mode, stats, verdicts}` without cursor pagination. |
| `GET /api/timeline` | Bare JSON array of buckets (24h / 1h). |
| `GET /api/spc-anomalies` | Same data as v1 (includes `generated_at`). |
| `POST /api/feedback/{id}` | Same as v1 write path (auth required). |

Removal target: **2026-12-31**.
