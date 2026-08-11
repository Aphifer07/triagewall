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

### The dashboard write cookie is not user authentication

API keys identify a caller. The dashboard write cookie does not. It is
**same-origin CSRF resistance for the trusted built-in interface**: it proves a
write came from a page Triagewall itself served, not that a particular user is
signed in. Every browser that can load the dashboard receives one.

That is deliberate — Triagewall targets a single trusted operator on a private
network — but it means the cookie is not a substitute for network controls.
**Remote access still requires a VPN or an authenticated reverse proxy.** There
is no multi-user login or SSO.

Cookie attributes: `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` when
`TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true`. Enable that whenever the dashboard
is reached over HTTPS so the browser will not send it over plaintext.

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

### Recommended production settings

The compatibility defaults favour a first-run experience on a trusted LAN. For
anything beyond that, set all of:

```env
TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=false
TRIAGEWALL_API_REDACT_IPS=true
TRIAGEWALL_API_IP_HASH_SECRET=<persistent-random-secret>
TRIAGEWALL_DASHBOARD_WRITE_SECRET=<persistent-random-secret>
TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true
```

The two secrets must be different from each other, and both must be persistent —
regenerating them invalidates open dashboard sessions and changes every IP
pseudonym.

## IP exposure

Responses may include internal `src_ip` / `dest_ip` values and SPC `ip` fields.
Default: **no redaction** (`TRIAGEWALL_API_REDACT_IPS=false`) so on-LAN
operators see real addresses.

Set `TRIAGEWALL_API_REDACT_IPS=true` to replace them with a **keyed
pseudonym**:

- Construction: `HMAC-SHA256(secret, "triagewall/api/ip-pseudonym/v1" || 0x00 ||
  address)`, rendered as `ip_` followed by the leading 32 hex characters.
- The secret comes from `TRIAGEWALL_API_IP_HASH_SECRET` (minimum 32
  characters). It is never logged and never appears in any error message.
- It **must differ** from `TRIAGEWALL_DASHBOARD_WRITE_SECRET`; reusing one
  secret for both means disclosing either compromises both.
- **Startup fails** if redaction is enabled without a valid secret. An unsalted
  digest of an IP address is not redaction — the address space is small enough
  to enumerate offline — so Triagewall refuses to imply protection it is not
  providing.
- Pseudonyms are deterministic within a deployment, so correlation across
  responses still works. Changing the secret changes every pseudonym.
- Verdict `reasoning`, operator `human_notes`, retained `raw_alert`, and both
  `asset_context` snapshots are omitted while redaction is enabled. Those are
  free-form channels that can repeat endpoint addresses or contain additional
  inventory addresses; withholding them keeps the boundary fail-closed rather
  than implying that changing only `src_ip` / `dest_ip` sanitized the row.

Demo mode continues to apply its stricter masking independently of this
setting.

## Endpoints

### `GET /api/v1/health`

Liveness only. No auth. Returns `{status, last_alert_age_seconds, generated_at}`.
HTTP 503 when the newest alert is older than `STALE_THRESHOLD_SECONDS`.

```bash
curl -sS -H 'Host: localhost' http://127.0.0.1:8084/api/v1/health
```

### `GET /api/v1/stats`

Summary counters for the rolling 24h window plus lifetime total. Includes
canonical `real` and deprecated `real_`. The model-only queue fields
`model_real_count`, `model_fp_count`, `model_uncertain_count`, and
`unreviewed_model_count` exclude deterministic prefilter decisions so the
operator queue can display source-of-truth totals rather than counts from only
the currently loaded page.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/stats
```

### `GET /api/v1/verdicts`

Verdict rows only (no stats).

| Param | Type | Bound |
|-------|------|-------|
| `verdict` | enum | `real` \| `false_positive` \| `uncertain` |
| `model` | enum | `llm` \| `prefilter` |
| `source` | enum | `suricata` \| `wazuh` |
| `review` | enum | `unreviewed` \| `agreed` \| `corrected` |
| `signature` | string | ≤ 200 characters (substring match) |
| `limit` | integer | 1–500, default 100 |
| `cursor` | opaque string | ≤ 512 characters |

Filter values are typed: an unrecognized `verdict`, `model`, `source`, or `review` returns **422**
rather than silently behaving like no filter. Values over a documented bound
also return 422.

Response: `{generated_at, mode, verdicts, next_cursor}`. Pass `next_cursor`
as `cursor` for the next page. Cursor is opaque over `(processed_at, id)`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/verdicts?limit=50&model=llm'
```

### `GET /api/v1/verdicts/{event_id}`

One complete decision for the routed alert-detail view. Response:
`{generated_at, mode, verdict}`. Unlike the bounded list endpoint, the detail
row includes the stored `raw_alert` sensor record when local-mode disclosure
policy permits it. Demo mode and API IP-redaction mode continue to omit that
field. IP-redaction mode also omits reasoning, operator notes, and asset
snapshots as described under **IP exposure**.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/verdicts/1
```

### `GET /api/v1/verdicts/{event_id}/investigation`

Bounded recurrence, related activity, and queue-aware neighbours for one alert.
Additive: it does not change `/api/v1/verdicts` or
`/api/v1/verdicts/{event_id}`.

| Param | Type | Bound |
|-------|------|-------|
| `hours` | integer | 1–24, default 24 |
| `verdict` | enum | `real` \| `false_positive` \| `uncertain` |
| `model` | enum | `llm` \| `prefilter` |
| `source` | enum | `suricata` \| `wazuh` |
| `review` | enum | `unreviewed` \| `agreed` \| `corrected` |
| `signature` | string | ≤ 200 characters (substring match) |

The filter parameters are the ones `/api/v1/verdicts` accepts, and they apply
only to `neighbors`, so previous/next stay inside the queue the analyst was
working from. An unknown event id returns **404**; unrecognized filter values
and an out-of-bound `hours` return **422**.

Response: `{generated_at, mode, event_id, window_hours, window_start,
recurrence, related, neighbors}`.

**`recurrence`** counts events sharing this alert's `(source type, signature
id)` inside the bounded candidate set. The source qualifier is load-bearing:
Suricata stores its SID in `signature_id` while Wazuh stores `rule.id` there,
so an unqualified group would merge two unrelated rules that happen to share an
integer. Rows predating source provenance are counted as Suricata. A row with
no `signature_id` has no group and reports `available: false`. `exact`,
`truncated`, `candidate_limit`, and `candidates_examined` state whether the
count covers the whole window or only its newest candidates.

**`related`** is a list of groups, each carrying `relationship`, a human
`label`, a `reason` explaining the link, and the honest scope of the query
behind it:

| Group | `exact` | Scope |
|-------|---------|-------|
| `same_rule` | conditional | Exact equality on `(source type, signature id)` inside the bounded candidate set. |
| `same_source_ip` | `false` | Exact `src_ip` equality, matched inside a bounded candidate set. |
| `same_destination_ip` | `false` | Exact `dest_ip` equality, matched inside a bounded candidate set. |

All correlation views examine at most `candidate_limit` (2000) of the newest
events in the window, selected through the `processed_at` index.
`candidates_examined` reports how many were read. `truncated: true` means an
additional row proved that older events in the window were not examined, so
recurrence counts and every related group are partial. When the candidate query
exhausts the window, recurrence and `same_rule` report `exact: true`; address
groups remain non-causal bounded matches. Each group returns at most 10 alerts.

An address match is a shared-addressing observation, not a causal finding.

**`neighbors`** is `{previous, next, filters}` in the queue's own order
(`processed_at DESC NULLS LAST, id DESC`). `previous` is the newer neighbour and
`next` the older one; either is `null` at a queue edge or when the filters
exclude every candidate. `filters` echoes what the neighbours were resolved
against.

Addresses inside `related` follow the same disclosure policy as verdict rows:
demo mode masks them, and API IP-redaction mode pseudonymizes them.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/verdicts/1/investigation?hours=24&model=llm'
```

### `POST /api/v1/feedback/{event_id}`

Body: `{"human_verdict":"real"|"false_positive"|"uncertain","notes":""}`.
`notes` is limited to 2000 characters; unknown body fields are rejected.
Requires `feedback:write` (or dashboard cookie). Disabled in demo mode.

```bash
curl -sS -X POST -H 'Host: localhost' -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"human_verdict":"false_positive"}' \
  http://127.0.0.1:8084/api/v1/feedback/1
```

### `GET /api/v1/timeline`

Hourly buckets. Query: `hours` (1–168, default 24), `interval` (typed enum;
`1h` is the only accepted value in v1 — anything else is a 422). Response wraps
buckets with `generated_at`, `hours`, and `interval`.

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

## Response contract enforcement

Every `/api/v1/*` response is validated against its declared Pydantic model
**at runtime**, before the ETag is computed and before anything is written to
the wire. The response models use `extra="forbid"`, so an undocumented field or
a wrong type is a server-side failure (HTTP 500) rather than something that
silently leaks into the stable contract.

One deliberate exception: the `asset_context.source` and
`asset_context.destination` objects stay free-form dictionaries. Their contents
come from the operator's own asset inventory, so Triagewall does not invent a
schema for fields it does not define.

## Caching

Read endpoints that are safe to poll emit `Cache-Control: private, max-age=…`
and a weak `ETag`. The ETag is derived from the **validated** representation,
so it always matches the bytes actually served. Send `If-None-Match` to receive
HTTP 304 when unchanged. Stats/timeline/SPC results also use short in-process
TTL caches. Payloads include `generated_at` (UTC).

The verdict endpoints are the exception. `GET /api/v1/verdicts`,
`GET /api/v1/verdicts/{event_id}` and
`GET /api/v1/verdicts/{event_id}/investigation` emit
`Cache-Control: private, no-store` and **no** `ETag`, and never answer 304.
Saving operator feedback rewrites the underlying row, so a stored or
revalidated copy would report a reviewed alert as unreviewed. Stats, timeline,
SPC and health keep their existing caching, as does the deprecated
`GET /api/verdicts` alias, whose shape and headers are frozen until removal.

## Deprecated aliases

| Alias | Behavior |
|-------|----------|
| `GET /api/health` | Like v1 health **plus** `storage` metrics (dashboard UI depends on this). |
| `GET /api/verdicts` | Combined `{mode, stats, verdicts}` without cursor pagination. |
| `GET /api/timeline` | Bare JSON array of buckets (24h / 1h). |
| `GET /api/spc-anomalies` | Same data as v1 (includes `generated_at`). |
| `POST /api/feedback/{id}` | Same as v1 write path (auth required). |

The aliases keep their historical behaviour until removal: their shapes are
frozen, and unrecognized filter values are still ignored rather than rejected.
New clients should use `/api/v1/*`, where those values are 422s.

Removal target: **2026-12-31**.
