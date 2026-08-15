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
| Scopes | `read`, `feedback:write`, `config:write` |
| Reads | Allowed without a key when `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true` (**default**). Set to `false` to require a key with `read` (or `feedback:write`) for read endpoints and `/metrics`. |
| Feedback writes | **Always** require a credential: an API key with `feedback:write`, or the same-origin dashboard write cookie. |
| Configuration | Every configuration endpoint requires an attributable API key with `config:write`; anonymous reads, `read`, `feedback:write`, the dashboard cookie, and demo mode never grant access. Draft mutations also require `TRIAGEWALL_CONFIG_WRITES_ENABLED=true`. |
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
TRIAGEWALL_API_KEYS=kiosk:pbkdf2_sha256$210000$<salt>$<digest>:read,operator:pbkdf2_sha256$210000$<salt>$<digest>:read|feedback:write,config-admin:pbkdf2_sha256$210000$<salt>$<digest>:config:write
TRIAGEWALL_DASHBOARD_WRITE_SECRET=<long-random-string>
TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true
TRIAGEWALL_CONFIG_WRITES_ENABLED=false
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

### Operator configuration

Configuration documents may contain private asset inventory and suppression
policy, so every endpoint below requires an `X-API-Key` carrying
`config:write`. That requirement is independent of ordinary API read settings.
Demo mode rejects configuration access even when such a key is supplied.

The dashboard exposes these operations at `/configuration`. Its administrator
key exists only in the current page's memory, is cleared from the password
field after connection, and is sent only in `X-API-Key`; navigation, URLs,
request bodies, logs, persistent browser storage, and the database never carry
it. Disconnecting or reloading the page discards the key. The editor follows
the API lifecycle explicitly: edit a structured candidate, inspect its exact
canonical JSON, create an immutable draft, validate it, run a bounded preview,
then confirm activation. Broad prefilter rules and candidates based on an older
shipped baseline require their specific acknowledgement before activation or
rollback.

`GET /api/v1/config` returns the active revision metadata for both kinds,
bundle generation, compatibility mode, revision counts, and per-consumer
reload health. Health includes each consumer's desired and loaded generation,
loaded revision pair, status age, and a bounded generic error. A missing Wazuh
row means the optional Wazuh ingest has not started; it is not synthesized as
healthy. `GET /api/v1/config/{kind}` returns the active canonical document for
`prefilter_policy` or `asset_inventory`. `GET /api/v1/config/{kind}/revisions`
lists newest-first revision metadata without documents; it accepts `state`,
`limit` (1–100), and an opaque `cursor`. The per-revision endpoint,
`GET /api/v1/config/{kind}/revisions/{id}`, retrieves one immutable document.

Draft mutation is disabled unless:

```env
TRIAGEWALL_CONFIG_WRITES_ENABLED=true
```

Enabling this without at least one configured `config:write` key fails process
startup. Draft creation requires the current active revision and generation:

```bash
curl -sS -X POST -H 'Host: localhost' -H "X-API-Key: $CONFIG_KEY" \
  -H 'X-Request-ID: change-2026-08-15-01' \
  -H 'Content-Type: application/json' \
  -d '{"document":{"version":1,"internal_cidrs":[],"auto_false_positive":[]},"parent_revision_id":1,"expected_generation":1,"note":"candidate"}' \
  http://127.0.0.1:8084/api/v1/config/prefilter_policy/drafts
```

`POST /api/v1/config/{kind}/drafts/{id}/validate` applies the production
validator. An invalid candidate becomes an immutable `rejected` revision with
a structured validation result. When normalization changes the effective
document, validation preserves the submitted draft and creates a canonical
`validated` child. Neither operation activates configuration or changes the
bundle generation.

`POST /api/v1/config/{kind}/drafts/{id}/preview` accepts
`expected_generation`, a capped time window, and a candidate limit up to
2,000. It compares only the newest eligible events, reports the examined count
and whether the sample was truncated, never calls Ollama, and never changes
verdicts or checkpoints. Prefilter previews report suppression deltas,
bounded event/signature examples, unmatched rules, and unscoped-rule warnings.
Asset previews report exact-IP match and context changes with bounded examples.

`POST /api/v1/config/{kind}/drafts/{id}/activate` requires the current
`expected_generation`. Prefilter candidates containing signature-only rules
also require `acknowledge_broad_rules=true`. Activation revalidates stored
content under `BEGIN IMMEDIATE`, checks the draft parent is still active, moves
the old and new revision states, updates both previous-bundle pointers, and
increments generation in one transaction. While the deployment remains in
`legacy` authority mode, the first successful activation atomically changes
authority to `database`; both ingest processes observe the new complete bundle
between records. A candidate based on an older packaged prefilter baseline also
requires `acknowledge_shipped_base_change=true`.

`POST /api/v1/config/{kind}/revisions/{id}/rollback` reactivates a superseded
revision through the same validation, acknowledgement, optimistic-generation,
transaction, audit, and runtime-reload path. Rollback creates a new bundle
generation; it never rewrites revision content or restores files.

`GET /api/v1/config/audit` returns newest-first audit records with `limit`
(1–100, default 50), optional `kind`, and an opaque `cursor`. Audit details are
bounded lifecycle metadata and never contain configuration documents or API
keys. All configuration responses use `Cache-Control: private, no-store` and
emit no ETag.

New verdict rows also store `config_generation`, `prefilter_revision`, and
`asset_revision`. Both ingest adapters load both documents as one immutable
bundle and verify legacy mounts while authority remains `legacy`. In `database`
mode, mounts are ignored. Startup fails closed without a valid complete bundle;
a later reload failure retains the last-known-good bundle, reports degraded
health, records bounded audit evidence, and retries with bounded backoff.

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

The verdict and configuration endpoints are the exception. `GET /api/v1/verdicts`,
`GET /api/v1/verdicts/{event_id}` and
`GET /api/v1/verdicts/{event_id}/investigation` emit
`Cache-Control: private, no-store` and **no** `ETag`, and never answer 304.
The `/api/v1/config*` family uses the same no-store policy because its private
documents and lifecycle state must not be retained by intermediaries.
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
