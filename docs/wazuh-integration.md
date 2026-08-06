# Wazuh alerts.json integration

Triagewall can optionally read Wazuh's local `alerts.json` stream on the same
Docker host. It does not use the Wazuh API, Indexer API, Docker socket, or any
Wazuh credentials. Wazuh remains the authoritative alert store.

## Requirements

- Wazuh and Triagewall run on the same Docker Engine host.
- Wazuh exposes its `/var/ossec/logs` directory through a named volume.
- Docker Engine 26 or newer and a current Docker Compose v2 release are
  required for the read-only volume `subpath` mount.
- Ollama and the private asset inventory are configured as for Suricata.

Find the volume and its numeric alerts-directory group without printing alert
content:

```bash
docker volume ls
docker volume inspect YOUR_WAZUH_LOGS_VOLUME
stat -c 'gid=%g mode=%a' /var/lib/docker/volumes/YOUR_WAZUH_LOGS_VOLUME/_data/alerts
```

The Triagewall service joins that numeric group and drops all Linux
capabilities. The volume is mounted read-only and restricted to its `alerts`
subdirectory.

## Configuration

Add private values to `.env`; do not commit deployment names or host details.
The optional Compose file must still be supplied explicitly when operating the
connector, so an ordinary `docker compose up` never depends on a Wazuh volume.

```dotenv
WAZUH_LOGS_VOLUME=your-wazuh-logs-volume
WAZUH_LOGS_GID=999
WAZUH_SOURCE_ID=your-wazuh-instance
WAZUH_MIN_LEVEL=8
WAZUH_START_MODE=end
WAZUH_POSITION_PATH=/var/lib/triagewall/wazuh-position.json
WAZUH_POLL_INTERVAL=10
TZ=UTC
```

Set `TZ` on the Triagewall wazuh-ingest service to the same timezone the
Wazuh manager uses for daily `ossec-alerts-DD` rotation. Archive day
boundaries follow that local calendar; a mismatched `TZ` can stop ingest
fail-closed at rotation.

`WAZUH_SOURCE_ID` must be a stable 1-64 character identifier using letters,
digits, dots, underscores, or hyphens. Changing it while an existing checkpoint
is present fails startup so one stream cannot silently assume another identity.

Level 8 is the recommended initial admission threshold. Lower-level records
remain available in Wazuh but are checkpointed without being copied to
Triagewall or sent to Ollama. Changing Wazuh's own `log_alert_level` is neither
required nor recommended for this integration.

`WAZUH_START_MODE` is consulted only when no Wazuh checkpoint exists. `end`
starts at the last complete record and processes new alerts; `beginning`
replays the current live file.

## Start and verify

```bash
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh config --quiet
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh up -d --build
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh ps
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh ps -a migrate
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml logs migrate
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml logs --tail=100 wazuh-ingest
```

Expected startup logs include the source identifier, minimum level, model, and
checkpoint date/offset. They never include raw Wazuh alert content or agent
names. The first `end` startup creates `wazuh-position.json` without replaying
the existing file.

The connector follows the live file and resumes through Wazuh's daily
`ossec-alerts-DD.json` or `.json.gz` archives. It stops instead of skipping when
a required archive is missing, corrupt, incomplete, or shorter than the saved
offset.

To acknowledge an unrecoverable archive gap and resume from the current end:

```bash
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh stop wazuh-ingest
mv data/wazuh-position.json data/wazuh-position.json.gap-backup
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh up -d wazuh-ingest
```

Adjust the host path in that command when `HOST_DATA_DIR` is not `./data`.
Retain the backup for incident review. Never modify Wazuh's alert volume.

## Dashboard and rollback

Wazuh verdicts carry a `wazuh` sensor badge, use `Rule` rather than `SID`, and
show the Wazuh agent when no network tuple is available. Demo mode removes the
source instance, event ID, and agent identity.

To roll back the connector without changing Wazuh or deleting Triagewall data:

```bash
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh stop wazuh-ingest
```

Omit `docker-compose.wazuh.yml` from subsequent Compose commands. The additive
source-context table and existing Wazuh verdicts are safe to leave in SQLite.
