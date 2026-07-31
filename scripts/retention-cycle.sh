#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/retention-cycle.sh --backup-dir PATH [options]

Options:
  --keep-days DAYS             Retain this many days (default: 60)
  --max-runtime-seconds SEC    Maximum full prune pause (default: 900)
  --cooldown-seconds SEC       Live catch-up time between pauses (default: 1800)
  --max-cycles COUNT           Maximum deletion pauses (default: 12)
  --wazuh                      Include docker-compose.wazuh.yml and wazuh-ingest
  --health-url URL             Dashboard health endpoint
  --help                       Show this help

Run this script from the repository root. For an SSH-independent job, launch it
with systemd-run as documented in README.md.
EOF
}

keep_days=60
max_runtime_seconds=900
cooldown_seconds=1800
max_cycles=12
with_wazuh=false
health_url="http://127.0.0.1:8084/api/health"
backup_dir=""

while (($#)); do
  case "$1" in
    --backup-dir)
      backup_dir="${2:-}"
      shift 2
      ;;
    --keep-days)
      keep_days="${2:-}"
      shift 2
      ;;
    --max-runtime-seconds)
      max_runtime_seconds="${2:-}"
      shift 2
      ;;
    --cooldown-seconds)
      cooldown_seconds="${2:-}"
      shift 2
      ;;
    --max-cycles)
      max_cycles="${2:-}"
      shift 2
      ;;
    --wazuh)
      with_wazuh=true
      shift
      ;;
    --health-url)
      health_url="${2:-}"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "retention cycle: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for value_name in keep_days max_runtime_seconds cooldown_seconds max_cycles; do
  value="${!value_name}"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value < 1)); then
    echo "retention cycle: $value_name must be a positive integer" >&2
    exit 2
  fi
done

if [[ -z "$backup_dir" ]]; then
  echo "retention cycle: --backup-dir is required" >&2
  exit 2
fi
if [[ ! -d "$backup_dir" || ! -w "$backup_dir" ]]; then
  echo "retention cycle: backup directory must exist and be writable: $backup_dir" >&2
  exit 2
fi
if [[ ! -f docker-compose.yml ]]; then
  echo "retention cycle: run from the Triagewall repository root" >&2
  exit 2
fi
for required_command in curl date docker flock id python3 realpath stat; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "retention cycle: $required_command is required" >&2
    exit 2
  fi
done

lock_path="${TRIAGEWALL_RETENTION_LOCK:-/run/lock/triagewall-retention-cycle.lock}"
exec 9>"$lock_path"
if ! flock -n 9; then
  echo "retention cycle: another retention cycle holds $lock_path" >&2
  exit 1
fi

umask 077
backup_dir="$(realpath "$backup_dir")"
backup_owner="$(stat -c %u "$backup_dir")"
backup_mode="$(stat -c %a "$backup_dir")"
if [[ "$backup_owner" != "$(id -u)" ]] \
  || (( (8#$backup_mode & 0022) != 0 )); then
  echo "retention cycle: backup directory must be owned by the runner and not group/world-writable" >&2
  exit 2
fi
export HOST_BACKUP_DIR="$backup_dir"

compose=(docker compose -f docker-compose.yml)
profiles=(--profile maintenance)
writers=(dashboard ingest)
if "$with_wazuh"; then
  if [[ ! -f docker-compose.wazuh.yml ]]; then
    echo "retention cycle: docker-compose.wazuh.yml is missing" >&2
    exit 2
  fi
  compose+=(-f docker-compose.wazuh.yml)
  profiles+=(--profile wazuh)
  writers+=(wazuh-ingest)
fi

compose_with_profiles=("${compose[@]}" "${profiles[@]}")
writers_stopped=false

start_writers() {
  "${compose_with_profiles[@]}" start "${writers[@]}"
  writers_stopped=false
}

recover_writers() {
  status=$?
  trap - EXIT INT TERM HUP
  if "$writers_stopped"; then
    echo "retention cycle: restoring monitoring services after exit" >&2
    "${compose_with_profiles[@]}" start "${writers[@]}" || true
  fi
  exit "$status"
}
trap recover_writers EXIT INT TERM HUP

stop_writers() {
  writers_stopped=true
  "${compose_with_profiles[@]}" stop -t 60 "${writers[@]}"
}

all_writers_running() {
  local running_services
  local writer
  running_services="$("${compose_with_profiles[@]}" ps --status running --services)"
  for writer in "${writers[@]}"; do
    if ! grep -Fxq "$writer" <<<"$running_services"; then
      return 1
    fi
  done
}

wait_for_recovery() {
  local attempt
  for attempt in {1..18}; do
    if all_writers_running \
      && curl -fsS -H "Host: localhost" "$health_url" >/dev/null; then
      echo "retention cycle: monitoring services and dashboard are healthy"
      return 0
    fi
    sleep 10
  done
  echo "retention cycle: dashboard health check failed: $health_url" >&2
  return 1
}

if ! all_writers_running; then
  echo "retention cycle: all selected writers must be running before start" >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cutoff="$(date -u -d "$keep_days days ago" +%Y-%m-%dT%H:%M:%S.000000Z)"
backup_name="triage-before-retention-${stamp}.db"
manifest_name="${backup_name}.manifest.json"
provenance_name="${backup_name}.provenance.json"
backup_host_path="$backup_dir/$backup_name"
manifest_host_path="$backup_dir/$manifest_name"
provenance_host_path="$backup_dir/$provenance_name"
backup_container_path="/var/backups/triagewall/$backup_name"
manifest_container_path="/var/backups/triagewall/$manifest_name"

if [[ -e "$backup_host_path" || -e "$manifest_host_path" \
  || -e "$provenance_host_path" ]]; then
  echo "retention cycle: generated backup, provenance, or manifest name already exists" >&2
  exit 1
fi

echo "retention cycle: cutoff=$cutoff backup=$backup_host_path"
echo "retention cycle: stopping writers for backup copy"
stop_writers
"${compose_with_profiles[@]}" run --rm --no-deps maintenance \
  backup \
  --output "$backup_container_path" \
  --confirm-writers-stopped \
  --json

echo "retention cycle: backup copy complete; restoring monitoring"
start_writers
wait_for_recovery

echo "retention cycle: verifying immutable backup while monitoring is live"
"${compose_with_profiles[@]}" run --rm --no-deps maintenance \
  verify-backup \
  --backup "$backup_container_path" \
  --manifest "$manifest_container_path" \
  --json

cycle=1
while ((cycle <= max_cycles)); do
  result_host_path="$backup_dir/retention-result-${stamp}-${cycle}.json"
  result_container_manifest="$manifest_container_path"
  echo "retention cycle: starting bounded prune pause $cycle/$max_cycles"
  stop_writers
  if ! "${compose_with_profiles[@]}" run --rm --no-deps maintenance \
    prune \
    --before "$cutoff" \
    --apply \
    --confirm-writers-stopped \
    --verified-backup-manifest "$result_container_manifest" \
    --max-runtime-seconds "$max_runtime_seconds" \
    --json >"$result_host_path"; then
    echo "retention cycle: prune pause $cycle failed" >&2
    exit 1
  fi

  start_writers
  wait_for_recovery

  read -r eligible_rows deleted_rows stopped_reason orphan_cleanup_deferred < <(
    python3 - "$result_host_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
orphan_cleanup_deferred = payload["result"]["orphan_cleanup_deferred"]
if not isinstance(orphan_cleanup_deferred, bool):
    raise TypeError("orphan_cleanup_deferred must be a boolean")
print(
    int(payload["plan"]["eligible_rows"]),
    int(payload["result"]["deleted_rows"]),
    payload["result"]["stopped_reason"],
    "true" if orphan_cleanup_deferred else "false",
)
PY
  )
  echo "retention cycle: pause=$cycle eligible=$eligible_rows deleted=$deleted_rows reason=$stopped_reason orphan_cleanup_deferred=$orphan_cleanup_deferred"
  if [[ "$stopped_reason" == "exhausted" ]]; then
    if [[ "$orphan_cleanup_deferred" == "false" ]]; then
      echo "retention cycle: retention target exhausted successfully"
      break
    fi
    echo "retention cycle: orphan cleanup deferred; scheduling another pause"
  elif ((deleted_rows < 1)); then
    echo "retention cycle: no forward deletion progress; refusing to loop" >&2
    exit 1
  fi

  ((cycle += 1))
  if ((cycle <= max_cycles)); then
    echo "retention cycle: monitoring live for ${cooldown_seconds}s before next pause"
    sleep "$cooldown_seconds"
  fi
done

if ((cycle > max_cycles)); then
  echo "retention cycle: maximum prune pauses reached before exhaustion" >&2
  exit 1
fi

echo "retention cycle: completed; verified backup retained at $backup_host_path"
echo "retention cycle: backup provenance retained at $provenance_host_path"
