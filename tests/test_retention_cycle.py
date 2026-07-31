#!/usr/bin/env python3
"""Linux integration tests for the unattended retention host runner."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "retention-cycle.sh"


@unittest.skipUnless(
    os.name == "posix" and Path("/bin/bash").is_file(),
    "host-runner integration requires Linux bash",
)
class RetentionCycleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.backup_dir = self.root / "backups"
        self.backup_dir.mkdir()
        (self.root / "docker-compose.yml").write_text(
            "services: {}\n",
            encoding="utf-8",
        )
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.docker_log = self.root / "docker.log"
        self.curl_log = self.root / "curl.log"
        self.timeout_log = self.root / "timeout.log"
        self._write_executable(
            "curl",
            """#!/bin/sh
printf '%s' "$*" | tr '\n' ' ' >>"$FAKE_CURL_LOG"
printf '\n' >>"$FAKE_CURL_LOG"
status="${FAKE_HEALTH_STATUS:-200}"
case "$status" in
  200) health=ok ;;
  503) health=stale ;;
  *) health=error ;;
esac
printf '{"status":"%s","storage":{}}\n%s' "$health" "$status"
exit 0
""",
        )
        self._write_executable(
            "sleep",
            """#!/bin/sh
exit 0
""",
        )
        self._write_executable(
            "timeout",
            """#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_TIMEOUT_LOG"
while [ "${1#--}" != "$1" ]; do
  shift
done
shift
exec "$@"
""",
        )
        self._write_executable(
            "docker",
            """#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case " $* " in
  *" start "*)
    attempts=0
    if [ -f "$FAKE_START_STATE" ]; then
      attempts="$(cat "$FAKE_START_STATE")"
    fi
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" >"$FAKE_START_STATE"
    if [ "$attempts" -le "${FAKE_START_FAILURES:-0}" ]; then
      exit 43
    fi
    ;;
  *" ps --status running --services "*)
    printf '%s\n' dashboard ingest
    ;;
  *" run "*" maintenance backup "*)
    if [ "${FAKE_FAIL_PHASE:-}" = "backup" ]; then
      exit 42
    fi
    printf '%s\n' '{"mode":"backup","verified":false}'
    ;;
  *" run "*" maintenance verify-backup "*)
    printf '%s\n' '{"mode":"verify_backup"}'
    ;;
  *" run "*" maintenance prune "*)
    if [ "${FAKE_DEFER_CLEANUP:-}" = "1" ] \
      && [ ! -e "$FAKE_PRUNE_STATE" ]; then
      : >"$FAKE_PRUNE_STATE"
      printf '%s\n' '{"plan":{"eligible_rows":1},"result":{"deleted_rows":1,"stopped_reason":"exhausted","orphan_cleanup_deferred":true}}'
    else
      printf '%s\n' '{"plan":{"eligible_rows":0},"result":{"deleted_rows":0,"stopped_reason":"exhausted","orphan_cleanup_deferred":false}}'
    fi
    ;;
esac
""",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_executable(self, name: str, content: str) -> None:
        path = self.fake_bin / name
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _run(
        self,
        *,
        fail_phase: str | None = None,
        defer_cleanup: bool = False,
        health_status: int = 200,
        max_cycles: int = 1,
        start_failures: int = 0,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_DOCKER_LOG"] = str(self.docker_log)
        env["FAKE_CURL_LOG"] = str(self.curl_log)
        env["FAKE_TIMEOUT_LOG"] = str(self.timeout_log)
        env["FAKE_PRUNE_STATE"] = str(self.root / "prune.state")
        env["FAKE_START_STATE"] = str(self.root / "start.state")
        env["FAKE_START_FAILURES"] = str(start_failures)
        env["FAKE_HEALTH_STATUS"] = str(health_status)
        env["TRIAGEWALL_RETENTION_LOCK"] = str(self.root / "cycle.lock")
        if fail_phase:
            env["FAKE_FAIL_PHASE"] = fail_phase
        if defer_cleanup:
            env["FAKE_DEFER_CLEANUP"] = "1"
        return subprocess.run(
            [
                "/bin/bash",
                str(SCRIPT),
                "--backup-dir",
                str(self.backup_dir),
                "--keep-days",
                "60",
                "--max-runtime-seconds",
                "1",
                "--cooldown-seconds",
                "1",
                "--max-cycles",
                str(max_cycles),
            ],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_cycle_restores_monitoring_between_every_long_phase(self):
        completed = self._run()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self.docker_log.read_text(encoding="utf-8").splitlines()
        stop_indexes = [
            index for index, call in enumerate(calls) if " stop " in f" {call} "
        ]
        start_indexes = [
            index for index, call in enumerate(calls) if " start " in f" {call} "
        ]
        backup_index = next(
            index for index, call in enumerate(calls) if " maintenance backup " in call
        )
        verify_index = next(
            index
            for index, call in enumerate(calls)
            if " maintenance verify-backup " in call
        )
        prune_index = next(
            index for index, call in enumerate(calls) if " maintenance prune " in call
        )
        self.assertEqual(len(stop_indexes), 2)
        self.assertEqual(len(start_indexes), 2)
        self.assertLess(stop_indexes[0], backup_index)
        self.assertLess(backup_index, start_indexes[0])
        self.assertLess(start_indexes[0], verify_index)
        self.assertLess(verify_index, stop_indexes[1])
        self.assertLess(stop_indexes[1], prune_index)
        self.assertLess(prune_index, start_indexes[1])

    def test_backup_failure_trap_restarts_writers(self):
        completed = self._run(fail_phase="backup")

        self.assertEqual(completed.returncode, 42)
        calls = self.docker_log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(any(" stop " in f" {call} " for call in calls))
        self.assertTrue(any(" start " in f" {call} " for call in calls))
        self.assertIn("restoring monitoring services", completed.stderr)

    def test_failure_trap_retries_transient_writer_startup_failures(self):
        completed = self._run(fail_phase="backup", start_failures=2)

        self.assertEqual(completed.returncode, 42)
        calls = self.docker_log.read_text(encoding="utf-8").splitlines()
        start_calls = [
            call for call in calls if " start " in f" {call} "
        ]
        self.assertEqual(len(start_calls), 3)
        self.assertIn(
            "monitoring services and dashboard are healthy",
            completed.stdout,
        )

    def test_failure_trap_surfaces_unrecoverable_writer_startup(self):
        completed = self._run(fail_phase="backup", start_failures=99)

        self.assertEqual(completed.returncode, 75)
        calls = self.docker_log.read_text(encoding="utf-8").splitlines()
        start_calls = [
            call for call in calls if " start " in f" {call} "
        ]
        self.assertEqual(len(start_calls), 18)
        self.assertIn(
            "CRITICAL: monitoring services could not be restored",
            completed.stderr,
        )

    def test_cycle_continues_until_deferred_orphan_cleanup_completes(self):
        completed = self._run(defer_cleanup=True, max_cycles=2)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self.docker_log.read_text(encoding="utf-8").splitlines()
        prune_calls = [
            call for call in calls if " maintenance prune " in call
        ]
        self.assertEqual(len(prune_calls), 2)
        self.assertIn("orphan cleanup deferred", completed.stdout)
        self.assertIn("retention target exhausted", completed.stdout)

    def test_recovery_accepts_dashboard_stale_status_for_quiet_stream(self):
        completed = self._run(health_status=503)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dashboard reports a stale alert stream", completed.stdout)

    def test_recovery_rejects_unexpected_dashboard_status(self):
        completed = self._run(health_status=500)

        self.assertEqual(completed.returncode, 75)
        self.assertIn("monitoring recovery failed", completed.stderr)
        self.assertIn(
            "CRITICAL: monitoring services could not be restored",
            completed.stderr,
        )

    def test_dashboard_health_requests_have_connection_and_transfer_limits(self):
        completed = self._run()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self.curl_log.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(calls), 2)
        for call in calls:
            self.assertIn("--connect-timeout 3", call)
            self.assertIn("--max-time 5", call)

    def test_compose_recovery_commands_have_host_side_limits(self):
        completed = self._run()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self.timeout_log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(
            any("75s docker compose" in call and " stop " in call for call in calls)
        )
        self.assertTrue(
            any("30s docker compose" in call and " start " in call for call in calls)
        )
        self.assertTrue(
            any(
                "10s docker compose" in call
                and " ps --status running --services" in call
                for call in calls
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
