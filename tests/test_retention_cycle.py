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
        self._write_executable(
            "curl",
            """#!/bin/sh
exit 0
""",
        )
        self._write_executable(
            "docker",
            """#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case " $* " in
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
        max_cycles: int = 1,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_DOCKER_LOG"] = str(self.docker_log)
        env["FAKE_PRUNE_STATE"] = str(self.root / "prune.state")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
