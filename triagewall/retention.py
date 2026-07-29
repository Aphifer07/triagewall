#!/usr/bin/env python3
"""Dry-run-first retention controls for the Triagewall SQLite database."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import timedelta
import errno
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import threading
import time

try:
    from .database import connect_database
    from .storage import get_storage_metrics
    from .time_utils import (
        format_utc_timestamp,
        parse_utc_timestamp,
        utc_now,
    )
except ImportError:  # Direct script-style execution inside the ingest image.
    from database import connect_database
    from storage import get_storage_metrics
    from time_utils import (
        format_utc_timestamp,
        parse_utc_timestamp,
        utc_now,
    )


DEFAULT_BATCH_SIZE = 500
DEFAULT_PAUSE_MS = 100
MAX_BATCH_SIZE = 10_000
MAX_PAUSE_MS = 60_000

DEFAULT_BACKUP_MAX_SECONDS = 1_800
DEFAULT_BACKUP_STALL_SECONDS = 120
DEFAULT_BACKUP_MAX_RESTARTS = 3
DEFAULT_BACKUP_PROGRESS_SECONDS = 30
DEFAULT_INTEGRITY_MAX_SECONDS = 10_800
DEFAULT_INTEGRITY_PROGRESS_SECONDS = 30
MAX_BACKUP_BOUND_SECONDS = 86_400
MAX_BACKUP_RESTARTS = 100

BACKUP_FILE_MODE = 0o600

# sqlite3 backup progress statuses (not always exported by the stdlib module).
SQLITE_OK = 0
SQLITE_BUSY = 5
SQLITE_LOCKED = 6


@dataclass(frozen=True)
class RetentionPlan:
    cutoff: str
    include_reviewed: bool
    eligible_rows: int
    reviewed_rows_below_cutoff: int
    lifetime_rows_inserted: int
    oldest_processed_at: str | None
    newest_processed_at: str | None


@dataclass(frozen=True)
class PruneResult:
    deleted_rows: int
    deleted_asset_snapshots: int
    batches: int
    checkpoint_busy_frames: int
    checkpoint_log_frames: int
    checkpointed_frames: int


@dataclass(frozen=True)
class BackupLimits:
    max_copy_seconds: float = DEFAULT_BACKUP_MAX_SECONDS
    stall_seconds: float = DEFAULT_BACKUP_STALL_SECONDS
    max_restarts: int = DEFAULT_BACKUP_MAX_RESTARTS
    progress_interval_seconds: float = DEFAULT_BACKUP_PROGRESS_SECONDS
    integrity_max_seconds: float = DEFAULT_INTEGRITY_MAX_SECONDS
    integrity_progress_interval_seconds: float = (
        DEFAULT_INTEGRITY_PROGRESS_SECONDS
    )


class BackupLimitExceeded(RuntimeError):
    """Raised when a bounded backup or integrity check hits a safety limit."""


def _retention_predicate(include_reviewed: bool) -> str:
    predicate = "processed_at IS NOT NULL AND processed_at < ?"
    if not include_reviewed:
        predicate += " AND human_verdict IS NULL"
    return predicate


def build_retention_plan(
    conn: sqlite3.Connection,
    cutoff: str,
    *,
    include_reviewed: bool = False,
) -> RetentionPlan:
    """Count exactly what a prune would remove before any write occurs."""
    canonical_cutoff = format_utc_timestamp(cutoff)
    counts = conn.execute(
        """SELECT
               COALESCE(SUM(human_verdict IS NULL), 0),
               COALESCE(SUM(human_verdict IS NOT NULL), 0)
           FROM triage_events
           WHERE processed_at IS NOT NULL AND processed_at < ?""",
        (canonical_cutoff,),
    ).fetchone()
    unreviewed_rows = int(counts[0])
    reviewed_rows_below_cutoff = int(counts[1])
    eligible_rows = (
        unreviewed_rows + reviewed_rows_below_cutoff
        if include_reviewed
        else unreviewed_rows
    )
    oldest_processed_at, newest_processed_at = _history_bounds(conn)
    return RetentionPlan(
        cutoff=canonical_cutoff,
        include_reviewed=include_reviewed,
        eligible_rows=eligible_rows,
        reviewed_rows_below_cutoff=reviewed_rows_below_cutoff,
        lifetime_rows_inserted=_lifetime_rows_inserted(conn),
        oldest_processed_at=oldest_processed_at,
        newest_processed_at=newest_processed_at,
    )


def _lifetime_rows_inserted(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        """SELECT seq FROM sqlite_sequence
           WHERE name = 'triage_events'"""
    ).fetchone()
    return int(row[0]) if row else 0


def _history_bounds(
    conn: sqlite3.Connection,
) -> tuple[str | None, str | None]:
    oldest = conn.execute(
        """SELECT processed_at FROM triage_events
           WHERE processed_at IS NOT NULL
           ORDER BY processed_at ASC
           LIMIT 1"""
    ).fetchone()
    newest = conn.execute(
        """SELECT processed_at FROM triage_events
           WHERE processed_at IS NOT NULL
           ORDER BY processed_at DESC
           LIMIT 1"""
    ).fetchone()
    return (
        oldest[0] if oldest else None,
        newest[0] if newest else None,
    )


def _default_backup_report(message: str) -> None:
    print(message, file=sys.stderr)


class BackupProgressMonitor:
    """Track SQLite online-backup progress and enforce copy bounds."""

    def __init__(
        self,
        limits: BackupLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
        report: Callable[[str], None] = _default_backup_report,
    ) -> None:
        self.limits = limits
        self.clock = clock
        self.report = report
        self.started_at = clock()
        self.last_progress_at = self.started_at
        self.last_report_at = self.started_at
        self.previous_remaining: int | None = None
        self.restarts = 0
        self.total = 0
        self.remaining = 0

    def __call__(self, status: int, remaining: int, total: int) -> None:
        now = self.clock()
        self.total = int(total)
        self.remaining = int(remaining)
        elapsed = now - self.started_at

        if elapsed >= self.limits.max_copy_seconds:
            raise BackupLimitExceeded(
                "backup copy exceeded maximum duration of "
                f"{self.limits.max_copy_seconds:g} seconds "
                f"(elapsed {elapsed:.1f}s, remaining pages "
                f"{self.remaining}/{self.total}, restarts {self.restarts})"
            )

        busy_or_locked = status in (SQLITE_BUSY, SQLITE_LOCKED)

        # BUSY/LOCKED callbacks are observations of contention, not page-copy
        # progress. Do not let their remaining-page values establish or move
        # the comparison baseline.
        if not busy_or_locked:
            if self.previous_remaining is None:
                self.previous_remaining = self.remaining
            elif self.remaining < self.previous_remaining:
                self.last_progress_at = now
                self.previous_remaining = self.remaining
            elif self.remaining > self.previous_remaining:
                self.restarts += 1
                self.previous_remaining = self.remaining
                if self.restarts > self.limits.max_restarts:
                    raise BackupLimitExceeded(
                        "backup copy exceeded maximum restarts of "
                        f"{self.limits.max_restarts} "
                        f"(detected {self.restarts}, remaining pages "
                        f"{self.remaining}/{self.total})"
                    )
        # equal remaining: no progress; do not refresh stall timer

        stalled_for = now - self.last_progress_at
        if stalled_for >= self.limits.stall_seconds:
            raise BackupLimitExceeded(
                "backup copy stalled without forward progress for "
                f"{stalled_for:.1f}s "
                f"(limit {self.limits.stall_seconds:g}s, remaining pages "
                f"{self.remaining}/{self.total}, restarts {self.restarts})"
            )

        if (
            now - self.last_report_at
            >= self.limits.progress_interval_seconds
        ):
            self.report(self._format_progress(elapsed))
            self.last_report_at = now

    def _format_progress(self, elapsed: float) -> str:
        copied = max(self.total - self.remaining, 0)
        if self.total > 0:
            percent = (copied / self.total) * 100.0
            percent_text = f", {percent:.1f}%"
        else:
            percent_text = ""
        return (
            "retention backup progress: phase=backup "
            f"elapsed={elapsed:.1f}s "
            f"copied_pages={copied} remaining_pages={self.remaining} "
            f"total_pages={self.total}{percent_text} "
            f"restarts={self.restarts}"
        )


class IntegrityCheckMonitor:
    """Emit integrity heartbeats and interrupt the connection on timeout."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        limits: BackupLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        report: Callable[[str], None] = _default_backup_report,
        poll_seconds: float = 0.05,
    ) -> None:
        self.conn = conn
        self.limits = limits
        self.clock = clock
        self.sleep = sleep
        self.report = report
        self.poll_seconds = poll_seconds
        self.started_at = clock()
        self._stop = threading.Event()
        self.timed_out = False
        self.thread = threading.Thread(
            target=self._run,
            name="retention-integrity-monitor",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.thread.join(timeout=5.0)
        if self.thread.is_alive():
            raise BackupLimitExceeded(
                "backup integrity monitor did not stop cleanly"
            )

    def _run(self) -> None:
        last_report_at = self.started_at
        while not self._stop.is_set():
            now = self.clock()
            elapsed = now - self.started_at
            if elapsed >= self.limits.integrity_max_seconds:
                self.timed_out = True
                try:
                    self.conn.interrupt()
                except Exception:
                    pass
                return
            if (
                now - last_report_at
                >= self.limits.integrity_progress_interval_seconds
            ):
                try:
                    self.report(
                        "retention backup progress: phase=integrity "
                        f"elapsed={elapsed:.1f}s"
                    )
                except Exception:
                    # A logging failure must not disable timeout enforcement.
                    pass
                last_report_at = now
            # Prefer Event.wait so stop() wakes promptly; fall back to sleep
            # when tests inject a fake sleeper for deterministic clocks.
            if self.sleep is time.sleep:
                if self._stop.wait(timeout=self.poll_seconds):
                    return
            else:
                self.sleep(self.poll_seconds)



def _reserve_backup_destination(target: Path) -> None:
    """Atomically create an exclusive empty backup file with mode 0600."""
    if not target.parent.exists():
        raise FileNotFoundError(
            f"backup parent directory does not exist: {target.parent}"
        )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(target, flags, BACKUP_FILE_MODE)
    except FileExistsError as exc:
        raise FileExistsError(
            f"backup target already exists: {target}"
        ) from exc
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise FileExistsError(
                f"backup target already exists: {target}"
            ) from exc
        raise
    os.close(fd)
    try:
        os.chmod(target, BACKUP_FILE_MODE)
    except OSError:
        pass


def _unlink_owned_backup(target: Path) -> None:
    try:
        target.unlink()
    except FileNotFoundError:
        return


def _ensure_backup_permissions(target: Path) -> None:
    try:
        os.chmod(target, BACKUP_FILE_MODE)
    except OSError as exc:
        raise OSError(
            f"failed to set backup permissions to 0600: {target}"
        ) from exc


def _default_integrity_check(conn: sqlite3.Connection) -> str:
    row = conn.execute("PRAGMA quick_check").fetchone()
    return str(row[0])


def _run_integrity_check(
    destination: sqlite3.Connection,
    limits: BackupLimits,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    integrity_check: Callable[[sqlite3.Connection], str] | None = None,
    monitor_factory: Callable[..., IntegrityCheckMonitor] | None = None,
) -> str:
    check = integrity_check or _default_integrity_check
    factory = monitor_factory or IntegrityCheckMonitor
    monitor = factory(
        destination,
        limits,
        clock=clock,
        sleep=sleep,
        report=report,
    )
    monitor.start()
    try:
        try:
            result = check(destination)
        except sqlite3.Error as exc:
            if monitor.timed_out:
                raise BackupLimitExceeded(
                    "backup integrity check exceeded maximum duration of "
                    f"{limits.integrity_max_seconds:g} seconds"
                ) from exc
            raise
        if monitor.timed_out:
            raise BackupLimitExceeded(
                "backup integrity check exceeded maximum duration of "
                f"{limits.integrity_max_seconds:g} seconds"
            )
        return result
    finally:
        monitor.stop()


def create_online_backup(
    source: sqlite3.Connection,
    backup_path: str | Path,
    *,
    limits: BackupLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    progress_monitor: BackupProgressMonitor | None = None,
    integrity_check: Callable[[sqlite3.Connection], str] | None = None,
    monitor_factory: Callable[..., IntegrityCheckMonitor] | None = None,
) -> Path:
    """Create and integrity-check a new SQLite backup without overwriting."""
    target = Path(backup_path)
    active_limits = limits or BackupLimits()
    if not target.parent.exists():
        raise FileNotFoundError(
            f"backup parent directory does not exist: {target.parent}"
        )
    page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(source.execute("PRAGMA page_count").fetchone()[0])
    backup_bytes = page_size * page_count
    safety_margin = max(64 * 1024 * 1024, backup_bytes // 20)
    free_bytes = shutil.disk_usage(target.parent).free
    if free_bytes < backup_bytes + safety_margin:
        raise OSError(
            "backup target lacks free space: "
            f"needs at least {backup_bytes + safety_margin} bytes, "
            f"has {free_bytes}"
        )

    owned_backup = False
    destination: sqlite3.Connection | None = None
    try:
        _reserve_backup_destination(target)
        owned_backup = True
        destination = sqlite3.connect(target)
        monitor = progress_monitor or BackupProgressMonitor(
            active_limits,
            clock=clock,
            report=report,
        )
        source.backup(
            destination,
            pages=1_024,
            progress=monitor,
            sleep=0.05,
        )
        result = _run_integrity_check(
            destination,
            active_limits,
            clock=clock,
            sleep=sleep,
            report=report,
            integrity_check=integrity_check,
            monitor_factory=monitor_factory,
        )
        if result != "ok":
            raise sqlite3.DatabaseError(
                f"backup integrity check failed: {result}"
            )
        destination.close()
        destination = None
        _ensure_backup_permissions(target)
        return target
    except Exception as exc:
        if destination is not None:
            try:
                destination.close()
            except Exception:
                pass
            destination = None
        if owned_backup:
            try:
                _unlink_owned_backup(target)
            except OSError as cleanup_exc:
                raise OSError(
                    "backup failed and the incomplete destination could not "
                    f"be removed: {target}: {cleanup_exc}"
                ) from exc
        raise


def prune_events(
    conn: sqlite3.Connection,
    cutoff: str,
    *,
    include_reviewed: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pause_ms: int = DEFAULT_PAUSE_MS,
    max_rows: int | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> PruneResult:
    """Delete eligible verdicts in short transactions and clean orphans."""
    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ValueError(
            f"batch_size must be between 1 and {MAX_BATCH_SIZE}"
        )
    if not 0 <= pause_ms <= MAX_PAUSE_MS:
        raise ValueError(
            f"pause_ms must be between 0 and {MAX_PAUSE_MS}"
        )
    if max_rows is not None and max_rows < 1:
        raise ValueError("max_rows must be at least 1")

    canonical_cutoff = format_utc_timestamp(cutoff)
    predicate = _retention_predicate(include_reviewed)
    deleted_rows = 0
    batches = 0

    while max_rows is None or deleted_rows < max_rows:
        current_batch = batch_size
        if max_rows is not None:
            current_batch = min(current_batch, max_rows - deleted_rows)

        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                f"""DELETE FROM triage_events
                    WHERE id IN (
                        SELECT id
                        FROM triage_events
                        WHERE {predicate}
                        ORDER BY processed_at, id
                        LIMIT ?
                    )""",
                (canonical_cutoff, current_batch),
            )
            deleted = int(conn.execute("SELECT changes()").fetchone()[0])
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        if deleted == 0:
            break
        deleted_rows += deleted
        batches += 1
        if progress is not None:
            progress(deleted_rows, batches)
        if deleted < current_batch:
            break
        if pause_ms:
            time.sleep(pause_ms / 1_000.0)

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """DELETE FROM asset_snapshots
               WHERE NOT EXISTS (
                   SELECT 1 FROM triage_events
                   WHERE src_asset_snapshot_id = asset_snapshots.id
                      OR dest_asset_snapshot_id = asset_snapshots.id
               )"""
        )
        deleted_asset_snapshots = int(
            conn.execute("SELECT changes()").fetchone()[0]
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
    return PruneResult(
        deleted_rows=deleted_rows,
        deleted_asset_snapshots=deleted_asset_snapshots,
        batches=batches,
        checkpoint_busy_frames=int(checkpoint[0]),
        checkpoint_log_frames=int(checkpoint[1]),
        checkpointed_frames=int(checkpoint[2]),
    )


def _default_db_path() -> Path:
    return Path(
        os.environ.get("DB_PATH")
        or os.environ.get("TRIAGE_DB")
        or "/var/lib/triagewall/triage.db"
    )


def _add_database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        type=Path,
        default=_default_db_path(),
        help="SQLite database path (default: DB_PATH/TRIAGE_DB or production path)",
    )


def _bounded_int(
    name: str,
    minimum: int,
    maximum: int | None = None,
) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer"
            ) from exc
        if parsed < minimum or (
            maximum is not None and parsed > maximum
        ):
            if maximum is None:
                bounds = f"at least {minimum}"
            else:
                bounds = f"between {minimum} and {maximum}"
            raise argparse.ArgumentTypeError(f"{name} must be {bounds}")
        return parsed

    return parse


def _backup_limits_from_args(args: argparse.Namespace) -> BackupLimits:
    return BackupLimits(
        max_copy_seconds=float(args.backup_max_seconds),
        stall_seconds=float(args.backup_stall_seconds),
        max_restarts=int(args.backup_max_restarts),
        progress_interval_seconds=float(args.backup_progress_seconds),
        integrity_max_seconds=float(args.integrity_check_max_seconds),
        integrity_progress_interval_seconds=float(
            args.integrity_progress_seconds
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect and safely prune Triagewall verdict history."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser(
        "status",
        help="Show storage allocation and verdict-history bounds.",
    )
    _add_database_argument(status)
    status.add_argument("--json", action="store_true")

    prune = subparsers.add_parser(
        "prune",
        help="Preview by default; --apply is required to delete.",
    )
    _add_database_argument(prune)
    cutoff = prune.add_mutually_exclusive_group(required=True)
    cutoff.add_argument(
        "--keep-days",
        type=_bounded_int("keep-days", 1),
    )
    cutoff.add_argument("--before")
    prune.add_argument(
        "--include-reviewed",
        action="store_true",
        help="Also delete rows carrying human verdicts (protected by default).",
    )
    prune.add_argument(
        "--batch-size",
        type=_bounded_int("batch-size", 1, MAX_BATCH_SIZE),
        default=DEFAULT_BATCH_SIZE,
    )
    prune.add_argument(
        "--pause-ms",
        type=_bounded_int("pause-ms", 0, MAX_PAUSE_MS),
        default=DEFAULT_PAUSE_MS,
    )
    prune.add_argument(
        "--max-rows",
        type=_bounded_int("max-rows", 1),
        help="Canary limit for one applied run.",
    )
    prune.add_argument(
        "--apply",
        action="store_true",
        help="Perform the planned deletion.",
    )
    prune.add_argument(
        "--confirm-writers-stopped",
        action="store_true",
        help=(
            "Operator acknowledgement that Suricata ingest and optional "
            "wazuh-ingest are stopped before --apply. This does not prove "
            "writers are stopped."
        ),
    )
    backup = prune.add_mutually_exclusive_group()
    backup.add_argument(
        "--backup",
        type=Path,
        help="Create and verify a new online SQLite backup before deleting.",
    )
    backup.add_argument(
        "--no-backup",
        action="store_true",
        help="Explicitly acknowledge applying without a backup.",
    )
    prune.add_argument(
        "--backup-max-seconds",
        type=_bounded_int(
            "backup-max-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_BACKUP_MAX_SECONDS,
        help=(
            "Abort online backup copy after this many seconds "
            f"(default: {DEFAULT_BACKUP_MAX_SECONDS})."
        ),
    )
    prune.add_argument(
        "--backup-stall-seconds",
        type=_bounded_int(
            "backup-stall-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_BACKUP_STALL_SECONDS,
        help=(
            "Abort when backup makes no forward page progress for this long "
            f"(default: {DEFAULT_BACKUP_STALL_SECONDS})."
        ),
    )
    prune.add_argument(
        "--backup-max-restarts",
        type=_bounded_int("backup-max-restarts", 0, MAX_BACKUP_RESTARTS),
        default=DEFAULT_BACKUP_MAX_RESTARTS,
        help=(
            "Abort after this many backup remaining-page resets "
            f"(default: {DEFAULT_BACKUP_MAX_RESTARTS})."
        ),
    )
    prune.add_argument(
        "--backup-progress-seconds",
        type=_bounded_int(
            "backup-progress-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_BACKUP_PROGRESS_SECONDS,
        help=(
            "Seconds between backup copy progress lines on stderr "
            f"(default: {DEFAULT_BACKUP_PROGRESS_SECONDS})."
        ),
    )
    prune.add_argument(
        "--integrity-check-max-seconds",
        type=_bounded_int(
            "integrity-check-max-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_INTEGRITY_MAX_SECONDS,
        help=(
            "Abort backup integrity checking after this many seconds "
            f"(default: {DEFAULT_INTEGRITY_MAX_SECONDS})."
        ),
    )
    prune.add_argument(
        "--integrity-progress-seconds",
        type=_bounded_int(
            "integrity-progress-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_INTEGRITY_PROGRESS_SECONDS,
        help=(
            "Seconds between integrity-check heartbeats on stderr "
            f"(default: {DEFAULT_INTEGRITY_PROGRESS_SECONDS})."
        ),
    )
    prune.add_argument("--json", action="store_true")
    return parser


def _cutoff_from_args(args: argparse.Namespace) -> str:
    if args.keep_days is not None:
        if args.keep_days < 1:
            raise ValueError("keep-days must be at least 1")
        return format_utc_timestamp(
            utc_now() - timedelta(days=args.keep_days)
        )
    return format_utc_timestamp(parse_utc_timestamp(args.before))


def _database_status(
    conn: sqlite3.Connection,
    db_path: Path,
) -> dict[str, object]:
    oldest_processed_at, newest_processed_at = _history_bounds(conn)
    return {
        "database": str(db_path),
        "storage": get_storage_metrics(conn, db_path),
        "history": {
            "lifetime_rows_inserted": _lifetime_rows_inserted(conn),
            "oldest_processed_at": oldest_processed_at,
            "newest_processed_at": newest_processed_at,
        },
    }


def _print_human(value: object, *, indent: int = 0) -> None:
    prefix = " " * indent
    if isinstance(value, dict):
        for key, child in value.items():
            label = key.replace("_", " ")
            if isinstance(child, dict):
                print(f"{prefix}{label}:")
                _print_human(child, indent=indent + 2)
            else:
                print(f"{prefix}{label}: {child}")
        return
    print(f"{prefix}{value}")


def _print_payload(payload: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    _print_human(payload)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.db.is_file():
        parser.error(f"database does not exist or is not a file: {args.db}")
    if (
        args.command == "prune"
        and args.apply
        and not args.backup
        and not args.no_backup
    ):
        parser.error(
            "--apply requires either --backup PATH or --no-backup"
        )
    if args.command == "prune" and args.apply and not args.confirm_writers_stopped:
        parser.error(
            "--apply requires --confirm-writers-stopped: stop Suricata "
            "ingest and optional wazuh-ingest first. This flag is an "
            "operator acknowledgement, not proof that all writers are stopped."
        )

    readonly = args.command == "status" or (
        args.command == "prune" and not args.apply
    )
    conn = connect_database(args.db, readonly=readonly)
    try:
        if args.command == "status":
            _print_payload(
                _database_status(conn, args.db),
                args.json,
            )
            return 0

        try:
            cutoff = _cutoff_from_args(args)
            plan = build_retention_plan(
                conn,
                cutoff,
                include_reviewed=args.include_reviewed,
            )
        except (TypeError, ValueError) as exc:
            parser.error(str(exc))

        payload: dict[str, object] = {
            "mode": "apply" if args.apply else "dry_run",
            "database": str(args.db),
            "plan": asdict(plan),
            "storage_before": get_storage_metrics(conn, args.db),
        }
        if not args.apply:
            _print_payload(payload, args.json)
            return 0

        if args.backup:
            payload["backup"] = str(
                create_online_backup(
                    conn,
                    args.backup,
                    limits=_backup_limits_from_args(args),
                )
            )

        def report_progress(rows: int, batches: int) -> None:
            if batches == 1 or batches % 10 == 0:
                print(
                    f"retention progress: {rows} rows in {batches} batches",
                    file=sys.stderr,
                )

        result = prune_events(
            conn,
            cutoff,
            include_reviewed=args.include_reviewed,
            batch_size=args.batch_size,
            pause_ms=args.pause_ms,
            max_rows=args.max_rows,
            progress=report_progress,
        )
        payload["result"] = asdict(result)
        payload["storage_after"] = get_storage_metrics(conn, args.db)
        _print_payload(payload, args.json)
        return 0
    except (
        BackupLimitExceeded,
        FileExistsError,
        FileNotFoundError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        print(f"retention failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
