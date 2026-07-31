#!/usr/bin/env python3
"""Dry-run-first retention controls for the Triagewall SQLite database."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import timedelta
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
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
DEFAULT_MANIFEST_MAX_AGE_SECONDS = 86_400
MAX_BACKUP_BOUND_SECONDS = 86_400
MAX_BACKUP_RESTARTS = 100
MAX_MANIFEST_BYTES = 64 * 1024
MAX_MANIFEST_AGE_SECONDS = 7 * 86_400
MAX_PRUNE_SECONDS = 86_400

BACKUP_FILE_MODE = 0o600
BACKUP_MANIFEST_VERSION = 1
BACKUP_PROVENANCE_VERSION = 1
MAX_BACKUP_STEP_BUSY_MS = 100

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
    orphan_cleanup_deferred: bool
    batches: int
    checkpoint_busy_frames: int
    checkpoint_log_frames: int
    checkpointed_frames: int
    stopped_reason: str


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


class RetentionDeadlineExceeded(RuntimeError):
    """Raised when pre-prune work consumes the bounded maintenance window."""


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
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RetentionPlan:
    """Count exactly what a prune would remove before any write occurs."""
    canonical_cutoff = format_utc_timestamp(cutoff)
    if deadline is not None and clock() >= deadline:
        raise RetentionDeadlineExceeded(
            "retention planning exceeded the maintenance deadline"
        )
    if deadline is not None:
        conn.set_progress_handler(
            lambda: 1 if clock() >= deadline else 0,
            1_000,
        )
    try:
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
    except sqlite3.OperationalError as exc:
        if deadline is not None and clock() >= deadline:
            raise RetentionDeadlineExceeded(
                "retention planning exceeded the maintenance deadline"
            ) from exc
        raise
    finally:
        if deadline is not None:
            conn.set_progress_handler(None, 0)


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


class BackupCopyWatchdog:
    """Enforce copy deadlines even while SQLite is inside a backup step."""

    def __init__(
        self,
        source: sqlite3.Connection,
        monitor: BackupProgressMonitor,
        limits: BackupLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 0.05,
    ) -> None:
        self.source = source
        self.monitor = monitor
        self.limits = limits
        self.clock = clock
        self.sleep = sleep
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self.failure: BackupLimitExceeded | None = None
        self.thread = threading.Thread(
            target=self._run,
            name="retention-backup-watchdog",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.thread.join(timeout=5.0)
        if self.thread.is_alive():
            raise BackupLimitExceeded(
                "backup copy watchdog did not stop cleanly"
            )

    def _fail(self, message: str) -> None:
        self.failure = BackupLimitExceeded(message)
        try:
            self.source.interrupt()
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.is_set():
            now = self.clock()
            elapsed = now - self.monitor.started_at
            stalled_for = now - self.monitor.last_progress_at
            if elapsed >= self.limits.max_copy_seconds:
                self._fail(
                    "backup copy exceeded maximum duration of "
                    f"{self.limits.max_copy_seconds:g} seconds "
                    f"(elapsed {elapsed:.1f}s, remaining pages "
                    f"{self.monitor.remaining}/{self.monitor.total}, "
                    f"restarts {self.monitor.restarts})"
                )
                return
            if stalled_for >= self.limits.stall_seconds:
                self._fail(
                    "backup copy stalled without forward progress for "
                    f"{stalled_for:.1f}s "
                    f"(limit {self.limits.stall_seconds:g}s, "
                    f"remaining pages {self.monitor.remaining}/"
                    f"{self.monitor.total}, "
                    f"restarts {self.monitor.restarts})"
                )
                return
            if (
                now - self.monitor.last_report_at
                >= self.limits.progress_interval_seconds
            ):
                try:
                    self.monitor.report(
                        self.monitor._format_progress(elapsed)
                    )
                except Exception:
                    pass
                self.monitor.last_report_at = now
            if self.sleep is time.sleep:
                if self._stop.wait(timeout=self.poll_seconds):
                    return
            else:
                self.sleep(self.poll_seconds)


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



def _reserve_backup_staging_file(target: Path) -> Path:
    """Create an unpredictable, exclusive staging file beside the target."""
    if not target.parent.exists():
        raise FileNotFoundError(
            f"backup parent directory does not exist: {target.parent}"
        )
    fd, staging_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    try:
        os.chmod(staging_name, BACKUP_FILE_MODE)
    except OSError as exc:
        os.close(fd)
        Path(staging_name).unlink(missing_ok=True)
        raise OSError(
            "failed to set backup staging permissions to 0600: "
            f"{staging_name}"
        ) from exc
    os.close(fd)
    return Path(staging_name)


def _publish_backup(staging: Path, target: Path) -> None:
    """Atomically publish a verified backup without replacing any target."""
    try:
        os.link(staging, target)
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


def _set_bounded_backup_busy_timeout(
    source: sqlite3.Connection,
    limits: BackupLimits,
) -> int:
    """Bound SQLite lock waits during backup and return the prior timeout."""
    previous = int(source.execute("PRAGMA busy_timeout").fetchone()[0])
    deadline_ms = max(
        1,
        int(
            min(
                limits.max_copy_seconds,
                limits.stall_seconds,
            )
            * 1_000
        ),
    )
    bounded = min(previous, deadline_ms, MAX_BACKUP_STEP_BUSY_MS)
    source.execute(f"PRAGMA busy_timeout={bounded}")
    return previous


def _restore_busy_timeout(
    source: sqlite3.Connection,
    timeout_ms: int,
) -> None:
    source.execute(f"PRAGMA busy_timeout={timeout_ms}")


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


def _create_backup(
    source: sqlite3.Connection,
    backup_path: str | Path,
    *,
    limits: BackupLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    progress_monitor: Callable[[int, int, int], None] | None = None,
    copy_watchdog_factory: Callable[..., BackupCopyWatchdog] | None = None,
    integrity_check: Callable[[sqlite3.Connection], str] | None = None,
    monitor_factory: Callable[..., IntegrityCheckMonitor] | None = None,
    verify_integrity: bool,
) -> Path:
    """Create a bounded SQLite backup without overwriting."""
    target = Path(backup_path)
    active_limits = limits or BackupLimits()
    if not target.parent.exists():
        raise FileNotFoundError(
            f"backup parent directory does not exist: {target.parent}"
        )
    if os.path.lexists(target):
        raise FileExistsError(f"backup target already exists: {target}")
    previous_busy_timeout = _set_bounded_backup_busy_timeout(
        source,
        active_limits,
    )
    try:
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
    except Exception as exc:
        _restore_busy_timeout(source, previous_busy_timeout)
        if isinstance(exc, sqlite3.OperationalError):
            raise BackupLimitExceeded(
                "backup preparation could not read source metadata within "
                "the bounded SQLite lock wait"
            ) from exc
        raise

    staging: Path | None = None
    destination: sqlite3.Connection | None = None
    try:
        staging = _reserve_backup_staging_file(target)
        destination = sqlite3.connect(staging)
        monitor = (
            progress_monitor
            if isinstance(progress_monitor, BackupProgressMonitor)
            else BackupProgressMonitor(
                active_limits,
                clock=clock,
                report=report,
            )
        )
        progress_callback: Callable[[int, int, int], None] = monitor
        if (
            progress_monitor is not None
            and progress_monitor is not monitor
        ):
            def progress_callback(
                status: int,
                remaining: int,
                total: int,
            ) -> None:
                monitor(status, remaining, total)
                progress_monitor(status, remaining, total)

        watchdog_factory = copy_watchdog_factory or BackupCopyWatchdog
        copy_watchdog = watchdog_factory(
            source,
            monitor,
            active_limits,
            clock=clock,
            sleep=sleep,
        )
        copy_watchdog.start()
        try:
            try:
                source.backup(
                    destination,
                    pages=1_024,
                    progress=progress_callback,
                    sleep=0.05,
                )
            except Exception as exc:
                if copy_watchdog.failure is not None:
                    raise copy_watchdog.failure from exc
                raise
            if copy_watchdog.failure is not None:
                raise copy_watchdog.failure
        finally:
            copy_watchdog.stop()
        if verify_integrity:
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
        _ensure_backup_permissions(staging)
        _publish_backup(staging, target)
        _unlink_owned_backup(staging)
        staging = None
        return target
    except Exception as exc:
        if destination is not None:
            try:
                destination.close()
            except Exception:
                pass
            destination = None
        if staging is not None:
            try:
                _unlink_owned_backup(staging)
            except OSError as cleanup_exc:
                raise OSError(
                    "backup failed and the incomplete staging file could not "
                    f"be removed: {staging}: {cleanup_exc}"
                ) from exc
        raise
    finally:
        _restore_busy_timeout(source, previous_busy_timeout)


def create_online_backup(
    source: sqlite3.Connection,
    backup_path: str | Path,
    *,
    limits: BackupLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    progress_monitor: Callable[[int, int, int], None] | None = None,
    copy_watchdog_factory: Callable[..., BackupCopyWatchdog] | None = None,
    integrity_check: Callable[[sqlite3.Connection], str] | None = None,
    monitor_factory: Callable[..., IntegrityCheckMonitor] | None = None,
) -> Path:
    """Create and integrity-check a new SQLite backup without overwriting."""
    return _create_backup(
        source,
        backup_path,
        limits=limits,
        clock=clock,
        sleep=sleep,
        report=report,
        progress_monitor=progress_monitor,
        copy_watchdog_factory=copy_watchdog_factory,
        integrity_check=integrity_check,
        monitor_factory=monitor_factory,
        verify_integrity=True,
    )


def create_backup_copy(
    source: sqlite3.Connection,
    backup_path: str | Path,
    *,
    source_path: str | Path | None = None,
    provenance_path: str | Path | None = None,
    limits: BackupLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    progress_monitor: Callable[[int, int, int], None] | None = None,
    copy_watchdog_factory: Callable[..., BackupCopyWatchdog] | None = None,
) -> Path:
    """Create a bounded backup plus provenance for later verification."""
    target = Path(backup_path)
    provenance = (
        Path(provenance_path)
        if provenance_path is not None
        else _backup_provenance_path(target)
    )
    if os.path.lexists(provenance):
        raise FileExistsError(
            f"backup provenance already exists: {provenance}"
        )
    created = _create_backup(
        source,
        target,
        limits=limits,
        clock=clock,
        sleep=sleep,
        report=report,
        progress_monitor=progress_monitor,
        copy_watchdog_factory=copy_watchdog_factory,
        verify_integrity=False,
    )
    created_identity = _regular_file_identity(created, label="backup")
    try:
        _write_backup_provenance(
            source,
            source_path or _main_database_path(source),
            created,
            provenance,
        )
    except Exception as exc:
        try:
            if _regular_file_identity(created, label="backup") == created_identity:
                _unlink_owned_backup(created)
        except OSError as cleanup_exc:
            raise OSError(
                "backup provenance failed and the published backup could not "
                f"be removed safely: {created}: {cleanup_exc}"
            ) from exc
        raise
    return created


def _regular_file_identity(path: Path, *, label: str) -> dict[str, int]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != BACKUP_FILE_MODE:
        raise PermissionError(f"{label} must have mode 0600: {path}")
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "size_bytes": int(metadata.st_size),
        "mtime_ns": int(metadata.st_mtime_ns),
    }


def _source_database_identity(path: Path) -> dict[str, int]:
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"source database does not exist: {path}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"source database must be a regular file: {path}")
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
    }


def _hash_file(
    path: Path,
    *,
    clock: Callable[[], float] = time.monotonic,
    report: Callable[[str], None] = _default_backup_report,
    progress_interval_seconds: float = DEFAULT_INTEGRITY_PROGRESS_SECONDS,
    max_seconds: float = DEFAULT_INTEGRITY_MAX_SECONDS,
) -> str:
    digest = hashlib.sha256()
    started_at = clock()
    last_report_at = started_at
    bytes_read = 0
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            bytes_read += len(block)
            now = clock()
            if now - started_at >= max_seconds:
                raise BackupLimitExceeded(
                    "backup hash exceeded maximum duration of "
                    f"{max_seconds:g} seconds"
                )
            if now - last_report_at >= progress_interval_seconds:
                report(
                    "retention backup progress: phase=hash "
                    f"elapsed={now - started_at:.1f}s "
                    f"bytes_read={bytes_read}"
                )
                last_report_at = now
    return f"sha256:{digest.hexdigest()}"


def _manifest_digest(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _write_exclusive_manifest(
    manifest_path: Path,
    payload: dict[str, object],
) -> Path:
    if not manifest_path.parent.exists():
        raise FileNotFoundError(
            "manifest parent directory does not exist: "
            f"{manifest_path.parent}"
        )
    if os.path.lexists(manifest_path):
        raise FileExistsError(
            f"verification manifest already exists: {manifest_path}"
        )

    staging = _reserve_backup_staging_file(manifest_path)
    try:
        with staging.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _ensure_backup_permissions(staging)
        _publish_backup(staging, manifest_path)
        _unlink_owned_backup(staging)
        return manifest_path
    except Exception as exc:
        try:
            _unlink_owned_backup(staging)
        except OSError as cleanup_exc:
            raise OSError(
                "manifest creation failed and its staging file could not "
                f"be removed: {staging}: {cleanup_exc}"
            ) from exc
        raise


def _main_database_path(conn: sqlite3.Connection) -> Path:
    for _, name, path in conn.execute("PRAGMA database_list").fetchall():
        if name == "main" and path:
            return Path(path)
    raise ValueError("source connection is not backed by a database file")


def _backup_provenance_path(backup_path: Path) -> Path:
    return Path(f"{backup_path}.provenance.json")


def _write_backup_provenance(
    source_conn: sqlite3.Connection,
    source_path: str | Path,
    backup_path: str | Path,
    provenance_path: str | Path,
) -> dict[str, object]:
    """Record where and when a split-workflow backup was created."""
    source = Path(source_path).resolve()
    backup = Path(backup_path).resolve()
    provenance = Path(provenance_path)
    source_lifetime_rows = _lifetime_rows_inserted(source_conn)
    source_page_size = int(
        source_conn.execute("PRAGMA page_size").fetchone()[0]
    )

    destination = _connect_immutable_backup(backup)
    try:
        backup_lifetime_rows = _lifetime_rows_inserted(destination)
        backup_page_size = int(
            destination.execute("PRAGMA page_size").fetchone()[0]
        )
        backup_page_count = int(
            destination.execute("PRAGMA page_count").fetchone()[0]
        )
    finally:
        destination.close()

    if backup_lifetime_rows != source_lifetime_rows:
        raise ValueError(
            "source database changed before backup provenance was recorded"
        )

    unsigned: dict[str, object] = {
        "version": BACKUP_PROVENANCE_VERSION,
        "created_at": format_utc_timestamp(utc_now()),
        "source_database": {
            "path": str(source),
            **_source_database_identity(source),
            "page_size_bytes": source_page_size,
            "lifetime_rows_inserted": source_lifetime_rows,
        },
        "backup": {
            "path": str(backup),
            **_regular_file_identity(backup, label="backup"),
            "page_size_bytes": backup_page_size,
            "page_count": backup_page_count,
            "lifetime_rows_inserted": backup_lifetime_rows,
        },
    }
    payload = {
        **unsigned,
        "provenance_hash": _manifest_digest(unsigned),
    }
    _write_exclusive_manifest(provenance, payload)
    return payload


def _validate_backup_provenance(
    provenance_path: str | Path,
    *,
    source_conn: sqlite3.Connection,
    source_path: str | Path,
    backup_path: str | Path,
) -> dict[str, object]:
    provenance = Path(provenance_path)
    _regular_file_identity(provenance, label="backup provenance")
    if provenance.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(
            "backup provenance exceeds "
            f"{MAX_MANIFEST_BYTES} bytes: {provenance}"
        )
    try:
        payload = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"backup provenance is not valid JSON: {provenance}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("backup provenance root must be an object")
    expected_keys = {
        "version",
        "created_at",
        "source_database",
        "backup",
        "provenance_hash",
    }
    if set(payload) != expected_keys:
        raise ValueError("backup provenance fields do not match version 1")
    if (
        type(payload["version"]) is not int
        or payload["version"] != BACKUP_PROVENANCE_VERSION
    ):
        raise ValueError(
            f"unsupported backup provenance version: {payload['version']}"
        )
    parse_utc_timestamp(payload["created_at"])
    unsigned = dict(payload)
    provenance_hash = unsigned.pop("provenance_hash")
    expected_hash = _manifest_digest(unsigned)
    if not isinstance(provenance_hash, str) or not hmac.compare_digest(
        provenance_hash,
        expected_hash,
    ):
        raise ValueError("backup provenance hash does not match")

    source_metadata = payload["source_database"]
    backup_metadata = payload["backup"]
    if not isinstance(source_metadata, dict) or not isinstance(
        backup_metadata,
        dict,
    ):
        raise ValueError("backup provenance metadata must be objects")
    expected_source_keys = {
        "path",
        "device",
        "inode",
        "page_size_bytes",
        "lifetime_rows_inserted",
    }
    expected_backup_keys = {
        "path",
        "device",
        "inode",
        "size_bytes",
        "mtime_ns",
        "page_size_bytes",
        "page_count",
        "lifetime_rows_inserted",
    }
    if set(source_metadata) != expected_source_keys:
        raise ValueError("backup provenance source metadata is invalid")
    if set(backup_metadata) != expected_backup_keys:
        raise ValueError("backup provenance backup metadata is invalid")

    source = Path(source_path).resolve()
    backup = Path(backup_path).resolve()
    if source_metadata.get("path") != str(source):
        raise ValueError("backup provenance belongs to a different source database")
    if backup_metadata.get("path") != str(backup):
        raise ValueError("backup provenance belongs to a different backup")
    current_source_identity = _source_database_identity(source)
    for key in ("device", "inode"):
        if source_metadata.get(key) != current_source_identity[key]:
            raise ValueError(
                "source database identity changed after backup creation"
            )
    if source_metadata.get("page_size_bytes") != int(
        source_conn.execute("PRAGMA page_size").fetchone()[0]
    ):
        raise ValueError("source database page size changed after backup creation")

    source_lifetime_rows = source_metadata.get("lifetime_rows_inserted")
    backup_lifetime_rows = backup_metadata.get("lifetime_rows_inserted")
    if (
        not isinstance(source_lifetime_rows, int)
        or isinstance(source_lifetime_rows, bool)
        or not isinstance(backup_lifetime_rows, int)
        or isinstance(backup_lifetime_rows, bool)
        or source_lifetime_rows != backup_lifetime_rows
        or _lifetime_rows_inserted(source_conn) < source_lifetime_rows
    ):
        raise ValueError("backup provenance database sequence is invalid")

    current_backup_identity = _regular_file_identity(
        backup,
        label="provenance-bound backup",
    )
    for key in ("device", "inode", "size_bytes", "mtime_ns"):
        if backup_metadata.get(key) != current_backup_identity[key]:
            raise ValueError("backup identity changed after backup creation")
    for key in ("page_size_bytes", "page_count"):
        value = backup_metadata.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("backup provenance database metadata is invalid")
    return payload


def _connect_immutable_backup(path: Path) -> sqlite3.Connection:
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def verify_backup(
    backup_path: str | Path,
    manifest_path: str | Path,
    *,
    source_conn: sqlite3.Connection,
    source_path: str | Path,
    provenance_path: str | Path | None = None,
    limits: BackupLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    report: Callable[[str], None] = _default_backup_report,
    integrity_check: Callable[[sqlite3.Connection], str] | None = None,
    monitor_factory: Callable[..., IntegrityCheckMonitor] | None = None,
) -> dict[str, object]:
    """Verify an immutable backup and publish a bound mode-0600 manifest."""
    backup = Path(backup_path).resolve()
    manifest = Path(manifest_path)
    source = Path(source_path).resolve()
    provenance = (
        Path(provenance_path)
        if provenance_path is not None
        else _backup_provenance_path(backup)
    )
    active_limits = limits or BackupLimits()
    provenance_payload = _validate_backup_provenance(
        provenance,
        source_conn=source_conn,
        source_path=source,
        backup_path=backup,
    )
    backup_identity_before = _regular_file_identity(
        backup,
        label="backup",
    )
    source_identity = _source_database_identity(source)

    destination = _connect_immutable_backup(backup)
    try:
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
        backup_page_size = int(
            destination.execute("PRAGMA page_size").fetchone()[0]
        )
        backup_page_count = int(
            destination.execute("PRAGMA page_count").fetchone()[0]
        )
        backup_lifetime_rows = _lifetime_rows_inserted(destination)
    finally:
        destination.close()

    backup_hash = _hash_file(
        backup,
        clock=clock,
        report=report,
        progress_interval_seconds=(
            active_limits.integrity_progress_interval_seconds
        ),
        max_seconds=active_limits.integrity_max_seconds,
    )
    backup_identity_after = _regular_file_identity(
        backup,
        label="backup",
    )
    if backup_identity_after != backup_identity_before:
        raise ValueError("backup changed while it was being verified")
    provenance_backup = provenance_payload["backup"]
    if (
        not isinstance(provenance_backup, dict)
        or provenance_backup.get("page_size_bytes") != backup_page_size
        or provenance_backup.get("page_count") != backup_page_count
        or provenance_backup.get("lifetime_rows_inserted")
        != backup_lifetime_rows
    ):
        raise ValueError("backup contents do not match backup provenance")

    source_metadata: dict[str, object] = {
        "path": str(source),
        **source_identity,
        "page_size_bytes": int(
            source_conn.execute("PRAGMA page_size").fetchone()[0]
        ),
        "lifetime_rows_inserted": _lifetime_rows_inserted(source_conn),
    }
    backup_metadata: dict[str, object] = {
        "path": str(backup),
        **backup_identity_after,
        "sha256": backup_hash,
        "page_size_bytes": backup_page_size,
        "page_count": backup_page_count,
        "lifetime_rows_inserted": backup_lifetime_rows,
    }
    provenance_identity = _regular_file_identity(
        provenance,
        label="backup provenance",
    )
    provenance_metadata: dict[str, object] = {
        "path": str(provenance.resolve()),
        **provenance_identity,
        "created_at": provenance_payload["created_at"],
        "provenance_hash": provenance_payload["provenance_hash"],
    }
    unsigned: dict[str, object] = {
        "version": BACKUP_MANIFEST_VERSION,
        "verified_at": format_utc_timestamp(utc_now()),
        "integrity_check": "ok",
        "source_database": source_metadata,
        "backup": backup_metadata,
        "backup_provenance": provenance_metadata,
    }
    payload = {
        **unsigned,
        "manifest_hash": _manifest_digest(unsigned),
    }
    _write_exclusive_manifest(manifest, payload)
    return payload


def validate_backup_manifest(
    manifest_path: str | Path,
    *,
    source_conn: sqlite3.Connection,
    source_path: str | Path,
    cutoff: str,
    include_reviewed: bool = False,
    max_age_seconds: float = DEFAULT_MANIFEST_MAX_AGE_SECONDS,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Validate a verified backup manifest without rereading the backup."""
    if max_age_seconds <= 0:
        raise ValueError("manifest max age must be greater than zero")
    manifest = Path(manifest_path)
    _regular_file_identity(manifest, label="verification manifest")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(
            "verification manifest exceeds "
            f"{MAX_MANIFEST_BYTES} bytes: {manifest}"
        )
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"verification manifest is not valid JSON: {manifest}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("verification manifest root must be an object")
    expected_keys = {
        "version",
        "verified_at",
        "integrity_check",
        "source_database",
        "backup",
        "backup_provenance",
        "manifest_hash",
    }
    if set(payload) != expected_keys:
        raise ValueError("verification manifest fields do not match version 1")
    if (
        type(payload["version"]) is not int
        or payload["version"] != BACKUP_MANIFEST_VERSION
    ):
        raise ValueError(
            f"unsupported verification manifest version: {payload['version']}"
        )
    if payload["integrity_check"] != "ok":
        raise ValueError("verification manifest does not record a clean check")

    unsigned = dict(payload)
    manifest_hash = unsigned.pop("manifest_hash")
    expected_hash = _manifest_digest(unsigned)
    if not isinstance(manifest_hash, str) or not hmac.compare_digest(
        manifest_hash,
        expected_hash,
    ):
        raise ValueError("verification manifest hash does not match")

    verified_at = parse_utc_timestamp(payload["verified_at"])
    age_seconds = (utc_now() - verified_at).total_seconds()
    if age_seconds < -300:
        raise ValueError("verification manifest timestamp is in the future")
    if age_seconds > max_age_seconds:
        raise ValueError(
            "verification manifest is too old "
            f"({age_seconds:.0f}s; limit {max_age_seconds:g}s)"
        )

    source_metadata = payload["source_database"]
    backup_metadata = payload["backup"]
    provenance_metadata = payload["backup_provenance"]
    if not isinstance(source_metadata, dict) or not isinstance(
        backup_metadata,
        dict,
    ) or not isinstance(provenance_metadata, dict):
        raise ValueError("verification manifest metadata must be objects")
    expected_source_keys = {
        "path",
        "device",
        "inode",
        "page_size_bytes",
        "lifetime_rows_inserted",
    }
    expected_backup_keys = {
        "path",
        "device",
        "inode",
        "size_bytes",
        "mtime_ns",
        "sha256",
        "page_size_bytes",
        "page_count",
        "lifetime_rows_inserted",
    }
    expected_provenance_keys = {
        "path",
        "device",
        "inode",
        "size_bytes",
        "mtime_ns",
        "created_at",
        "provenance_hash",
    }
    if set(source_metadata) != expected_source_keys:
        raise ValueError("verification manifest source metadata is invalid")
    if set(backup_metadata) != expected_backup_keys:
        raise ValueError("verification manifest backup metadata is invalid")
    if set(provenance_metadata) != expected_provenance_keys:
        raise ValueError(
            "verification manifest provenance metadata is invalid"
        )
    source = Path(source_path).resolve()
    if source_metadata.get("path") != str(source):
        raise ValueError(
            "verification manifest belongs to a different source database"
        )
    current_source_identity = _source_database_identity(source)
    for key in ("device", "inode"):
        if source_metadata.get(key) != current_source_identity[key]:
            raise ValueError(
                "source database identity changed after backup verification"
            )
    if source_metadata.get("page_size_bytes") != int(
        source_conn.execute("PRAGMA page_size").fetchone()[0]
    ):
        raise ValueError("source database page size no longer matches")

    source_lifetime_rows = source_metadata.get("lifetime_rows_inserted")
    backup_lifetime_rows = backup_metadata.get("lifetime_rows_inserted")
    if (
        not isinstance(source_lifetime_rows, int)
        or isinstance(source_lifetime_rows, bool)
        or not isinstance(backup_lifetime_rows, int)
        or isinstance(backup_lifetime_rows, bool)
        or source_lifetime_rows < backup_lifetime_rows
    ):
        raise ValueError("verification manifest database sequence is invalid")
    current_lifetime_rows = _lifetime_rows_inserted(source_conn)
    if current_lifetime_rows < source_lifetime_rows:
        raise ValueError(
            "source database sequence predates the verified backup"
        )

    backup_path_value = backup_metadata.get("path")
    if not isinstance(backup_path_value, str):
        raise ValueError("verification manifest backup path is invalid")
    backup = Path(backup_path_value)
    current_backup_identity = _regular_file_identity(
        backup,
        label="verified backup",
    )
    for key in ("device", "inode", "size_bytes", "mtime_ns"):
        if backup_metadata.get(key) != current_backup_identity[key]:
            raise ValueError(
                "verified backup identity changed after verification"
            )
    backup_hash = backup_metadata.get("sha256")
    if (
        not isinstance(backup_hash, str)
        or not backup_hash.startswith("sha256:")
        or len(backup_hash) != 71
        or any(
            character not in "0123456789abcdef"
            for character in backup_hash[7:]
        )
    ):
        raise ValueError("verification manifest backup hash is invalid")

    provenance_path_value = provenance_metadata.get("path")
    if not isinstance(provenance_path_value, str):
        raise ValueError("verification manifest provenance path is invalid")
    provenance = Path(provenance_path_value)
    current_provenance_identity = _regular_file_identity(
        provenance,
        label="verified backup provenance",
    )
    for key in ("device", "inode", "size_bytes", "mtime_ns"):
        if provenance_metadata.get(key) != current_provenance_identity[key]:
            raise ValueError(
                "verified backup provenance identity changed after verification"
            )
    provenance_payload = _validate_backup_provenance(
        provenance,
        source_conn=source_conn,
        source_path=source,
        backup_path=backup,
    )
    if provenance_metadata.get("provenance_hash") != provenance_payload.get(
        "provenance_hash"
    ):
        raise ValueError("verified backup provenance hash changed")
    created_at = parse_utc_timestamp(provenance_payload["created_at"])
    if provenance_metadata.get("created_at") != provenance_payload.get(
        "created_at"
    ):
        raise ValueError("verified backup provenance timestamp changed")
    backup_age_seconds = (utc_now() - created_at).total_seconds()
    if backup_age_seconds < -300:
        raise ValueError("backup provenance timestamp is in the future")
    if backup_age_seconds > max_age_seconds:
        raise ValueError(
            "verified backup is too old "
            f"({backup_age_seconds:.0f}s; limit {max_age_seconds:g}s)"
        )

    provenance_source = provenance_payload["source_database"]
    if not isinstance(provenance_source, dict):
        raise ValueError("backup provenance source metadata is invalid")
    backup_sequence = provenance_source["lifetime_rows_inserted"]
    canonical_cutoff = format_utc_timestamp(cutoff)
    predicate = _retention_predicate(include_reviewed)
    if deadline is not None:
        source_conn.set_progress_handler(
            lambda: 1 if clock() >= deadline else 0,
            1_000,
        )
    try:
        missing_eligible_row = source_conn.execute(
            f"""SELECT 1
                FROM triage_events
                WHERE id > ? AND {predicate}
                LIMIT 1""",
            (backup_sequence, canonical_cutoff),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if deadline is not None and clock() >= deadline:
            raise RetentionDeadlineExceeded(
                "backup authorization exceeded the maintenance deadline"
            ) from exc
        raise
    finally:
        if deadline is not None:
            source_conn.set_progress_handler(None, 0)
    if missing_eligible_row is not None:
        raise ValueError(
            "verified backup does not contain every row eligible for this prune"
        )
    return payload


def prune_events(
    conn: sqlite3.Connection,
    cutoff: str,
    *,
    include_reviewed: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pause_ms: int = DEFAULT_PAUSE_MS,
    max_rows: int | None = None,
    max_runtime_seconds: float | None = None,
    deadline: float | None = None,
    progress: Callable[[int, int], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
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
    if max_runtime_seconds is not None and max_runtime_seconds <= 0:
        raise ValueError("max_runtime_seconds must be greater than zero")

    canonical_cutoff = format_utc_timestamp(cutoff)
    predicate = _retention_predicate(include_reviewed)
    deleted_rows = 0
    batches = 0
    started_at = clock()
    runtime_deadline = (
        started_at + max_runtime_seconds
        if max_runtime_seconds is not None
        else None
    )
    effective_deadline = deadline
    if runtime_deadline is not None:
        effective_deadline = (
            min(effective_deadline, runtime_deadline)
            if effective_deadline is not None
            else runtime_deadline
        )
    stopped_reason = "exhausted"

    while True:
        if max_rows is not None and deleted_rows >= max_rows:
            stopped_reason = "max_rows"
            break
        if effective_deadline is not None and clock() >= effective_deadline:
            stopped_reason = "max_runtime"
            break

        current_batch = batch_size
        if max_rows is not None:
            current_batch = min(current_batch, max_rows - deleted_rows)

        interrupted_for_deadline = False
        if effective_deadline is not None:
            conn.set_progress_handler(
                lambda: 1 if clock() >= effective_deadline else 0,
                1_000,
            )
        try:
            conn.execute("BEGIN IMMEDIATE")
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
        except sqlite3.OperationalError:
            conn.rollback()
            if (
                effective_deadline is not None
                and clock() >= effective_deadline
            ):
                interrupted_for_deadline = True
            else:
                raise
        except Exception:
            conn.rollback()
            raise
        finally:
            if effective_deadline is not None:
                conn.set_progress_handler(None, 0)

        if interrupted_for_deadline:
            stopped_reason = "max_runtime"
            break

        if deleted == 0:
            break
        deleted_rows += deleted
        batches += 1
        if progress is not None:
            progress(deleted_rows, batches)
        if deleted < current_batch:
            stopped_reason = "exhausted"
            break
        if pause_ms:
            time.sleep(pause_ms / 1_000.0)

    if stopped_reason != "exhausted" and not (
        effective_deadline is not None and clock() >= effective_deadline
    ):
        if effective_deadline is not None:
            conn.set_progress_handler(
                lambda: 1 if clock() >= effective_deadline else 0,
                1_000,
            )
        try:
            remaining = conn.execute(
                f"""SELECT 1
                    FROM triage_events
                    WHERE {predicate}
                    LIMIT 1""",
                (canonical_cutoff,),
            ).fetchone()
            if remaining is None:
                stopped_reason = "exhausted"
        except sqlite3.OperationalError:
            if not (
                effective_deadline is not None
                and clock() >= effective_deadline
            ):
                raise
        finally:
            if effective_deadline is not None:
                conn.set_progress_handler(None, 0)

    deleted_asset_snapshots = 0
    orphan_cleanup_deferred = stopped_reason != "exhausted"
    if stopped_reason == "exhausted":
        if (
            effective_deadline is not None
            and clock() >= effective_deadline
        ):
            orphan_cleanup_deferred = True
        else:
            if effective_deadline is not None:
                conn.set_progress_handler(
                    lambda: 1 if clock() >= effective_deadline else 0,
                    1_000,
                )
            try:
                conn.execute("BEGIN IMMEDIATE")
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
                orphan_cleanup_deferred = False
            except sqlite3.OperationalError:
                conn.rollback()
                if (
                    effective_deadline is not None
                    and clock() >= effective_deadline
                ):
                    orphan_cleanup_deferred = True
                else:
                    raise
            except Exception:
                conn.rollback()
                raise
            finally:
                if effective_deadline is not None:
                    conn.set_progress_handler(None, 0)

    checkpoint = (0, 0, 0)
    if not (
        effective_deadline is not None and clock() >= effective_deadline
    ):
        if effective_deadline is not None:
            conn.set_progress_handler(
                lambda: 1 if clock() >= effective_deadline else 0,
                1_000,
            )
        try:
            checkpoint = conn.execute(
                "PRAGMA wal_checkpoint(PASSIVE)"
            ).fetchone()
        except sqlite3.OperationalError:
            if not (
                effective_deadline is not None
                and clock() >= effective_deadline
            ):
                raise
        finally:
            if effective_deadline is not None:
                conn.set_progress_handler(None, 0)
    return PruneResult(
        deleted_rows=deleted_rows,
        deleted_asset_snapshots=deleted_asset_snapshots,
        orphan_cleanup_deferred=orphan_cleanup_deferred,
        batches=batches,
        checkpoint_busy_frames=int(checkpoint[0]),
        checkpoint_log_frames=int(checkpoint[1]),
        checkpointed_frames=int(checkpoint[2]),
        stopped_reason=stopped_reason,
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


def _add_backup_limit_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_copy: bool = True,
    include_integrity: bool = True,
) -> None:
    if include_copy:
        parser.add_argument(
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
        parser.add_argument(
            "--backup-stall-seconds",
            type=_bounded_int(
                "backup-stall-seconds", 1, MAX_BACKUP_BOUND_SECONDS
            ),
            default=DEFAULT_BACKUP_STALL_SECONDS,
            help=(
                "Abort when backup makes no forward page progress for this "
                f"long (default: {DEFAULT_BACKUP_STALL_SECONDS})."
            ),
        )
        parser.add_argument(
            "--backup-max-restarts",
            type=_bounded_int("backup-max-restarts", 0, MAX_BACKUP_RESTARTS),
            default=DEFAULT_BACKUP_MAX_RESTARTS,
            help=(
                "Abort after this many backup remaining-page resets "
                f"(default: {DEFAULT_BACKUP_MAX_RESTARTS})."
            ),
        )
        parser.add_argument(
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
    else:
        parser.set_defaults(
            backup_max_seconds=DEFAULT_BACKUP_MAX_SECONDS,
            backup_stall_seconds=DEFAULT_BACKUP_STALL_SECONDS,
            backup_max_restarts=DEFAULT_BACKUP_MAX_RESTARTS,
            backup_progress_seconds=DEFAULT_BACKUP_PROGRESS_SECONDS,
        )
    if not include_integrity:
        parser.set_defaults(
            integrity_check_max_seconds=DEFAULT_INTEGRITY_MAX_SECONDS,
            integrity_progress_seconds=DEFAULT_INTEGRITY_PROGRESS_SECONDS,
        )
        return
    parser.add_argument(
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
    parser.add_argument(
        "--integrity-progress-seconds",
        type=_bounded_int(
            "integrity-progress-seconds", 1, MAX_BACKUP_BOUND_SECONDS
        ),
        default=DEFAULT_INTEGRITY_PROGRESS_SECONDS,
        help=(
            "Seconds between integrity/hash progress lines on stderr "
            f"(default: {DEFAULT_INTEGRITY_PROGRESS_SECONDS})."
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

    backup_copy = subparsers.add_parser(
        "backup",
        help="Create a bounded backup copy without holding writers for verification.",
    )
    _add_database_argument(backup_copy)
    backup_copy.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Exclusive destination for the unverified backup copy.",
    )
    backup_copy.add_argument(
        "--provenance",
        type=Path,
        help=(
            "Exclusive provenance destination (default: "
            "OUTPUT.provenance.json)."
        ),
    )
    backup_copy.add_argument(
        "--confirm-writers-stopped",
        action="store_true",
        help=(
            "Operator acknowledgement that dashboard and ingest writers are "
            "stopped for a convergent production backup."
        ),
    )
    _add_backup_limit_arguments(backup_copy, include_integrity=False)
    backup_copy.add_argument("--json", action="store_true")

    verify = subparsers.add_parser(
        "verify-backup",
        help="Verify a backup while live monitoring continues and write a manifest.",
    )
    _add_database_argument(verify)
    verify.add_argument("--backup", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument(
        "--provenance",
        type=Path,
        help=(
            "Backup provenance created by the backup command (default: "
            "BACKUP.provenance.json)."
        ),
    )
    _add_backup_limit_arguments(verify, include_copy=False)
    verify.add_argument("--json", action="store_true")

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
        "--max-runtime-seconds",
        type=_bounded_int(
            "max-runtime-seconds", 1, MAX_PRUNE_SECONDS
        ),
        help=(
            "Bound the full applied prune command, including planning and "
            "reporting. Orphan cleanup is deferred when time expires."
        ),
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
            "Operator acknowledgement that the dashboard, Suricata ingest, "
            "and optional wazuh-ingest are stopped before --apply. This does "
            "not prove writers are stopped."
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
    backup.add_argument(
        "--verified-backup-manifest",
        type=Path,
        help=(
            "Use a fresh verification manifest instead of repeating backup "
            "copy and integrity checking."
        ),
    )
    prune.add_argument(
        "--verified-backup-max-age-seconds",
        type=_bounded_int(
            "verified-backup-max-age-seconds",
            1,
            MAX_MANIFEST_AGE_SECONDS,
        ),
        default=DEFAULT_MANIFEST_MAX_AGE_SECONDS,
    )
    _add_backup_limit_arguments(prune)
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


def _storage_metrics_before_deadline(
    conn: sqlite3.Connection,
    db_path: Path,
    *,
    deadline: float | None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, int | float | str] | None:
    if deadline is not None and clock() >= deadline:
        return None
    if deadline is not None:
        conn.set_progress_handler(
            lambda: 1 if clock() >= deadline else 0,
            1_000,
        )
    try:
        return get_storage_metrics(conn, db_path)
    except sqlite3.OperationalError:
        if deadline is not None and clock() >= deadline:
            return None
        raise
    finally:
        if deadline is not None:
            conn.set_progress_handler(None, 0)


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
        and not args.verified_backup_manifest
    ):
        parser.error(
            "--apply requires --backup PATH, --verified-backup-manifest "
            "PATH, or --no-backup"
        )
    if args.command == "prune" and args.apply and not args.confirm_writers_stopped:
        parser.error(
            "--apply requires --confirm-writers-stopped: stop the dashboard, "
            "Suricata ingest, and optional wazuh-ingest first. This flag is "
            "an operator acknowledgement, not proof that all writers are "
            "stopped."
        )
    if (
        args.command == "prune"
        and args.apply
        and args.backup
        and args.max_runtime_seconds is not None
    ):
        parser.error(
            "--max-runtime-seconds cannot bound an inline backup; use the "
            "split backup, verify-backup, and verified-manifest workflow"
        )
    if (
        args.command == "backup"
        and not args.confirm_writers_stopped
    ):
        parser.error(
            "backup requires --confirm-writers-stopped: stop the dashboard, "
            "Suricata ingest, and optional wazuh-ingest first. This flag is "
            "an operator acknowledgement, not proof that all writers are "
            "stopped."
        )

    maintenance_deadline = None
    if (
        args.command == "prune"
        and args.apply
        and args.max_runtime_seconds is not None
    ):
        maintenance_deadline = (
            time.monotonic() + args.max_runtime_seconds
        )

    readonly = args.command in {"status", "backup", "verify-backup"} or (
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
        if args.command == "backup":
            output = create_backup_copy(
                conn,
                args.output,
                source_path=args.db,
                provenance_path=args.provenance,
                limits=_backup_limits_from_args(args),
            )
            provenance = (
                args.provenance
                if args.provenance is not None
                else _backup_provenance_path(args.output)
            )
            _print_payload(
                {
                    "mode": "backup",
                    "database": str(args.db),
                    "backup": str(output),
                    "provenance": str(provenance),
                    "verified": False,
                },
                args.json,
            )
            return 0
        if args.command == "verify-backup":
            verification = verify_backup(
                args.backup,
                args.manifest,
                source_conn=conn,
                source_path=args.db,
                provenance_path=args.provenance,
                limits=_backup_limits_from_args(args),
            )
            _print_payload(
                {
                    "mode": "verify_backup",
                    "database": str(args.db),
                    "backup": str(args.backup),
                    "manifest": str(args.manifest),
                    "verification": verification,
                },
                args.json,
            )
            return 0

        try:
            cutoff = _cutoff_from_args(args)
            plan = build_retention_plan(
                conn,
                cutoff,
                include_reviewed=args.include_reviewed,
                deadline=maintenance_deadline,
                clock=time.monotonic,
            )
        except (TypeError, ValueError) as exc:
            parser.error(str(exc))

        payload: dict[str, object] = {
            "mode": "apply" if args.apply else "dry_run",
            "database": str(args.db),
            "plan": asdict(plan),
            "storage_before": _storage_metrics_before_deadline(
                conn,
                args.db,
                deadline=maintenance_deadline,
                clock=time.monotonic,
            ),
        }
        if args.apply and payload["storage_before"] is None:
            raise RetentionDeadlineExceeded(
                "retention preflight consumed the maintenance deadline"
            )
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
        elif args.verified_backup_manifest:
            verification = validate_backup_manifest(
                args.verified_backup_manifest,
                source_conn=conn,
                source_path=args.db,
                cutoff=cutoff,
                include_reviewed=args.include_reviewed,
                max_age_seconds=float(
                    args.verified_backup_max_age_seconds
                ),
                deadline=maintenance_deadline,
                clock=time.monotonic,
            )
            payload["verified_backup"] = verification["backup"]
            payload["verification_manifest"] = str(
                args.verified_backup_manifest
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
            deadline=maintenance_deadline,
            progress=report_progress,
            clock=time.monotonic,
        )
        payload["result"] = asdict(result)
        payload["storage_after"] = _storage_metrics_before_deadline(
            conn,
            args.db,
            deadline=maintenance_deadline,
            clock=time.monotonic,
        )
        _print_payload(payload, args.json)
        return 0
    except (
        BackupLimitExceeded,
        RetentionDeadlineExceeded,
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
