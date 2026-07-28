#!/usr/bin/env python3
"""Dry-run-first retention controls for the Triagewall SQLite database."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import timedelta
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
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


def create_online_backup(
    source: sqlite3.Connection,
    backup_path: str | Path,
) -> Path:
    """Create and integrity-check a new SQLite backup without overwriting."""
    target = Path(backup_path)
    if target.exists():
        raise FileExistsError(f"backup target already exists: {target}")
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

    destination = sqlite3.connect(target)
    try:
        source.backup(destination, pages=1_024, sleep=0.05)
        result = destination.execute("PRAGMA quick_check").fetchone()[0]
        if result != "ok":
            raise sqlite3.DatabaseError(
                f"backup integrity check failed: {result}"
            )
    except Exception:
        destination.close()
        try:
            target.unlink()
        except OSError:
            pass
        raise
    destination.close()
    return target


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
            payload["backup"] = str(create_online_backup(conn, args.backup))

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
