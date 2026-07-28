"""Cheap SQLite storage telemetry for operators and health endpoints."""

from pathlib import Path
import sqlite3


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def get_storage_metrics(
    conn: sqlite3.Connection,
    db_path: str | Path,
) -> dict[str, int | float | str]:
    """Return allocation metrics without scanning application tables."""
    path = Path(db_path)
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    freelist_pages = int(
        conn.execute("PRAGMA freelist_count").fetchone()[0]
    )
    auto_vacuum_value = int(
        conn.execute("PRAGMA auto_vacuum").fetchone()[0]
    )
    auto_vacuum = {
        0: "none",
        1: "full",
        2: "incremental",
    }.get(auto_vacuum_value, "unknown")

    database_bytes = _file_size(path)
    wal_bytes = _file_size(Path(f"{path}-wal"))
    shm_bytes = _file_size(Path(f"{path}-shm"))
    reusable_bytes = freelist_pages * page_size
    allocated_bytes = page_count * page_size
    reusable_percent = (
        round((reusable_bytes / allocated_bytes) * 100.0, 2)
        if allocated_bytes
        else 0.0
    )

    return {
        "database_bytes": database_bytes,
        "wal_bytes": wal_bytes,
        "shm_bytes": shm_bytes,
        "total_on_disk_bytes": database_bytes + wal_bytes + shm_bytes,
        "page_size_bytes": page_size,
        "page_count": page_count,
        "freelist_pages": freelist_pages,
        "reusable_bytes": reusable_bytes,
        "reusable_percent": reusable_percent,
        "auto_vacuum": auto_vacuum,
    }
