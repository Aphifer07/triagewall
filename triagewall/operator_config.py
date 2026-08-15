"""Immutable operator-configuration revision persistence and bootstrap."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .asset_inventory import AssetInventory, canonical_json
    from .database import connect_database
    from .migrations import verify_db_initialized
    from .prefilter import MAX_CONFIG_BYTES, PrefilterPolicy
    from .time_utils import utc_now_iso
except ImportError:  # Direct script-style imports used by container entrypoints.
    from asset_inventory import AssetInventory, canonical_json
    from database import connect_database
    from migrations import verify_db_initialized
    from prefilter import MAX_CONFIG_BYTES, PrefilterPolicy
    from time_utils import utc_now_iso


PREFILTER_KIND = "prefilter_policy"
ASSET_KIND = "asset_inventory"
CONFIG_KINDS = frozenset({PREFILTER_KIND, ASSET_KIND})
SYSTEM_ACTOR = "system:config-bootstrap"
SYSTEM_AUTH_VIA = "system"


class OperatorConfigError(RuntimeError):
    """Raised when durable configuration state is unsafe or inconsistent."""


@dataclass(frozen=True)
class CanonicalRevision:
    kind: str
    source: str
    revision: str
    document_json: str
    validation_json: str


@dataclass(frozen=True)
class BootstrapResult:
    generation: int
    mode: str
    active_prefilter_revision: str
    active_asset_revision: str
    initialized: bool
    discovered_shipped_revision: bool


@dataclass(frozen=True)
class ActiveState:
    generation: int
    mode: str
    active_prefilter_id: int
    active_asset_id: int
    active_prefilter_revision: str
    active_asset_revision: str


@dataclass(frozen=True)
class DecisionBundle:
    """Exact durable configuration tuple used for one classification."""

    generation: int
    prefilter_revision: str
    asset_revision: str


def _read_json_document(path: Path | str, label: str) -> Any:
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise OperatorConfigError(f"cannot read {label}: {exc}") from exc
    if size > MAX_CONFIG_BYTES:
        raise OperatorConfigError(f"{label} exceeds the 1 MiB size limit")
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise OperatorConfigError(f"cannot read {label}: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise OperatorConfigError(f"{label} exceeds the 1 MiB size limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorConfigError(f"{label} must be valid UTF-8 JSON") from exc


def _revision(kind: str, source: str, document: Any, validation: Any) -> CanonicalRevision:
    document_json = canonical_json(document)
    encoded = document_json.encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise OperatorConfigError("canonical configuration exceeds the 1 MiB size limit")
    return CanonicalRevision(
        kind=kind,
        source=source,
        revision="sha256:" + hashlib.sha256(encoded).hexdigest(),
        document_json=document_json,
        validation_json=canonical_json(validation),
    )


def canonicalize_document(kind: str, document: Any) -> tuple[Any, dict[str, Any]]:
    """Validate and normalize one decoded configuration document."""
    if kind == PREFILTER_KIND:
        policy = PrefilterPolicy.from_document(document)
        return policy.to_document(), {
            "status": "valid",
            "kind": kind,
            "rule_count": len(policy.rules),
            "scoped_rule_count": sum(rule.match is not None for rule in policy.rules),
        }
    if kind == ASSET_KIND:
        inventory = AssetInventory.from_document(document)
        return inventory.to_document(), {
            "status": "valid",
            "kind": kind,
            "asset_count": inventory.count,
        }
    raise OperatorConfigError(f"unsupported configuration kind {kind!r}")


def load_revision(kind: str, path: Path | str, source: str) -> CanonicalRevision:
    """Load, strictly validate, normalize, and fingerprint one document."""
    if source not in {"shipped", "operator_import", "operator"}:
        raise OperatorConfigError(f"unsupported configuration source {source!r}")
    decoded = _read_json_document(path, kind)
    try:
        document, validation = canonicalize_document(kind, decoded)
    except (TypeError, ValueError) as exc:
        raise OperatorConfigError(f"invalid {kind}: {exc}") from exc
    return _revision(kind, source, document, validation)


def validate_stored_revision(
    kind: str,
    document_json: str,
    expected_revision: str,
) -> None:
    """Fail when stored content is invalid, non-canonical, or digest-mismatched."""
    try:
        decoded = json.loads(document_json)
        document, validation = canonicalize_document(kind, decoded)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise OperatorConfigError(f"stored {kind} revision is invalid: {exc}") from exc
    actual = _revision(kind, "operator", document, validation)
    if actual.document_json != document_json:
        raise OperatorConfigError(f"stored {kind} revision is not canonical")
    if actual.revision != expected_revision:
        raise OperatorConfigError(f"stored {kind} revision digest does not match content")


def _insert_revision(
    conn: sqlite3.Connection,
    revision: CanonicalRevision,
    *,
    state: str,
    shipped_base_revision: str | None,
    created_at: str,
) -> tuple[int, bool]:
    cursor = conn.execute(
        """INSERT OR IGNORE INTO operator_config_revisions (
               kind, revision, document_json, source, shipped_base_revision,
               state, validation_json, created_at, created_by
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            revision.kind,
            revision.revision,
            revision.document_json,
            revision.source,
            shipped_base_revision,
            state,
            revision.validation_json,
            created_at,
            SYSTEM_ACTOR,
        ),
    )
    row = conn.execute(
        """SELECT id, document_json FROM operator_config_revisions
           WHERE kind = ? AND revision = ?""",
        (revision.kind, revision.revision),
    ).fetchone()
    if row is None:
        raise OperatorConfigError("configuration revision insert did not persist")
    if str(row[1]) != revision.document_json:
        raise OperatorConfigError(
            f"stored {revision.kind} revision content does not match its digest"
        )
    return int(row[0]), cursor.rowcount == 1


def _is_new_shipped_observation(
    conn: sqlite3.Connection,
    revision_id: int,
    inserted: bool,
) -> bool:
    if inserted:
        return True
    row = conn.execute(
        "SELECT source FROM operator_config_revisions WHERE id = ?",
        (revision_id,),
    ).fetchone()
    if row is None:
        raise OperatorConfigError("shipped configuration revision is missing")
    if row[0] == "shipped":
        return False
    observed = conn.execute(
        """SELECT 1 FROM operator_config_audit
           WHERE revision_id = ? AND action = 'shipped_revision_discovered'
           LIMIT 1""",
        (revision_id,),
    ).fetchone()
    return observed is None


def _audit(
    conn: sqlite3.Connection,
    *,
    occurred_at: str,
    action: str,
    kind: str | None = None,
    revision_id: int | None = None,
    to_revision_id: int | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """INSERT INTO operator_config_audit (
               occurred_at, kind, revision_id, to_revision_id, actor,
               auth_via, action, detail_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            occurred_at,
            kind,
            revision_id,
            to_revision_id,
            SYSTEM_ACTOR,
            SYSTEM_AUTH_VIA,
            action,
            canonical_json(detail or {}),
        ),
    )


def _active_revision(
    conn: sqlite3.Connection,
    revision_id: int,
    expected_kind: str,
) -> str:
    row = conn.execute(
        """SELECT kind, revision, document_json, state
           FROM operator_config_revisions WHERE id = ?""",
        (revision_id,),
    ).fetchone()
    if row is None:
        raise OperatorConfigError(f"active {expected_kind} revision is missing")
    kind, revision, document_json, state = row
    if kind != expected_kind:
        raise OperatorConfigError(f"active {expected_kind} pointer names {kind!r}")
    if state != "active":
        raise OperatorConfigError(f"active {expected_kind} revision has state {state!r}")
    validate_stored_revision(kind, document_json, revision)
    return str(revision)


def _read_existing_state(conn: sqlite3.Connection) -> ActiveState | None:
    row = conn.execute(
        """SELECT active_prefilter_revision_id, active_asset_revision_id,
                  generation, mode
           FROM operator_config_state WHERE id = 1"""
    ).fetchone()
    if row is None:
        return None
    prefilter_revision = _active_revision(conn, int(row[0]), PREFILTER_KIND)
    asset_revision = _active_revision(conn, int(row[1]), ASSET_KIND)
    mode = str(row[3])
    if mode not in {"legacy", "database"}:
        raise OperatorConfigError(f"operator configuration mode is invalid: {mode!r}")
    return ActiveState(
        generation=int(row[2]),
        mode=mode,
        active_prefilter_id=int(row[0]),
        active_asset_id=int(row[1]),
        active_prefilter_revision=prefilter_revision,
        active_asset_revision=asset_revision,
    )


def load_decision_bundle(
    conn: sqlite3.Connection,
    *,
    effective_prefilter_document: Any,
    effective_asset_revision: str,
) -> DecisionBundle:
    """Resolve and verify the durable bundle represented by loaded runtime data.

    Slice 3 still runs consumers from legacy-mounted files. Refuse database mode
    until the hot-reload cutover in Slice 4, and refuse any legacy/database
    mismatch so an event can never be stamped with provenance it did not use.
    """
    state = _read_existing_state(conn)
    if state is None:
        raise OperatorConfigError("active operator configuration state is missing")
    if state.mode != "legacy":
        raise OperatorConfigError(
            "database configuration mode requires generation-aware consumers"
        )
    try:
        canonical_prefilter, validation = canonicalize_document(
            PREFILTER_KIND,
            effective_prefilter_document,
        )
    except (TypeError, ValueError) as exc:
        raise OperatorConfigError("effective prefilter policy is invalid") from exc
    effective_prefilter = _revision(
        PREFILTER_KIND,
        "operator",
        canonical_prefilter,
        validation,
    ).revision
    if effective_prefilter != state.active_prefilter_revision:
        raise OperatorConfigError(
            "loaded prefilter policy does not match the active durable revision"
        )
    if effective_asset_revision != state.active_asset_revision:
        raise OperatorConfigError(
            "loaded asset inventory does not match the active durable revision"
        )
    return DecisionBundle(
        generation=state.generation,
        prefilter_revision=state.active_prefilter_revision,
        asset_revision=state.active_asset_revision,
    )


def bootstrap_operator_configuration(
    db_path: Path | str,
    *,
    packaged_prefilter_path: Path | str,
    legacy_prefilter_path: Path | str,
    asset_inventory_path: Path | str,
    occurred_at: str | None = None,
) -> BootstrapResult:
    """Initialize or synchronize the durable operator-configuration bundle.

    In ``legacy`` mode, the mounted files remain the runtime authority, so each
    startup mirrors their validated effective documents into the database. In
    ``database`` mode, durable active pointers are authoritative and mounted
    legacy files are ignored.
    """
    verify_db_initialized(db_path)
    probe = connect_database(db_path, readonly=True)
    try:
        probed_state = _read_existing_state(probe)
    finally:
        probe.close()

    packaged = load_revision(PREFILTER_KIND, packaged_prefilter_path, "shipped")
    legacy = None
    assets = None
    if probed_state is None or probed_state.mode == "legacy":
        legacy = load_revision(
            PREFILTER_KIND,
            legacy_prefilter_path,
            "operator_import",
        )
        assets = load_revision(
            ASSET_KIND,
            asset_inventory_path,
            "operator_import",
        )
    timestamp = occurred_at or utc_now_iso()

    conn = connect_database(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = _read_existing_state(conn)
        shipped_id, shipped_inserted = _insert_revision(
            conn,
            packaged,
            state="validated",
            shipped_base_revision=packaged.revision,
            created_at=timestamp,
        )
        shipped_discovered = _is_new_shipped_observation(
            conn,
            shipped_id,
            shipped_inserted,
        )

        if shipped_discovered and (existing is not None or not shipped_inserted):
            _audit(
                conn,
                occurred_at=timestamp,
                action="shipped_revision_discovered",
                kind=PREFILTER_KIND,
                revision_id=shipped_id,
                detail={"revision": packaged.revision},
            )

        if existing is not None and existing.mode == "database":
            conn.commit()
            return BootstrapResult(
                generation=existing.generation,
                mode=existing.mode,
                active_prefilter_revision=existing.active_prefilter_revision,
                active_asset_revision=existing.active_asset_revision,
                initialized=False,
                discovered_shipped_revision=shipped_discovered,
            )

        if legacy is None or assets is None:
            raise OperatorConfigError(
                "operator configuration mode changed during bootstrap"
            )
        if legacy.revision == packaged.revision:
            desired_prefilter_id = shipped_id
        else:
            desired_prefilter_id, _ = _insert_revision(
                conn,
                legacy,
                state="validated",
                shipped_base_revision=packaged.revision,
                created_at=timestamp,
            )
        desired_asset_id, _ = _insert_revision(
            conn,
            assets,
            state="validated",
            shipped_base_revision=None,
            created_at=timestamp,
        )

        if existing is not None:
            changed = (
                desired_prefilter_id != existing.active_prefilter_id
                or desired_asset_id != existing.active_asset_id
            )
            if not changed:
                conn.commit()
                return BootstrapResult(
                    generation=existing.generation,
                    mode=existing.mode,
                    active_prefilter_revision=existing.active_prefilter_revision,
                    active_asset_revision=existing.active_asset_revision,
                    initialized=False,
                    discovered_shipped_revision=shipped_discovered,
                )

            old_ids = {
                revision_id
                for revision_id, desired_id in (
                    (existing.active_prefilter_id, desired_prefilter_id),
                    (existing.active_asset_id, desired_asset_id),
                )
                if revision_id != desired_id
            }
            conn.executemany(
                """UPDATE operator_config_revisions SET state = 'superseded'
                   WHERE id = ?""",
                ((revision_id,) for revision_id in old_ids),
            )
            conn.execute(
                """UPDATE operator_config_revisions SET state = 'active'
                   WHERE id IN (?, ?)""",
                (desired_prefilter_id, desired_asset_id),
            )
            next_generation = existing.generation + 1
            conn.execute(
                """UPDATE operator_config_state
                   SET active_prefilter_revision_id = ?,
                       active_asset_revision_id = ?,
                       previous_prefilter_revision_id = ?,
                       previous_asset_revision_id = ?,
                       generation = ?, updated_at = ?
                   WHERE id = 1""",
                (
                    desired_prefilter_id,
                    desired_asset_id,
                    existing.active_prefilter_id,
                    existing.active_asset_id,
                    next_generation,
                    timestamp,
                ),
            )
            _audit(
                conn,
                occurred_at=timestamp,
                action="legacy_sync_activated",
                detail={
                    "mode": "legacy",
                    "generation": next_generation,
                    "prefilter_revision_id": desired_prefilter_id,
                    "prefilter_revision": legacy.revision,
                    "asset_revision_id": desired_asset_id,
                    "asset_revision": assets.revision,
                },
            )
            conn.commit()
            return BootstrapResult(
                generation=next_generation,
                mode="legacy",
                active_prefilter_revision=legacy.revision,
                active_asset_revision=assets.revision,
                initialized=False,
                discovered_shipped_revision=shipped_discovered,
            )

        active_prefilter_id = desired_prefilter_id
        active_asset_id = desired_asset_id
        conn.execute(
            """UPDATE operator_config_revisions SET state = 'active'
               WHERE id IN (?, ?)""",
            (active_prefilter_id, active_asset_id),
        )
        conn.execute(
            """INSERT INTO operator_config_state (
                   id, active_prefilter_revision_id, active_asset_revision_id,
                   mode, generation, updated_at
               ) VALUES (1, ?, ?, 'legacy', 1, ?)""",
            (active_prefilter_id, active_asset_id, timestamp),
        )
        _audit(
            conn,
            occurred_at=timestamp,
            action="bootstrap_activated",
            detail={
                "mode": "legacy",
                "generation": 1,
                "prefilter_revision_id": active_prefilter_id,
                "prefilter_revision": legacy.revision
                if legacy.revision != packaged.revision
                else packaged.revision,
                "asset_revision_id": active_asset_id,
                "asset_revision": assets.revision,
                "legacy_prefilter_imported": legacy.revision != packaged.revision,
            },
        )
        conn.commit()
        return BootstrapResult(
            generation=1,
            mode="legacy",
            active_prefilter_revision=legacy.revision
            if legacy.revision != packaged.revision
            else packaged.revision,
            active_asset_revision=assets.revision,
            initialized=True,
            discovered_shipped_revision=shipped_discovered,
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
