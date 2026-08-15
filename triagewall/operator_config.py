"""Immutable operator-configuration revision persistence and bootstrap."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
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
class ConfigurationBundle:
    """One complete, immutable runtime configuration generation."""

    generation: int
    mode: str
    prefilter_policy: PrefilterPolicy
    prefilter_revision: str
    prefilter_shipped_base_revision: str | None
    asset_inventory: AssetInventory
    asset_revision: str
    asset_shipped_base_revision: str | None
    loaded_at: str


RUNTIME_CONSUMERS = frozenset({"suricata", "wazuh"})
DEFAULT_RELOAD_INTERVAL_SECONDS = 5.0
MAX_RELOAD_BACKOFF_SECONDS = 60.0


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
    actor: str = SYSTEM_ACTOR,
    auth_via: str = SYSTEM_AUTH_VIA,
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
            actor,
            auth_via,
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


def _runtime_revision_row(
    conn: sqlite3.Connection,
    revision_id: int,
    expected_kind: str,
):
    row = conn.execute(
        """SELECT id, kind, revision, document_json, shipped_base_revision,
                  state
           FROM operator_config_revisions WHERE id = ?""",
        (revision_id,),
    ).fetchone()
    if row is None:
        raise OperatorConfigError(f"active {expected_kind} revision is missing")
    if row[1] != expected_kind or row[5] != "active":
        raise OperatorConfigError(f"active {expected_kind} pointer is inconsistent")
    validate_stored_revision(expected_kind, str(row[3]), str(row[2]))
    return row


def load_configuration_bundle(
    conn: sqlite3.Connection,
    *,
    legacy_prefilter_policy: PrefilterPolicy,
    legacy_asset_inventory: AssetInventory,
    loaded_at: str | None = None,
) -> ConfigurationBundle:
    """Read, validate, and construct both active documents from one snapshot."""
    if conn.in_transaction:
        raise OperatorConfigError(
            "runtime configuration must be loaded between database transactions"
        )
    try:
        conn.execute("BEGIN")
        state = conn.execute(
            """SELECT mode, generation, active_prefilter_revision_id,
                      active_asset_revision_id
               FROM operator_config_state WHERE id = 1"""
        ).fetchone()
        if state is None:
            raise OperatorConfigError("active operator configuration state is missing")
        mode = str(state[0])
        if mode not in {"legacy", "database"}:
            raise OperatorConfigError("active operator configuration mode is invalid")
        prefilter_row = _runtime_revision_row(
            conn,
            int(state[2]),
            PREFILTER_KIND,
        )
        asset_row = _runtime_revision_row(
            conn,
            int(state[3]),
            ASSET_KIND,
        )
        if mode == "legacy":
            effective_prefilter = _revision(
                PREFILTER_KIND,
                "operator",
                legacy_prefilter_policy.to_document(),
                canonicalize_document(
                    PREFILTER_KIND,
                    legacy_prefilter_policy.to_document(),
                )[1],
            ).revision
            if effective_prefilter != prefilter_row[2]:
                raise OperatorConfigError(
                    "loaded prefilter policy does not match the active durable revision"
                )
            if legacy_asset_inventory.revision != asset_row[2]:
                raise OperatorConfigError(
                    "loaded asset inventory does not match the active durable revision"
                )
            policy = legacy_prefilter_policy
            inventory = legacy_asset_inventory
        else:
            try:
                policy = PrefilterPolicy.from_document(
                    json.loads(str(prefilter_row[3]))
                )
                inventory = AssetInventory.from_document(
                    json.loads(str(asset_row[3]))
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise OperatorConfigError(
                    "active database configuration could not be constructed"
                ) from exc
        bundle = ConfigurationBundle(
            generation=int(state[1]),
            mode=mode,
            prefilter_policy=policy,
            prefilter_revision=str(prefilter_row[2]),
            prefilter_shipped_base_revision=(
                str(prefilter_row[4]) if prefilter_row[4] is not None else None
            ),
            asset_inventory=inventory,
            asset_revision=str(asset_row[2]),
            asset_shipped_base_revision=(
                str(asset_row[4]) if asset_row[4] is not None else None
            ),
            loaded_at=loaded_at or utc_now_iso(),
        )
        conn.commit()
        return bundle
    except Exception:
        conn.rollback()
        raise


def _bounded_reload_error(_exc: Exception) -> str:
    return "active configuration reload failed validation"


def _record_consumer_status(
    conn: sqlite3.Connection,
    *,
    consumer: str,
    bundle: ConfigurationBundle,
    desired_generation: int,
    status: str,
    checked_at: str,
    last_error: str | None,
) -> None:
    conn.execute(
        """INSERT INTO operator_config_consumers (
               consumer, loaded_generation, desired_generation, status,
               prefilter_revision, asset_revision, loaded_at, checked_at,
               last_error
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(consumer) DO UPDATE SET
               loaded_generation = excluded.loaded_generation,
               desired_generation = excluded.desired_generation,
               status = excluded.status,
               prefilter_revision = excluded.prefilter_revision,
               asset_revision = excluded.asset_revision,
               loaded_at = excluded.loaded_at,
               checked_at = excluded.checked_at,
               last_error = excluded.last_error""",
        (
            consumer,
            bundle.generation,
            desired_generation,
            status,
            bundle.prefilter_revision,
            bundle.asset_revision,
            bundle.loaded_at,
            checked_at,
            last_error,
        ),
    )


class ConfigurationBundleOwner:
    """Atomically publish validated generations and retain last-known-good."""

    def __init__(
        self,
        *,
        consumer: str,
        legacy_prefilter_policy: PrefilterPolicy,
        legacy_asset_inventory: AssetInventory,
        reload_interval_seconds: float = DEFAULT_RELOAD_INTERVAL_SECONDS,
        clock=time.monotonic,
    ):
        if consumer not in RUNTIME_CONSUMERS:
            raise ValueError("unsupported runtime configuration consumer")
        if reload_interval_seconds <= 0:
            raise ValueError("reload interval must be positive")
        self.consumer = consumer
        self.legacy_prefilter_policy = legacy_prefilter_policy
        self.legacy_asset_inventory = legacy_asset_inventory
        self.reload_interval_seconds = float(reload_interval_seconds)
        self.clock = clock
        self._bundle: ConfigurationBundle | None = None
        self._next_check = 0.0
        self._backoff = self.reload_interval_seconds
        self._last_audited_failure_generation: int | None = None

    @property
    def bundle(self) -> ConfigurationBundle:
        if self._bundle is None:
            raise OperatorConfigError("runtime configuration owner has not started")
        return self._bundle

    def start(self, conn: sqlite3.Connection) -> ConfigurationBundle:
        replacement = load_configuration_bundle(
            conn,
            legacy_prefilter_policy=self.legacy_prefilter_policy,
            legacy_asset_inventory=self.legacy_asset_inventory,
        )
        checked_at = utc_now_iso()
        try:
            _record_consumer_status(
                conn,
                consumer=self.consumer,
                bundle=replacement,
                desired_generation=replacement.generation,
                status="ok",
                checked_at=checked_at,
                last_error=None,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        self._bundle = replacement
        self._next_check = self.clock() + self.reload_interval_seconds
        return replacement

    def maybe_reload(
        self,
        conn: sqlite3.Connection,
        *,
        force: bool = False,
    ) -> bool:
        current = self.bundle
        now = self.clock()
        if not force and now < self._next_check:
            return False
        self._next_check = now + self.reload_interval_seconds
        checked_at = utc_now_iso()
        desired_generation = current.generation
        try:
            row = conn.execute(
                "SELECT generation FROM operator_config_state WHERE id = 1"
            ).fetchone()
            if row is not None:
                desired_generation = int(row[0])
            if row is not None and desired_generation == current.generation:
                try:
                    _record_consumer_status(
                        conn,
                        consumer=self.consumer,
                        bundle=current,
                        desired_generation=desired_generation,
                        status="ok",
                        checked_at=checked_at,
                        last_error=None,
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                self._backoff = self.reload_interval_seconds
                return False
            replacement = load_configuration_bundle(
                conn,
                legacy_prefilter_policy=self.legacy_prefilter_policy,
                legacy_asset_inventory=self.legacy_asset_inventory,
            )
        except Exception as exc:
            error = _bounded_reload_error(exc)
            try:
                _record_consumer_status(
                    conn,
                    consumer=self.consumer,
                    bundle=current,
                    desired_generation=desired_generation,
                    status="error",
                    checked_at=checked_at,
                    last_error=error,
                )
                if self._last_audited_failure_generation != desired_generation:
                    _audit(
                        conn,
                        occurred_at=checked_at,
                        action="runtime_reload_failed",
                        detail={
                            "consumer": self.consumer,
                            "loaded_generation": current.generation,
                            "desired_generation": desired_generation,
                            "error": error,
                        },
                        actor=f"system:{self.consumer}-ingest",
                    )
                conn.commit()
            except Exception:
                conn.rollback()
            self._last_audited_failure_generation = desired_generation
            self._next_check = now + self._backoff
            self._backoff = min(
                self._backoff * 2,
                MAX_RELOAD_BACKOFF_SECONDS,
            )
            return False

        try:
            _record_consumer_status(
                conn,
                consumer=self.consumer,
                bundle=replacement,
                desired_generation=replacement.generation,
                status="ok",
                checked_at=checked_at,
                last_error=None,
            )
            _audit(
                conn,
                occurred_at=checked_at,
                action="runtime_reload_succeeded",
                detail={
                    "consumer": self.consumer,
                    "from_generation": current.generation,
                    "generation": replacement.generation,
                },
                actor=f"system:{self.consumer}-ingest",
            )
            conn.commit()
        except Exception:
            conn.rollback()
            return False
        self._bundle = replacement
        self._last_audited_failure_generation = None
        self._backoff = self.reload_interval_seconds
        self._next_check = now + self.reload_interval_seconds
        return True


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
