"""Bounded repository operations for the operator-configuration lifecycle."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

try:
    from .asset_inventory import AssetInventory, canonical_json
    from .operator_config import (
        ASSET_KIND,
        CONFIG_KINDS,
        PREFILTER_KIND,
        OperatorConfigError,
        canonicalize_document,
        validate_stored_revision,
    )
    from .prefilter import MAX_CONFIG_BYTES, PrefilterPolicy
    from .time_utils import (
        format_utc_timestamp,
        parse_utc_timestamp,
        utc_now,
        utc_now_iso,
    )
except ImportError:  # Direct script-style imports used by container entrypoints.
    from asset_inventory import AssetInventory, canonical_json
    from operator_config import (
        ASSET_KIND,
        CONFIG_KINDS,
        PREFILTER_KIND,
        OperatorConfigError,
        canonicalize_document,
        validate_stored_revision,
    )
    from prefilter import MAX_CONFIG_BYTES, PrefilterPolicy
    from time_utils import format_utc_timestamp, parse_utc_timestamp, utc_now, utc_now_iso


MAX_NOTE_LENGTH = 2_000
MAX_REQUEST_ID_LENGTH = 128
DEFAULT_AUDIT_LIMIT = 50
MAX_AUDIT_LIMIT = 100
MAX_CONFIG_CURSOR_LENGTH = 512
DEFAULT_REVISION_LIMIT = 50
MAX_REVISION_LIMIT = 100
DEFAULT_PREVIEW_HOURS = 24
MAX_PREVIEW_HOURS = 168
DEFAULT_PREVIEW_CANDIDATES = 500
MAX_PREVIEW_CANDIDATES = 2_000
MAX_PREVIEW_EXAMPLES = 10
MAX_PREVIEW_SIGNATURES = 100
# Row and time bounds alone do not bound memory: one alert may be up to the
# document limit, so the sample also stops at an aggregate byte budget.
MAX_PREVIEW_SAMPLE_BYTES = 8 * 1024 * 1024
MAX_RESUME_HANDLE_SCAN = 50


class ConfigRepositoryError(RuntimeError):
    """Base class for safe configuration repository failures."""


class ConfigNotFoundError(ConfigRepositoryError):
    pass


class ConfigConflictError(ConfigRepositoryError):
    pass


class ConfigIntegrityError(ConfigRepositoryError):
    pass


def _require_kind(kind: str) -> None:
    if kind not in CONFIG_KINDS:
        raise ConfigNotFoundError("configuration kind not found")


def _decode_object(value: str | None, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ConfigIntegrityError(f"stored {label} is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise ConfigIntegrityError(f"stored {label} must be an object")
    return decoded


def _revision_row(conn: sqlite3.Connection, revision_id: int):
    return conn.execute(
        """SELECT id, kind, revision, document_json, source,
                  parent_revision_id, shipped_base_revision, state,
                  validation_json, created_at, created_by, note
           FROM operator_config_revisions WHERE id = ?""",
        (revision_id,),
    ).fetchone()


def _revision_metadata(row) -> dict[str, Any]:
    if row is None:
        raise ConfigNotFoundError("configuration revision not found")
    return {
        "id": int(row[0]),
        "kind": str(row[1]),
        "revision": str(row[2]),
        "source": str(row[4]),
        "parent_revision_id": int(row[5]) if row[5] is not None else None,
        "shipped_base_revision": str(row[6]) if row[6] is not None else None,
        "state": str(row[7]),
        "validation": _decode_object(row[8], "validation result"),
        "created_at": str(row[9]),
        "created_by": str(row[10]),
        "note": str(row[11]) if row[11] is not None else None,
    }


def _state_row(conn: sqlite3.Connection):
    row = conn.execute(
        """SELECT mode, generation, updated_at,
                  active_prefilter_revision_id, active_asset_revision_id
           FROM operator_config_state WHERE id = 1"""
    ).fetchone()
    if row is None:
        raise ConfigIntegrityError("active configuration state is missing")
    if row[0] not in {"legacy", "database"}:
        raise ConfigIntegrityError("active configuration mode is invalid")
    return row


def _validate_active_row(row, expected_kind: str) -> None:
    _validate_active_pointer(row, expected_kind)
    try:
        validate_stored_revision(str(row[1]), str(row[3]), str(row[2]))
    except OperatorConfigError as exc:
        raise ConfigIntegrityError(str(exc)) from exc


def _validate_active_pointer(row, expected_kind: str) -> None:
    """Validate summary-safe pointer metadata without decoding private content."""
    if row is None:
        raise ConfigIntegrityError(f"active {expected_kind} revision is missing")
    if row[1] != expected_kind or row[7] != "active":
        raise ConfigIntegrityError(f"active {expected_kind} pointer is inconsistent")


def get_config_summary(
    conn: sqlite3.Connection,
    *,
    writes_enabled: bool,
) -> dict[str, Any]:
    state = _state_row(conn)
    active = {}
    for kind, revision_id in (
        (PREFILTER_KIND, int(state[3])),
        (ASSET_KIND, int(state[4])),
    ):
        row = _revision_row(conn, revision_id)
        _validate_active_pointer(row, kind)
        active[kind] = _revision_metadata(row)
    counts = {
        kind: {str(state_name): int(count) for state_name, count in rows}
        for kind, rows in (
            (
                config_kind,
                conn.execute(
                    """SELECT state, COUNT(*) FROM operator_config_revisions
                       WHERE kind = ? GROUP BY state""",
                    (config_kind,),
                ).fetchall(),
            )
            for config_kind in sorted(CONFIG_KINDS)
        )
    }
    now = utc_now()
    consumer_rows = conn.execute(
        """SELECT consumer, loaded_generation, desired_generation, status,
                  prefilter_revision, asset_revision, loaded_at, checked_at,
                  last_error
           FROM operator_config_consumers ORDER BY consumer"""
    ).fetchall()
    consumers = []
    for row in consumer_rows:
        try:
            age = max(0, int((now - parse_utc_timestamp(str(row[7]))).total_seconds()))
        except (TypeError, ValueError):
            age = 10**9
        consumers.append(
            {
                "consumer": str(row[0]),
                "loaded_generation": int(row[1]),
                "desired_generation": int(row[2]),
                "status": str(row[3]),
                "prefilter_revision": str(row[4]),
                "asset_revision": str(row[5]),
                "loaded_at": str(row[6]),
                "checked_at": str(row[7]),
                "status_age_seconds": age,
                "last_error": str(row[8]) if row[8] is not None else None,
            }
        )
    return {
        "generated_at": utc_now_iso(),
        "mode": str(state[0]),
        "generation": int(state[1]),
        "updated_at": str(state[2]),
        "writes_enabled": writes_enabled,
        "reload": {
            "supported": True,
            "desired_generation": int(state[1]),
            "consumers": consumers,
        },
        "active": active,
        "revision_counts": counts,
    }


def get_active_config(conn: sqlite3.Connection, kind: str) -> dict[str, Any]:
    _require_kind(kind)
    state = _state_row(conn)
    revision_id = int(state[3] if kind == PREFILTER_KIND else state[4])
    row = _revision_row(conn, revision_id)
    _validate_active_row(row, kind)
    document = _decode_object(str(row[3]), f"{kind} document")
    return {
        "generated_at": utc_now_iso(),
        "mode": str(state[0]),
        "generation": int(state[1]),
        "revision": _revision_metadata(row),
        "document": document,
    }


def get_config_revision(
    conn: sqlite3.Connection,
    *,
    kind: str,
    revision_id: int,
) -> dict[str, Any]:
    _require_kind(kind)
    state = _state_row(conn)
    row = _revision_row(conn, revision_id)
    if row is None or row[1] != kind:
        raise ConfigNotFoundError("configuration revision not found")
    document_json = str(row[3])
    if _raw_revision(kind, document_json) != row[2]:
        raise ConfigIntegrityError(
            "stored configuration revision content does not match its digest"
        )
    if row[7] in {"active", "validated"}:
        try:
            validate_stored_revision(kind, document_json, str(row[2]))
        except OperatorConfigError as exc:
            raise ConfigIntegrityError(str(exc)) from exc
    return {
        "generated_at": utc_now_iso(),
        "mode": str(state[0]),
        "generation": int(state[1]),
        "revision": _revision_metadata(row),
        "document": _decode_object(document_json, f"{kind} document"),
    }


def list_revisions(
    conn: sqlite3.Connection,
    *,
    kind: str,
    limit: int,
    cursor: str | None,
    state: str | None,
) -> dict[str, Any]:
    _require_kind(kind)
    if not 1 <= limit <= MAX_REVISION_LIMIT:
        raise ConfigRepositoryError("revision limit is out of range")
    allowed_states = {"draft", "validated", "active", "superseded", "rejected"}
    if state is not None and state not in allowed_states:
        raise ConfigRepositoryError("invalid configuration revision state")
    cursor_id = decode_id_cursor(cursor) if cursor else None
    where = ["kind = ?"]
    params: list[Any] = [kind]
    if cursor_id is not None:
        where.append("id < ?")
        params.append(cursor_id)
    if state is not None:
        where.append("state = ?")
        params.append(state)
    params.append(limit + 1)
    rows = conn.execute(
        """SELECT id, kind, revision, document_json, source,
                  parent_revision_id, shipped_base_revision, state,
                  validation_json, created_at, created_by, note
           FROM operator_config_revisions
           WHERE """
        + " AND ".join(where)
        + " ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "generated_at": utc_now_iso(),
        "kind": kind,
        "revisions": [_revision_metadata(row) for row in rows],
        "next_cursor": (
            _encode_id_cursor(int(rows[-1][0])) if has_more and rows else None
        ),
    }


def _insert_audit(
    conn: sqlite3.Connection,
    *,
    occurred_at: str,
    actor: str,
    auth_via: str,
    action: str,
    kind: str | None = None,
    revision_id: int | None = None,
    from_revision_id: int | None = None,
    to_revision_id: int | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """INSERT INTO operator_config_audit (
               occurred_at, kind, revision_id, from_revision_id,
               to_revision_id, actor, auth_via, request_id, action, detail_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            occurred_at,
            kind,
            revision_id,
            from_revision_id,
            to_revision_id,
            actor,
            auth_via,
            request_id,
            action,
            canonical_json(detail or {}),
        ),
    )


def _raw_revision(kind: str, document_json: str) -> str:
    return "sha256:" + hashlib.sha256(
        document_json.encode("utf-8")
    ).hexdigest()


def _conflict(message: str, *, reason: str, **detail: Any) -> ConfigConflictError:
    """Build a refusal that carries bounded, document-free audit evidence."""
    error = ConfigConflictError(message)
    error.audit_detail = {"reason": reason, **detail}
    return error


class _RejectionRecorder:
    """Roll back a refused mutation, then record why it was refused.

    Evidence of a refused configuration change is only useful if it survives the
    rollback of that change, so the audit row is written afterwards in its own
    immediate transaction. Only bounded lifecycle metadata is recorded: never
    document content, note text, or credentials. A failure to record is not
    swallowed -- unrecorded evidence is itself reportable.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        kind: str | None,
        actor: str,
        auth_via: str,
        request_id: str | None,
        action: str,
        revision_id: int | None,
        occurred_at: str | None,
    ):
        self.conn = conn
        self.kind = kind
        self.actor = actor
        self.auth_via = auth_via
        self.request_id = request_id
        self.action = action
        self.revision_id = revision_id
        self.occurred_at = occurred_at

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc is None:
            return False
        if self.conn.in_transaction:
            self.conn.rollback()
        if isinstance(exc, ConfigConflictError):
            self._record(exc)
        return False

    def _record(self, exc: ConfigConflictError) -> None:
        detail = dict(getattr(exc, "audit_detail", None) or {"reason": "conflict"})
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            _insert_audit(
                self.conn,
                occurred_at=self.occurred_at or utc_now_iso(),
                actor=self.actor,
                auth_via=self.auth_via,
                request_id=self.request_id,
                action=self.action,
                kind=self.kind,
                revision_id=self.revision_id,
                detail=detail,
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise


def _rejection_recorder(
    conn: sqlite3.Connection,
    *,
    kind: str | None,
    actor: str,
    auth_via: str,
    request_id: str | None,
    action: str,
    revision_id: int | None = None,
    occurred_at: str | None = None,
) -> _RejectionRecorder:
    return _RejectionRecorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action=action,
        revision_id=revision_id,
        occurred_at=occurred_at,
    )


def create_draft(
    conn: sqlite3.Connection,
    *,
    kind: str,
    document: dict[str, Any],
    parent_revision_id: int,
    expected_generation: int,
    note: str | None,
    actor: str,
    auth_via: str,
    request_id: str | None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    _require_kind(kind)
    if not isinstance(document, dict):
        raise ConfigRepositoryError("configuration document must be an object")
    if note is not None and len(note) > MAX_NOTE_LENGTH:
        raise ConfigRepositoryError("configuration note is too long")
    try:
        document_json = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ConfigRepositoryError(
            "configuration document must contain only finite JSON values"
        ) from exc
    if len(document_json.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ConfigRepositoryError("configuration document exceeds the 1 MiB limit")
    revision = _raw_revision(kind, document_json)
    timestamp = occurred_at or utc_now_iso()

    with _rejection_recorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action="draft_creation_rejected",
        occurred_at=timestamp,
    ):
        conn.execute("BEGIN IMMEDIATE")
        state = _state_row(conn)
        active_id = int(state[3] if kind == PREFILTER_KIND else state[4])
        if int(state[1]) != expected_generation:
            raise _conflict(
                "configuration generation is stale",
                reason="stale_generation",
                expected_generation=expected_generation,
                generation=int(state[1]),
            )
        if active_id != parent_revision_id:
            raise _conflict(
                "parent revision is not active",
                reason="stale_parent",
                expected_generation=expected_generation,
                parent_revision_id=parent_revision_id,
                active_revision_id=active_id,
            )
        parent = _revision_row(conn, parent_revision_id)
        _validate_active_row(parent, kind)
        try:
            cursor = conn.execute(
                """INSERT INTO operator_config_revisions (
                       kind, revision, document_json, source,
                       parent_revision_id, shipped_base_revision, state,
                       validation_json, created_at, created_by, note
                   ) VALUES (?, ?, ?, 'operator', ?, ?, 'draft', ?, ?, ?, ?)""",
                (
                    kind,
                    revision,
                    document_json,
                    parent_revision_id,
                    parent[6],
                    canonical_json({"status": "pending", "kind": kind}),
                    timestamp,
                    actor,
                    note,
                ),
            )
        except sqlite3.IntegrityError as exc:
            resumed = _resumable_revision(
                conn,
                kind=kind,
                revision=revision,
                document_json=document_json,
                parent_revision_id=parent_revision_id,
            )
            if resumed is None:
                raise _conflict(
                    "an identical configuration revision already exists",
                    reason="duplicate_revision",
                    expected_generation=expected_generation,
                ) from exc
            normalized_id = _normalized_revision_id(resumed)
            _insert_audit(
                conn,
                occurred_at=timestamp,
                actor=actor,
                auth_via=auth_via,
                request_id=request_id,
                action="draft_resumed",
                kind=kind,
                revision_id=int(resumed[0]),
                from_revision_id=parent_revision_id,
                to_revision_id=normalized_id,
                detail={
                    "expected_generation": expected_generation,
                    "state": str(resumed[7]),
                    "normalized": normalized_id is not None,
                },
            )
            conn.commit()
            return {
                "draft": _revision_metadata(resumed),
                "resumed": True,
                # A resumed normalization input has already been validated: its
                # canonical result is the revision the lifecycle will preview
                # and activate through this same handle.
                "validated_revision_id": (
                    normalized_id
                    if normalized_id is not None
                    else (int(resumed[0]) if str(resumed[7]) == "validated" else None)
                ),
            }
        draft_id = int(cursor.lastrowid)
        _insert_audit(
            conn,
            occurred_at=timestamp,
            actor=actor,
            auth_via=auth_via,
            request_id=request_id,
            action="draft_created",
            kind=kind,
            revision_id=draft_id,
            from_revision_id=parent_revision_id,
            detail={"expected_generation": expected_generation},
        )
        row = _revision_row(conn, draft_id)
        conn.commit()
        return {
            "draft": _revision_metadata(row),
            "resumed": False,
            "validated_revision_id": None,
        }


def _normalized_revision_id(row) -> int | None:
    """Return the canonical revision one normalization input produced."""
    if row is None or str(row[7]) != "superseded":
        return None
    validation = _decode_object(row[8], "validation result")
    value = validation.get("normalized_revision_id")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _is_normalization_input(conn: sqlite3.Connection, row) -> bool:
    """Report whether a superseded row is a draft that validation normalized.

    Such a row was never active: it holds the operator's submitted bytes, which
    canonicalization replaced. It remains a lifecycle handle, never a rollback
    target, and its content need not be canonical.
    """
    normalized_id = _normalized_revision_id(row)
    if normalized_id is None:
        return False
    normalized = _revision_row(conn, normalized_id)
    return normalized is not None and normalized[1] == row[1]


def _resumable_revision(
    conn: sqlite3.Connection,
    *,
    kind: str,
    revision: str,
    document_json: str,
    parent_revision_id: int,
):
    """Return an existing lifecycle handle this request may safely resume.

    Content digests are unique per kind, so an operator who loses editor state
    (reload, disconnect, new browser session) and resubmits the identical
    document cannot create a second row. Resuming is safe only for a handle that
    is still unactivated and was raised against the very parent the caller named
    -- which the caller has already proven to be the active revision under the
    expected generation. Three shapes qualify:

    * the `draft` or `validated` row itself;
    * a `superseded` draft that validation normalized, whose canonical content
      the preview and activation paths already resolve through its pointer;
    * when the digest names canonical content that a normalized draft produced,
      that draft, provided it hangs off the caller's parent.

    A historical, active, or rejected revision, and any handle raised from a
    different parent, stay conflicts.
    """
    row = conn.execute(
        """SELECT id, kind, revision, document_json, source,
                  parent_revision_id, shipped_base_revision, state,
                  validation_json, created_at, created_by, note
           FROM operator_config_revisions
           WHERE kind = ? AND revision = ?""",
        (kind, revision),
    ).fetchone()
    if row is None:
        return None
    if str(row[3]) != document_json:
        raise ConfigIntegrityError(
            "stored configuration revision content does not match its digest"
        )
    own_parent = row[5] is not None and int(row[5]) == parent_revision_id
    if own_parent:
        if str(row[7]) in {"draft", "validated"}:
            return row
        if _is_normalization_input(conn, row):
            return row
    if str(row[7]) in {"validated", "superseded"}:
        return _handle_for_canonical_revision(
            conn,
            kind=kind,
            canonical_id=int(row[0]),
            parent_revision_id=parent_revision_id,
        )
    return None


def _handle_for_canonical_revision(
    conn: sqlite3.Connection,
    *,
    kind: str,
    canonical_id: int,
    parent_revision_id: int,
):
    """Return the newest normalized draft off this parent naming that content.

    Resubmitting the already canonical form of a normalized candidate collides
    with the canonical row, whose own lineage may be historical. The submitted
    draft that produced it is the handle that carries the caller's parent, so it
    is the only safe thing to resume. The scan is bounded to the newest handles
    raised against that parent.
    """
    rows = conn.execute(
        """SELECT id, kind, revision, document_json, source,
                  parent_revision_id, shipped_base_revision, state,
                  validation_json, created_at, created_by, note
           FROM operator_config_revisions
           WHERE kind = ? AND parent_revision_id = ? AND state = 'superseded'
           ORDER BY id DESC LIMIT ?""",
        (kind, parent_revision_id, MAX_RESUME_HANDLE_SCAN),
    ).fetchall()
    for row in rows:
        if _normalized_revision_id(row) == canonical_id:
            return row
    return None


def validate_draft(
    conn: sqlite3.Connection,
    *,
    kind: str,
    draft_id: int,
    actor: str,
    auth_via: str,
    request_id: str | None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    _require_kind(kind)
    timestamp = occurred_at or utc_now_iso()
    with _rejection_recorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action="draft_validation_refused",
        revision_id=draft_id,
        occurred_at=timestamp,
    ):
        conn.execute("BEGIN IMMEDIATE")
        draft = _revision_row(conn, draft_id)
        if draft is None or draft[1] != kind:
            raise ConfigNotFoundError("configuration draft not found")
        # Revalidating an already validated candidate is idempotent: revision
        # content is immutable, so a resumed candidate re-derives the identical
        # result instead of forcing the operator to mutate the document. A draft
        # that was already normalized is reported through its canonical result
        # rather than revalidated, so a resumed handle stays usable.
        if _is_normalization_input(conn, draft):
            normalized = _revision_row(conn, _normalized_revision_id(draft))
            payload = {
                "draft_id": draft_id,
                "validation": _decode_object(normalized[8], "validation result"),
                "revision": _revision_metadata(normalized),
                "candidate_parent_revision_id": (
                    int(draft[5]) if draft[5] is not None else None
                ),
            }
            conn.commit()
            return payload
        if draft[7] not in {"draft", "validated"}:
            raise _conflict(
                "configuration revision is not a draft",
                reason="not_a_draft",
                state=str(draft[7]),
            )
        try:
            decoded = json.loads(str(draft[3]))
            canonical_document, validation = canonicalize_document(kind, decoded)
        except (json.JSONDecodeError, TypeError, ValueError, OperatorConfigError) as exc:
            error = str(exc)[:2_000]
            validation = {
                "status": "invalid",
                "kind": kind,
                "error": error,
            }
            conn.execute(
                """UPDATE operator_config_revisions
                   SET state = 'rejected', validation_json = ? WHERE id = ?""",
                (canonical_json(validation), draft_id),
            )
            _insert_audit(
                conn,
                occurred_at=timestamp,
                actor=actor,
                auth_via=auth_via,
                request_id=request_id,
                action="draft_validation_rejected",
                kind=kind,
                revision_id=draft_id,
                detail={"status": "invalid"},
            )
            rejected = _revision_row(conn, draft_id)
            conn.commit()
            return {
                "draft_id": draft_id,
                "validation": validation,
                "revision": _revision_metadata(rejected),
                "candidate_parent_revision_id": (
                    int(draft[5]) if draft[5] is not None else None
                ),
            }

        canonical_document_json = canonical_json(canonical_document)
        canonical_revision = _raw_revision(kind, canonical_document_json)
        validation_json = canonical_json(validation)
        if (
            canonical_revision == draft[2]
            and canonical_document_json == draft[3]
        ):
            conn.execute(
                """UPDATE operator_config_revisions
                   SET state = 'validated', validation_json = ? WHERE id = ?""",
                (validation_json, draft_id),
            )
            validated_id = draft_id
            normalized = False
            reused = False
        else:
            if draft[7] == "validated":
                raise ConfigIntegrityError(
                    "stored configuration revision content is not canonical"
                )
            # Canonical content that already exists is reused rather than
            # rewritten, so the immutable revision keeps its original content,
            # digest, and lineage. The submitted draft carries this candidate's
            # parent relationship forward for preview and activation.
            existing = conn.execute(
                """SELECT id FROM operator_config_revisions
                   WHERE kind = ? AND revision = ?""",
                (kind, canonical_revision),
            ).fetchone()
            if existing is None:
                cursor = conn.execute(
                    """INSERT INTO operator_config_revisions (
                           kind, revision, document_json, source,
                           parent_revision_id, shipped_base_revision, state,
                           validation_json, created_at, created_by, note
                       ) VALUES (?, ?, ?, 'operator', ?, ?, 'validated', ?, ?, ?, ?)""",
                    (
                        kind,
                        canonical_revision,
                        canonical_document_json,
                        draft[5],
                        draft[6],
                        validation_json,
                        timestamp,
                        actor,
                        draft[11],
                    ),
                )
                validated_id = int(cursor.lastrowid)
            else:
                validated_id = int(existing[0])
                known = _revision_row(conn, validated_id)
                if known is None or known[3] != canonical_document_json:
                    raise ConfigIntegrityError(
                        "stored configuration revision content is inconsistent"
                    )
                if known[7] in {"draft", "rejected"}:
                    conn.execute(
                        """UPDATE operator_config_revisions
                           SET state = 'validated', validation_json = ?
                           WHERE id = ?""",
                        (validation_json, validated_id),
                    )
            conn.execute(
                """UPDATE operator_config_revisions
                   SET state = 'superseded', validation_json = ? WHERE id = ?""",
                (
                    canonical_json(
                        {
                            **validation,
                            "normalized_revision_id": validated_id,
                        }
                    ),
                    draft_id,
                ),
            )
            normalized = True
            reused = existing is not None

        _insert_audit(
            conn,
            occurred_at=timestamp,
            actor=actor,
            auth_via=auth_via,
            request_id=request_id,
            action="draft_validated",
            kind=kind,
            revision_id=draft_id,
            to_revision_id=validated_id,
            detail={
                "status": "valid",
                "normalized": normalized,
                "reused_existing_revision": reused,
            },
        )
        validated = _revision_row(conn, validated_id)
        conn.commit()
        return {
            "draft_id": draft_id,
            "validation": validation,
            "revision": _revision_metadata(validated),
            "candidate_parent_revision_id": (
                int(draft[5]) if draft[5] is not None else None
            ),
        }


@dataclass(frozen=True)
class _CandidateLineage:
    """What the submitted lifecycle handle was raised against.

    Reused canonical content keeps its own immutable lineage, which may be
    historical. Every guard that asks "what is this operator changing, and from
    which shipped baseline" must read the submitted handle's lineage instead.
    """

    handle_revision_id: int
    parent_revision_id: int | None
    shipped_base_revision: str | None


def _validated_candidate(conn: sqlite3.Connection, kind: str, draft_id: int):
    """Resolve one lifecycle handle to its content row and its live lineage.

    Canonicalization can normalize a submitted draft onto an existing immutable
    revision, including an older superseded one. Revision content and digests
    never change, so the reused row keeps the lineage of whenever it was first
    written. The submitted draft is what was raised against the current active
    revision and the current shipped baseline, so its lineage -- not the reused
    row's historical lineage -- is what the rest of the lifecycle must enforce.
    """
    row = _revision_row(conn, draft_id)
    if row is None or row[1] != kind:
        raise ConfigNotFoundError("configuration draft not found")
    lineage = _CandidateLineage(
        handle_revision_id=int(row[0]),
        parent_revision_id=int(row[5]) if row[5] is not None else None,
        shipped_base_revision=str(row[6]) if row[6] is not None else None,
    )
    if row[7] == "validated":
        return row, lineage
    if row[7] == "superseded":
        normalized_id = _normalized_revision_id(row)
        if normalized_id is not None:
            normalized = _revision_row(conn, normalized_id)
            if normalized is not None and normalized[1] == kind:
                return normalized, lineage
    raise _conflict(
        "configuration draft has not produced a validated revision",
        reason="unvalidated_candidate",
        state=str(row[7]),
    )


def _validated_document(conn: sqlite3.Connection, kind: str, draft_id: int):
    candidate, lineage = _validated_candidate(conn, kind, draft_id)
    document_json = str(candidate[3])
    try:
        validate_stored_revision(kind, document_json, str(candidate[2]))
        document = json.loads(document_json)
    except (OperatorConfigError, json.JSONDecodeError) as exc:
        raise ConfigIntegrityError(str(exc)) from exc
    return candidate, document, lineage


def _active_document(conn: sqlite3.Connection, kind: str, state):
    revision_id = int(state[3] if kind == PREFILTER_KIND else state[4])
    row = _revision_row(conn, revision_id)
    _validate_active_row(row, kind)
    try:
        return row, json.loads(str(row[3]))
    except json.JSONDecodeError as exc:
        raise ConfigIntegrityError(f"stored {kind} document is invalid JSON") from exc


def _preview_bounds(hours: int, candidate_limit: int) -> None:
    if not 1 <= hours <= MAX_PREVIEW_HOURS:
        raise ConfigRepositoryError("preview hours is out of range")
    if not 1 <= candidate_limit <= MAX_PREVIEW_CANDIDATES:
        raise ConfigRepositoryError("preview candidate limit is out of range")


@dataclass(frozen=True)
class _PreviewSample:
    """One bounded preview sample and why it stopped where it did."""

    rows: list
    truncated: bool
    truncated_by_bytes: bool
    truncated_by_unsized: bool


def _sample_rows(
    conn: sqlite3.Connection,
    *,
    kind: str,
    window_start: str,
    candidate_limit: int,
):
    """Read one bounded preview sample: rows, window, and aggregate bytes.

    Sensor context is joined outward on purpose. Rows retained before that table
    existed have no companion row, and excluding them silently narrowed previews
    to post-migration traffic; only records positively identified as another
    sensor are excluded from a prefilter preview.

    The row cap alone does not bound memory, because one retained alert may be
    arbitrarily large. The scan therefore reads each candidate's metadata and
    the size recorded beside its alert at ingestion -- never the body, and never
    an expression over the body, because measuring one inside SQLite makes the
    engine materialize it first. A body is fetched only once its recorded size
    is known to fit the remaining budget, so no oversized body is materialized,
    transferred, retained, or decoded, including the first one. The sample stops
    at whichever bound is reached first and reports the truncation to the
    operator rather than silently narrowing the comparison.
    """
    source_clause = (
        "AND (sensor.source_type IS NULL OR sensor.source_type = 'suricata')"
        if kind == PREFILTER_KIND
        else ""
    )
    # An asset preview compares addresses only, so it never reads alert bodies,
    # never spends the byte budget, and is unaffected by an unrecorded size.
    reads_alerts = kind == PREFILTER_KIND
    size_column = "events.raw_alert_bytes" if reads_alerts else "NULL"
    cursor = conn.execute(
        f"""SELECT events.id, {size_column}, events.signature_id,
                   events.src_ip, events.dest_ip
            FROM triage_events AS events
            LEFT JOIN sensor_event_context AS sensor
              ON sensor.triage_event_id = events.id
            WHERE events.processed_at IS NOT NULL
              AND events.processed_at >= ?
              {source_clause}
            ORDER BY events.processed_at DESC, events.id DESC
            LIMIT ?""",
        (window_start, candidate_limit + 1),
    )
    rows = []
    remaining_bytes = MAX_PREVIEW_SAMPLE_BYTES
    truncated_by_rows = False
    truncated_by_bytes = False
    truncated_by_unsized = False
    for event_id, alert_bytes, signature_id, src_ip, dest_ip in cursor:
        if len(rows) >= candidate_limit:
            truncated_by_rows = True
            break
        alert = None
        if reads_alerts:
            if alert_bytes is None:
                # Retained before sizes were recorded. Fetching it would mean
                # trusting an unknown length, so the sample stops here and says
                # so instead of weakening the byte bound.
                truncated_by_unsized = True
                break
            size = int(alert_bytes)
            if size > remaining_bytes:
                truncated_by_bytes = True
                break
            alert = _bounded_alert_body(conn, int(event_id), size)
            if alert is None:
                # The row changed or vanished between the two reads; skipping it
                # keeps the guarantee that nothing oversized is ever decoded.
                continue
            # Charge what actually arrived. A recorded size that understates the
            # body must not silently buy extra budget for later rows.
            actual = len(alert.encode("utf-8"))
            if actual > remaining_bytes:
                truncated_by_bytes = True
                break
            remaining_bytes -= max(size, actual)
        rows.append((int(event_id), alert, signature_id, src_ip, dest_ip))
    return _PreviewSample(
        rows=rows,
        truncated=truncated_by_rows or truncated_by_bytes or truncated_by_unsized,
        truncated_by_bytes=truncated_by_bytes,
        truncated_by_unsized=truncated_by_unsized,
    )


def _bounded_alert_body(
    conn: sqlite3.Connection,
    event_id: int,
    recorded_bytes: int,
) -> str | None:
    """Fetch one retained alert body against its recorded size.

    The size predicate is the trusted stored integer, never a measurement of the
    body, so a row whose size changed under us is skipped rather than read.
    """
    row = conn.execute(
        """SELECT raw_alert FROM triage_events
           WHERE id = ? AND raw_alert_bytes IS NOT NULL
             AND raw_alert_bytes = ?""",
        (event_id, recorded_bytes),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _prefilter_preview(
    active_document,
    candidate_document,
    active_asset_document,
    rows,
):
    active = PrefilterPolicy.from_document(active_document)
    candidate = PrefilterPolicy.from_document(candidate_document)
    active_assets = AssetInventory.from_document(active_asset_document)
    counts = {
        "newly_suppressed": 0,
        "no_longer_suppressed": 0,
        "unchanged_suppressed": 0,
        "unchanged_unsuppressed": 0,
        "skipped_invalid_records": 0,
    }
    affected_ids: list[int] = []
    affected_signatures: set[int] = set()
    matched_rule_indexes: set[int] = set()
    for row in rows:
        try:
            alert = json.loads(str(row[1]))
        except json.JSONDecodeError:
            counts["skipped_invalid_records"] += 1
            continue
        if not isinstance(alert, dict):
            counts["skipped_invalid_records"] += 1
            continue
        asset_context = active_assets.resolve_alert(alert)
        active_match = active.match_reason(alert, asset_context) is not None
        candidate_match = candidate.match_reason(alert, asset_context) is not None
        sid = alert.get("alert", {}).get("signature_id")
        if isinstance(sid, int) and not isinstance(sid, bool):
            for index, rule in enumerate(candidate.rules):
                if sid not in rule.signature_ids:
                    continue
                if rule.match is None or rule.match.matches(
                    alert,
                    asset_context,
                    candidate.internal_cidrs,
                ):
                    matched_rule_indexes.add(index)
        if not active_match and candidate_match:
            bucket = "newly_suppressed"
        elif active_match and not candidate_match:
            bucket = "no_longer_suppressed"
        elif active_match:
            bucket = "unchanged_suppressed"
        else:
            bucket = "unchanged_unsuppressed"
        counts[bucket] += 1
        if active_match != candidate_match:
            if len(affected_ids) < MAX_PREVIEW_EXAMPLES:
                affected_ids.append(int(row[0]))
            if (
                isinstance(row[2], int)
                and len(affected_signatures) < MAX_PREVIEW_SIGNATURES
            ):
                affected_signatures.add(int(row[2]))
    broad = [index for index, rule in enumerate(candidate.rules) if rule.match is None]
    unmatched = [
        index for index in range(len(candidate.rules)) if index not in matched_rule_indexes
    ]
    warnings = []
    if broad:
        warnings.append("candidate contains unscoped signature-only rules")
    if unmatched:
        warnings.append("candidate contains rules with no matches in the sample")
    return {
        "counts": counts,
        "affected_event_ids": affected_ids,
        "affected_signature_ids": sorted(affected_signatures),
        "broad_rule_indexes": broad,
        "unmatched_rule_indexes": unmatched,
    }, warnings


def _asset_value(inventory: AssetInventory, address: str):
    snapshot = inventory.resolve(address)
    if snapshot is None:
        return None
    return {key: value for key, value in snapshot.items() if key != "inventory_revision"}


def _asset_preview(active_document, candidate_document, rows):
    active = AssetInventory.from_document(active_document)
    candidate = AssetInventory.from_document(candidate_document)
    addresses: dict[str, list[int]] = {}
    skipped = 0
    for row in rows:
        for value in (row[3], row[4]):
            if value is None:
                continue
            try:
                normalized = str(ipaddress.ip_address(str(value)))
            except ValueError:
                skipped += 1
                continue
            addresses.setdefault(normalized, []).append(int(row[0]))
    counts = {
        "newly_matched_addresses": 0,
        "no_longer_matched_addresses": 0,
        "changed_context_addresses": 0,
        "unchanged_addresses": 0,
        "skipped_invalid_addresses": skipped,
    }
    affected_addresses: list[str] = []
    affected_event_ids: list[int] = []
    for address in sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))):
        before = _asset_value(active, address)
        after = _asset_value(candidate, address)
        if before is None and after is not None:
            bucket = "newly_matched_addresses"
        elif before is not None and after is None:
            bucket = "no_longer_matched_addresses"
        elif before != after:
            bucket = "changed_context_addresses"
        else:
            bucket = "unchanged_addresses"
        counts[bucket] += 1
        if before != after:
            if len(affected_addresses) < MAX_PREVIEW_EXAMPLES:
                affected_addresses.append(address)
            for event_id in addresses[address]:
                if event_id not in affected_event_ids and len(affected_event_ids) < MAX_PREVIEW_EXAMPLES:
                    affected_event_ids.append(event_id)
    return {
        "counts": counts,
        "unique_addresses_examined": len(addresses),
        "affected_addresses": affected_addresses,
        "affected_event_ids": affected_event_ids,
    }, []


def preview_draft(
    conn: sqlite3.Connection,
    *,
    kind: str,
    draft_id: int,
    expected_generation: int,
    hours: int,
    candidate_limit: int,
    actor: str,
    auth_via: str,
    request_id: str | None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Compare a validated candidate with active config over a bounded corpus."""
    _require_kind(kind)
    _preview_bounds(hours, candidate_limit)
    rejection = _rejection_recorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action="draft_preview_rejected",
        revision_id=draft_id,
        occurred_at=occurred_at,
    )
    with rejection:
        state = _state_row(conn)
        if int(state[1]) != expected_generation:
            raise _conflict(
                "configuration generation is stale",
                reason="stale_generation",
                expected_generation=expected_generation,
                generation=int(state[1]),
            )
        candidate, candidate_document, lineage = _validated_document(
            conn,
            kind,
            draft_id,
        )
        active, active_document = _active_document(conn, kind, state)
        # Preview must describe the change the operator can actually activate.
        # A candidate whose parent has been replaced is rejected before any
        # sampling or audit, exactly as activation rejects it.
        if lineage.parent_revision_id != int(active[0]):
            raise _conflict(
                "configuration draft parent is no longer active",
                reason="stale_parent",
                expected_generation=expected_generation,
                parent_revision_id=lineage.parent_revision_id,
                active_revision_id=int(active[0]),
            )
    now = utc_now()
    window_start = format_utc_timestamp(now - timedelta(hours=hours))
    sample = _sample_rows(
        conn,
        kind=kind,
        window_start=window_start,
        candidate_limit=candidate_limit,
    )
    sampled = sample.rows
    truncated = sample.truncated
    if kind == PREFILTER_KIND:
        _, active_asset_document = _active_document(conn, ASSET_KIND, state)
        summary, warnings = _prefilter_preview(
            active_document,
            candidate_document,
            active_asset_document,
            sampled,
        )
    else:
        summary, warnings = _asset_preview(
            active_document,
            candidate_document,
            sampled,
        )
    if sample.truncated_by_bytes:
        warnings.append("preview sample reached its byte budget before its row limit")
    if sample.truncated_by_unsized:
        warnings.append(
            "preview sample stopped at a retained alert with no recorded size"
        )
    timestamp = occurred_at or utc_now_iso()
    with rejection:
        conn.execute("BEGIN IMMEDIATE")
        locked_state = _state_row(conn)
        if int(locked_state[1]) != expected_generation:
            raise _conflict(
                "configuration generation changed during preview",
                reason="stale_generation",
                expected_generation=expected_generation,
                generation=int(locked_state[1]),
            )
        _insert_audit(
            conn,
            occurred_at=timestamp,
            actor=actor,
            auth_via=auth_via,
            request_id=request_id,
            action="draft_previewed",
            kind=kind,
            revision_id=draft_id,
            from_revision_id=int(active[0]),
            to_revision_id=int(candidate[0]),
            detail={
                "expected_generation": expected_generation,
                "candidate_limit": candidate_limit,
                "candidates_examined": len(sampled),
                "truncated": truncated,
                "truncated_by_bytes": sample.truncated_by_bytes,
                "truncated_by_unsized": sample.truncated_by_unsized,
                "warning_count": len(warnings),
            },
        )
        conn.commit()
    return {
        "generated_at": timestamp,
        "kind": kind,
        "draft_id": draft_id,
        "candidate_revision_id": int(candidate[0]),
        "active_revision_id": int(active[0]),
        "generation": expected_generation,
        "window_hours": hours,
        "window_start": window_start,
        "candidate_limit": candidate_limit,
        "candidates_examined": len(sampled),
        "truncated": truncated,
        "summary": summary,
        "warnings": warnings,
    }


def activate_draft(
    conn: sqlite3.Connection,
    *,
    kind: str,
    draft_id: int,
    expected_generation: int,
    acknowledge_broad_rules: bool,
    acknowledge_shipped_base_change: bool,
    actor: str,
    auth_via: str,
    request_id: str | None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Atomically activate one validated draft and cut over legacy authority."""
    _require_kind(kind)
    timestamp = occurred_at or utc_now_iso()
    with _rejection_recorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action="revision_activation_rejected",
        revision_id=draft_id,
        occurred_at=timestamp,
    ):
        conn.execute("BEGIN IMMEDIATE")
        state = _state_row(conn)
        if int(state[1]) != expected_generation:
            raise _conflict(
                "configuration generation is stale",
                reason="stale_generation",
                expected_generation=expected_generation,
                generation=int(state[1]),
            )
        candidate, document, lineage = _validated_document(conn, kind, draft_id)
        active_id = int(state[3] if kind == PREFILTER_KIND else state[4])
        active = _revision_row(conn, active_id)
        _validate_active_row(active, kind)
        if int(candidate[0]) == active_id:
            raise _conflict(
                "configuration revision is already active",
                reason="already_active",
                expected_generation=expected_generation,
                revision_id=active_id,
            )
        if lineage.parent_revision_id != active_id:
            raise _conflict(
                "configuration draft parent is no longer active",
                reason="stale_parent",
                expected_generation=expected_generation,
                parent_revision_id=lineage.parent_revision_id,
                active_revision_id=active_id,
            )
        payload = _activate_revision_locked(
            conn,
            state=state,
            kind=kind,
            candidate=candidate,
            document=document,
            shipped_base_revision=lineage.shipped_base_revision,
            expected_generation=expected_generation,
            acknowledge_broad_rules=acknowledge_broad_rules,
            acknowledge_shipped_base_change=acknowledge_shipped_base_change,
            actor=actor,
            auth_via=auth_via,
            request_id=request_id,
            timestamp=timestamp,
            action="revision_activated",
        )
        conn.commit()
        return payload


def _activate_revision_locked(
    conn: sqlite3.Connection,
    *,
    state,
    kind: str,
    candidate,
    document: dict[str, Any],
    shipped_base_revision: str | None,
    expected_generation: int,
    acknowledge_broad_rules: bool,
    acknowledge_shipped_base_change: bool,
    actor: str,
    auth_via: str,
    request_id: str | None,
    timestamp: str,
    action: str,
) -> dict[str, Any]:
    active_id = int(state[3] if kind == PREFILTER_KIND else state[4])
    active = _revision_row(conn, active_id)
    _validate_active_row(active, kind)
    broad_rule_count = 0
    if kind == PREFILTER_KIND:
        policy = PrefilterPolicy.from_document(document)
        broad_rule_count = sum(rule.match is None for rule in policy.rules)
        if broad_rule_count and not acknowledge_broad_rules:
            raise _conflict(
                "activation requires acknowledgement of unscoped rules",
                reason="unacknowledged_broad_rules",
                expected_generation=expected_generation,
                broad_rule_count=broad_rule_count,
            )
        newest_shipped = conn.execute(
            """SELECT revisions.revision
               FROM operator_config_audit AS audit
               JOIN operator_config_revisions AS revisions
                 ON revisions.id = audit.revision_id
               WHERE audit.action = 'shipped_revision_discovered'
                 AND audit.kind = 'prefilter_policy'
               ORDER BY audit.id DESC LIMIT 1"""
        ).fetchone()
        if newest_shipped is None:
            newest_shipped = conn.execute(
                """SELECT revision FROM operator_config_revisions
                   WHERE kind = 'prefilter_policy' AND source = 'shipped'
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()
        if newest_shipped is None:
            raise ConfigIntegrityError("shipped prefilter baseline is missing")
        # The submitted lifecycle's shipped baseline decides this guard. Reused
        # canonical content may carry a much older baseline of its own, and
        # honouring that would let a candidate raised against a superseded
        # baseline activate without the operator ever acknowledging it.
        if (
            shipped_base_revision != newest_shipped[0]
            and not acknowledge_shipped_base_change
        ):
            raise _conflict(
                "activation requires acknowledgement of a shipped-base change",
                reason="unacknowledged_shipped_base_change",
                expected_generation=expected_generation,
            )
    previous_prefilter = int(state[3])
    previous_asset = int(state[4])
    authority_cutover = state[0] == "legacy"
    conn.execute(
        "UPDATE operator_config_revisions SET state = 'superseded' WHERE id = ?",
        (active_id,),
    )
    conn.execute(
        "UPDATE operator_config_revisions SET state = 'active' WHERE id = ?",
        (int(candidate[0]),),
    )
    next_generation = expected_generation + 1
    if kind == PREFILTER_KIND:
        conn.execute(
            """UPDATE operator_config_state
               SET active_prefilter_revision_id = ?,
                   previous_prefilter_revision_id = ?,
                   previous_asset_revision_id = ?, mode = 'database',
                   generation = ?, updated_at = ?
               WHERE id = 1""",
            (
                int(candidate[0]),
                previous_prefilter,
                previous_asset,
                next_generation,
                timestamp,
            ),
        )
    else:
        conn.execute(
            """UPDATE operator_config_state
               SET active_asset_revision_id = ?,
                   previous_prefilter_revision_id = ?,
                   previous_asset_revision_id = ?, mode = 'database',
                   generation = ?, updated_at = ?
               WHERE id = 1""",
            (
                int(candidate[0]),
                previous_prefilter,
                previous_asset,
                next_generation,
                timestamp,
            ),
        )
    _insert_audit(
        conn,
        occurred_at=timestamp,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action=action,
        kind=kind,
        revision_id=int(candidate[0]),
        from_revision_id=active_id,
        to_revision_id=int(candidate[0]),
        detail={
            "expected_generation": expected_generation,
            "generation": next_generation,
            "broad_rule_count": broad_rule_count,
            "broad_rules_acknowledged": acknowledge_broad_rules,
            "shipped_base_change_acknowledged": acknowledge_shipped_base_change,
            "authority_cutover": authority_cutover,
        },
    )
    activated = _revision_row(conn, int(candidate[0]))
    return {
        "activated_at": timestamp,
        "kind": kind,
        "generation": next_generation,
        "previous_revision_id": active_id,
        "authority_cutover": authority_cutover,
        "revision": _revision_metadata(activated),
    }


def rollback_revision(
    conn: sqlite3.Connection,
    *,
    kind: str,
    revision_id: int,
    expected_generation: int,
    acknowledge_broad_rules: bool,
    acknowledge_shipped_base_change: bool,
    actor: str,
    auth_via: str,
    request_id: str | None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Reactivate one superseded revision through the guarded activation path."""
    _require_kind(kind)
    timestamp = occurred_at or utc_now_iso()
    with _rejection_recorder(
        conn,
        kind=kind,
        actor=actor,
        auth_via=auth_via,
        request_id=request_id,
        action="revision_rollback_rejected",
        revision_id=revision_id,
        occurred_at=timestamp,
    ):
        conn.execute("BEGIN IMMEDIATE")
        state = _state_row(conn)
        if state[0] != "database":
            raise _conflict(
                "rollback requires database authority mode",
                reason="legacy_authority",
                expected_generation=expected_generation,
            )
        if int(state[1]) != expected_generation:
            raise _conflict(
                "configuration generation is stale",
                reason="stale_generation",
                expected_generation=expected_generation,
                generation=int(state[1]),
            )
        candidate = _revision_row(conn, revision_id)
        if candidate is None or candidate[1] != kind:
            raise ConfigNotFoundError("configuration revision not found")
        if candidate[7] != "superseded":
            raise _conflict(
                "only a superseded revision can be rolled back",
                reason="not_superseded",
                expected_generation=expected_generation,
                state=str(candidate[7]),
            )
        # A superseded row is not necessarily a previously active revision: a
        # draft that validation normalized is retained in the same state, still
        # holding the operator's pre-canonical bytes. It was never active, so it
        # is refused here rather than failing later as stored-content corruption.
        if _is_normalization_input(conn, candidate):
            raise _conflict(
                "a normalization input revision cannot be rolled back",
                reason="normalization_input",
                expected_generation=expected_generation,
            )
        document_json = str(candidate[3])
        try:
            validate_stored_revision(kind, document_json, str(candidate[2]))
            document = json.loads(document_json)
        except (OperatorConfigError, json.JSONDecodeError) as exc:
            raise ConfigIntegrityError(str(exc)) from exc
        payload = _activate_revision_locked(
            conn,
            state=state,
            kind=kind,
            candidate=candidate,
            document=document,
            shipped_base_revision=(
                str(candidate[6]) if candidate[6] is not None else None
            ),
            expected_generation=expected_generation,
            acknowledge_broad_rules=acknowledge_broad_rules,
            acknowledge_shipped_base_change=acknowledge_shipped_base_change,
            actor=actor,
            auth_via=auth_via,
            request_id=request_id,
            timestamp=timestamp,
            action="revision_rolled_back",
        )
        conn.commit()
        return payload


def _encode_id_cursor(row_id: int) -> str:
    raw = canonical_json({"i": row_id}).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_id_cursor(cursor: str) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(
            cursor + padding,
            altchars=b"-_",
            validate=True,
        )
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict) or set(decoded) != {"i"}:
            raise ValueError("invalid shape")
        audit_id = decoded["i"]
        if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
            raise ValueError("invalid id")
        return audit_id
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ConfigRepositoryError("invalid cursor") from exc


def list_audit(
    conn: sqlite3.Connection,
    *,
    limit: int,
    cursor: str | None,
    kind: str | None,
) -> dict[str, Any]:
    if not 1 <= limit <= MAX_AUDIT_LIMIT:
        raise ConfigRepositoryError("audit limit is out of range")
    if kind is not None:
        _require_kind(kind)
    cursor_id = decode_id_cursor(cursor) if cursor else None
    where = []
    params: list[Any] = []
    if cursor_id is not None:
        where.append("id < ?")
        params.append(cursor_id)
    if kind is not None:
        where.append("kind = ?")
        params.append(kind)
    clause = " WHERE " + " AND ".join(where) if where else ""
    params.append(limit + 1)
    rows = conn.execute(
        """SELECT id, occurred_at, kind, revision_id, from_revision_id,
                  to_revision_id, actor, auth_via, request_id, action,
                  detail_json
           FROM operator_config_audit"""
        + clause
        + " ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    entries = [
        {
            "id": int(row[0]),
            "occurred_at": str(row[1]),
            "kind": str(row[2]) if row[2] is not None else None,
            "revision_id": int(row[3]) if row[3] is not None else None,
            "from_revision_id": int(row[4]) if row[4] is not None else None,
            "to_revision_id": int(row[5]) if row[5] is not None else None,
            "actor": str(row[6]),
            "auth_via": str(row[7]),
            "request_id": str(row[8]) if row[8] is not None else None,
            "action": str(row[9]),
            "detail": _decode_object(row[10], "audit detail"),
        }
        for row in rows
    ]
    next_cursor = (
        _encode_id_cursor(int(rows[-1][0])) if has_more and rows else None
    )
    return {
        "generated_at": utc_now_iso(),
        "entries": entries,
        "next_cursor": next_cursor,
    }
