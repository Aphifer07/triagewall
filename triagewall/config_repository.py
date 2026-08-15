"""Bounded repository operations for the operator-configuration lifecycle."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from typing import Any

try:
    from .asset_inventory import canonical_json
    from .operator_config import (
        ASSET_KIND,
        CONFIG_KINDS,
        PREFILTER_KIND,
        OperatorConfigError,
        canonicalize_document,
        validate_stored_revision,
    )
    from .prefilter import MAX_CONFIG_BYTES
    from .time_utils import utc_now_iso
except ImportError:  # Direct script-style imports used by container entrypoints.
    from asset_inventory import canonical_json
    from operator_config import (
        ASSET_KIND,
        CONFIG_KINDS,
        PREFILTER_KIND,
        OperatorConfigError,
        canonicalize_document,
        validate_stored_revision,
    )
    from prefilter import MAX_CONFIG_BYTES
    from time_utils import utc_now_iso


MAX_NOTE_LENGTH = 2_000
MAX_REQUEST_ID_LENGTH = 128
DEFAULT_AUDIT_LIMIT = 50
MAX_AUDIT_LIMIT = 100
MAX_CONFIG_CURSOR_LENGTH = 512
DEFAULT_REVISION_LIMIT = 50
MAX_REVISION_LIMIT = 100


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
    if row is None:
        raise ConfigIntegrityError(f"active {expected_kind} revision is missing")
    if row[1] != expected_kind or row[7] != "active":
        raise ConfigIntegrityError(f"active {expected_kind} pointer is inconsistent")
    try:
        validate_stored_revision(str(row[1]), str(row[3]), str(row[2]))
    except OperatorConfigError as exc:
        raise ConfigIntegrityError(str(exc)) from exc


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
        _validate_active_row(row, kind)
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
    return {
        "generated_at": utc_now_iso(),
        "mode": str(state[0]),
        "generation": int(state[1]),
        "updated_at": str(state[2]),
        "writes_enabled": writes_enabled,
        "reload": {
            "supported": False,
            "desired_generation": int(state[1]),
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

    try:
        conn.execute("BEGIN IMMEDIATE")
        state = _state_row(conn)
        active_id = int(state[3] if kind == PREFILTER_KIND else state[4])
        if int(state[1]) != expected_generation:
            raise ConfigConflictError("configuration generation is stale")
        if active_id != parent_revision_id:
            raise ConfigConflictError("parent revision is not active")
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
            raise ConfigConflictError(
                "an identical configuration revision already exists"
            ) from exc
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
        return {"draft": _revision_metadata(row)}
    except Exception:
        conn.rollback()
        raise


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
    try:
        conn.execute("BEGIN IMMEDIATE")
        draft = _revision_row(conn, draft_id)
        if draft is None or draft[1] != kind:
            raise ConfigNotFoundError("configuration draft not found")
        if draft[7] != "draft":
            raise ConfigConflictError("configuration revision is not a draft")
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
        else:
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
            detail={"status": "valid", "normalized": normalized},
        )
        validated = _revision_row(conn, validated_id)
        conn.commit()
        return {
            "draft_id": draft_id,
            "validation": validation,
            "revision": _revision_metadata(validated),
        }
    except Exception:
        conn.rollback()
        raise


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
