"""API-key and dashboard write-cookie authentication."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader

from triagewall.environment import parse_boolean

logger = logging.getLogger(__name__)

API_KEY_HEADER_NAME = "X-API-Key"
DASHBOARD_WRITE_COOKIE = "tw_dash_write"
SCOPE_READ = "read"
SCOPE_FEEDBACK_WRITE = "feedback:write"
_VALID_SCOPES = frozenset({SCOPE_READ, SCOPE_FEEDBACK_WRITE})

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


@dataclass(frozen=True)
class ApiKeyRecord:
    """One configured API key (hash only; plaintext never stored)."""

    name: str
    key_hash_hex: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class AuthContext:
    """Resolved caller identity for a request."""

    principal: str
    scopes: frozenset[str]
    via: str  # "api_key" | "dashboard_cookie" | "anonymous"


def _hash_plaintext_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def parse_api_keys(raw: str | None) -> tuple[ApiKeyRecord, ...]:
    """Parse ``name:sha256hex:scope|scope`` entries from env."""
    if not raw or not raw.strip():
        return ()
    records: list[ApiKeyRecord] = []
    for part in raw.split(","):
        entry = part.strip()
        if not entry:
            continue
        pieces = entry.split(":", 2)
        if len(pieces) != 3:
            raise RuntimeError(
                "TRIAGEWALL_API_KEYS entries must be name:sha256hex:scopes"
            )
        name, key_hash_hex, scopes_raw = (p.strip() for p in pieces)
        if not name or not key_hash_hex:
            raise RuntimeError(
                "TRIAGEWALL_API_KEYS entries require a non-empty name and hash"
            )
        if len(key_hash_hex) != 64 or any(
            c not in "0123456789abcdef" for c in key_hash_hex.lower()
        ):
            raise RuntimeError(
                f"TRIAGEWALL_API_KEYS hash for {name!r} must be 64 lowercase hex"
            )
        scopes = frozenset(
            s.strip() for s in scopes_raw.replace(",", "|").split("|") if s.strip()
        )
        if not scopes or not scopes <= _VALID_SCOPES:
            raise RuntimeError(
                f"TRIAGEWALL_API_KEYS scopes for {name!r} must be subset of "
                f"{sorted(_VALID_SCOPES)}"
            )
        records.append(
            ApiKeyRecord(
                name=name,
                key_hash_hex=key_hash_hex.lower(),
                scopes=scopes,
            )
        )
    return tuple(records)


def load_auth_settings_from_env() -> tuple[
    tuple[ApiKeyRecord, ...],
    str,
    bool,
]:
    """Load API keys, dashboard write secret, and unauthenticated-reads flag."""
    keys = parse_api_keys(os.environ.get("TRIAGEWALL_API_KEYS"))
    secret = os.environ.get("TRIAGEWALL_DASHBOARD_WRITE_SECRET", "").strip()
    if not secret:
        secret = secrets.token_hex(32)
        logger.info(
            "TRIAGEWALL_DASHBOARD_WRITE_SECRET unset; using ephemeral process secret"
        )
    allow_unauth_reads = parse_boolean(
        os.environ.get("TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS", "true"),
        "TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS",
    )
    return keys, secret, allow_unauth_reads


def issue_dashboard_write_cookie(secret: str) -> str:
    """Return an HMAC cookie value granting feedback:write for the local UI."""
    digest = hmac.new(
        secret.encode("utf-8"),
        b"dashboard-write-v1",
        hashlib.sha256,
    ).hexdigest()
    return f"v1.{digest}"


def verify_dashboard_write_cookie(secret: str, value: str | None) -> bool:
    if not value or not isinstance(value, str):
        return False
    expected = issue_dashboard_write_cookie(secret)
    return hmac.compare_digest(expected, value)


def lookup_api_key(
    keys: tuple[ApiKeyRecord, ...],
    plaintext: str | None,
) -> ApiKeyRecord | None:
    if not plaintext:
        return None
    digest = _hash_plaintext_key(plaintext)
    for record in keys:
        if hmac.compare_digest(record.key_hash_hex, digest):
            return record
    return None


def require_scopes(
    ctx: AuthContext,
    *needed: str,
) -> None:
    missing = [scope for scope in needed if scope not in ctx.scopes]
    if missing:
        raise HTTPException(
            status_code=403,
            detail="insufficient API key scope",
        )


class AuthState:
    """Process-wide auth configuration bound into FastAPI dependencies."""

    def __init__(
        self,
        keys: tuple[ApiKeyRecord, ...] | None = None,
        dashboard_write_secret: str | None = None,
        allow_unauthenticated_reads: bool | None = None,
    ) -> None:
        if keys is None or dashboard_write_secret is None or allow_unauthenticated_reads is None:
            env_keys, env_secret, env_allow = load_auth_settings_from_env()
            keys = keys if keys is not None else env_keys
            dashboard_write_secret = (
                dashboard_write_secret
                if dashboard_write_secret is not None
                else env_secret
            )
            allow_unauthenticated_reads = (
                allow_unauthenticated_reads
                if allow_unauthenticated_reads is not None
                else env_allow
            )
        self.keys = keys
        self.dashboard_write_secret = dashboard_write_secret
        self.allow_unauthenticated_reads = allow_unauthenticated_reads

    def resolve(
        self,
        request: Request,
        api_key: str | None,
    ) -> AuthContext:
        record = lookup_api_key(self.keys, api_key)
        if record is not None:
            return AuthContext(
                principal=record.name,
                scopes=record.scopes,
                via="api_key",
            )
        cookie = request.cookies.get(DASHBOARD_WRITE_COOKIE)
        if verify_dashboard_write_cookie(self.dashboard_write_secret, cookie):
            return AuthContext(
                principal="dashboard",
                scopes=frozenset({SCOPE_READ, SCOPE_FEEDBACK_WRITE}),
                via="dashboard_cookie",
            )
        return AuthContext(
            principal="anonymous",
            scopes=frozenset(),
            via="anonymous",
        )

    def require_read(
        self,
        request: Request,
        api_key: str | None = Security(api_key_header),
    ) -> AuthContext:
        ctx = self.resolve(request, api_key)
        if self.allow_unauthenticated_reads:
            return ctx
        if SCOPE_READ not in ctx.scopes and SCOPE_FEEDBACK_WRITE not in ctx.scopes:
            raise HTTPException(status_code=401, detail="API key required")
        return ctx

    def require_feedback_write(
        self,
        request: Request,
        api_key: str | None = Security(api_key_header),
    ) -> AuthContext:
        ctx = self.resolve(request, api_key)
        if SCOPE_FEEDBACK_WRITE not in ctx.scopes:
            raise HTTPException(
                status_code=401,
                detail="API key with feedback:write scope required",
            )
        return ctx
