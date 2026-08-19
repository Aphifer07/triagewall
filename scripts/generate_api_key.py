#!/usr/bin/env python3
"""Generate one attributable Triagewall API-key record for operator setup."""

from __future__ import annotations

import argparse
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Sequence

SCOPE_READ = "read"
SCOPE_FEEDBACK_WRITE = "feedback:write"
SCOPE_CONFIG_WRITE = "config:write"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VALID_SCOPES = frozenset(
    {SCOPE_READ, SCOPE_FEEDBACK_WRITE, SCOPE_CONFIG_WRITE}
)
PBKDF2_ITERATIONS = 210_000
SALT_BYTES = 16


@dataclass(frozen=True)
class GeneratedKeyMaterial:
    plaintext: str
    record: str


def generate_key_material(
    *,
    name: str = "config-admin",
    scopes: Sequence[str] = (SCOPE_CONFIG_WRITE,),
    plaintext: str | None = None,
    salt: bytes | None = None,
) -> GeneratedKeyMaterial:
    """Return a one-time plaintext key and its hash-only environment record."""
    if not isinstance(name, str) or SAFE_NAME.fullmatch(name) is None:
        raise ValueError("name must be a safe 1-64 character identifier")
    normalized_scopes = tuple(scopes)
    if (
        not normalized_scopes
        or len(set(normalized_scopes)) != len(normalized_scopes)
        or any(scope not in VALID_SCOPES for scope in normalized_scopes)
    ):
        raise ValueError(
            "scopes must be unique values from " + ", ".join(sorted(VALID_SCOPES))
        )
    key = plaintext if plaintext is not None else secrets.token_urlsafe(32)
    if not isinstance(key, str) or not key:
        raise ValueError("plaintext key must be non-empty")
    salt_bytes = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    if not isinstance(salt_bytes, bytes) or not salt_bytes:
        raise ValueError("salt must be non-empty bytes")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        key.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    ).hex()
    key_hash = (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_bytes.hex()}${digest}"
    )
    record = f"{name}:{key_hash}:{'|'.join(normalized_scopes)}"
    return GeneratedKeyMaterial(plaintext=key, record=record)


def compose_env_assignment(record: str) -> str:
    """Quote a generated record so Compose does not expand PBKDF2 dollar signs."""
    if not record or any(character in record for character in ("'", "\r", "\n")):
        raise ValueError("record cannot be represented safely in a Compose .env file")
    return f"TRIAGEWALL_API_KEYS='{record}'"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an attributable Triagewall API key. The plaintext is "
            "shown once; only its PBKDF2 hash belongs in .env."
        )
    )
    parser.add_argument(
        "--name",
        default="config-admin",
        help="Attributable key name (default: config-admin).",
    )
    parser.add_argument(
        "--scope",
        action="append",
        choices=sorted(VALID_SCOPES),
        dest="scopes",
        help=(
            "Scope to grant; repeat for more than one. "
            "Defaults to config:write."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        material = generate_key_material(
            name=args.name,
            scopes=tuple(args.scopes or (SCOPE_CONFIG_WRITE,)),
        )
    except ValueError as exc:
        _build_parser().error(str(exc))

    print("Plaintext API key (save now; shown once):")
    print(material.plaintext)
    print()
    print("API key record to append to an existing TRIAGEWALL_API_KEYS value:")
    print(material.record)
    print()
    print("Compose-safe .env entry for a new installation:")
    print(compose_env_assignment(material.record))
    print("TRIAGEWALL_CONFIG_WRITES_ENABLED=true")
    print()
    print(
        "If TRIAGEWALL_API_KEYS already exists, keep its records and append "
        "the new record inside the same single quotes, separated by a comma."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
