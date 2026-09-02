#!/usr/bin/env python3
"""Generate one private Lab access key and its PBKDF2 configuration hash."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagewall.lab.auth import hash_lab_api_key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate a TriageWall Lab access key.")
    parser.add_argument("--bytes", type=int, default=32)
    args = parser.parse_args(argv)
    if not 24 <= args.bytes <= 64:
        parser.error("--bytes must be between 24 and 64")
    plaintext = secrets.token_urlsafe(args.bytes)
    digest = hash_lab_api_key(plaintext)
    session_secret = secrets.token_urlsafe(48)
    print("Store the access key in your password manager; it is shown only now:")
    print(plaintext)
    print("\nAdd these hash/secret values to .env (they do not contain the access key):")
    print(f"TRIAGEWALL_LAB_API_KEY_HASH='{digest}'")
    print(f"TRIAGEWALL_LAB_SESSION_SECRET='{session_secret}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

