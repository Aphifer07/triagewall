"""Keyed pseudonymization for IP addresses in API responses.

An unsalted truncated SHA-256 of an IP address is not redaction: the address
space is small enough to enumerate exhaustively, so anyone holding the output
can recover the input offline. Deriving the pseudonym with HMAC under a secret
that never leaves the deployment removes that shortcut while keeping the
mapping deterministic, so correlation across responses still works.
"""

from __future__ import annotations

import hashlib
import hmac

# Domain separation: this secret must never produce a value that is meaningful
# in another context, and no other Triagewall construction may collide with it.
_PSEUDONYM_DOMAIN = b"triagewall/api/ip-pseudonym/v1"

# Documented, constant output format: "ip_" followed by 32 lowercase hex
# characters (the leading 128 bits of the HMAC-SHA256 tag). Stable across
# releases so operators can correlate historical exports.
PSEUDONYM_PREFIX = "ip_"
PSEUDONYM_HEX_LENGTH = 32

# Short secrets defeat the point, since the attacker's offline enumeration
# simply moves to the secret. Enforced at startup, not per request.
MIN_SECRET_LENGTH = 32

ENV_IP_HASH_SECRET = "TRIAGEWALL_API_IP_HASH_SECRET"
ENV_REDACT_IPS = "TRIAGEWALL_API_REDACT_IPS"
ENV_DASHBOARD_WRITE_SECRET = "TRIAGEWALL_DASHBOARD_WRITE_SECRET"


class IpPseudonymConfigError(RuntimeError):
    """Raised at startup when IP redaction is enabled but unusable."""


def pseudonymize_ip(ip: str | None, secret: bytes) -> str | None:
    """Return a deterministic, keyed pseudonym for one IP address.

    ``None`` and empty values pass through unchanged so callers can apply this
    to optional columns without special-casing every field.
    """
    if not ip:
        return ip
    if not secret:
        raise IpPseudonymConfigError(
            "IP pseudonymization requires a configured secret"
        )
    tag = hmac.new(
        secret,
        _PSEUDONYM_DOMAIN + b"\x00" + ip.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{PSEUDONYM_PREFIX}{tag[:PSEUDONYM_HEX_LENGTH]}"


def load_ip_pseudonym_secret(
    raw_secret: str | None,
    *,
    redact_ips: bool,
    dashboard_write_secret: str | None = None,
) -> bytes | None:
    """Validate the configured pseudonymization secret at startup.

    Returns ``None`` when redaction is disabled. When redaction is enabled the
    secret must be present, long enough, and distinct from the dashboard write
    cookie secret -- otherwise startup fails rather than silently degrading to
    weak redaction. The secret value is never included in any message raised
    from here.
    """
    secret = (raw_secret or "").strip()
    if not redact_ips:
        return None
    if not secret:
        raise IpPseudonymConfigError(
            f"{ENV_REDACT_IPS} is enabled but {ENV_IP_HASH_SECRET} is not set. "
            "Unsalted hashing of an IP address is reversible by exhaustive "
            "search and is not redaction, so Triagewall will not start. "
            f"Generate a persistent secret (for example "
            f"`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`) "
            f"and set {ENV_IP_HASH_SECRET}, or set {ENV_REDACT_IPS}=false."
        )
    if len(secret) < MIN_SECRET_LENGTH:
        raise IpPseudonymConfigError(
            f"{ENV_IP_HASH_SECRET} must be at least {MIN_SECRET_LENGTH} "
            "characters; a short secret can be recovered by brute force just "
            "as easily as the addresses it is meant to protect."
        )
    # Compare as UTF-8 bytes, not as ``str``. ``hmac.compare_digest`` only
    # accepts ASCII-only strings and raises ``TypeError`` otherwise, so a
    # non-ASCII passphrase in either secret would abort startup with an
    # uncaught TypeError instead of loading (or failing cleanly). The dashboard
    # cookie HMAC already encodes the same secret this way.
    other = (dashboard_write_secret or "").strip()
    if other and hmac.compare_digest(
        secret.encode("utf-8"),
        other.encode("utf-8"),
    ):
        raise IpPseudonymConfigError(
            f"{ENV_IP_HASH_SECRET} must differ from "
            f"{ENV_DASHBOARD_WRITE_SECRET}. Reusing one secret for two "
            "purposes means disclosing either one compromises both."
        )
    return secret.encode("utf-8")
