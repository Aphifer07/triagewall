"""
Field isolation for prompt injection defense (fail-closed).

Wraps attacker-/network-controlled alert fields in base64 with explicit
boundary markers, preventing in-content instructions from reaching the
LLM's instruction-following pathway.

DESIGN: fail-closed allowlist.
--------------------------------
Earlier versions used a denylist of exact dotted paths to wrap, trusting
everything else by default. That is fail-OPEN: any field not enumerated
(new eve.json protocol records, renamed fields, ARRAY-NESTED fields like
`dns.queries.0.rrname`) silently reached the model as trusted plain text.

This version inverts it: a small allowlist of structurally trusted,
Suricata-/sensor-authored fields is emitted plain; EVERYTHING ELSE is
wrapped by default. Adding a new protocol or upgrading Suricata cannot
open a hole — unknown fields wrap automatically.

Two extra safeguards:
  1. Type assertion — a trusted path is only honored if its value matches
     the expected type (e.g. severity must be a number). A free-text value
     showing up in a "trusted" slot still wraps.
  2. Array-index normalization — `dns.queries.0.rrname` and
     `dns.queries.5.rrname` both normalize to `dns.queries.rrname` before
     matching, so array nesting can't bypass the allowlist.

Foundation-Sec-8B cannot reliably ignore in-content instructions even when
told to (validated 2026-05-25), so the defense hides untrusted content from
the instruction pathway rather than relying on the model to ignore it.
"""
import base64
import json
import re


# Trusted paths: Suricata-/sensor-authored, structured metadata only.
# Path is matched AFTER array-index normalization (see _normalize_path).
# Each entry maps a normalized dotted path to the JSON type(s) it must have
# to be trusted. If the runtime value's type isn't allowed, it is WRAPPED.
#
# "number" covers int and float. "string" here is reserved for values that
# are Suricata enums/identifiers (action, category, proto, app_proto, ja3
# hashes, etc.) — NOT free text from the wire. IPs/ports are structured.
#
# NOTE: alert.signature is deliberately NOT trusted. It is free text and the
# system prompt must not claim it as authoritative (finding D-1).
TRUSTED_PATHS = {
    # --- sensor / flow envelope ---
    "timestamp": ("string",),
    "flow_id": ("number",),
    "in_iface": ("string",),
    "pkt_src": ("string",),
    "event_type": ("string",),
    "direction": ("string",),
    "ip_v": ("number",),
    "proto": ("string",),
    "app_proto": ("string",),
    "tx_id": ("number",),
    "tc_progress": ("number", "string"),
    "ts_progress": ("number", "string"),
    "vlan": ("number",),

    # --- 5-tuple ---
    "src_ip": ("string",),
    "src_port": ("number",),
    "dest_ip": ("string",),
    "dest_port": ("number",),

    # --- alert metadata (ruleset-authored, not wire) ---
    "alert.action": ("string",),
    "alert.category": ("string",),
    "alert.gid": ("number",),
    "alert.rev": ("number",),
    "alert.severity": ("number",),
    "alert.signature_id": ("number",),
    "alert.source.ip": ("string",),
    "alert.source.port": ("number",),
    "alert.target.ip": ("string",),
    "alert.target.port": ("number",),
    # rule metadata block — all authored by the ruleset, not the attacker
    "alert.metadata.affected_product": ("string",),
    "alert.metadata.attack_target": ("string",),
    "alert.metadata.confidence": ("string",),
    "alert.metadata.created_at": ("string",),
    "alert.metadata.deployment": ("string",),
    "alert.metadata.former_sid": ("string",),
    "alert.metadata.performance_impact": ("string",),
    "alert.metadata.reviewed_at": ("string",),
    "alert.metadata.signature_severity": ("string",),
    "alert.metadata.tag": ("string",),
    "alert.metadata.updated_at": ("string",),

    # --- flow stats (Suricata-measured) ---
    "flow.bytes_toclient": ("number",),
    "flow.bytes_toserver": ("number",),
    "flow.pkts_toclient": ("number",),
    "flow.pkts_toserver": ("number",),
    "flow.src_ip": ("string",),
    "flow.dest_ip": ("string",),
    "flow.src_port": ("number",),
    "flow.dest_port": ("number",),
    "flow.start": ("string",),

    # --- anomaly records (Suricata-authored) ---
    "anomaly.event": ("string",),
    "anomaly.layer": ("string",),
    "anomaly.type": ("string",),
    "metadata.flowbits": ("string",),

    # --- DNS structured fields (enums/ids). rrname is NOT here (free text). ---
    "dns.flags": ("string",),
    "dns.id": ("number",),
    "dns.opcode": ("number",),
    "dns.rcode": ("string",),
    "dns.rd": ("boolean",),
    "dns.tx_id": ("number",),
    "dns.type": ("string",),
    "dns.version": ("number",),
    "dns.queries.rrtype": ("string",),  # rrtype is an enum; rrname is wrapped

    # --- TLS computed/enum fields. sni is NOT here (free text). ---
    "tls.version": ("string",),
    "tls.ja3.hash": ("string",),
    "tls.ja3.string": ("string",),
    "tls.ja3s.hash": ("string",),
    "tls.ja3s.string": ("string",),
    "tls.ja4": ("string",),
    "tls.client_alpns": ("string",),

    # --- HTTP structured fields. hostname/url/user_agent/content_type wrap. ---
    "http.http_method": ("string",),
    "http.length": ("number",),
    "http.protocol": ("string",),
    "http.status": ("number",),
}

_ARRAY_INDEX_RE = re.compile(r"\.\d+(?=\.|$)")


def _normalize_path(path: str) -> str:
    """Strip array indices so dns.queries.0.rrname -> dns.queries.rrname."""
    return _ARRAY_INDEX_RE.sub("", path)


def _json_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    return "other"


def _is_trusted(norm_path: str, value) -> bool:
    """A leaf is trusted only if its normalized path is allowlisted AND its
    value type is one the allowlist permits for that path."""
    allowed = TRUSTED_PATHS.get(norm_path)
    if allowed is None:
        return False
    return _json_type(value) in allowed


def _wrap_value(field_path: str, value) -> str:
    """Base64-wrap an untrusted value with explicit boundary markers."""
    if value is None:
        return "<null>"
    if isinstance(value, (dict, list)):
        s = json.dumps(value, separators=(",", ":"))
    else:
        s = str(value)
    encoded = base64.b64encode(s.encode("utf-8")).decode("ascii")
    return (
        f"=== UNTRUSTED FIELD [{field_path}] (base64) ===\n"
        f"{encoded}\n"
        f"=== END UNTRUSTED FIELD ==="
    )


def _walk(obj, path: str = ""):
    """Recursively walk the alert tree. Leaf string/number/bool values are
    emitted plain only if trusted; otherwise wrapped. Containers recurse."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                result[key] = _walk(value, new_path)
            else:
                norm = _normalize_path(new_path)
                if _is_trusted(norm, value):
                    result[key] = value
                else:
                    result[key] = _wrap_value(new_path, value)
        return result
    if isinstance(obj, list):
        return [_walk(item, path) for item in obj]
    return obj


def format_alert_for_llm(alert: dict) -> str:
    """
    Build a hybrid alert representation: trusted Suricata/sensor metadata as
    plain JSON, everything else base64-wrapped with explicit boundary markers.
    Fail-closed: any field not on the trusted allowlist is wrapped.
    """
    isolated = _walk(alert)
    return json.dumps(isolated, indent=2)


def has_untrusted_fields(alert: dict) -> bool:
    """Return True if the alert contains any field that would be wrapped."""
    return _has_untrusted(alert, "")


def _has_untrusted(obj, path: str) -> bool:
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                if _has_untrusted(value, new_path):
                    return True
            else:
                if not _is_trusted(_normalize_path(new_path), value):
                    return True
    elif isinstance(obj, list):
        for item in obj:
            if _has_untrusted(item, path):
                return True
    return False
