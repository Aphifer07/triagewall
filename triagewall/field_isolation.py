"""
Field isolation for prompt injection defense.

Wraps attacker-controlled alert fields in base64 with explicit boundary
markers, preventing in-content instructions from being executed by the
LLM. See docs/v0.2.1-field-isolation-design.md for design rationale and
empirical validation.

The model is instructed (via the system prompt in triage.py) to mentally
decode the base64 to analyze content, but never to treat decoded content
as instructions. Foundation-Sec-8B cannot reliably ignore in-content
instructions even when explicitly told to (validated 2026-05-25), so the
defense must hide instructions from the instruction-following pathway
rather than rely on the model to selectively ignore them.
"""
import base64
import json


# Dotted-path field names that contain attacker-controlled content.
# Values at these paths are base64-wrapped before being shown to the LLM.
UNTRUSTED_FIELD_PATHS = frozenset({
    # HTTP fields - URLs, headers, request/response bodies
    "http.url",
    "http.hostname",
    "http.user_agent",
    "http.http_user_agent",
    "http.http_refer",
    "http.http_refer_user_agent",
    "http.request_body_printable",
    "http.response_body_printable",
    "http.http_content_type",

    # DNS - query names are attacker-controlled when probing
    "dns.rrname",
    "dns.query.rrname",

    # TLS - subject/issuer/SNI are attacker-controlled when cert is theirs
    "tls.subject",
    "tls.issuer",
    "tls.sni",
    "tls.fingerprint",

    # File info - filenames in transferred files
    "fileinfo.filename",
    "fileinfo.magic",

    # SSH banners - attacker-controlled when banner is theirs
    "ssh.client.software_version",
    "ssh.server.software_version",
    "ssh.client.proto_version",
    "ssh.server.proto_version",

    # Raw payload content
    "payload",
    "payload_printable",
})


def _wrap_value(field_path: str, value) -> str:
    """Base64-wrap an untrusted value with explicit boundary markers."""
    if value is None:
        return "<null>"
    if isinstance(value, (dict, list)):
        # Serialize complex types before encoding
        s = json.dumps(value, separators=(",", ":"))
    else:
        s = str(value)
    encoded = base64.b64encode(s.encode("utf-8")).decode("ascii")
    return (
        f"=== UNTRUSTED FIELD [{field_path}] (base64) ===\n"
        f"{encoded}\n"
        f"=== END UNTRUSTED FIELD ==="
    )


def _walk_and_isolate(obj, path: str = ""):
    """Recursively walk a dict/list tree, wrapping values at untrusted paths."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            if new_path in UNTRUSTED_FIELD_PATHS:
                result[key] = _wrap_value(new_path, value)
            elif isinstance(value, (dict, list)):
                result[key] = _walk_and_isolate(value, new_path)
            else:
                result[key] = value
        return result
    if isinstance(obj, list):
        return [_walk_and_isolate(item, path) for item in obj]
    return obj


def format_alert_for_llm(alert: dict) -> str:
    """
    Build a hybrid alert representation with trusted Suricata metadata as
    plain JSON and untrusted attacker-controlled fields wrapped in base64
    with explicit boundary markers.

    Returns a JSON-formatted string ready for inclusion in the LLM prompt.
    """
    isolated = _walk_and_isolate(alert)
    return json.dumps(isolated, indent=2)


def has_untrusted_fields(alert: dict) -> bool:
    """Return True if the alert contains any fields that would be wrapped."""
    return _has_untrusted(alert, "")


def _has_untrusted(obj, path: str) -> bool:
    """Helper for has_untrusted_fields."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            if new_path in UNTRUSTED_FIELD_PATHS:
                return True
            if isinstance(value, (dict, list)) and _has_untrusted(value, new_path):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _has_untrusted(item, path):
                return True
    return False
