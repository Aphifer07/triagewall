"""Bounded prompt projection for untrusted Wazuh alert evidence."""

from __future__ import annotations

import base64
import hashlib
import json


MAX_PROMPT_BYTES = 32 * 1024
_BUDGETS = (8192, 4096, 2048, 1024, 512, 0)


def _bounded_text(value, limit: int) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    digest = hashlib.sha256(encoded).hexdigest()
    prefix = encoded[:limit].decode("utf-8", errors="ignore")
    return (
        f"{prefix}\n[TRUNCATED bytes={len(encoded)} "
        f"sha256={digest}]"
    )


def _wrap(field_path: str, value) -> str:
    if value is None:
        serialized = "<null>"
    elif isinstance(value, str):
        serialized = value
    else:
        serialized = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    encoded = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
    return (
        f"=== UNTRUSTED FIELD [{field_path}] (base64) ===\n"
        f"{encoded}\n"
        f"=== END UNTRUSTED FIELD ==="
    )


def _number_or_wrapped(field_path: str, value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return _wrap(field_path, value)


def _project(alert: dict, data_budget: int, log_budget: int) -> dict:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    manager = alert.get("manager") if isinstance(alert.get("manager"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []

    known = {
        "timestamp", "id", "rule", "agent", "manager", "decoder",
        "location", "data", "full_log",
    }
    projection = {
        "timestamp": _wrap("timestamp", alert.get("timestamp")),
        "id": _wrap("id", alert.get("id")),
        "rule": {
            "id": _number_or_wrapped("rule.id", rule.get("id")),
            "level": _number_or_wrapped("rule.level", rule.get("level")),
            "description": _wrap(
                "rule.description", _bounded_text(rule.get("description"), 2048)
            ),
            "groups": [
                _wrap(f"rule.groups.{index}", _bounded_text(group, 256))
                for index, group in enumerate(groups[:32])
            ],
        },
        "agent": {
            "id": _wrap("agent.id", _bounded_text(agent.get("id"), 256)),
            "name": _wrap("agent.name", _bounded_text(agent.get("name"), 256)),
        },
        "manager": {
            "name": _wrap(
                "manager.name", _bounded_text(manager.get("name"), 256)
            )
        },
        "decoder": {
            "name": _wrap(
                "decoder.name", _bounded_text(decoder.get("name"), 256)
            ),
            "parent": _wrap(
                "decoder.parent", _bounded_text(decoder.get("parent"), 256)
            ),
        },
        "location": _wrap(
            "location", _bounded_text(alert.get("location"), 1024)
        ),
        "data": _wrap("data", _bounded_text(alert.get("data"), data_budget)),
        "full_log": _wrap(
            "full_log", _bounded_text(alert.get("full_log"), log_budget)
        ),
        "omitted_top_level_fields": len(set(alert) - known),
    }
    if len(groups) > 32:
        projection["rule"]["omitted_group_count"] = len(groups) - 32
    return projection


def format_wazuh_for_llm(alert: dict) -> str:
    """Return isolated Wazuh evidence within the fixed prompt budget."""
    for budget in _BUDGETS:
        rendered = json.dumps(
            _project(alert, budget, budget),
            indent=2,
            ensure_ascii=True,
        )
        if len(rendered.encode("utf-8")) <= MAX_PROMPT_BYTES:
            return rendered
    raise ValueError("Wazuh evidence projection exceeded the prompt size limit")
