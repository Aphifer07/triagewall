"""Validation and normalization for Wazuh alerts.json records."""

from __future__ import annotations

import ipaddress
import re

from sensor_event import SensorContext, SensorEvent
from time_utils import format_utc_timestamp


SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_DESCRIPTION_CHARS = 4096
MAX_AGENT_FIELD_CHARS = 256


class WazuhValidationError(ValueError):
    """A complete Wazuh record cannot be safely normalized."""


def validate_source_id(value: str) -> str:
    if not isinstance(value, str) or SOURCE_ID_RE.fullmatch(value) is None:
        raise WazuhValidationError(
            "WAZUH_SOURCE_ID must be a safe 1-64 character identifier"
        )
    return value


def _required_rule_integer(value, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise WazuhValidationError(f"{label} must be an integer")
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or not minimum <= value <= maximum:
        raise WazuhValidationError(
            f"{label} must be an integer from {minimum} to {maximum}"
        )
    return value


def _optional_agent_field(agent: dict, key: str) -> str | None:
    value = agent.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > MAX_AGENT_FIELD_CHARS:
        raise WazuhValidationError(
            f"agent.{key} must be a non-empty string of at most "
            f"{MAX_AGENT_FIELD_CHARS} characters"
        )
    return value


def _optional_ip(data: dict, key: str) -> str | None:
    value = data.get(key)
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _optional_port(data: dict, key: str) -> int | None:
    value = data.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    if isinstance(value, int) and 1 <= value <= 65535:
        return value
    return None


def _optional_protocol(data: dict) -> str | None:
    value = data.get("protocol") or data.get("proto")
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    if not normalized or len(normalized) > 16:
        return None
    if not all(character.isalnum() or character in "_-" for character in normalized):
        return None
    return normalized


def normalize_wazuh_event(alert: dict, source_instance: str) -> SensorEvent:
    """Validate one Wazuh record and map it to the shared event contract."""
    validate_source_id(source_instance)
    if not isinstance(alert, dict):
        raise WazuhValidationError("top-level JSON value must be an object")

    timestamp = alert.get("timestamp")
    try:
        timestamp = format_utc_timestamp(timestamp)
    except (TypeError, ValueError) as exc:
        raise WazuhValidationError(f"invalid Wazuh timestamp: {exc}") from exc

    event_id = alert.get("id")
    if not isinstance(event_id, str) or EVENT_ID_RE.fullmatch(event_id) is None:
        raise WazuhValidationError(
            "id must be a safe non-empty string of at most 128 characters"
        )

    rule = alert.get("rule")
    if not isinstance(rule, dict):
        raise WazuhValidationError("rule must be an object")
    rule_id = _required_rule_integer(rule.get("id"), "rule.id", 1, 999999)
    level = _required_rule_integer(rule.get("level"), "rule.level", 1, 16)
    description = rule.get("description")
    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > MAX_DESCRIPTION_CHARS
    ):
        raise WazuhValidationError(
            f"rule.description must be a non-empty string of at most "
            f"{MAX_DESCRIPTION_CHARS} characters"
        )

    agent = alert.get("agent")
    if agent is None:
        agent = {}
    if not isinstance(agent, dict):
        raise WazuhValidationError("agent must be an object when present")
    agent_id = _optional_agent_field(agent, "id")
    agent_name = _optional_agent_field(agent, "name")

    data = alert.get("data")
    if not isinstance(data, dict):
        data = {}

    return SensorEvent(
        timestamp=timestamp,
        signature_id=rule_id,
        signature=description,
        severity=level,
        src_ip=_optional_ip(data, "srcip"),
        src_port=_optional_port(data, "srcport"),
        dest_ip=_optional_ip(data, "dstip"),
        dest_port=_optional_port(data, "dstport"),
        proto=_optional_protocol(data),
        raw_event=alert,
        sensor=SensorContext(
            source="wazuh",
            instance=source_instance,
            event_id=event_id,
            agent_id=agent_id,
            agent_name=agent_name,
        ),
    )
