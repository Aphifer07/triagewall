"""Source-neutral event representation used by ingest and persistence."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from .time_utils import format_utc_timestamp
except ImportError:  # Direct script-style import used by ingest.py.
    from time_utils import format_utc_timestamp


MAX_SQLITE_INTEGER = (2**63) - 1
MAX_SIGNATURE_CHARS = 4096
MAX_RULE_TEXT_CHARS = 1024
PROTOCOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,31}$")


class SuricataValidationError(ValueError):
    """A complete Suricata alert cannot be safely normalized."""


def _required_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SuricataValidationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise SuricataValidationError(
            f"{label} must be an integer from {minimum} to {maximum}"
        )
    return value


def _optional_integer(
    value: Any,
    label: str,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    return _required_integer(value, label, minimum, maximum)


def _required_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SuricataValidationError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _optional_text(value: Any, label: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _required_text(value, label, maximum)


def _optional_ip(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SuricataValidationError(f"{label} must be an IP address string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise SuricataValidationError(
            f"{label} must be a valid IPv4 or IPv6 address"
        ) from exc


def _optional_protocol(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or PROTOCOL_RE.fullmatch(value) is None:
        raise SuricataValidationError(
            "proto must be a safe protocol identifier of at most 32 characters"
        )
    return value.upper()


@dataclass(frozen=True)
class SensorContext:
    """Stable provenance attached to one persisted verdict."""

    source: str
    instance: str | None = None
    event_id: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None


@dataclass(frozen=True)
class SensorEvent:
    """Fields shared by supported alert sources."""

    timestamp: str
    signature_id: int
    signature: str
    raw_event: Mapping[str, Any]
    sensor: SensorContext
    flow_id: int | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    in_iface: str | None = None
    pkt_src: str | None = None
    category: str | None = None
    severity: int | None = None
    action: str | None = None


def normalize_suricata_event(alert: Mapping[str, Any]) -> SensorEvent:
    """Validate and map one Suricata alert to the shared representation."""
    if not isinstance(alert, Mapping):
        raise SuricataValidationError("top-level JSON value must be an object")

    try:
        timestamp = format_utc_timestamp(alert.get("timestamp"))
    except (TypeError, ValueError) as exc:
        raise SuricataValidationError(
            f"invalid Suricata timestamp: {exc}"
        ) from exc

    metadata = alert.get("alert")
    if not isinstance(metadata, Mapping):
        raise SuricataValidationError("alert event metadata must be an object")

    return SensorEvent(
        timestamp=timestamp,
        flow_id=_optional_integer(
            alert.get("flow_id"),
            "flow_id",
            1,
            MAX_SQLITE_INTEGER,
        ),
        src_ip=_optional_ip(alert.get("src_ip"), "src_ip"),
        src_port=_optional_integer(alert.get("src_port"), "src_port", 0, 65535),
        dest_ip=_optional_ip(alert.get("dest_ip"), "dest_ip"),
        dest_port=_optional_integer(
            alert.get("dest_port"),
            "dest_port",
            0,
            65535,
        ),
        proto=_optional_protocol(alert.get("proto")),
        in_iface=_optional_text(
            alert.get("in_iface"),
            "in_iface",
            MAX_RULE_TEXT_CHARS,
        ),
        pkt_src=_optional_text(
            alert.get("pkt_src"),
            "pkt_src",
            MAX_RULE_TEXT_CHARS,
        ),
        signature_id=_required_integer(
            metadata.get("signature_id"),
            "alert.signature_id",
            1,
            MAX_SQLITE_INTEGER,
        ),
        signature=_required_text(
            metadata.get("signature"),
            "alert.signature",
            MAX_SIGNATURE_CHARS,
        ),
        category=_optional_text(
            metadata.get("category"),
            "alert.category",
            MAX_RULE_TEXT_CHARS,
        ),
        severity=_optional_integer(
            metadata.get("severity"),
            "alert.severity",
            1,
            255,
        ),
        action=_optional_text(
            metadata.get("action"),
            "alert.action",
            MAX_RULE_TEXT_CHARS,
        ),
        raw_event=alert,
        sensor=SensorContext(source="suricata"),
    )
