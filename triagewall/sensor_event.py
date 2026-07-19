"""Source-neutral event representation used by ingest and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


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
    """Map the current Suricata JSON contract to the shared representation."""
    metadata = alert.get("alert")
    if not isinstance(metadata, Mapping):
        metadata = {}
    return SensorEvent(
        timestamp=alert.get("timestamp"),
        flow_id=alert.get("flow_id"),
        src_ip=alert.get("src_ip"),
        src_port=alert.get("src_port"),
        dest_ip=alert.get("dest_ip"),
        dest_port=alert.get("dest_port"),
        proto=alert.get("proto"),
        in_iface=alert.get("in_iface"),
        pkt_src=alert.get("pkt_src"),
        signature_id=metadata.get("signature_id"),
        signature=metadata.get("signature"),
        category=metadata.get("category"),
        severity=metadata.get("severity"),
        action=metadata.get("action"),
        raw_event=alert,
        sensor=SensorContext(source="suricata"),
    )
