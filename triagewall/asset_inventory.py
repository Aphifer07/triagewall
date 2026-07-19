"""Strict, restart-loaded asset inventory for exact-IP alert enrichment."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_INVENTORY_BYTES = 1024 * 1024
INVENTORY_VERSION = 1
CRITICALITIES = {"low", "medium", "high", "critical"}
PROTOCOLS = {"tcp", "udp"}
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOP_LEVEL_FIELDS = {"version", "assets"}
ASSET_FIELDS = {
    "hostname",
    "role",
    "ips",
    "criticality",
    "internet_facing",
    "exposed_ports",
}
PORT_FIELDS = {"protocol", "port"}


class AssetInventoryError(ValueError):
    """Raised when the configured inventory violates its contract."""


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used for hashes and storage."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _require_exact_fields(value: dict, expected: set[str], location: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing:
        raise AssetInventoryError(
            f"{location} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise AssetInventoryError(
            f"{location} contains unknown fields: {', '.join(sorted(unknown))}"
        )


def _require_identifier(value: Any, location: str) -> str:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise AssetInventoryError(
            f"{location} must be a safe 1-64 character identifier"
        )
    return value


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _validate_port(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssetInventoryError(f"{location} must be an object")
    _require_exact_fields(value, PORT_FIELDS, location)

    protocol = value["protocol"]
    if not isinstance(protocol, str) or protocol not in PROTOCOLS:
        raise AssetInventoryError(f"{location}.protocol must be tcp or udp")
    port = value["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise AssetInventoryError(f"{location}.port must be an integer from 1 to 65535")
    return {"protocol": protocol, "port": port}


def _validate_asset(value: Any, index: int) -> dict[str, Any]:
    location = f"assets[{index}]"
    if not isinstance(value, dict):
        raise AssetInventoryError(f"{location} must be an object")
    _require_exact_fields(value, ASSET_FIELDS, location)

    hostname = _require_identifier(value["hostname"], f"{location}.hostname")
    role = _require_identifier(value["role"], f"{location}.role")

    raw_ips = value["ips"]
    if not isinstance(raw_ips, list) or not raw_ips:
        raise AssetInventoryError(f"{location}.ips must be a non-empty array")
    normalized_ips = []
    local_ips = set()
    for ip_index, raw_ip in enumerate(raw_ips):
        if not isinstance(raw_ip, str):
            raise AssetInventoryError(f"{location}.ips[{ip_index}] must be an IP string")
        try:
            normalized = str(ipaddress.ip_address(raw_ip))
        except ValueError as exc:
            raise AssetInventoryError(
                f"{location}.ips[{ip_index}] is not a valid IPv4 or IPv6 address"
            ) from exc
        if normalized in local_ips:
            raise AssetInventoryError(f"{location}.ips contains duplicate IP {normalized}")
        local_ips.add(normalized)
        normalized_ips.append(normalized)

    criticality = value["criticality"]
    if not isinstance(criticality, str) or criticality not in CRITICALITIES:
        raise AssetInventoryError(
            f"{location}.criticality must be low, medium, high, or critical"
        )
    internet_facing = value["internet_facing"]
    if not isinstance(internet_facing, bool):
        raise AssetInventoryError(f"{location}.internet_facing must be a boolean")

    raw_ports = value["exposed_ports"]
    if not isinstance(raw_ports, list):
        raise AssetInventoryError(f"{location}.exposed_ports must be an array")
    ports = []
    port_pairs = set()
    for port_index, raw_port in enumerate(raw_ports):
        port = _validate_port(raw_port, f"{location}.exposed_ports[{port_index}]")
        pair = (port["protocol"], port["port"])
        if pair in port_pairs:
            raise AssetInventoryError(
                f"{location}.exposed_ports contains duplicate {pair[0]}/{pair[1]}"
            )
        port_pairs.add(pair)
        ports.append(port)

    return {
        "hostname": hostname,
        "role": role,
        "ips": sorted(normalized_ips, key=_ip_sort_key),
        "criticality": criticality,
        "internet_facing": internet_facing,
        "exposed_ports": sorted(ports, key=lambda item: (item["protocol"], item["port"])),
    }


@dataclass(frozen=True)
class AssetInventory:
    """Validated inventory plus an O(1) normalized-IP lookup."""

    version: int
    assets: tuple[dict[str, Any], ...]
    revision: str
    _by_ip: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: Path | str) -> "AssetInventory":
        inventory_path = Path(path)
        try:
            size = inventory_path.stat().st_size
        except FileNotFoundError as exc:
            raise AssetInventoryError(f"asset inventory not found: {inventory_path}") from exc
        except OSError as exc:
            raise AssetInventoryError(f"cannot stat asset inventory: {inventory_path}") from exc
        if size > MAX_INVENTORY_BYTES:
            raise AssetInventoryError(
                f"asset inventory exceeds the {MAX_INVENTORY_BYTES}-byte limit"
            )

        try:
            raw = inventory_path.read_bytes()
        except OSError as exc:
            raise AssetInventoryError(f"cannot read asset inventory: {inventory_path}") from exc
        if len(raw) > MAX_INVENTORY_BYTES:
            raise AssetInventoryError(
                f"asset inventory exceeds the {MAX_INVENTORY_BYTES}-byte limit"
            )
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AssetInventoryError("asset inventory must be valid UTF-8 JSON") from exc
        if not isinstance(document, dict):
            raise AssetInventoryError("asset inventory root must be an object")
        _require_exact_fields(document, TOP_LEVEL_FIELDS, "asset inventory")

        version = document["version"]
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != INVENTORY_VERSION
        ):
            raise AssetInventoryError(f"asset inventory version must be {INVENTORY_VERSION}")
        raw_assets = document["assets"]
        if not isinstance(raw_assets, list):
            raise AssetInventoryError("asset inventory assets must be an array")

        assets = tuple(_validate_asset(value, index) for index, value in enumerate(raw_assets))
        by_ip: dict[str, dict[str, Any]] = {}
        for asset in assets:
            for address in asset["ips"]:
                if address in by_ip:
                    raise AssetInventoryError(f"duplicate IP ownership for {address}")
                by_ip[address] = asset

        canonical_document = {"version": version, "assets": list(assets)}
        revision = "sha256:" + hashlib.sha256(
            canonical_json(canonical_document).encode("utf-8")
        ).hexdigest()
        return cls(version=version, assets=assets, revision=revision, _by_ip=by_ip)

    @property
    def count(self) -> int:
        return len(self.assets)

    def resolve(self, value: Any) -> dict[str, Any] | None:
        """Resolve one IPv4/IPv6 value exactly, returning a detached snapshot."""
        if not isinstance(value, str):
            return None
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            return None
        asset = self._by_ip.get(normalized)
        if asset is None:
            return None
        snapshot = json.loads(canonical_json(asset))
        snapshot["inventory_revision"] = self.revision
        return snapshot

    def resolve_alert(self, alert: dict[str, Any]) -> dict[str, dict[str, Any] | None]:
        """Resolve the alert source and destination independently."""
        return {
            "source": self.resolve(alert.get("src_ip")),
            "destination": self.resolve(alert.get("dest_ip")),
        }


def configured_inventory_path() -> Path:
    """Return the process-start inventory path."""
    default = Path(__file__).parent / "config" / "assets.example.json"
    return Path(os.environ.get("ASSET_INVENTORY_PATH", str(default)))


def load_configured_inventory() -> AssetInventory:
    """Load the configured inventory exactly once at caller startup."""
    return AssetInventory.load(configured_inventory_path())
