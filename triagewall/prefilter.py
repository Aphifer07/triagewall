"""Validated, context-aware prefilter policy matching."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re

try:
    from .asset_inventory import is_valid_asset_snapshot
except ImportError:  # Direct script-style imports used by ingest entrypoints.
    from asset_inventory import is_valid_asset_snapshot


MAX_CONFIG_BYTES = 1024 * 1024
MAX_RULES = 512
MAX_VALUES = 256
MAX_REASON_LENGTH = 4096

NETWORK_DIRECTIONS = frozenset({
    "internal_to_internal",
    "internal_to_external",
    "external_to_internal",
    "external_to_external",
})
FLOW_DIRECTIONS = frozenset({"to_server", "to_client"})
PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6"})
CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PrefilterConfigError(ValueError):
    """Raised when a prefilter configuration is unsafe or malformed."""


def _require_object(value, label):
    if not isinstance(value, dict):
        raise PrefilterConfigError(f"{label} must be an object")
    return value


def _reject_unknown_fields(value, allowed, label):
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise PrefilterConfigError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _require_list(value, label, *, allow_empty=False, max_items=MAX_VALUES):
    if not isinstance(value, list):
        raise PrefilterConfigError(f"{label} must be an array")
    if not allow_empty and not value:
        raise PrefilterConfigError(f"{label} must not be empty")
    if len(value) > max_items:
        raise PrefilterConfigError(f"{label} exceeds the {max_items}-item limit")
    return value


def _unique(values, label):
    if len(values) != len(set(values)):
        raise PrefilterConfigError(f"{label} contains duplicate values")
    return tuple(values)


def _string_list(value, label, allowed=None, *, identifiers=False):
    items = _require_list(value, label)
    normalized = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise PrefilterConfigError(f"{label}[{index}] must be a string")
        item = item.lower()
        if allowed is not None and item not in allowed:
            raise PrefilterConfigError(f"{label}[{index}] has unsupported value {item!r}")
        if identifiers and not IDENTIFIER_RE.fullmatch(item):
            raise PrefilterConfigError(f"{label}[{index}] is not a safe identifier")
        normalized.append(item)
    return _unique(normalized, label)


def _integer_list(value, label, *, minimum, maximum):
    items = _require_list(value, label)
    normalized = []
    for index, item in enumerate(items):
        if isinstance(item, bool) or not isinstance(item, int):
            raise PrefilterConfigError(f"{label}[{index}] must be an integer")
        if not minimum <= item <= maximum:
            raise PrefilterConfigError(
                f"{label}[{index}] must be between {minimum} and {maximum}"
            )
        normalized.append(item)
    return _unique(normalized, label)


def _network_list(value, label, *, allow_empty=False):
    items = _require_list(value, label, allow_empty=allow_empty)
    networks = []
    canonical = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise PrefilterConfigError(f"{label}[{index}] must be a CIDR string")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise PrefilterConfigError(f"{label}[{index}] is not a canonical CIDR") from exc
        networks.append(network)
        canonical.append(str(network))
    _unique(canonical, label)
    return tuple(networks)


@dataclass(frozen=True)
class AssetSelector:
    matched: bool | None = None
    hostnames: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    criticalities: tuple[str, ...] = ()
    internet_facing: bool | None = None

    def matches(self, asset):
        if asset is not None and not is_valid_asset_snapshot(asset):
            return False
        is_matched = asset is not None
        if self.matched is not None and is_matched != self.matched:
            return False
        if not is_matched:
            return not (
                self.hostnames
                or self.roles
                or self.criticalities
                or self.internet_facing is not None
            )
        if self.hostnames:
            hostname = asset.get("hostname")
            if not isinstance(hostname, str) or hostname.lower() not in self.hostnames:
                return False
        if self.roles:
            role = asset.get("role")
            if not isinstance(role, str) or role.lower() not in self.roles:
                return False
        if self.criticalities and asset.get("criticality") not in self.criticalities:
            return False
        if (
            self.internet_facing is not None
            and asset.get("internet_facing") is not self.internet_facing
        ):
            return False
        return True


def _parse_asset_selector(value, label):
    value = _require_object(value, label)
    allowed = {"matched", "hostnames", "roles", "criticalities", "internet_facing"}
    _reject_unknown_fields(value, allowed, label)
    if not value:
        raise PrefilterConfigError(f"{label} must contain at least one condition")

    for field in ("matched", "internet_facing"):
        if field in value and not isinstance(value[field], bool):
            raise PrefilterConfigError(f"{label}.{field} must be a boolean")

    selector = AssetSelector(
        matched=value.get("matched"),
        hostnames=_string_list(value["hostnames"], f"{label}.hostnames", identifiers=True)
        if "hostnames" in value else (),
        roles=_string_list(value["roles"], f"{label}.roles", identifiers=True)
        if "roles" in value else (),
        criticalities=_string_list(
            value["criticalities"], f"{label}.criticalities", CRITICALITIES
        ) if "criticalities" in value else (),
        internet_facing=value.get("internet_facing"),
    )
    if selector.matched is False and len(value) != 1:
        raise PrefilterConfigError(f"{label}.matched=false cannot be combined with asset fields")
    return selector


@dataclass(frozen=True)
class RuleMatch:
    network_directions: tuple[str, ...] = ()
    flow_directions: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    source_ports: tuple[int, ...] = ()
    destination_ports: tuple[int, ...] = ()
    source_cidrs: tuple = ()
    destination_cidrs: tuple = ()
    source_asset: AssetSelector | None = None
    destination_asset: AssetSelector | None = None

    def matches(self, alert, asset_context, internal_cidrs):
        if self.flow_directions:
            direction = alert.get("direction")
            if not isinstance(direction, str) or direction.lower() not in self.flow_directions:
                return False

        if self.protocols:
            protocol = alert.get("proto")
            if not isinstance(protocol, str) or protocol.lower() not in self.protocols:
                return False

        if self.source_ports and not _alert_port_matches(alert.get("src_port"), self.source_ports):
            return False
        if self.destination_ports and not _alert_port_matches(
            alert.get("dest_port"), self.destination_ports
        ):
            return False

        source_ip = _alert_ip(alert.get("src_ip"))
        destination_ip = _alert_ip(alert.get("dest_ip"))
        if self.source_cidrs and not _ip_in_networks(source_ip, self.source_cidrs):
            return False
        if self.destination_cidrs and not _ip_in_networks(destination_ip, self.destination_cidrs):
            return False

        if self.network_directions:
            if source_ip is None or destination_ip is None:
                return False
            source_internal = _ip_in_networks(source_ip, internal_cidrs)
            destination_internal = _ip_in_networks(destination_ip, internal_cidrs)
            network_direction = (
                ("internal" if source_internal else "external")
                + "_to_"
                + ("internal" if destination_internal else "external")
            )
            if network_direction not in self.network_directions:
                return False

        if self.source_asset or self.destination_asset:
            if not isinstance(asset_context, dict):
                return False
            if self.source_asset:
                if "source" not in asset_context or not self.source_asset.matches(
                    asset_context["source"]
                ):
                    return False
            if self.destination_asset:
                if "destination" not in asset_context or not self.destination_asset.matches(
                    asset_context["destination"]
                ):
                    return False
        return True


def _alert_port_matches(value, allowed):
    return isinstance(value, int) and not isinstance(value, bool) and value in allowed


def _alert_ip(value):
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _ip_in_networks(address, networks):
    if address is None:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _parse_match(value, label, internal_cidrs):
    value = _require_object(value, label)
    allowed = {
        "network_directions", "flow_directions", "protocols",
        "source_ports", "destination_ports", "source_cidrs", "destination_cidrs",
        "source_asset", "destination_asset",
    }
    _reject_unknown_fields(value, allowed, label)
    if not value:
        raise PrefilterConfigError(f"{label} must contain at least one condition")
    network_directions = _string_list(
        value["network_directions"], f"{label}.network_directions", NETWORK_DIRECTIONS
    ) if "network_directions" in value else ()
    if network_directions and not internal_cidrs:
        raise PrefilterConfigError(
            f"{label}.network_directions requires at least one top-level internal_cidr"
        )
    return RuleMatch(
        network_directions=network_directions,
        flow_directions=_string_list(
            value["flow_directions"], f"{label}.flow_directions", FLOW_DIRECTIONS
        ) if "flow_directions" in value else (),
        protocols=_string_list(value["protocols"], f"{label}.protocols", PROTOCOLS)
        if "protocols" in value else (),
        source_ports=_integer_list(
            value["source_ports"], f"{label}.source_ports", minimum=1, maximum=65535
        ) if "source_ports" in value else (),
        destination_ports=_integer_list(
            value["destination_ports"], f"{label}.destination_ports", minimum=1, maximum=65535
        ) if "destination_ports" in value else (),
        source_cidrs=_network_list(value["source_cidrs"], f"{label}.source_cidrs")
        if "source_cidrs" in value else (),
        destination_cidrs=_network_list(
            value["destination_cidrs"], f"{label}.destination_cidrs"
        ) if "destination_cidrs" in value else (),
        source_asset=_parse_asset_selector(value["source_asset"], f"{label}.source_asset")
        if "source_asset" in value else None,
        destination_asset=_parse_asset_selector(
            value["destination_asset"], f"{label}.destination_asset"
        ) if "destination_asset" in value else None,
    )


def _asset_selector_document(selector):
    document = {}
    if selector.matched is not None:
        document["matched"] = selector.matched
    if selector.hostnames:
        document["hostnames"] = list(selector.hostnames)
    if selector.roles:
        document["roles"] = list(selector.roles)
    if selector.criticalities:
        document["criticalities"] = list(selector.criticalities)
    if selector.internet_facing is not None:
        document["internet_facing"] = selector.internet_facing
    return document


def _rule_match_document(match):
    document = {}
    if match.network_directions:
        document["network_directions"] = list(match.network_directions)
    if match.flow_directions:
        document["flow_directions"] = list(match.flow_directions)
    if match.protocols:
        document["protocols"] = list(match.protocols)
    if match.source_ports:
        document["source_ports"] = list(match.source_ports)
    if match.destination_ports:
        document["destination_ports"] = list(match.destination_ports)
    if match.source_cidrs:
        document["source_cidrs"] = [str(value) for value in match.source_cidrs]
    if match.destination_cidrs:
        document["destination_cidrs"] = [
            str(value) for value in match.destination_cidrs
        ]
    if match.source_asset is not None:
        document["source_asset"] = _asset_selector_document(match.source_asset)
    if match.destination_asset is not None:
        document["destination_asset"] = _asset_selector_document(
            match.destination_asset
        )
    return document


@dataclass(frozen=True)
class PrefilterRule:
    signature_ids: tuple[int, ...]
    reason: str
    match: RuleMatch | None = None


@dataclass(frozen=True)
class PrefilterPolicy:
    internal_cidrs: tuple
    rules: tuple[PrefilterRule, ...]
    rules_by_sid: dict

    @classmethod
    def empty(cls):
        return cls((), (), {})

    @classmethod
    def load(cls, path):
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PrefilterConfigError(f"cannot read prefilter config {path}: {exc}") from exc
        if size > MAX_CONFIG_BYTES:
            raise PrefilterConfigError("prefilter config exceeds the 1 MiB size limit")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PrefilterConfigError(f"cannot read prefilter config {path}: {exc}") from exc
        if len(raw) > MAX_CONFIG_BYTES:
            raise PrefilterConfigError("prefilter config exceeds the 1 MiB size limit")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrefilterConfigError(f"cannot parse prefilter config {path}: {exc}") from exc
        return cls.from_document(document)

    @classmethod
    def from_document(cls, document):
        document = _require_object(document, "prefilter config")
        version = document.get("version")
        if version is None:
            _reject_unknown_fields(document, {"auto_false_positive"}, "prefilter config")
            internal_cidrs = ()
        else:
            if isinstance(version, bool) or version != 1:
                raise PrefilterConfigError("prefilter config.version must be 1")
            _reject_unknown_fields(
                document, {"version", "internal_cidrs", "auto_false_positive"}, "prefilter config"
            )
            if "internal_cidrs" not in document:
                raise PrefilterConfigError("prefilter config.internal_cidrs is required")
            internal_cidrs = _network_list(
                document["internal_cidrs"], "prefilter config.internal_cidrs", allow_empty=True
            )

        if "auto_false_positive" not in document:
            raise PrefilterConfigError("prefilter config.auto_false_positive is required")
        rule_documents = _require_list(
            document["auto_false_positive"], "prefilter config.auto_false_positive",
            allow_empty=True, max_items=MAX_RULES,
        )
        if len(rule_documents) > MAX_RULES:
            raise PrefilterConfigError(f"prefilter config exceeds the {MAX_RULES}-rule limit")

        rules = []
        rules_by_sid = {}
        for index, rule_document in enumerate(rule_documents):
            label = f"prefilter config.auto_false_positive[{index}]"
            rule_document = _require_object(rule_document, label)
            allowed = {"signature_ids", "reason"} if version is None else {
                "signature_ids", "reason", "match"
            }
            _reject_unknown_fields(rule_document, allowed, label)
            for required in ("signature_ids", "reason"):
                if required not in rule_document:
                    raise PrefilterConfigError(f"{label}.{required} is required")
            signature_ids = _integer_list(
                rule_document["signature_ids"], f"{label}.signature_ids",
                minimum=1, maximum=2147483647,
            )
            reason = rule_document["reason"]
            if not isinstance(reason, str) or not reason.strip():
                raise PrefilterConfigError(f"{label}.reason must be a non-empty string")
            if len(reason) > MAX_REASON_LENGTH:
                raise PrefilterConfigError(
                    f"{label}.reason exceeds the {MAX_REASON_LENGTH}-character limit"
                )
            match = (
                _parse_match(rule_document["match"], f"{label}.match", internal_cidrs)
                if "match" in rule_document
                else None
            )
            rule = PrefilterRule(signature_ids, reason, match)
            rules.append(rule)
            for sid in signature_ids:
                rules_by_sid.setdefault(sid, []).append(rule)

        return cls(
            internal_cidrs,
            tuple(rules),
            {sid: tuple(sid_rules) for sid, sid_rules in rules_by_sid.items()},
        )

    @property
    def signature_ids(self):
        return frozenset(self.rules_by_sid)

    def to_document(self):
        """Return the normalized, versioned policy represented by this object."""
        rules = []
        for rule in self.rules:
            document = {
                "signature_ids": list(rule.signature_ids),
                "reason": rule.reason,
            }
            if rule.match is not None:
                document["match"] = _rule_match_document(rule.match)
            rules.append(document)
        return {
            "version": 1,
            "internal_cidrs": [str(value) for value in self.internal_cidrs],
            "auto_false_positive": rules,
        }

    def match_reason(self, alert, asset_context=None):
        if not isinstance(alert, dict):
            return None
        alert_metadata = alert.get("alert")
        if not isinstance(alert_metadata, dict):
            return None
        sid = alert_metadata.get("signature_id")
        if isinstance(sid, bool) or not isinstance(sid, int):
            return None
        for rule in self.rules_by_sid.get(sid, ()):
            if rule.match is None or rule.match.matches(alert, asset_context, self.internal_cidrs):
                return rule.reason
        return None
