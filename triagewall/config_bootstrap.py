#!/usr/bin/env python3
"""Serialized one-shot bootstrap for durable operator configuration."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from operator_config import bootstrap_operator_configuration


ROOT = Path(__file__).resolve().parent


def packaged_prefilter_path() -> str:
    """Resolve the immutable shipped baseline for this deployment.

    The container image keeps a copy under ``defaults`` that no operator mount
    can cover. A source checkout has no such copy, so the unmodified shipped
    file under ``config`` is the packaged baseline there.
    """
    configured = os.environ.get("PACKAGED_PREFILTER_PATH")
    if configured:
        return configured
    packaged = ROOT / "defaults" / "prefilter.json"
    if packaged.exists():
        return str(packaged)
    return str(ROOT / "config" / "prefilter.json")


def legacy_prefilter_path() -> str:
    return os.environ.get(
        "LEGACY_PREFILTER_PATH",
        str(ROOT / "config" / "prefilter.json"),
    )


def asset_inventory_path() -> str:
    return os.environ.get(
        "ASSET_INVENTORY_PATH",
        str(ROOT / "config" / "assets.example.json"),
    )


def database_path() -> str:
    return os.environ.get("DB_PATH", "/var/lib/triagewall/triage.db")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    log = logging.getLogger("triagewall.config_bootstrap")
    log.info("Operator configuration bootstrap starting")
    result = bootstrap_operator_configuration(
        database_path(),
        packaged_prefilter_path=packaged_prefilter_path(),
        legacy_prefilter_path=legacy_prefilter_path(),
        asset_inventory_path=asset_inventory_path(),
    )
    log.info(
        "Operator configuration bootstrap complete: generation=%s mode=%s initialized=%s "
        "shipped_discovered=%s prefilter=%s asset=%s",
        result.generation,
        result.mode,
        result.initialized,
        result.discovered_shipped_revision,
        result.active_prefilter_revision,
        result.active_asset_revision,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
