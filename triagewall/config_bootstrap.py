#!/usr/bin/env python3
"""Serialized one-shot bootstrap for durable operator configuration."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from operator_config import bootstrap_operator_configuration


ROOT = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", "/var/lib/triagewall/triage.db")
PACKAGED_PREFILTER_PATH = os.environ.get(
    "PACKAGED_PREFILTER_PATH",
    str(ROOT / "defaults" / "prefilter.json"),
)
LEGACY_PREFILTER_PATH = os.environ.get(
    "LEGACY_PREFILTER_PATH",
    str(ROOT / "config" / "prefilter.json"),
)
ASSET_INVENTORY_PATH = os.environ.get(
    "ASSET_INVENTORY_PATH",
    str(ROOT / "config" / "assets.example.json"),
)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    log = logging.getLogger("triagewall.config_bootstrap")
    log.info("Operator configuration bootstrap starting")
    result = bootstrap_operator_configuration(
        DB_PATH,
        packaged_prefilter_path=PACKAGED_PREFILTER_PATH,
        legacy_prefilter_path=LEGACY_PREFILTER_PATH,
        asset_inventory_path=ASSET_INVENTORY_PATH,
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
