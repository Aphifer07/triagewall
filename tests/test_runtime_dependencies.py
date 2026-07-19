#!/usr/bin/env python3
"""Regression tests for the dashboard's reproducible runtime lock."""

import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_LOCK = PROJECT_ROOT / "triagewall" / "dashboard" / "requirements.txt"

EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[A-Za-z0-9._,-]+\])?=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)$"
)

EXPECTED_PACKAGES = {
    "annotated-doc",
    "annotated-types",
    "anyio",
    "click",
    "fastapi",
    "h11",
    "httptools",
    "idna",
    "pydantic",
    "pydantic-core",
    "python-dotenv",
    "pyyaml",
    "starlette",
    "typing-extensions",
    "typing-inspection",
    "uvicorn",
    "uvloop",
    "watchfiles",
    "websockets",
}


def normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class RuntimeDependencyLockTests(unittest.TestCase):
    def test_every_runtime_requirement_is_exactly_pinned(self):
        requirements = [
            line.strip()
            for line in RUNTIME_LOCK.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        parsed = []
        for requirement in requirements:
            match = EXACT_REQUIREMENT.fullmatch(requirement)
            self.assertIsNotNone(match, f"Runtime dependency is not exact: {requirement}")
            parsed.append(match)

        names = [normalized_name(match.group("name")) for match in parsed]
        self.assertEqual(len(names), len(set(names)), "Runtime lock has duplicate packages")
        self.assertEqual(set(names), EXPECTED_PACKAGES)

    def test_direct_runtime_dependencies_remain_explicit(self):
        lock_text = RUNTIME_LOCK.read_text()

        self.assertIn("fastapi==", lock_text)
        self.assertIn("uvicorn[standard]==", lock_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
