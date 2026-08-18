#!/usr/bin/env python3
"""Guided API-key provisioning regressions."""

from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts import generate_api_key
from triagewall.dashboard.api.auth import lookup_api_key, parse_api_keys


class GenerateApiKeyTests(unittest.TestCase):
    def test_default_record_is_a_parseable_config_administrator(self):
        material = generate_api_key.generate_key_material(
            plaintext="fixed-test-key",
            salt=b"s" * 16,
        )

        records = parse_api_keys(material.record)
        self.assertEqual(records[0].name, "config-admin")
        self.assertEqual(records[0].scopes, frozenset({"config:write"}))
        self.assertIsNotNone(lookup_api_key(records, "fixed-test-key"))
        self.assertIsNone(lookup_api_key(records, "wrong-key"))
        self.assertNotIn("fixed-test-key", material.record)

    def test_env_assignment_is_single_quoted_for_compose(self):
        material = generate_api_key.generate_key_material(
            plaintext="fixed-test-key",
            salt=b"s" * 16,
        )
        assignment = generate_api_key.compose_env_assignment(material.record)

        self.assertEqual(
            assignment,
            f"TRIAGEWALL_API_KEYS='{material.record}'",
        )
        self.assertIn("$210000$", assignment)
        self.assertNotIn("fixed-test-key", assignment)

    def test_name_and_scopes_are_strictly_validated(self):
        for name in ("", "bad name", "bad:name", "bad,name", "x" * 65):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    generate_api_key.generate_key_material(
                        name=name,
                        plaintext="fixed-test-key",
                        salt=b"s" * 16,
                    )

        for scopes in ((), ("admin",), ("config:write", "config:write")):
            with self.subTest(scopes=scopes):
                with self.assertRaises(ValueError):
                    generate_api_key.generate_key_material(
                        scopes=scopes,
                        plaintext="fixed-test-key",
                        salt=b"s" * 16,
                    )

    def test_cli_prints_one_time_key_record_and_safe_env_line(self):
        output = io.StringIO()
        with patch.object(
            generate_api_key.secrets,
            "token_urlsafe",
            return_value="generated-plaintext-key",
        ), patch.object(
            generate_api_key.secrets,
            "token_bytes",
            return_value=b"s" * 16,
        ), redirect_stdout(output):
            self.assertEqual(generate_api_key.main([]), 0)

        rendered = output.getvalue()
        self.assertEqual(rendered.count("generated-plaintext-key"), 1)
        self.assertIn("API key record to append", rendered)
        self.assertIn("TRIAGEWALL_API_KEYS='config-admin:", rendered)
        self.assertIn("TRIAGEWALL_CONFIG_WRITES_ENABLED=true", rendered)

    def test_script_runs_with_only_the_python_standard_library(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-S",
                str(PROJECT_ROOT / "scripts" / "generate_api_key.py"),
                "--name",
                "headless-admin",
            ],
            cwd=PROJECT_ROOT.parent,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("headless-admin:pbkdf2_sha256$210000$", completed.stdout)
        self.assertIn("TRIAGEWALL_API_KEYS='headless-admin:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
