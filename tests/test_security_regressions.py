#!/usr/bin/env python3
"""Focused regressions for the 2026-07-17 security report."""

import io
import csv
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import field_isolation
import ingest
import triage
from scripts import benchmark_quants
from fastapi.testclient import TestClient
from triagewall.dashboard import app as dashboard


class _OllamaResponse:
    def __init__(self, raw_response):
        self._body = json.dumps({"response": raw_response}).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class PromptBoundaryTests(unittest.TestCase):
    def test_wire_method_and_primitive_array_elements_are_isolated(self):
        rendered = json.loads(field_isolation.format_alert_for_llm({
            "http": {"http_method": "GET"},
            "tls": {"client_alpns": ["h2", "http/1.1"]},
            "alert": {"severity": 2, "metadata": {"confidence": ["High"]}},
        }))

        self.assertIn("UNTRUSTED FIELD [http.http_method]", rendered["http"]["http_method"])
        self.assertIn("UNTRUSTED FIELD [tls.client_alpns.0]", rendered["tls"]["client_alpns"][0])
        self.assertIn("UNTRUSTED FIELD [tls.client_alpns.1]", rendered["tls"]["client_alpns"][1])
        self.assertEqual(rendered["alert"]["severity"], 2)
        self.assertEqual(rendered["alert"]["metadata"]["confidence"], ["High"])

    def _call_with_response(self, raw_response):
        alert = {"event_type": "alert", "alert": {"signature_id": 999999}}
        with patch.object(
            triage.urllib.request,
            "urlopen",
            return_value=_OllamaResponse(raw_response),
        ), patch.object(triage, "OLLAMA_URL", "http://ollama.test/api/generate"):
            return triage.call_ollama(alert)

    def test_malformed_model_json_is_not_salvaged(self):
        verdict = self._call_with_response(
            '{"verdict":"false_positive","confidence":0.99,"reasoning":"truncated'
        )
        self.assertEqual(verdict["verdict"], "uncertain")
        self.assertEqual(verdict["confidence"], 0.0)

    def test_json_escaped_canary_is_detected_after_decode(self):
        escaped_canary = triage.CANARY_TOKEN.replace("C", "\\u0043", 1)
        verdict = self._call_with_response(
            json.dumps({
                "verdict": "false_positive",
                "confidence": 0.99,
                "reasoning": escaped_canary,
            }).replace("\\\\u0043", "\\u0043")
        )
        self.assertEqual(verdict["verdict"], "real")
        self.assertIn("Prompt injection", verdict["reasoning"])

    def test_non_object_model_json_is_rejected(self):
        verdict = self._call_with_response('["false_positive", 0.99]')
        self.assertEqual(verdict["verdict"], "uncertain")
        self.assertEqual(verdict["confidence"], 0.0)

    def test_schema_valid_model_json_remains_accepted(self):
        verdict = self._call_with_response(json.dumps({
            "verdict": "real",
            "confidence": 0.75,
            "reasoning": "Signature evidence supports escalation.",
        }))
        self.assertEqual(verdict["verdict"], "real")
        self.assertEqual(verdict["confidence"], 0.75)


class IngestDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())

    def tearDown(self):
        self.conn.close()

    def test_non_object_json_is_durably_quarantined(self):
        self.assertFalse(ingest.process_line(self.conn, '[{"event_type":"alert"}]'))
        row = self.conn.execute(
            "SELECT raw_line, error FROM ingest_failures"
        ).fetchone()
        self.assertEqual(row[0], '[{"event_type":"alert"}]')
        self.assertIn("object", row[1])

    def test_invalid_alert_metadata_is_durably_quarantined(self):
        raw = '{"event_type":"alert","alert":[]}'
        self.assertFalse(ingest.process_line(self.conn, raw))
        row = self.conn.execute(
            "SELECT raw_line, error FROM ingest_failures"
        ).fetchone()
        self.assertEqual(row[0], raw)
        self.assertIn("metadata", row[1])

    def test_unterminated_record_is_not_complete_until_newline_arrives(self):
        stream = io.StringIO('{"event_type":"alert"}')
        line = stream.readline()
        self.assertFalse(ingest._line_is_complete(line))

        stream.seek(0, io.SEEK_END)
        stream.write("\n")
        stream.seek(0)
        self.assertTrue(ingest._line_is_complete(stream.readline()))


class DashboardBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "triage.db"
        conn = sqlite3.connect(self.db_path)
        conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        conn.execute(
            """
            INSERT INTO triage_events (
                timestamp, signature_id, signature, raw_alert, verdict,
                confidence, reasoning, model_used, processed_at, human_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-07-18T12:00:00+00:00", 1, "Test", "{}", "real",
                0.9, "private model reasoning", "test", "2026-07-18T12:00:00+00:00",
                "private analyst note",
            ),
        )
        conn.execute(
            """
            CREATE TABLE spc_anomalies (
                id INTEGER PRIMARY KEY, detected_at TEXT, feature TEXT, ip TEXT,
                signature_id INTEGER, z REAL, note TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO spc_anomalies VALUES (1, ?, ?, ?, ?, ?, ?)",
            ("2026-07-18T12:00:00+00:00", "novel_sid", "192.168.1.44", 1, 4.2,
             "192.168.1.44 triggered a private rule"),
        )
        conn.commit()
        conn.close()

        self.old_db_path = dashboard.DB_PATH
        self.old_mode = dashboard.MODE
        dashboard.DB_PATH = self.db_path
        dashboard.MODE = "local"
        dashboard._stats_cache.update(data=None, ts=0.0)
        dashboard._spc_cache.update(data=None, ts=0.0)
        self.client = TestClient(dashboard.app)

    def tearDown(self):
        dashboard.DB_PATH = self.old_db_path
        dashboard.MODE = self.old_mode
        dashboard._stats_cache.update(data=None, ts=0.0)
        dashboard._spc_cache.update(data=None, ts=0.0)
        self.temp_dir.cleanup()

    def test_rebinding_style_host_is_rejected_for_read_and_write_routes(self):
        for method, path, kwargs in (
            ("get", "/api/verdicts", {}),
            ("post", "/api/feedback/1", {"json": {"human_verdict": "real"}}),
            ("get", "/api/spc-anomalies", {}),
        ):
            response = getattr(self.client, method)(
                path, headers={"host": "attacker.example"}, **kwargs
            )
            self.assertEqual(response.status_code, 400, path)

        local_response = self.client.get(
            "/api/verdicts", headers={"host": "localhost"}
        )
        self.assertEqual(local_response.status_code, 200)
        self.assertEqual(
            local_response.json()["verdicts"][0]["reasoning"],
            "private model reasoning",
        )
        self.assertEqual(
            self.client.get("/api/verdicts", headers={"host": "192.168.1.10:8084"}).status_code,
            200,
        )
        feedback = self.client.post(
            "/api/feedback/1",
            headers={"host": "localhost"},
            json={"human_verdict": "false_positive", "notes": "reviewed"},
        )
        self.assertEqual(feedback.status_code, 200)
        conn = sqlite3.connect(self.db_path)
        try:
            saved = conn.execute(
                "SELECT human_verdict, human_notes FROM triage_events WHERE id = 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(saved, ("false_positive", "reviewed"))
        for malformed in ("attacker.example@localhost", "localhost/path", " localhost"):
            self.assertEqual(
                self.client.get(
                    "/api/verdicts", headers={"host": malformed}
                ).status_code,
                400,
                malformed,
            )

    def test_demo_verdicts_mask_ips_and_remove_free_text(self):
        dashboard.MODE = "demo"
        payload = self.client.get(
            "/api/verdicts", headers={"host": "localhost"}
        ).json()["verdicts"][0]
        row = dashboard.row_to_dict({
            "src_ip": "192.168.1.44",
            "dest_ip": "10.2.3.4",
            "reasoning": "private model reasoning",
            "human_notes": "private analyst note",
            "raw_alert": "{}",
        })

        self.assertIsNone(payload["reasoning"])
        self.assertEqual(row["src_ip"], "192.168.x.x")
        self.assertEqual(row["dest_ip"], "10.x.x.x")
        self.assertIsNone(row["reasoning"])
        self.assertIsNone(row["human_notes"])
        self.assertIsNone(row["raw_alert"])

    def test_demo_spc_masks_ip_and_removes_note(self):
        dashboard.MODE = "demo"
        anomaly = self.client.get(
            "/api/spc-anomalies", headers={"host": "localhost"}
        ).json()["anomalies"][0]
        self.assertEqual(anomaly["ip"], "192.168.x.x")
        self.assertIsNone(anomaly["note"])


class BenchmarkExportTests(unittest.TestCase):
    def test_formula_capable_cells_are_neutralized(self):
        for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "\t=1+1", "\r=1+1"):
            self.assertTrue(
                benchmark_quants.sanitize_csv_cell(value).startswith("'"),
                value,
            )
        self.assertEqual(
            benchmark_quants.sanitize_csv_cell("ordinary reasoning"),
            "ordinary reasoning",
        )

    def test_benchmark_writer_uses_neutralized_reasoning(self):
        verdict = {
            "verdict": "real",
            "confidence": 0.9,
            "reasoning": "=HYPERLINK(\"https://attacker.invalid\")",
        }
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(
            benchmark_quants,
            "call_model",
            return_value=(verdict, 1.0, {}, None),
        ):
            path = benchmark_quants.benchmark_model(
                "test-model",
                [{"id": 1, "alert": {}, "human_verdict": "real"}],
                "http://ollama.test",
                Path(temp_dir),
                skip_existing=False,
            )
            with path.open(newline="") as handle:
                row = next(csv.DictReader(handle))
        self.assertTrue(row["reasoning"].startswith("'="))


if __name__ == "__main__":
    unittest.main(verbosity=2)
