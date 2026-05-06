#!/usr/bin/env python3
"""
Triage agent v0 — single-alert classifier.

Reads Suricata alerts from a fixtures file (one JSON per line),
sends each to a local Ollama model with a SOC-analyst system prompt,
parses the verdict, and writes a row to triage.db.

Usage:
    python3 src/triage.py tests/fixtures/suricata_samples.json
"""
import os
import sys
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
import urllib.request
import urllib.error

# --- Config ---
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_URL = f"{OLLAMA_HOST.rstrip('/')}/api/generate"
MODEL = os.environ.get("OLLAMA_MODEL", "gemma4:e4b")
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or str(Path(__file__).parent.parent / "triage.db")
)
REQUEST_TIMEOUT = 120  # seconds
INTERNAL_SUBNETS = os.environ.get("INTERNAL_SUBNETS", "10.0.0.0/24 and 192.168.1.0/24")

SYSTEM_PROMPT = f"""You are a SOC analyst classifying Suricata IDS alerts.

Network facts:
- Internal subnets: {INTERNAL_SUBNETS}
- Multicast addresses (224.0.0.0/4) are not endpoints

Your job: examine each alert and decide if it warrants investigation.

For each alert, analyze:
1. Source and destination IPs (internal vs external?)
2. The signature category (DOS, INFO, USER_AGENTS, MALWARE, etc.)
3. Whether the traffic pattern matches the rule's intent or is incidental

Output strict JSON with this exact structure (no other text):
   {{
     "verdict": "real" | "false_positive" | "uncertain",
     "confidence": 0.0-1.0,
     "reasoning": "1-2 sentences. State what specific elements suggest real and what suggest benign before giving the verdict."
   }}

Verdict guidance:
- "real" = something an analyst should actually look at
- "false_positive" = the rule fired on traffic that does not match its intent
- "uncertain" = genuinely ambiguous; could go either way

Be honest about uncertainty. Do not default to false_positive when you lack context."""

PREFILTER_CONFIG_PATH = Path(__file__).parent / "config" / "prefilter.json"

def load_prefilter():
    """Load the prefilter config. Returns dict mapping signature_id -> reason string."""
    if not PREFILTER_CONFIG_PATH.exists():
        return {}
    config = json.loads(PREFILTER_CONFIG_PATH.read_text())
    sid_to_reason = {}
    for rule in config.get("auto_false_positive", []):
        for sid in rule.get("signature_ids", []):
            sid_to_reason[sid] = rule.get("reason", "Auto-classified as false_positive")
    return sid_to_reason

PREFILTER_SIDS = load_prefilter()
print(f"[triage] Loaded prefilter for SIDs: {sorted(PREFILTER_SIDS.keys())}", flush=True)


def prefilter_verdict(alert):
    """Return a verdict dict if the alert matches a prefilter rule, else None."""
    sid = alert.get("alert", {}).get("signature_id")
    if sid in PREFILTER_SIDS:
        return {
            "verdict": "false_positive",
            "confidence": 0.99,
            "reasoning": PREFILTER_SIDS[sid],
            "model_used": "prefilter",
        }
    return None

def call_ollama(alert: dict) -> dict:
    """Send one alert to Ollama, return parsed verdict dict. Falls through to prefilter for known-noise signatures"""
    pre = prefilter_verdict(alert)
    if pre is not None:
        return pre
    user_prompt = f"Classify this Suricata alert:\n\n{json.dumps(alert, indent=2)}"

    payload = {
        "model": MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",  # forces structured JSON output
        "options": {"temperature": 0.2, "num_predict": 250},
    }

    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    raw_response = body.get("response", "").strip()
    try:
        verdict = json.loads(raw_response)
    except json.JSONDecodeError:
        verdict = {"verdict": "uncertain", "confidence": 0.0,
                   "reasoning": f"Failed to parse model output: {raw_response[:200]}"}

    # Normalize/validate
    if verdict.get("verdict") not in ("false_positive", "real", "uncertain"):
        verdict["verdict"] = "uncertain"
    try:
        verdict["confidence"] = max(0.0, min(1.0, float(verdict.get("confidence", 0.0))))
    except (TypeError, ValueError):
        verdict["confidence"] = 0.0
    verdict["reasoning"] = str(verdict.get("reasoning", ""))[:1000]
    return verdict


def insert_triage_row(conn: sqlite3.Connection, alert: dict, verdict: dict) -> None:
    """Insert one alert + its verdict into triage_events."""
    a = alert.get("alert", {})
    conn.execute(
        """INSERT INTO triage_events (
            timestamp, flow_id, src_ip, src_port, dest_ip, dest_port, proto,
            in_iface, pkt_src, signature_id, signature, category, severity, action,
            raw_alert, verdict, confidence, reasoning, model_used, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert.get("timestamp"),
            alert.get("flow_id"),
            alert.get("src_ip"),
            alert.get("src_port"),
            alert.get("dest_ip"),
            alert.get("dest_port"),
            alert.get("proto"),
            alert.get("in_iface"),
            alert.get("pkt_src"),
            a.get("signature_id"),
            a.get("signature"),
            a.get("category"),
            a.get("severity"),
            a.get("action"),
            json.dumps(alert),
            verdict["verdict"],
            verdict["confidence"],
            verdict["reasoning"],
            verdict.get("model_used", MODEL),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()


def main(fixture_path: str) -> None:
    if not DB_PATH.exists():
        print(f"ERROR: {DB_PATH} not found. Run schema setup first.", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    alerts = []
    with open(fixture_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Skipping unparseable line: {e}", file=sys.stderr)

    print(f"Triaging {len(alerts)} alerts using {MODEL}...\n")
    counts = {"real": 0, "false_positive": 0, "uncertain": 0, "errors": 0}
    start = time.time()

    for i, alert in enumerate(alerts, 1):
        sig = alert.get("alert", {}).get("signature", "?")
        try:
            verdict = call_ollama(alert)
            insert_triage_row(conn, alert, verdict)
            counts[verdict["verdict"]] += 1
            v = verdict["verdict"].ljust(15)
            c = f"{verdict['confidence']:.2f}"
            print(f"[{i:>3}/{len(alerts)}] {v} {c}  {sig[:70]}")
        except urllib.error.URLError as e:
            counts["errors"] += 1
            print(f"[{i:>3}/{len(alerts)}] ERROR (Ollama unreachable): {e}", file=sys.stderr)
        except Exception as e:
            counts["errors"] += 1
            print(f"[{i:>3}/{len(alerts)}] ERROR: {type(e).__name__}: {e}", file=sys.stderr)

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.1f}s ({elapsed/max(len(alerts),1):.1f}s/alert)")
    print(f"Verdicts: real={counts['real']}  false_positive={counts['false_positive']}  "
          f"uncertain={counts['uncertain']}  errors={counts['errors']}")
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 src/triage.py <fixtures_file>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
