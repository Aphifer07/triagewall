#!/usr/bin/env python3
"""
Triagewall v0.2 model benchmark.

Evaluates multiple Ollama models against the human-labeled ground-truth set
in triage.db. Produces per-model CSVs and a summary markdown report.

Usage:
    python3 benchmark_quants.py                         # all models, all labeled alerts
    python3 benchmark_quants.py --limit 20              # smoke test first
    python3 benchmark_quants.py --models mistral:7b     # single model
    python3 benchmark_quants.py --no-resume             # restart from scratch

Environment overrides (or pass --ollama / --db / --out):
    OLLAMA_HOST  default http://10.0.1.100:11434
    DB_PATH      default /opt/axon-agents/triage-agent/data/triage.db
    OUT_DIR      default ./results/benchmark_<timestamp>
"""

import argparse
import csv
import json
import os
import sqlite3
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# --- Constants matching production triage.py ---

INTERNAL_SUBNETS = "10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24"
REQUEST_TIMEOUT = 600  # seconds

SYSTEM_PROMPT = f"""You are a SOC analyst classifying Suricata IDS alerts on a home network with a homelab. Be decisive and accurate. Hedge ("uncertain") only when you genuinely cannot tell.

# Network facts

- Internal subnets: {INTERNAL_SUBNETS}
- Anything else is external.
- Internal devices include: a home server with ~40 Docker containers (Wazuh, Pi-hole, Home Assistant, GitLab, etc.), a desktop PC, laptops, an LG smart TV, an Xbox, Ring cameras, mobile phones (iPhone, Android), and various IoT devices. The TV streams Netflix, YouTube, Disney+, etc.

# How to classify

Read the alert's signature, category, source/destination IPs, and any metadata. Then apply the rules below in order.

## Strong indicators of a real threat (default: "real", confidence 0.85+)

These signature categories and families have very low false-positive rates. Default to "real" unless you have specific evidence the alert is benign.

- ET DROP / EDROP (Spamhaus) — Spamhaus DROP/EDROP lists contain IPs Spamhaus has confirmed as part of cybercriminal infrastructure (botnets, malware hosting, spam operations). Near-zero false positive rate by design. Any internal host contacting a Spamhaus-listed IP, or any traffic from one, is a real threat. Category is typically "Misc Attack".
- ET EXPLOIT_KIT — Detects known exploit kit behavior (packed/obfuscated JavaScript, browser exploitation patterns). External sources serving exploit-kit content to internal devices is a real threat.
- ET MALWARE / ET TROJAN / ET CnC — Detects malware C2 traffic, known malicious payloads, or command-and-control beacons. Default real.
- ET CURRENT_EVENTS with an attack/exploit name — usually points to active exploitation of a specific CVE.
- Signatures naming a specific vulnerability or CVE in their description.

## Strong indicators of a false positive (default: "false_positive", confidence 0.85+)

- ET INFO signatures classified as "Misc activity" or "Device Retrieving External IP Address" — informational only. Includes external IP lookup (ip-api.com, ipinfo.io, ipify.org), Android/Microsoft connectivity checks (connectivitycheck.gstatic.com, msftncsi.com), Discord/Spotify/Steam service domains, observed-cert signatures (ZeroSSL etc.), DNS-over-HTTPS providers.
- ET SCAN NMAP -sA (SID 2000538, 2000540) — these fire on legitimate TCP ACK return traffic from major cloud providers (Google: 74.125.x.x, 142.250.x.x, 142.251.x.x, 64.233.x.x, 172.217.x.x, 216.58.x.x, 34.x.x.x, 35.x.x.x; Cloudflare: 162.159.x.x, 104.16-18.x.x; AWS: 3.x.x.x, 13.x.x.x, 18.x.x.x, 52.x.x.x, 54.x.x.x). These are not real scans — they are noise on legitimate HTTPS connections.
- ET DOS Possible SSDP Amplification Scan (SID 2019102) with internal source and internal destination — normal UPnP discovery, not a real DOS.
- ET SHELLCODE UTF-8/16 Encoded Shellcode (SID 2012510) — known-noisy rule that fires on benign Base64-encoded data in JavaScript, images, and video streams.
- STUN binding requests/responses (SID 2016149, 2016150) — normal NAT traversal for Tailscale, WebRTC, gaming, VoIP.
- DNS NXDOMAIN responses to smart TV — almost always Pi-hole blocking ad/tracker domains the TV is requesting. Source is internal DNS, destination is the TV.

## Context that matters

- Source geography on alerts to home devices. Connections from foreign residential or ISP ranges (Russia, China non-cloud, Iran, Vietnam, etc.) to smart TVs, IoT devices, or cameras warrant elevated suspicion even on informational signatures. Major cloud providers (AWS, GCP, Azure, Alibaba, Tencent) are neutral on their own — depends on the signature.
- Smart TV ad-tech caveat. Smart TVs (LG, Samsung, Vizio, Roku) connect to programmatic ad infrastructure that is loosely curated and sometimes overlaps with Spamhaus DROP IPs or hosts flagged for obfuscated JS. When this happens, the alert is still a real threat on its merits — but note in your reasoning that the likely root cause is "TV ad SDK pulling from sketchy CDN" rather than "device compromise."
- Direction matters. External source + internal destination on a server port (80/443) usually means the internal host initiated the connection and this is response traffic. External source + internal destination on a high port without prior internal traffic is more suspicious.
- Internal-to-internal traffic is almost always benign discovery, container chatter, or service announcement. Real lateral movement is rare on a home network unless there's a clear pattern of unusual ports/protocols.

## When to use "uncertain"

Reserve "uncertain" for cases where the signature is ambiguous AND you have no contextual clues. Don't default to uncertain — pick a side when you can.

# Output format

Respond with JSON ONLY (no prose, no markdown):

{{
  "verdict": "false_positive" | "real" | "uncertain",
  "confidence": <float 0.0 to 1.0>,
  "reasoning": "<one short paragraph explaining your decision, citing the signature category and any specific factors>"
}}
"""

DEFAULT_MODELS = [
    "mistral:7b",
    "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",
    "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M",
    "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K",
    "hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest",
]


# --- Data loading ---

def load_labeled_alerts(db_path, limit=None):
    """Pull labeled alerts from triage_events (read-only)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    query = """
        SELECT id, raw_alert, human_verdict
        FROM triage_events
        WHERE human_verdict IS NOT NULL
          AND raw_alert IS NOT NULL
        ORDER BY id
    """
    if limit:
        query += f" LIMIT {int(limit)}"
    cur.execute(query)
    rows = []
    skipped = 0
    for r in cur.fetchall():
        try:
            alert = json.loads(r["raw_alert"])
        except (json.JSONDecodeError, TypeError):
            skipped += 1
            continue
        rows.append({
            "id": r["id"],
            "alert": alert,
            "human_verdict": r["human_verdict"],
        })
    conn.close()
    if skipped:
        print(f"  [warn] skipped {skipped} rows with unparseable raw_alert JSON")
    return rows


# --- Model inference ---

def call_model(ollama_url, model, alert):
    """Single inference call. Returns (verdict_dict, latency_ms, body, error)."""
    user_prompt = f"Classify this Suricata alert:\n\n{json.dumps(alert, indent=2)}"
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2, "num_predict": 250, "num_ctx": 4096},
        "keep_alive": -1,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{ollama_url.rstrip('/')}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return None, (time.time() - start) * 1000, {}, f"http_error: {e}"
    except json.JSONDecodeError as e:
        return None, (time.time() - start) * 1000, {}, f"body_json_error: {e}"
    latency_ms = (time.time() - start) * 1000

    raw_response = body.get("response", "").strip()
    try:
        verdict_obj = json.loads(raw_response)
    except json.JSONDecodeError:
        return None, latency_ms, body, "verdict_parse_error"

    verdict_label = verdict_obj.get("verdict")
    if verdict_label not in ("false_positive", "real", "uncertain"):
        verdict_label = "uncertain"
    try:
        confidence = max(0.0, min(1.0, float(verdict_obj.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0
    reasoning = str(verdict_obj.get("reasoning", ""))[:1000]

    return {
        "verdict": verdict_label,
        "confidence": confidence,
        "reasoning": reasoning,
    }, latency_ms, body, None


# --- Metrics ---

def cohens_kappa(confusion):
    """Cohen's kappa from confusion[true_label][pred_label] = count."""
    labels = sorted(set(confusion.keys()) | {
        m for d in confusion.values() for m in d.keys()
    })
    n = sum(c for d in confusion.values() for c in d.values())
    if n == 0:
        return 0.0
    po = sum(confusion.get(l, {}).get(l, 0) for l in labels) / n
    pe = 0.0
    for l in labels:
        row_sum = sum(confusion.get(l, {}).values())
        col_sum = sum(confusion.get(other, {}).get(l, 0) for other in labels)
        pe += (row_sum * col_sum) / (n * n)
    if pe >= 1.0:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1.0 - pe)


def per_class_metrics(confusion):
    """precision, recall, F1 per class."""
    labels = sorted(set(confusion.keys()) | {
        p for d in confusion.values() for p in d.keys()
    })
    out = {}
    for label in labels:
        tp = confusion.get(label, {}).get(label, 0)
        fn = sum(v for k, v in confusion.get(label, {}).items() if k != label)
        fp = sum(
            confusion.get(other, {}).get(label, 0)
            for other in labels if other != label
        )
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        out[label] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "support": tp + fn,
        }
    return out


# --- Run loop ---

def safe_filename(model_name):
    return model_name.replace("/", "_").replace(":", "_").replace(".", "_")


def load_existing(csv_path):
    """For resumability — return set of alert IDs already in the CSV."""
    if not csv_path.exists():
        return set()
    done = set()
    try:
        with open(csv_path, newline="") as f:
            for row in csv.DictReader(f):
                try:
                    done.add(int(row["alert_id"]))
                except (KeyError, ValueError):
                    continue
    except Exception:
        pass
    return done


def benchmark_model(model, alerts, ollama_url, out_dir, skip_existing=True):
    csv_path = out_dir / f"{safe_filename(model)}.csv"
    done = load_existing(csv_path) if skip_existing else set()
    if done:
        print(f"  [resume] {len(done)}/{len(alerts)} alerts already done")

    fieldnames = [
        "alert_id", "human_verdict", "model_verdict", "model_confidence",
        "agree", "latency_ms", "eval_count", "eval_duration_ns",
        "prompt_eval_count", "prompt_eval_duration_ns", "total_duration_ns",
        "tokens_per_sec", "error", "reasoning",
    ]
    write_header = not csv_path.exists() or not done

    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        new = 0
        for item in alerts:
            if item["id"] in done:
                continue
            verdict, latency_ms, body, err = call_model(ollama_url, model, item["alert"])
            eval_count = body.get("eval_count", 0) or 0
            eval_duration_ns = body.get("eval_duration", 0) or 0
            tps = (eval_count * 1e9 / eval_duration_ns) if eval_count and eval_duration_ns else 0.0

            row = {
                "alert_id": item["id"],
                "human_verdict": item["human_verdict"],
                "model_verdict": verdict["verdict"] if verdict else "ERROR",
                "model_confidence": verdict["confidence"] if verdict else 0.0,
                "agree": 1 if verdict and verdict["verdict"] == item["human_verdict"] else 0,
                "latency_ms": round(latency_ms, 1),
                "eval_count": eval_count,
                "eval_duration_ns": eval_duration_ns,
                "prompt_eval_count": body.get("prompt_eval_count", 0) or 0,
                "prompt_eval_duration_ns": body.get("prompt_eval_duration", 0) or 0,
                "total_duration_ns": body.get("total_duration", 0) or 0,
                "tokens_per_sec": round(tps, 2),
                "error": err or "",
                "reasoning": (verdict["reasoning"] if verdict else "")[:500],
            }
            writer.writerow(row)
            f.flush()
            new += 1
            done_count = new + len(done)
            mv = verdict["verdict"] if verdict else "ERR"
            mark = "OK" if row["agree"] else "XX"
            print(
                f"  [{done_count:>3}/{len(alerts)}] {mark} "
                f"{mv:<14} vs {item['human_verdict']:<14} "
                f"{latency_ms:>7.0f}ms"
                + (f"  err={err}" if err else "")
            )
    return csv_path


# --- Aggregation ---

def percentile(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(int(len(s) * p / 100), len(s) - 1)
    return s[idx]


def aggregate(csv_path):
    confusion = {}
    latencies = []
    tps_list = []
    parse_errors = 0
    http_errors = 0
    total = 0
    for row in csv.DictReader(open(csv_path)):
        total += 1
        if row.get("error"):
            if "parse" in row["error"]:
                parse_errors += 1
            else:
                http_errors += 1
            continue
        confusion.setdefault(row["human_verdict"], {}).setdefault(row["model_verdict"], 0)
        confusion[row["human_verdict"]][row["model_verdict"]] += 1
        try:
            latencies.append(float(row["latency_ms"]))
            tps = float(row.get("tokens_per_sec", 0))
            if tps > 0:
                tps_list.append(tps)
        except (ValueError, KeyError):
            pass

    kappa = cohens_kappa(confusion)
    classes = per_class_metrics(confusion)
    correct = sum(confusion.get(l, {}).get(l, 0) for l in confusion)
    total_scored = sum(c for d in confusion.values() for c in d.values())
    accuracy = correct / total_scored if total_scored else 0.0

    return {
        "total": total,
        "scored": total_scored,
        "parse_errors": parse_errors,
        "http_errors": http_errors,
        "accuracy": accuracy,
        "kappa": kappa,
        "classes": classes,
        "confusion": confusion,
        "latency_mean_ms": statistics.mean(latencies) if latencies else 0,
        "latency_p50_ms": percentile(latencies, 50),
        "latency_p95_ms": percentile(latencies, 95),
        "tps_mean": statistics.mean(tps_list) if tps_list else 0,
    }


# --- Markdown summary ---

def render_summary(results, out_dir, n_alerts, class_counts):
    lines = []
    lines.append("# Triagewall v0.2 Quantization Benchmark\n")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
    lines.append(f"**Dataset:** {n_alerts} human-labeled alerts from triage.db\n")
    lines.append(
        "**Class distribution:** "
        + ", ".join(f"{k}={v}" for k, v in sorted(class_counts.items()))
        + "\n"
    )
    lines.append(f"**Internal subnets in prompt:** `{INTERNAL_SUBNETS}`\n")
    lines.append("**System prompt:** see `system_prompt.txt` in this directory\n")
    lines.append("\n---\n")

    # Overall table
    lines.append("\n## Overall comparison\n")
    lines.append("| Model | Cohen's k | Accuracy | Mean latency | p95 latency | Tok/s | Errors |")
    lines.append("|-------|---:|---:|---:|---:|---:|---:|")
    for model, r in results.items():
        lines.append(
            f"| `{model}` | {r['kappa']:.3f} | {r['accuracy']:.1%} | "
            f"{r['latency_mean_ms']:.0f}ms | {r['latency_p95_ms']:.0f}ms | "
            f"{r['tps_mean']:.1f} | {r['parse_errors'] + r['http_errors']} |"
        )

    # Per-class precision/recall for each model
    lines.append("\n## Per-class performance\n")
    for model, r in results.items():
        lines.append(f"\n### `{model}`\n")
        lines.append("| Class | Precision | Recall | F1 | Support |")
        lines.append("|-------|---:|---:|---:|---:|")
        for cls in ("real", "false_positive", "uncertain"):
            c = r["classes"].get(cls, {})
            if not c:
                lines.append(f"| {cls} | - | - | - | 0 |")
            else:
                lines.append(
                    f"| {cls} | {c['precision']:.1%} | {c['recall']:.1%} | "
                    f"{c['f1']:.1%} | {c['support']} |"
                )

    # Confusion matrices
    lines.append("\n## Confusion matrices\n")
    for model, r in results.items():
        lines.append(f"\n### `{model}`\n")
        lines.append("Rows = human label, columns = model prediction.\n")
        all_classes = ("real", "false_positive", "uncertain")
        lines.append("| | " + " | ".join(f"pred {c}" for c in all_classes) + " |")
        lines.append("|---|" + "---|" * len(all_classes))
        for true_cls in all_classes:
            row_vals = [
                str(r["confusion"].get(true_cls, {}).get(pred_cls, 0))
                for pred_cls in all_classes
            ]
            lines.append(f"| **true {true_cls}** | " + " | ".join(row_vals) + " |")

    # Notes
    lines.append("\n## Notes\n")
    lines.append(
        "- Cohen's kappa: >0.80 strong agreement, 0.61-0.80 substantial, "
        "0.41-0.60 moderate, <0.41 weak/poor.\n"
    )
    lines.append(
        "- True-positive recall is the most important metric. "
        "Missing real threats is worse than over-alerting.\n"
    )
    lines.append(
        "- Latency includes model load time on first call. Subsequent calls reuse "
        "the loaded model (keep_alive=-1 in the request).\n"
    )

    (out_dir / "summary.md").write_text("\n".join(lines))
    (out_dir / "system_prompt.txt").write_text(SYSTEM_PROMPT)


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Benchmark Ollama models for Triagewall")
    parser.add_argument("--ollama", default=os.environ.get("OLLAMA_HOST", "http://10.0.1.100:11434"))
    parser.add_argument("--db", default=os.environ.get("DB_PATH", "/opt/axon-agents/triage-agent/data/triage.db"))
    parser.add_argument(
        "--out",
        default=os.environ.get("OUT_DIR", f"./results/benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
    )
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS,
                        help="Models to test (space-separated)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit alerts processed (smoke test)")
    parser.add_argument("--no-resume", action="store_true",
                        help="Don't skip already-processed (model, alert) pairs")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("\n=== Triagewall v0.2 Benchmark ===")
    print(f"Ollama:  {args.ollama}")
    print(f"DB:      {args.db}")
    print(f"Output:  {out_dir.resolve()}")
    print(f"Models:  {len(args.models)}")
    for m in args.models:
        print(f"           {m}")
    print()

    # Load alerts
    alerts = load_labeled_alerts(args.db, limit=args.limit)
    if not alerts:
        print("ERROR: no labeled alerts found in DB")
        sys.exit(1)
    class_counts = {}
    for a in alerts:
        class_counts[a["human_verdict"]] = class_counts.get(a["human_verdict"], 0) + 1
    print(f"Loaded {len(alerts)} labeled alerts: {class_counts}")
    print()

    # Run each model
    results = {}
    for model in args.models:
        print(f"\n--- {model} ---")
        try:
            csv_path = benchmark_model(
                model, alerts, args.ollama, out_dir,
                skip_existing=not args.no_resume,
            )
            results[model] = aggregate(csv_path)
            r = results[model]
            print(
                f"  DONE: k={r['kappa']:.3f} acc={r['accuracy']:.1%} "
                f"latency_p50={r['latency_p50_ms']:.0f}ms "
                f"tps={r['tps_mean']:.1f} errors={r['parse_errors'] + r['http_errors']}"
            )
        except KeyboardInterrupt:
            print("\n  [interrupted] partial results preserved in CSV")
            sys.exit(130)
        except Exception as e:
            print(f"  [error] {model} failed: {e}")
            continue

    # Write summary
    if results:
        render_summary(results, out_dir, len(alerts), class_counts)
        print(f"\n=== Summary written to {out_dir / 'summary.md'} ===\n")
    else:
        print("\nNo successful results.\n")


if __name__ == "__main__":
    main()
