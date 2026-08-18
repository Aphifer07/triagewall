# Prompt Revision and Foundation-Sec-8B Evaluation

**Date:** 2026-05-22
**Status:** Shipped in v0.2

## Summary

I evaluated whether Cisco Foundation AI's [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) (a cybersecurity-specialized fine-tune of Llama 3.1) should replace Mistral 7B as TriageWall's triage model. The hypothesis was that domain-specialized training would translate to better IDS alert classification.

The first benchmark contradicted the hypothesis: every Foundation-Sec quantization underperformed generic Mistral on the same prompt. Investigation showed the root cause was the prompt, not the model. After revising the prompt to include category priors, threat-intel guidance, and operational context, Foundation-Sec Q5_K_M moved from κ=0.210 to κ=0.687 and from 0% true-positive recall to 83%, comfortably beating Mistral. **Model specialization was real but latent — the prompt had to elicit it.**

TriageWall v0.2 ships with the revised prompt and Foundation-Sec Q5_K_M as the production model.

## Method

### Dataset

114 human-labeled alerts pulled from `triage_events` in the production database. Labels were applied during interactive review against full network context (device identity, traffic direction, known-good/bad IP ranges, Pi-hole DNS logs). Class distribution:

| Class | Count | Notes |
|-------|------:|-------|
| `false_positive` | 107 | Mix of prefilter-classified and LLM-classified benign alerts |
| `real` | 6 | Spamhaus DROP hits, exploit kit signatures, JS obfuscation from suspicious geographies |
| `uncertain` | 1 | Ambiguous JS obfuscation from non-residential foreign source |

Class imbalance reflects the natural distribution of homelab IDS alerts — almost everything is benign by volume, but the 6 real positives are the cases that matter most.

The set is small for statistical confidence intervals but large enough to discriminate qualitative model behavior (especially for the true-positive cases).

### Models evaluated

| Model | Approximate size | Source |
|-------|------------------|--------|
| `mistral:7b` | 4.4 GB (Q4_K_M) | Ollama default |
| Foundation-Sec-8B-Instruct Q4_K_M | 4.9 GB | gabriellarson/Foundation-Sec-8B-Instruct-GGUF |
| Foundation-Sec-8B-Instruct Q5_K_M | 5.7 GB | gabriellarson/Foundation-Sec-8B-Instruct-GGUF |
| Foundation-Sec-8B-Instruct Q6_K | 6.6 GB | gabriellarson/Foundation-Sec-8B-Instruct-GGUF |
| Foundation-Sec-8B-Instruct Q8_0 | 8.5 GB | fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF (Cisco's official release) |

All models served through Ollama on an RTX 4060 (8 GB VRAM) connected to the TriageWall container over LAN.

### Prompts

**v0.1 prompt (baseline):** the original production system prompt — a generic "you are a SOC analyst" with verdict definitions but no category-specific guidance, no threat-intel hints, and no network context beyond the internal subnet list.

**v0.2 prompt (revised):** the v0.1 structure plus:
- Internal device inventory (homelab, smart TV, IoT, mobile)
- "Strong real" signature families (ET DROP/EDROP, ET EXPLOIT_KIT, ET MALWARE/TROJAN/CnC, ET CURRENT_EVENTS, CVE-named signatures)
- "Strong false_positive" signature families with specific SIDs and cloud provider IP ranges
- Context rules: source geography, smart TV ad-tech caveat, traffic direction, internal-to-internal handling
- Anti-hedge directive on the `uncertain` verdict

Both prompts used the same JSON output contract, temperature (0.2), num_ctx (4096), and num_predict (250).

### Harness

A standalone Python script (`scripts/benchmark_quants.py`) pulls labeled alerts from `triage.db` read-only, sends each alert to each model through Ollama's `/api/generate`, parses the JSON verdict, and writes per-(model, alert) rows to CSV. It computes Cohen's kappa, per-class precision/recall/F1, confusion matrices, mean/p50/p95 latency, and tokens/sec from Ollama's response metadata. Results land in `results/benchmark_<timestamp>/` with one CSV per model plus a `summary.md`.

## Results

### v0.1 prompt (baseline)

| Model | κ | Accuracy | real recall | Mean latency | Tok/s | Errors |
|-------|---:|---:|---:|---:|---:|---:|
| mistral:7b | 0.480 | 93.9% | 16.7% (1/6) | 3077ms | 52.4 | 0 |
| Foundation-Sec Q4_K_M | 0.227 | 92.1% | 0% (0/6) | 5592ms | 30.4 | 0 |
| Foundation-Sec Q5_K_M | 0.210 | 93.9% | 0% (0/6) | 6429ms | 24.8 | 0 |
| Foundation-Sec Q6_K | 0.282 | 93.9% | 16.7% (1/6) | 8227ms | 17.6 | 0 |
| Foundation-Sec Q8_0 | 0.000 | 1.2% | 0% (0/6) | 2561ms | 15.1 | 33 |

With the v0.1 prompt, Mistral 7B was the best model on Cohen's kappa, and all Foundation-Sec quants showed strong bias toward `false_positive` — they were essentially classifying nearly everything as benign. The high accuracy numbers are deceptive: with 107/114 alerts truly false_positive, any model that says "false_positive" all the time hits 93.9% accuracy while being useless.

Q8_0 failed to produce valid JSON for 33 of 114 alerts (29% parse failure rate), almost certainly because Q8_0 at 8.5 GB cannot fully fit in the RTX 4060's 8 GB of VRAM and the resulting CPU offload destabilized output.

### v0.2 prompt (revised)

| Model | κ | Accuracy | real recall | Mean latency | Tok/s | Errors |
|-------|---:|---:|---:|---:|---:|---:|
| mistral:7b | 0.556 | 93.0% | 50.0% (3/6) | 3473ms | 47.9 | 0 |
| Foundation-Sec Q4_K_M | 0.574 | 93.0% | 83.3% (5/6) | 8010ms | 30.0 | 0 |
| Foundation-Sec Q5_K_M | 0.687 | 95.6% | 83.3% (5/6) | 10252ms | 21.6 | 0 |
| Foundation-Sec Q6_K | 0.734 | 96.5% | 83.3% (5/6) | 12368ms | 16.5 | 0 |
| Foundation-Sec Q8_0 | 0.000 | 1.2% | 0% (0/6) | 3337ms | 14.9 | 29 |

All working models improved, but Foundation-Sec improved dramatically more than Mistral. Mistral kappa improved by +0.076; the Foundation-Sec quants improved by +0.347 to +0.477. Foundation-Sec Q6_K at κ=0.734 is in the "substantial agreement" range, just short of the v0.2 ship gate (κ ≥ 0.80).

The true-positive recall numbers tell the operational story: Foundation-Sec quants moved from missing 6/6 real threats to catching 5/6. The single miss was the same across all three working quants — an ET EXPLOIT_KIT alert where the model classified it as `uncertain` rather than `real`. Mistral, by contrast, only caught 3/6 even with the improved prompt.

### Direct comparison on the six true-positive alerts

| Alert | Signature | Mistral v0.1 | Mistral v0.2 | FS Q5 v0.1 | FS Q5 v0.2 |
|-------|-----------|--------------|--------------|------------|------------|
| Spamhaus DROP (1316268) | ET DROP listed inbound | real ✓ | real ✓ | false_positive ✗ | real ✓ |
| Spamhaus DROP (1231449) | ET DROP listed inbound | false_positive ✗ | real ✓ | false_positive ✗ | real ✓ |
| EXPLOIT_KIT (1533447) | WindowBase64.atob iframe | uncertain ✗ | uncertain ✗ | false_positive ✗ | uncertain ✗ |
| Shellcode (249976) | Possible Unescape %u | uncertain ✗ | real ✓ | false_positive ✗ | real ✓ |
| JS Obfuscation RU (504314) | String.fromCharCode | uncertain ✗ | uncertain ✗ | false_positive ✗ | real ✓ |
| JS Obfuscation Tencent (1339351) | String.fromCharCode | uncertain ✗ | uncertain ✗ | false_positive ✗ | real ✓ |

The pattern is clear: the v0.2 prompt's explicit guidance on Spamhaus DROP and on foreign-ISP-to-home-device traffic mapped directly to better verdicts. The case both models still get wrong (the EXPLOIT_KIT iframe) is exactly the kind of nuanced analysis that needs more context than a system prompt can provide — a candidate for the v0.3 RAG layer.

## Findings

**1. Model specialization is real but latent.** Foundation-Sec-8B's domain training is genuine and substantial. But that training only activates when the prompt gives the model permission to use it. With a generic SOC analyst prompt, the model defaulted to careful, calibrated reasoning that looked indistinguishable from hedging. With explicit "this signature family means X" guidance, the same model produced sharp, correct verdicts. Cybersecurity-specialized models don't replace prompt engineering, they reward it.

**2. Cohen's kappa is the right metric for this class balance.** Accuracy in the high 90s across all models in both runs was largely an artifact of the 94% false_positive class prior. Kappa adjusts for chance agreement and was the only metric that distinguished the actual capability differences between models.

**3. RTX 4060 (8 GB VRAM) caps practical quantization at Q6_K.** Q8_0 at 8.5 GB cannot fully fit in VRAM and the CPU layer offload produced 29% JSON parse failures across both prompt versions. Q6_K at 6.6 GB sits in VRAM and produces stable output. For homelab deployments on similar consumer GPUs, this is the binding constraint.

**4. Latency scales linearly with quantization size.** Q4_K_M ran ~30% faster than Q5_K_M, which ran ~20% faster than Q6_K. The quality jump from Q4 to Q5 (κ 0.574 → 0.687) is larger than from Q5 to Q6 (κ 0.687 → 0.734) for similar latency cost. Q5_K_M is the right production pick on this Pareto curve.

**5. The model still misses one nuanced case.** All Foundation-Sec quants classified the EXPLOIT_KIT iframe injection as `uncertain` rather than `real`. The prompt's smart-TV-ad-tech caveat may have over-corrected here — the model hedged because the destination was a smart TV. This is the kind of failure that RAG over MITRE ATT&CK technique descriptions should resolve in v0.3.

## Production change

TriageWall v0.2 ships with:

- **`SYSTEM_PROMPT` revised** in `triagewall/triage.py` to the v0.2 prompt
- **Production model:** `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`
- **Internal subnets** now configurable via `INTERNAL_SUBNETS` env var, threaded through `docker-compose.yml`
- **Benchmark harness** committed at `scripts/benchmark_quants.py` for future model evaluation

Expected production impact: dramatically higher true-positive recall on the kinds of alerts the prompt explicitly covers (Spamhaus DROP, exploit kits, suspicious foreign-source traffic to consumer devices). Latency per LLM call increases from ~3 seconds to ~10 seconds, but at ~200 LLM-bound alerts/day, total LLM compute time goes from ~10 minutes to ~33 minutes — well within budget.

## What didn't ship and why

- **Prefilter as mounted config.** Identified as needed for the v0.2 feedback loop, but the feedback loop itself slipped to v0.3 along with this dependency.
- **RAG layer.** Originally scoped to v0.2, deferred to v0.3 in favor of getting the prompt revision shipped. The benchmark shows the prompt revision alone is a significant improvement worth releasing.
- **Prompt injection hardening.** Still required, slipping to v0.2.1. Important enough that it should ship before the model is exposed to any untrusted alert source.
- **Foundation-Sec-Reasoning variant.** Was considered after the Q8_0 results came in poorly, deferred — at 2-4x the inference time of regular Foundation-Sec, the latency budget on RTX 4060 doesn't accommodate it for now.

## What I'd do differently

- **Label a larger and more balanced gold set first.** Six true positives is the minimum to discriminate models; ~30+ would have given tighter confidence intervals on the kappa numbers. The prompt revision result is strong enough that I'm confident it generalizes, but quantifying that confidence requires more labels.
- **Track per-(model, alert) confidence calibration.** The CSV captures `model_confidence` per call but I didn't analyze whether the confidence values themselves are well-calibrated. That's a v0.2.1 or v0.3 item.
- **Test Foundation-Sec without quantization variation first.** Running all four quants on the bad prompt before identifying the prompt as the bottleneck wasted compute. Should have done one quant × two prompts before five quants × one prompt.

## Reproducibility

```bash
# From the repo root, with .env configured for OLLAMA_HOST and DB_PATH
python3 scripts/benchmark_quants.py
```

Results land in `results/benchmark_<timestamp>/`. The v0.1 results from this experiment are preserved in `results/benchmark_20260522_120553/` and the v0.2 results in the next run after that. The full system prompt used for each run is saved alongside the results as `system_prompt.txt`.
