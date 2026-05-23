# Triagewall v0.2 Quantization Benchmark

**Generated:** 2026-05-22T15:52:43.850742+00:00

**Dataset:** 5 human-labeled alerts from triage.db

**Class distribution:** false_positive=5

**Internal subnets in prompt:** `10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24`

**System prompt:** see `system_prompt.txt` in this directory


---


## Overall comparison

| Model | Cohen's k | Accuracy | Mean latency | p95 latency | Tok/s | Errors |
|-------|---:|---:|---:|---:|---:|---:|
| `mistral:7b` | 1.000 | 100.0% | 10105ms | 12474ms | 14.6 | 0 |

## Per-class performance


### `mistral:7b`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | - | - | - | 0 |
| false_positive | 100.0% | 100.0% | 100.0% | 5 |
| uncertain | - | - | - | 0 |

## Confusion matrices


### `mistral:7b`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 0 | 0 | 0 |
| **true false_positive** | 0 | 5 | 0 |
| **true uncertain** | 0 | 0 | 0 |

## Notes

- Cohen's kappa: >0.80 strong agreement, 0.61-0.80 substantial, 0.41-0.60 moderate, <0.41 weak/poor.

- True-positive recall is the most important metric. Missing real threats is worse than over-alerting.

- Latency includes model load time on first call. Subsequent calls reuse the loaded model (keep_alive=-1 in the request).
