# Triagewall v0.2 Quantization Benchmark

**Generated:** 2026-05-22T22:19:02.283615+00:00

**Dataset:** 114 human-labeled alerts from triage.db

**Class distribution:** false_positive=107, real=6, uncertain=1

**Internal subnets in prompt:** `10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24`

**System prompt:** see `system_prompt.txt` in this directory


---


## Overall comparison

| Model | Cohen's k | Accuracy | Mean latency | p95 latency | Tok/s | Errors |
|-------|---:|---:|---:|---:|---:|---:|
| `mistral:7b` | 0.556 | 93.0% | 3473ms | 4513ms | 47.9 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | 0.574 | 93.0% | 8010ms | 9592ms | 30.0 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M` | 0.687 | 95.6% | 10252ms | 12640ms | 21.6 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K` | 0.734 | 96.5% | 12368ms | 15216ms | 16.5 | 0 |
| `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest` | 0.000 | 1.2% | 3337ms | 16383ms | 14.9 | 29 |

## Per-class performance


### `mistral:7b`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 100.0% | 50.0% | 66.7% | 6 |
| false_positive | 100.0% | 95.3% | 97.6% | 107 |
| uncertain | 11.1% | 100.0% | 20.0% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 71.4% | 83.3% | 76.9% | 6 |
| false_positive | 100.0% | 94.4% | 97.1% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 71.4% | 83.3% | 76.9% | 6 |
| false_positive | 100.0% | 97.2% | 98.6% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 71.4% | 83.3% | 76.9% | 6 |
| false_positive | 100.0% | 98.1% | 99.1% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 0.0% | 0.0% | 0.0% | 4 |
| false_positive | 0.0% | 0.0% | 0.0% | 80 |
| uncertain | 1.2% | 100.0% | 2.3% | 1 |

## Confusion matrices


### `mistral:7b`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 3 | 0 | 3 |
| **true false_positive** | 0 | 102 | 5 |
| **true uncertain** | 0 | 0 | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 5 | 0 | 1 |
| **true false_positive** | 1 | 101 | 5 |
| **true uncertain** | 1 | 0 | 0 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 5 | 0 | 1 |
| **true false_positive** | 1 | 104 | 2 |
| **true uncertain** | 1 | 0 | 0 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 5 | 0 | 1 |
| **true false_positive** | 1 | 105 | 1 |
| **true uncertain** | 1 | 0 | 0 |

### `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 0 | 0 | 4 |
| **true false_positive** | 0 | 0 | 80 |
| **true uncertain** | 0 | 0 | 1 |

## Notes

- Cohen's kappa: >0.80 strong agreement, 0.61-0.80 substantial, 0.41-0.60 moderate, <0.41 weak/poor.

- True-positive recall is the most important metric. Missing real threats is worse than over-alerting.

- Latency includes model load time on first call. Subsequent calls reuse the loaded model (keep_alive=-1 in the request).
