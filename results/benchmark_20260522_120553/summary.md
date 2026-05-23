# Triagewall v0.2 Quantization Benchmark

**Generated:** 2026-05-22T17:02:54.064973+00:00

**Dataset:** 114 human-labeled alerts from triage.db

**Class distribution:** false_positive=107, real=6, uncertain=1

**Internal subnets in prompt:** `10.0.0.0/24, 10.0.1.0/24, and 10.0.2.0/24`

**System prompt:** see `system_prompt.txt` in this directory


---


## Overall comparison

| Model | Cohen's k | Accuracy | Mean latency | p95 latency | Tok/s | Errors |
|-------|---:|---:|---:|---:|---:|---:|
| `mistral:7b` | 0.480 | 93.9% | 3077ms | 3955ms | 52.4 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | 0.227 | 92.1% | 5592ms | 6929ms | 30.4 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M` | 0.210 | 93.9% | 6429ms | 7818ms | 24.8 | 0 |
| `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K` | 0.282 | 93.9% | 8227ms | 10308ms | 17.6 | 0 |
| `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest` | 0.000 | 1.2% | 2561ms | 7005ms | 15.1 | 33 |

## Per-class performance


### `mistral:7b`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 100.0% | 16.7% | 28.6% | 6 |
| false_positive | 98.1% | 98.1% | 98.1% | 107 |
| uncertain | 16.7% | 100.0% | 28.6% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 0.0% | 0.0% | 0.0% | 6 |
| false_positive | 96.3% | 98.1% | 97.2% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 0.0% | 0.0% | 0.0% | 6 |
| false_positive | 95.5% | 100.0% | 97.7% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 100.0% | 16.7% | 28.6% | 6 |
| false_positive | 95.5% | 99.1% | 97.2% | 107 |
| uncertain | 0.0% | 0.0% | 0.0% | 1 |

### `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest`

| Class | Precision | Recall | F1 | Support |
|-------|---:|---:|---:|---:|
| real | 0.0% | 0.0% | 0.0% | 5 |
| false_positive | 0.0% | 0.0% | 0.0% | 75 |
| uncertain | 1.2% | 100.0% | 2.4% | 1 |

## Confusion matrices


### `mistral:7b`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 1 | 2 | 3 |
| **true false_positive** | 0 | 105 | 2 |
| **true uncertain** | 0 | 0 | 1 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 0 | 3 | 3 |
| **true false_positive** | 0 | 105 | 2 |
| **true uncertain** | 0 | 1 | 0 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 0 | 4 | 2 |
| **true false_positive** | 0 | 107 | 0 |
| **true uncertain** | 0 | 1 | 0 |

### `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q6_K`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 1 | 4 | 1 |
| **true false_positive** | 0 | 106 | 1 |
| **true uncertain** | 0 | 1 | 0 |

### `hf.co/fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF:latest`

Rows = human label, columns = model prediction.

| | pred real | pred false_positive | pred uncertain |
|---|---|---|---|
| **true real** | 0 | 0 | 5 |
| **true false_positive** | 0 | 0 | 75 |
| **true uncertain** | 0 | 0 | 1 |

## Notes

- Cohen's kappa: >0.80 strong agreement, 0.61-0.80 substantial, 0.41-0.60 moderate, <0.41 weak/poor.

- True-positive recall is the most important metric. Missing real threats is worse than over-alerting.

- Latency includes model load time on first call. Subsequent calls reuse the loaded model (keep_alive=-1 in the request).
