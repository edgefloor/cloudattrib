# Offline embedding inference probe

Issue #31 requires measured local model throughput and memory before selecting a supported semantic generation. On 2026-10-03, the [offline inference probe](../../scripts/qualify-embedding-inference.py) streamed 100,000 synthetic renderer-derived descriptions through each of the two cached ONNX candidates with FastEmbed 0.8.1. It verified each cache revision and artifact SHA-256 digest against the frozen [retrieval evaluation](inventory-retrieval-evaluation-v2.json) before loading the model. Hugging Face offline mode and disabled telemetry were set by the script; no artifact was downloaded during the run.

The source was the 30-document [v2 rendered corpus](inventory-retrieval-corpus-v2.json). The probe cycled its descriptions and replaced the hostname token with a unique `qNNNNNN.example.com` value. It streamed inputs to `TextEmbedding.embed` in batches of 256 using four inference threads. These are short synthetic descriptions, not 100,000 distinct retained reports. The measurements therefore qualify this input shape and local process only; they do not establish production indexing throughput or relevance.

| Model | Documents | Embedding time | Throughput | Process peak RSS |
| --- | ---: | ---: | ---: | ---: |
| MiniLM L6 v2 ONNX | 10,000 | 6.21 s | 1,611/s | 542 MB |
| MiniLM L6 v2 ONNX | 100,000 | 62.19 s | 1,608/s | 639 MB |
| BGE small v1.5 ONNX | 10,000 | 20.26 s | 494/s | 636 MB |
| BGE small v1.5 ONNX | 100,000 | 202.25 s | 494/s | 663 MB |

The host reported `macOS-27.0-arm64` (Apple M4 Pro). Peak RSS comes from `resource.getrusage` for each Python process; it includes Python, ONNX Runtime, model state, and temporary batches. The JSON artifacts record exact bytes, revisions, digests, library version, and timings: [MiniLM](inventory-inference-minilm-v2.json) and [BGE](inventory-inference-bge-v2.json). The recorded `model_load_seconds` field measures `TextEmbedding` constructor time only; lazy model initialization is included in the first embedding checkpoint. It is not a cold-start bound.

MiniLM was about 3.25 times faster at 100,000 descriptions in this probe and also scored higher on the small synthetic [relevance evaluation](inventory-retrieval-evaluation-v2.md). Those two probes make MiniLM the stronger candidate for a held-out trial, but they do not select a production model. A held-out judged set with realistic retained reports, opaque hostnames, and longer descriptions is still needed. A later [local worker qualification](local-embedding-worker.md) measured warm Unix-socket request latency, process startup with warm file cache, real-model indexing of 100,000 synthetic descriptions, and ten-concurrent service queries. Uncached host startup and target-completion latency under a large indexing load remain unmeasured.

To reproduce with explicitly provisioned cached artifacts:

```sh
uv run --offline --with fastembed==0.8.1 python scripts/qualify-embedding-inference.py \
  --model sentence-transformers/all-MiniLM-L6-v2 \
  --cache-dir /path/to/pinned-model-cache \
  --output docs/benchmarks/inventory-inference-minilm-v2.json

uv run --offline --with fastembed==0.8.1 python scripts/qualify-embedding-inference.py \
  --model BAAI/bge-small-en-v1.5 \
  --cache-dir /path/to/pinned-model-cache \
  --output docs/benchmarks/inventory-inference-bge-v2.json
```

The script rejects missing or mismatched artifacts and accepts 10,000 to 100,000 documents. It does not retain input descriptions in its output.
