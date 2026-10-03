# Inventory retrieval candidate evaluation

This is an exploratory retrieval probe for issue #31, not a supported semantic-search release result. The [v1 corpus](inventory-retrieval-corpus-v1.json) contains 30 synthetic descriptions and ten manually judged natural-language queries. It includes opaque and misleading hostnames, historical and partial evidence, and multiple service categories. The descriptions are hand-authored and include explanatory words that the current `DescribeReport` renderer does not emit. These scores likely overstate retrieval quality for actual retained reports. A corpus generated from retained report facts and a larger held-out set are required before selecting a model.

The [result JSON](inventory-retrieval-evaluation-v1.json) records per-query rankings, model revisions, SHA-256 digests, dimensions, timings, package version, and machine details. The PostgreSQL baseline used the current `to_tsvector('simple', description) @@ plainto_tsquery('simple', query)` expression, so every query term had to match. Hybrid used equal-weight reciprocal rank fusion with constant 60 and at most 100 candidates per path. Those settings are evaluation candidates, not tuned product defaults.

| Retrieval path | Mean nDCG@10 | Mean Recall@20 |
| --- | ---: | ---: |
| Current PostgreSQL lexical expression | 0.123 | 0.100 |
| BGE small v1.5 ONNX | 0.951 | 1.000 |
| BGE small plus lexical fusion | 0.951 | 1.000 |
| MiniLM L6 v2 ONNX | 0.939 | 1.000 |
| MiniLM plus lexical fusion | 0.939 | 1.000 |

The BGE run used the Qdrant ONNX artifact at revision `aa8f8b060edb00e03bfdd08813a2949946c8ba55`, with model file SHA-256 `51f1bd0addd6e859e42c2c8021a5e5461385bb676a649f4b269aa445449f2431`. The MiniLM run used revision `d13954661f83248295ba75c1ed411eef3b7b936e`, with model file SHA-256 `bbd7b466f6d58e646fdc2bd5fd67b2f5e93c0b687011bd4548c420f7bd46f0c5`. Both returned 384-dimensional vectors. The model provider lists BGE small under the MIT license and gives its retrieval query prefix in the [model card](https://huggingface.co/BAAI/bge-small-en-v1.5). FastEmbed's [supported-model list](https://qdrant.github.io/fastembed/examples/Supported_Models/) identifies the two ONNX variants used here. This probe did not test alternate query prefixes or document truncation.

The run used FastEmbed 0.8.1 and psycopg 3.3.6 on an Apple arm64 host with PostgreSQL 18 Alpine in a disposable local container. The model cache consumed about 151 MiB. The process peak RSS reported by macOS was about 528 MiB. Model loading was measured after artifacts were cached. A separate disposable `pgvector/pgvector:0.8.6-pg18` image, pinned to digest `sha256:2ba9ca5f2e7daa0f0e7723cba1ee9167bab54efd3640516a44ac1a928dd67e7a`, accepted `CREATE EXTENSION vector` and returned extension version 0.8.6 and cosine distance zero for an identical 3-dimensional vector. This only proves that image's basic extension setup. No stored asset vectors, service concurrency, backup/restore, or 10,000/100,000-document capacity test was involved.

To repeat the offline evaluation after explicitly provisioning the artifacts, run:

```sh
HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
uv run --with fastembed==0.8.1 --with 'psycopg[binary]==3.3.6' \
  python scripts/evaluate-inventory-retrieval.py \
  --cache-dir /path/to/pinned-model-cache \
  --postgres-dsn 'postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
  --output docs/benchmarks/inventory-retrieval-evaluation-v1.json
```

The script defaults to offline model loading. `--download` is an explicit evaluation-only provisioning step. A shipping runtime must pin and verify model artifacts separately and never download on a query path.
