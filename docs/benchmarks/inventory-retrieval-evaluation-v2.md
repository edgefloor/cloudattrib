# Inventory retrieval probe with rendered descriptions

The [v2 facts](inventory-retrieval-facts-v2.json) contain 30 synthetic typed report summaries and ten manually judged natural-language queries. Running `go run ./scripts/generate-inventory-corpus` passes each summary through the production `inventory.DescribeReport` function and writes the [v2 corpus](inventory-retrieval-corpus-v2.json). The generator test compares the checked-in corpus with current renderer output. No live hosts or customer data were used.

These are invented facts, including some category labels chosen for the probe; the corpus does not establish that collectors or classifiers currently produce those labels. It is small, has no held-out judgments, and includes hostnames that disclose service roles. Recall@20 is weak evidence with only 30 documents. The [v1 probe](inventory-retrieval-evaluation-v1.md) used hand-written descriptions that contained explanatory words absent from renderer output; compare its scores only as a demonstration of how much corpus construction matters.

The [result JSON](inventory-retrieval-evaluation-v2.json) records per-query rankings, model artifact digests and revisions, dimensions, timings, and runtime. PostgreSQL lexical search ran the current `to_tsvector('simple', description) @@ plainto_tsquery('simple', query)` expression against each rendered description. Every term in each natural-language query had to match, yielding no results for this corpus. Hybrid used equal-weight reciprocal rank fusion with constant 60 over up to 100 candidates per path; because lexical returned no candidates, its scores equal the semantic scores.

| Retrieval path | Mean nDCG@10 | Mean Recall@20 |
| --- | ---: | ---: |
| Current PostgreSQL lexical expression | 0.000 | 0.000 |
| BGE small v1.5 ONNX | 0.781 | 0.950 |
| BGE small plus lexical fusion | 0.781 | 0.950 |
| MiniLM L6 v2 ONNX | 0.968 | 1.000 |
| MiniLM plus lexical fusion | 0.968 | 1.000 |

The BGE model's `content delivery edge cache` query is a notable failure: its top five results included neither judged CDN asset. MiniLM ranked one of the two CDN assets first, but missed the other from its top five. A larger corpus with actual retained report fixtures, obscured hostnames, and held-out queries is needed before choosing a model or acceptance threshold. Both models used cached ONNX artifacts with no network access at evaluation time. Model revisions and SHA-256 digests are recorded in the JSON. The [BGE model card](https://huggingface.co/BAAI/bge-small-en-v1.5) describes its query-prefix option; this run used FastEmbed defaults and did not compare prefixes or truncation settings.

The run used FastEmbed 0.8.1, psycopg 3.3.6, and a disposable PostgreSQL 18 Alpine container on an Apple arm64 host. It did not exercise pgvector, service concurrency, projection failure handling, or 10,000/100,000-document capacity. The timings are local probes, not a service latency bound.

To regenerate and evaluate with previously provisioned model artifacts and a disposable PostgreSQL instance:

```sh
go run ./scripts/generate-inventory-corpus
HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
uv run --with fastembed==0.8.1 --with 'psycopg[binary]==3.3.6' \
  python scripts/evaluate-inventory-retrieval.py \
  --corpus docs/benchmarks/inventory-retrieval-corpus-v2.json \
  --cache-dir /path/to/pinned-model-cache \
  --postgres-dsn 'postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
  --output docs/benchmarks/inventory-retrieval-evaluation-v2.json
```

The evaluator loads models offline by default. `--download` is an explicit evaluation-only provisioning option. A service must pin and verify its own model artifacts before enabling semantic search.
