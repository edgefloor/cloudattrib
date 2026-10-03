# Judged retrieval evaluation with opaque hostnames

The [v3 facts](inventory-retrieval-facts-v3.json) contain 54 synthetic typed report summaries rendered through the production `inventory.DescribeReport` function. Sixteen new natural-language queries and their relevant document IDs were written before running either candidate on this corpus. Most hostnames are opaque; five intentionally suggest the wrong service type. The facts cover identity, monitoring, test environments, mail, CDN, API, storage, payments, and miscellaneous evidence. The judgments describe what those invented facts mean. They are not sampled from a real deployment, and some category labels are synthetic rather than current collector output. This is a held-out *fixture* relative to the earlier v2 probe, not a representative production relevance benchmark.

The [result JSON](inventory-retrieval-evaluation-v3.json) records model revisions, ONNX artifact digests, dimensions, timing, per-query top five, and metrics. PostgreSQL 18 lexical retrieval used the new any-term query with a maximum of 32 distinct terms. Hybrid used reciprocal rank fusion with constant 60 over up to 100 candidates per path. Both candidate models ran from previously provisioned local caches with network access disabled. Vector coordinates were rounded to half precision to model pgvector `halfvec` storage and query casts. An otherwise identical full-precision run produced the same top-five rankings and summary metrics on these 16 queries; this does not prove equivalence on other corpora. The host was an Apple M4 Pro, `darwin/arm64`; FastEmbed was 0.8.1, and the database was a disposable PostgreSQL 18.6/pgvector 0.8.6 container.

| Retrieval path | Mean nDCG@10 | Mean Recall@20 |
| --- | ---: | ---: |
| PostgreSQL any-term lexical | 0.473 | 0.471 |
| BGE small v1.5 | 0.849 | 0.901 |
| BGE small + lexical | 0.851 | 0.917 |
| MiniLM L6 v2 | 0.835 | 0.956 |
| MiniLM + lexical | 0.819 | 0.956 |

MiniLM is the initial recommended local model because it retrieved more of the judged relevant assets by rank 20 on this corpus, led the earlier 30-document probe on both metrics, and completed this corpus's document and query inference faster. BGE had slightly better top-ten ranking here. Both candidates performed poorly on `content delivery edge cache`, and MiniLM also ranked historical or unreachable evidence weakly. Operators should inspect the retained description and source evidence; semantic similarity is not a provider claim or calibrated confidence. The selected MiniLM artifact is the Apache-2.0, 384-dimensional ONNX revision and SHA-256 recorded in the JSON. Its FastEmbed model description caps input at 256 tokens. Description format 3 keeps high-priority retained facts inside a 1,024-byte and 128-word bound and records dropped terms; the worker checks untruncated token count and rejects any remaining over-limit input instead of silently embedding a prefix. Such an asset remains available to lexical search and appears in embedding failure coverage until the description is revised.

The earlier [real-model capacity probe](local-embedding-worker.md) measured MiniLM with `vector` storage at 10,000 and 100,000 synthetic assets. The 10,000-asset warm hybrid p95 was 153 ms under ten concurrent readers. At 100,000 assets, p95 was 859 ms unscoped and 1.01 s with a selective scope. The [new half-precision and scoped-query probe](inventory-semantic-capacity.md#half-precision-and-scope-query-follow-up) reduced the deterministic-embedder path but still measured 674 ms unscoped hybrid p95. The 500 ms target remains unmet for that case. Deployments approaching 100,000 assets should measure their own query mix and capacity before relying on a sub-500 ms service objective.

To regenerate the corpus and repeat the local model evaluation:

```sh
go run ./scripts/generate-inventory-corpus \
  --input docs/benchmarks/inventory-retrieval-facts-v3.json \
  --output docs/benchmarks/inventory-retrieval-corpus-v3.json
HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
uv run --with fastembed==0.8.1 --with 'psycopg[binary]==3.3.6' \
  python scripts/evaluate-inventory-retrieval.py \
  --corpus docs/benchmarks/inventory-retrieval-corpus-v3.json \
  --cache-dir /path/to/pinned-model-cache \
  --postgres-dsn 'postgres://postgres@127.0.0.1:5432/disposable?sslmode=disable' \
  --lexical-mode any \
  --vector-precision half \
  --output docs/benchmarks/inventory-retrieval-evaluation-v3.json
```

The evaluator computes rankings in process from local vectors; it does not exercise HTTP admission, the live projection queue, concurrent writes, or an actual production dataset. The lifecycle and capacity tests cover those paths separately where noted.
