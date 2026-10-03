#!/usr/bin/env python3
"""Measure local embedding retrieval on a fixed, synthetic judged corpus.

Dependencies are supplied explicitly at invocation. Production never runs this
script or downloads a model as part of search.
"""

import argparse
import hashlib
import importlib.metadata
import json
import math
import platform
import re
import resource
import time
from pathlib import Path


def ndcg_at(ranked, relevant, limit):
    actual = sum((1 / math.log2(position + 2)) for position, item in enumerate(ranked[:limit]) if item in relevant)
    ideal = sum(1 / math.log2(position + 2) for position in range(min(limit, len(relevant))))
    return actual / ideal if ideal else 0.0


def recall_at(ranked, relevant, limit):
    return len(set(ranked[:limit]) & relevant) / len(relevant) if relevant else 0.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="docs/benchmarks/inventory-retrieval-corpus-v2.json")
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--download", action="store_true", help="Explicitly provision missing model artifacts")
    parser.add_argument("--output", required=True)
    parser.add_argument("--postgres-dsn", help="Disposable PostgreSQL database for the current lexical query")
    parser.add_argument("--lexical-mode", choices=("all", "any"), default="all")
    parser.add_argument("--vector-precision", choices=("full", "half"), default="full")
    args = parser.parse_args()

    from fastembed import TextEmbedding
    import numpy as np

    corpus = json.loads(Path(args.corpus).read_text())
    documents = corpus["documents"]
    queries = corpus["queries"]
    ids = [document["id"] for document in documents]
    descriptions = [document["description"] for document in documents]
    query_texts = [query["text"] for query in queries]
    scores = {}
    lexical_rankings = []
    if args.postgres_dsn:
        import psycopg

        with psycopg.connect(args.postgres_dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("CREATE TEMP TABLE retrieval_eval(id text PRIMARY KEY, description text NOT NULL, search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple',description)) STORED)")
                cursor.executemany("INSERT INTO retrieval_eval(id,description) VALUES(%s,%s)", list(zip(ids, descriptions)))
                for query in queries:
                    if args.lexical_mode == "any":
                        terms = list(dict.fromkeys(re.findall(r"[^\W_]+", query["text"].lower())))
                        if not terms or len(terms) > 32:
                            raise ValueError("judged query exceeds the retrieval lexical term contract")
                        expression = " | ".join(terms)
                        cursor.execute("SELECT id FROM retrieval_eval WHERE search_vector @@ to_tsquery('simple',%s) ORDER BY ts_rank_cd(search_vector,to_tsquery('simple',%s)) DESC,id", (expression, expression))
                    else:
                        cursor.execute("SELECT id FROM retrieval_eval WHERE search_vector @@ plainto_tsquery('simple',%s) ORDER BY ts_rank_cd(search_vector,plainto_tsquery('simple',%s)) DESC,id", (query["text"], query["text"]))
                    lexical_rankings.append([row[0] for row in cursor.fetchall()])
    lexical_score = None
    if lexical_rankings:
        lexical_score = {
            "mean_ndcg10": sum(ndcg_at(ranked, set(query["relevant"]), 10) for ranked, query in zip(lexical_rankings, queries)) / len(queries),
            "mean_recall20": sum(recall_at(ranked, set(query["relevant"]), 20) for ranked, query in zip(lexical_rankings, queries)) / len(queries),
        }
    model_artifacts = {
        "BAAI/bge-small-en-v1.5": ("models--Qdrant--bge-small-en-v1.5-onnx-Q", "model_optimized.onnx"),
        "sentence-transformers/all-MiniLM-L6-v2": ("models--qdrant--all-MiniLM-L6-v2-onnx", "model.onnx"),
    }
    for model_name in ["BAAI/bge-small-en-v1.5", "sentence-transformers/all-MiniLM-L6-v2"]:
        started = time.perf_counter()
        model = TextEmbedding(
            model_name=model_name,
            cache_dir=args.cache_dir,
            local_files_only=not args.download,
            threads=4,
        )
        load_seconds = time.perf_counter() - started
        started = time.perf_counter()
        document_vectors = np.stack(list(model.embed(descriptions)))
        document_seconds = time.perf_counter() - started
        started = time.perf_counter()
        query_vectors = np.stack(list(model.embed(query_texts)))
        query_seconds = time.perf_counter() - started
        document_vectors /= np.linalg.norm(document_vectors, axis=1, keepdims=True)
        query_vectors /= np.linalg.norm(query_vectors, axis=1, keepdims=True)
        if args.vector_precision == "half":
            # pgvector halfvec rounds both stored and query coordinates before
            # cosine distance. Normalize again to mirror cosine ranking.
            document_vectors = document_vectors.astype(np.float16).astype(np.float32)
            query_vectors = query_vectors.astype(np.float16).astype(np.float32)
            document_vectors /= np.linalg.norm(document_vectors, axis=1, keepdims=True)
            query_vectors /= np.linalg.norm(query_vectors, axis=1, keepdims=True)
        similarities = query_vectors @ document_vectors.T
        ndcg = []
        recall = []
        ranked_examples = []
        hybrid_ndcg = []
        hybrid_recall = []
        for index, query in enumerate(queries):
            order = sorted(range(len(ids)), key=lambda candidate: (-float(similarities[index, candidate]), ids[candidate]))
            ranked = [ids[candidate] for candidate in order]
            relevant = set(query["relevant"])
            ndcg.append(ndcg_at(ranked, relevant, 10))
            recall.append(recall_at(ranked, relevant, 20))
            ranked_examples.append({"query": query["text"], "top5": ranked[:5], "ndcg10": ndcg[-1]})
            if lexical_rankings:
                fused = {}
                for candidate_rank, item in enumerate(ranked[:100]):
                    fused[item] = fused.get(item, 0) + 1 / (60 + candidate_rank + 1)
                for candidate_rank, item in enumerate(lexical_rankings[index][:100]):
                    fused[item] = fused.get(item, 0) + 1 / (60 + candidate_rank + 1)
                hybrid = sorted(fused, key=lambda item: (-fused[item], item))
                hybrid_ndcg.append(ndcg_at(hybrid, relevant, 10))
                hybrid_recall.append(recall_at(hybrid, relevant, 20))
        cache_repo, model_file = model_artifacts[model_name]
        cache_root = Path(args.cache_dir) / cache_repo
        revision = (cache_root / "refs" / "main").read_text().strip()
        artifact = cache_root / "snapshots" / revision / model_file
        scores[model_name] = {
            "source_revision": revision,
            "model_file_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "model_file_bytes": artifact.stat().st_size,
            "dimensions": int(document_vectors.shape[1]),
            "load_seconds": load_seconds,
            "document_seconds": document_seconds,
            "query_seconds": query_seconds,
            "mean_ndcg10": sum(ndcg) / len(ndcg),
            "mean_recall20": sum(recall) / len(recall),
            "per_query": ranked_examples,
        }
        if lexical_rankings:
            scores[model_name]["hybrid_mean_ndcg10"] = sum(hybrid_ndcg) / len(hybrid_ndcg)
            scores[model_name]["hybrid_mean_recall20"] = sum(hybrid_recall) / len(hybrid_recall)
    result = {
        "corpus_version": corpus["version"],
        "document_count": len(documents),
        "query_count": len(queries),
        "lexical_mode": args.lexical_mode,
        "vector_precision": args.vector_precision,
        "runtime": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "fastembed": importlib.metadata.version("fastembed"),
            "peak_maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "models": scores,
        "lexical": lexical_score,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"models": {name: {"mean_ndcg10": value["mean_ndcg10"], "mean_recall20": value["mean_recall20"]} for name, value in scores.items()}}))


if __name__ == "__main__":
    main()
