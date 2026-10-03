#!/usr/bin/env python3
"""Measure pinned local model inference without network access or retained text."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import resource
import time
from pathlib import Path


ARTIFACTS = {
    "BAAI/bge-small-en-v1.5": ("models--Qdrant--bge-small-en-v1.5-onnx-Q", "model_optimized.onnx"),
    "sentence-transformers/all-MiniLM-L6-v2": ("models--qdrant--all-MiniLM-L6-v2-onnx", "model.onnx"),
}


def peak_rss_bytes():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if platform.system() == "Darwin" else value * 1024


def verify_artifact(cache_directory, model_id, expected):
    repository, filename = ARTIFACTS[model_id]
    root = Path(cache_directory).resolve(strict=True)
    cache = root / repository
    revision = (cache / "refs" / "main").read_text().strip()
    if revision != expected["source_revision"]:
        raise ValueError("cached model revision differs from pinned evaluation")
    artifact = (cache / "snapshots" / revision / filename).resolve(strict=True)
    if not artifact.is_relative_to(root) or not artifact.is_file():
        raise ValueError("model artifact escapes the configured cache")
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected["model_file_sha256"]:
        raise ValueError("cached model digest differs from pinned evaluation")
    return artifact.stat().st_size


def descriptions(corpus, count):
    items = [item["description"] for item in corpus["documents"]]
    if not items or any(not isinstance(item, str) or not item for item in items):
        raise ValueError("corpus must contain nonempty rendered descriptions")
    for index in range(count):
        source = items[index % len(items)]
        yield re.sub(r"hostname \S+", f"hostname q{index:06d}.example.com", source, count=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=ARTIFACTS, required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--corpus", default="docs/benchmarks/inventory-retrieval-corpus-v2.json")
    parser.add_argument("--pins", default="docs/benchmarks/inventory-retrieval-evaluation-v2.json")
    parser.add_argument("--count", type=int, default=100000)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.count < 10000 or args.count > 100000:
        parser.error("count must be between 10000 and 100000")
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    if importlib.metadata.version("fastembed") != "0.8.1":
        raise RuntimeError("FastEmbed 0.8.1 is required")
    pins = json.loads(Path(args.pins).read_text())
    expected = pins["models"][args.model]
    checked_at = time.perf_counter()
    artifact_bytes = verify_artifact(args.cache_dir, args.model, expected)
    verification_seconds = time.perf_counter() - checked_at
    corpus = json.loads(Path(args.corpus).read_text())
    from fastembed import TextEmbedding

    started = time.perf_counter()
    model = TextEmbedding(model_name=args.model, cache_dir=args.cache_dir, local_files_only=True, threads=4)
    load_seconds = time.perf_counter() - started
    load_peak_rss = peak_rss_bytes()
    checkpoints = []
    started = time.perf_counter()
    for index, vector in enumerate(model.embed(descriptions(corpus, args.count), batch_size=256), start=1):
        if len(vector) != expected["dimensions"]:
            raise ValueError("model output dimensions differ from pinned evaluation")
        if index in (10000, args.count):
            elapsed = time.perf_counter() - started
            checkpoints.append({"documents": index, "embedding_seconds": elapsed,
                                "documents_per_second": index / elapsed, "peak_rss_bytes": peak_rss_bytes()})
            print(f"embedded={index} elapsed_seconds={elapsed:.3f} peak_rss_bytes={checkpoints[-1]['peak_rss_bytes']}", flush=True)
    if not checkpoints or checkpoints[-1]["documents"] != args.count:
        raise RuntimeError("embedding stream ended before requested count")
    result = {
        "model_id": args.model,
        "model_revision": expected["source_revision"],
        "artifact_sha256": expected["model_file_sha256"],
        "artifact_bytes": artifact_bytes,
        "fastembed_version": "0.8.1",
        "corpus_version": corpus["version"],
        "source_document_count": len(corpus["documents"]),
        "synthetic_hostname_pattern": "qNNNNNN.example.com",
        "threads": 4,
        "batch_size": 256,
        "platform": platform.platform(),
        "verification_seconds": verification_seconds,
        "model_load_seconds": load_seconds,
        "model_load_peak_rss_bytes": load_peak_rss,
        "checkpoints": checkpoints,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
