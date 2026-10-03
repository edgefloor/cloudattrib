#!/usr/bin/env python3
"""Serve explicitly provisioned FastEmbed models over a private Unix socket.

Install dependencies before launch. This process never downloads a model,
accepts network connections, or writes input text to ordinary logs.
"""

import argparse
import errno
import fcntl
import hashlib
import importlib.metadata
import json
import math
import os
import re
import signal
import socket
import socketserver
import stat
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path


MODELS = {
    "BAAI/bge-small-en-v1.5": ("models--Qdrant--bge-small-en-v1.5-onnx-Q", "model_optimized.onnx"),
    "sentence-transformers/all-MiniLM-L6-v2": ("models--qdrant--all-MiniLM-L6-v2-onnx", "model.onnx"),
}
MODEL_TOKEN_LIMITS = {
    "BAAI/bge-small-en-v1.5": 512,
    "sentence-transformers/all-MiniLM-L6-v2": 256,
}
SAFE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
MAXIMUM_BODY_BYTES = 16 * 1024


def load_contract(path):
    contract = json.loads(Path(path).read_text())
    required = {
        "generation_id", "model_id", "model_revision", "artifact_sha256", "license",
        "dimensions", "document_format_version", "preprocessing", "query_prefix",
        "document_prefix", "metric",
    }
    if (set(contract) != required or not isinstance(contract["generation_id"], str)
            or contract["generation_id"] in (".", "..")
            or not SAFE_ID.fullmatch(contract["generation_id"])):
        raise ValueError("invalid embedding generation contract")
    if contract["model_id"] not in MODELS or contract["metric"] != "cosine":
        raise ValueError("unsupported local embedding model or metric")
    if contract["preprocessing"] != "fastembed-0.8.1-default":
        raise ValueError("unsupported embedding preprocessing contract")
    if not isinstance(contract["dimensions"], int) or contract["dimensions"] != 384:
        raise ValueError("unsupported embedding dimensions")
    if not re.fullmatch(r"[a-f0-9]{64}", contract["artifact_sha256"]):
        raise ValueError("invalid model artifact digest")
    for key in ("model_revision", "license", "document_format_version", "query_prefix", "document_prefix"):
        if not isinstance(contract[key], str) or len(contract[key]) > 256 or "\x00" in contract[key]:
            raise ValueError("invalid model contract field")
    return contract


def verify_artifact(cache_dir, contract):
    repository, filename = MODELS[contract["model_id"]]
    root = Path(cache_dir).resolve(strict=True)
    cache = root / repository
    revision = (cache / "refs" / "main").read_text().strip()
    if revision != contract["model_revision"]:
        raise ValueError("cached model revision differs from generation contract")
    artifact = (cache / "snapshots" / revision / filename).resolve(strict=True)
    if not artifact.is_relative_to(root) or not artifact.is_file():
        raise ValueError("model artifact escapes the configured cache")
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != contract["artifact_sha256"]:
        raise ValueError("model artifact digest differs from generation contract")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, value):
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path != "/health":
            self.respond(404, {"error": "not_found"})
            return
        self.respond(200, self.server.contract)

    def do_POST(self):
        if self.path != "/embed":
            self.respond(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAXIMUM_BODY_BYTES:
                raise ValueError("invalid input length")
            payload = json.loads(self.rfile.read(length))
            text = payload["text"]
            if not isinstance(text, str) or not text or len(text.encode()) > 8192:
                raise ValueError("invalid input text")
            if len(self.server.untruncated_tokenizer.encode(text).ids) > MODEL_TOKEN_LIMITS[self.server.contract["model_id"]]:
                raise ValueError("input exceeds the selected model token limit")
            vector = next(iter(self.server.model.embed([text]))).tolist()
            if len(vector) != self.server.contract["dimensions"] or not all(math.isfinite(value) for value in vector):
                raise RuntimeError("invalid model output")
            self.respond(200, {"vector": vector})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.respond(422, {"error": "invalid_input"})
        except Exception:
            self.respond(503, {"error": "model_unavailable"})


class Server(socketserver.UnixStreamServer):
    # Ten concurrent searches can reach the socket before the single model
    # process accepts them. Keep the kernel backlog finite but large enough
    # to admit that supported burst.
    request_queue_size = 32
    allow_reuse_address = False

    def handle_error(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--socket-dir", required=True)
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["ORT_DISABLE_TELEMETRY"] = "1"
    if importlib.metadata.version("fastembed") != "0.8.1":
        raise RuntimeError("FastEmbed 0.8.1 is required")
    contract = load_contract(args.contract)
    verify_artifact(args.cache_dir, contract)
    from fastembed import TextEmbedding
    from tokenizers import Tokenizer

    model = TextEmbedding(model_name=contract["model_id"], cache_dir=args.cache_dir,
                          local_files_only=True, threads=4)
    untruncated_tokenizer = Tokenizer.from_str(model.model.tokenizer.to_str())
    untruncated_tokenizer.no_truncation()
    probe = next(iter(model.embed(["local model startup probe"])))
    if len(probe) != contract["dimensions"]:
        raise RuntimeError("model dimensions differ from generation contract")
    directory = Path(args.socket_dir)
    directory_info = directory.lstat()
    if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_mode & 0o077 or directory_info.st_uid != os.geteuid():
        raise ValueError("socket directory must be private and owned by this user")
    path = directory / (contract["generation_id"] + ".sock")
    lock_path = directory / (contract["generation_id"] + ".lock")
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        lock_info = os.fstat(lock.fileno())
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_mode & 0o077 or lock_info.st_uid != os.geteuid():
            raise ValueError("embedding worker lock must be private and owned by this user")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise FileExistsError("embedding generation worker is already running") from error
        if path.exists() or path.is_symlink():
            socket_info = path.lstat()
            if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != os.geteuid() or socket_info.st_mode & 0o077:
                raise FileExistsError("embedding socket path is not an owned private socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                connected = probe.connect_ex(str(path))
            if connected == 0:
                raise FileExistsError("embedding socket is already serving")
            if connected != errno.ECONNREFUSED:
                raise OSError(connected, "cannot verify stale embedding socket")
            path.unlink()
        with Server(str(path), Handler) as server:
            server.contract = contract
            server.model = model
            server.untruncated_tokenizer = untruncated_tokenizer
            os.chmod(path, 0o600)
            inode = path.stat().st_ino

            def stop(*_):
                threading.Thread(target=server.shutdown, daemon=True).start()

            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            try:
                server.serve_forever(poll_interval=0.1)
            finally:
                if path.exists() and path.stat().st_ino == inode:
                    path.unlink()


if __name__ == "__main__":
    main()
