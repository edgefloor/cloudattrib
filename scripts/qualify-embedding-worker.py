#!/usr/bin/env python3
"""Measure warm local embedding worker latency under simultaneous clients."""

import argparse
import concurrent.futures
import http.client
import json
import math
import socket
import statistics
import threading
import time


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


def embed(path, dimensions):
    client = UnixHTTP(path)
    started = time.perf_counter()
    try:
        body = json.dumps({"text": "customer login service"}).encode()
        client.request("POST", "/embed", body=body, headers={"Content-Type": "application/json"})
        response = client.getresponse()
        payload = json.load(response)
        if response.status != 200 or len(payload.get("vector", [])) != dimensions:
            raise RuntimeError(f"worker returned status {response.status} or wrong dimensions")
        return time.perf_counter() - started
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--waves", type=int, default=5)
    parser.add_argument("--dimensions", type=int, default=384)
    args = parser.parse_args()
    if args.concurrency < 1 or args.waves < 1 or args.dimensions < 1:
        parser.error("concurrency, waves, and dimensions must be positive")

    embed(args.socket, args.dimensions)
    samples = []
    for _ in range(args.waves):
        start = threading.Barrier(args.concurrency)

        def run():
            start.wait(timeout=10)
            return embed(args.socket, args.dimensions)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            samples.extend(pool.map(lambda _: run(), range(args.concurrency)))

    ordered = sorted(samples)
    output = {
        "samples": len(samples),
        "concurrency": args.concurrency,
        "p50_ms": round(statistics.median(samples) * 1000, 2),
        "p95_ms": round(ordered[math.ceil(0.95 * len(ordered)) - 1] * 1000, 2),
        "max_ms": round(ordered[-1] * 1000, 2),
    }
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
