#!/usr/bin/env python3
"""Measure process startup and first request for an offline local worker."""

import argparse
import http.client
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(self.path)


def request(path, method, route, body=None):
    client = UnixHTTP(path)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        client.request(method, route, body=body, headers=headers)
        response = client.getresponse()
        return response.status, json.load(response)
    finally:
        client.close()


def measure(worker, source_contract, cache_dir, run):
    with tempfile.TemporaryDirectory(prefix="caw-start-", dir="/tmp") as root:
        directory = pathlib.Path(root)
        contract = dict(source_contract)
        contract["generation_id"] = f"startup-{run}"
        contract_path = directory / "contract.json"
        contract_path.write_text(json.dumps(contract))
        socket_path = directory / f"startup-{run}.sock"
        started = time.perf_counter()
        process = subprocess.Popen(
            [sys.executable, worker, "--contract", str(contract_path),
             "--cache-dir", cache_dir, "--socket-dir", str(directory)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            deadline = started + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"worker exited during startup: {process.stderr.read().decode()[-500:]}")
                if socket_path.exists():
                    try:
                        status, health = request(str(socket_path), "GET", "/health")
                        if status == 200 and health == contract:
                            break
                    except (ConnectionError, TimeoutError, OSError):
                        pass
                if time.perf_counter() >= deadline:
                    raise TimeoutError("worker did not become ready within 20 seconds")
                time.sleep(0.01)
            ready_ms = (time.perf_counter() - started) * 1000
            first_started = time.perf_counter()
            status, result = request(str(socket_path), "POST", "/embed",
                                     json.dumps({"text": "customer login service"}).encode())
            first_ms = (time.perf_counter() - first_started) * 1000
            if status != 200 or len(result.get("vector", [])) != contract["dimensions"]:
                raise RuntimeError("first embedding request failed or returned wrong dimensions")
            return round(ready_ms, 2), round(first_ms, 2)
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", default="scripts/embedding-worker.py")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.runs < 1 or args.runs > 10:
        parser.error("runs must be between 1 and 10")
    contract = json.loads(pathlib.Path(args.contract).read_text())
    ready, first = [], []
    for index in range(args.runs):
        ready_ms, first_ms = measure(args.worker, contract, args.cache_dir, index)
        ready.append(ready_ms)
        first.append(first_ms)
    print(json.dumps({"runs": args.runs, "ready_ms": ready, "first_embed_ms": first}, sort_keys=True))


if __name__ == "__main__":
    main()
