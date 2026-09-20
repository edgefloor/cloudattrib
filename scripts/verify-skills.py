#!/usr/bin/env python3
"""Check copied skill packages against their recorded content hashes."""

import hashlib
import json
import os
from pathlib import Path
import sys


def package_hash(directory):
    entries = []
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError(f"unexpected package symlink: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError(f"unexpected package entry: {path}")
            entries.append({
                "executable": bool(path.stat().st_mode & 0o111),
                "path": path.relative_to(directory).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
    entries.sort(key=lambda entry: entry["path"])
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "skills-lock.json").read_text())
    if lock["version"] != 1 or lock["hashAlgorithm"] != "sha256-path-content-v1":
        raise ValueError("unsupported skill lock format")
    canonical = root / ".agents/skills"
    records = lock["skills"]
    if {path.name for path in canonical.iterdir()} != set(records):
        raise ValueError("skill inventory differs from skills-lock.json")
    for name, record in sorted(records.items()):
        directory = canonical / name
        if directory.is_symlink() or not (directory / "SKILL.md").is_file():
            raise ValueError(f"invalid skill package: {name}")
        if package_hash(directory) != record["localHash"]:
            raise ValueError(f"skill hash mismatch: {name}")
    print(f"Verified {len(records)} Go skill packages.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Skill verification failed: {error}", file=sys.stderr)
        sys.exit(1)
