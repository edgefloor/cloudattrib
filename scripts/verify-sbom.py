#!/usr/bin/env python3
"""Verify that the checked-in CycloneDX file lists every linked Go module."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SBOM = ROOT / "sbom" / "cloudattrib.cdx.json"


def main() -> int:
    document = json.loads(SBOM.read_text(encoding="utf-8"))
    recorded = {
        (component["name"], component["version"])
        for component in document["components"]
        if component.get("type") == "library" and component.get("properties") == [{"name": "cloudattrib:ecosystem", "value": "go"}]
    }
    output = subprocess.check_output(
        [
            "go",
            "list",
            "-deps",
            "-f",
            "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}",
            "./cmd/cloudattrib",
        ],
        cwd=ROOT,
        text=True,
    )
    linked = {tuple(line.split(" ", 1)) for line in output.splitlines() if line.strip()}
    missing = sorted(linked - recorded)
    stale = sorted(recorded - linked)
    if missing or stale:
        if missing:
            print("SBOM missing linked modules:", *missing, sep="\n  ", file=sys.stderr)
        if stale:
            print("SBOM contains unlinked Go modules:", *stale, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
