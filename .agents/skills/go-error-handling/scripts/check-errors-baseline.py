#!/usr/bin/env python3
"""Compare check-errors findings for selected Go files at two Git commits."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import difflib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any


SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SCANNER_DIR = ".agents/skills/go-error-handling/scripts"
WRAPPER = f"{SCANNER_DIR}/check-errors.sh"
AST = f"{SCANNER_DIR}/check-errors-ast.go"
DISPLAY_LIMIT = 50


class ComparisonError(Exception):
    """The requested comparison cannot be performed safely."""


@dataclass(frozen=True)
class Finding:
    line: int
    rule: str
    message: str


def run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=False
    )


def checked(repo: Path, *args: str) -> str:
    result = run(repo, *args)
    if result.returncode:
        raise ComparisonError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def full_commit(repo: Path, value: str, label: str) -> str:
    if not SHA.fullmatch(value):
        raise ComparisonError(f"{label} must be a full lowercase repository object SHA")
    resolved = checked(repo, "rev-parse", f"{value}^{{commit}}")
    if resolved != value:
        raise ComparisonError(f"{label} does not resolve to the supplied immutable SHA")
    return resolved


def validate_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"", ".", "..", ".git", "vendor"} for part in path.parts)
        or path.suffix != ".go"
        or path.name.endswith("_test.go")
    ):
        raise ComparisonError(
            f"unsupported path {value!r}: select a repo-relative non-test Go file outside .git and vendor"
        )
    return path.as_posix()


def object_info(repo: Path, commit: str, path: str) -> tuple[str, str]:
    result = run(repo, "ls-tree", "-z", commit, "--", path)
    if result.returncode:
        raise ComparisonError(result.stderr.strip() or f"cannot inspect {path} at {commit}")
    record = result.stdout.rstrip("\0")
    if not record:
        raise ComparisonError(f"missing selected path {path} at {commit}")
    try:
        meta, actual_path = record.split("\t", 1)
        mode, kind, blob = meta.split()
    except ValueError as exc:
        raise ComparisonError(f"unexpected Git tree entry for {path} at {commit}") from exc
    if actual_path != path or kind != "blob" or mode not in {"100644", "100755"}:
        raise ComparisonError(f"selected path {path} at {commit} is not a tracked regular file")
    return mode, blob


def reject_rename(repo: Path, base: str, candidate: str, path: str) -> None:
    changed = checked(repo, "diff", "--name-status", "-M", base, candidate)
    for line in changed.splitlines():
        fields = line.split("\t")
        if fields and fields[0].startswith("R") and path in fields[1:]:
            raise ComparisonError(f"selected path {path} participates in a rename between base and candidate")


def git_blob(repo: Path, commit: str, path: str) -> tuple[str, bytes]:
    _, blob = object_info(repo, commit, path)
    result = subprocess.run(
        ["git", "cat-file", "blob", blob], cwd=repo, capture_output=True, check=False
    )
    if result.returncode:
        raise ComparisonError(f"cannot materialize {path} at {commit}")
    return blob, result.stdout


def scanner_provenance(repo: Path, base: str, candidate: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, path in (("wrapper_blob", WRAPPER), ("ast_blob", AST)):
        _, base_blob = object_info(repo, base, path)
        _, candidate_blob = object_info(repo, candidate, path)
        if base_blob != candidate_blob:
            raise ComparisonError(f"scanner {path} differs between base and candidate")
        local = (Path(__file__).resolve().parent / Path(path).name).read_bytes()
        recorded = subprocess.run(
            ["git", "cat-file", "blob", base_blob], cwd=repo, capture_output=True, check=False
        )
        if recorded.returncode or local != recorded.stdout:
            raise ComparisonError(f"invoking helper sibling {path} does not match the committed scanner blob")
        result[name] = base_blob
    return result


def materialize(root: Path, repo: Path, commit: str, path: str) -> Path:
    for scanner_path in (WRAPPER, AST):
        _, data = git_blob(repo, commit, scanner_path)
        destination = root / scanner_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    _, data = git_blob(repo, commit, path)
    selected = root / path
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_bytes(data)
    return selected


def scan(repo: Path, root: Path, selected: Path, environment: dict[str, str]) -> tuple[int, list[Finding], int]:
    wrapper = root / WRAPPER
    wrapper.chmod(0o755)
    result = subprocess.run(
        ["bash", str(wrapper), "--json", "--limit", "0", str(selected)],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    if result.returncode not in {0, 1}:
        raise ComparisonError(
            f"scanner failed for {selected.relative_to(root)} with exit {result.returncode}: {result.stderr.strip()}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ComparisonError(f"scanner returned invalid JSON for {selected.relative_to(root)}") from exc
    if not isinstance(payload, dict) or set(payload) != {"findings", "total", "truncated"}:
        raise ComparisonError(f"scanner returned an unsupported JSON structure for {selected.relative_to(root)}")
    findings_data = payload["findings"]
    total = payload["total"]
    if not isinstance(findings_data, list) or type(total) is not int or type(payload["truncated"]) is not bool:
        raise ComparisonError(f"scanner returned invalid finding metadata for {selected.relative_to(root)}")
    if payload["truncated"] or total != len(findings_data):
        raise ComparisonError(f"scanner response was truncated or has an inconsistent total for {selected.relative_to(root)}")
    if (result.returncode == 0) != (total == 0):
        raise ComparisonError(f"scanner exit status and total disagree for {selected.relative_to(root)}")
    source_line_count = len(selected.read_bytes().splitlines())
    findings: list[Finding] = []
    for item in findings_data:
        if not isinstance(item, dict) or set(item) != {"file", "line", "rule", "message"}:
            raise ComparisonError(f"scanner returned an invalid finding for {selected.relative_to(root)}")
        if (
            not isinstance(item["file"], str)
            or item["file"] != str(selected)
            or type(item["line"]) is not int
            or item["line"] < 1
            or item["line"] > source_line_count
            or not isinstance(item["rule"], str)
            or not item["rule"]
            or not isinstance(item["message"], str)
            or not item["message"]
        ):
            raise ComparisonError(f"scanner returned malformed finding values for {selected.relative_to(root)}")
        findings.append(Finding(item["line"], item["rule"], item["message"]))
    return result.returncode, findings, total


def line_mapping(base_bytes: bytes, candidate_bytes: bytes) -> dict[int, int]:
    base_lines = base_bytes.decode("utf-8", errors="surrogateescape").splitlines(keepends=True)
    candidate_lines = candidate_bytes.decode("utf-8", errors="surrogateescape").splitlines(keepends=True)
    mapping: dict[int, int] = {}
    matcher = difflib.SequenceMatcher(None, base_lines, candidate_lines, autojunk=False)
    for tag, base_start, base_end, candidate_start, _ in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(base_end - base_start):
                mapping[base_start + offset + 1] = candidate_start + offset + 1
    return mapping


def display(findings: Counter[tuple[str, int, str]]) -> tuple[list[dict[str, Any]], int, bool]:
    expanded = [
        {"rule": rule, "line": line, "message": message}
        for (rule, line, message), count in sorted(findings.items())
        for _ in range(count)
    ]
    return expanded[:DISPLAY_LIMIT], len(expanded), len(expanded) > DISPLAY_LIMIT


def compare_path(
    repo: Path, base: str, candidate: str, path: str, environment: dict[str, str]
) -> dict[str, Any]:
    base_mode, _ = object_info(repo, base, path)
    candidate_mode, _ = object_info(repo, candidate, path)
    if base_mode != candidate_mode:
        raise ComparisonError(f"selected path {path} changed regular-file mode between base and candidate")
    reject_rename(repo, base, candidate, path)
    base_blob, base_bytes = git_blob(repo, base, path)
    candidate_blob, candidate_bytes = git_blob(repo, candidate, path)
    with tempfile.TemporaryDirectory(prefix="check-errors-base-") as base_dir, tempfile.TemporaryDirectory(prefix="check-errors-candidate-") as candidate_dir:
        base_root = Path(base_dir)
        candidate_root = Path(candidate_dir)
        base_selected = materialize(base_root, repo, base, path)
        candidate_selected = materialize(candidate_root, repo, candidate, path)
        base_status, baseline, base_total = scan(repo, base_root, base_selected, environment)
        candidate_status, current, candidate_total = scan(repo, candidate_root, candidate_selected, environment)
    mapping = line_mapping(base_bytes, candidate_bytes)
    mapped_baseline = Counter((finding.rule, mapping[finding.line], finding.message) for finding in baseline if finding.line in mapping)
    candidate_findings = Counter((finding.rule, finding.line, finding.message) for finding in current)
    matched = candidate_findings & mapped_baseline
    added = candidate_findings - mapped_baseline
    unmatched = matched.copy()
    removed = Counter()
    for finding in baseline:
        mapped = (
            (finding.rule, mapping[finding.line], finding.message)
            if finding.line in mapping
            else None
        )
        if mapped is not None and unmatched[mapped]:
            unmatched[mapped] -= 1
            continue
        removed[(finding.rule, finding.line, finding.message)] += 1
    added_items, added_total, added_truncated = display(added)
    removed_items, removed_total, removed_truncated = display(removed)
    return {
        "path": path,
        "base_blob": base_blob,
        "candidate_blob": candidate_blob,
        "base_scan": {"exit_status": base_status, "total": base_total},
        "candidate_scan": {"exit_status": candidate_status, "total": candidate_total},
        "matched_count": sum(matched.values()),
        "added_total": added_total,
        "added": added_items,
        "added_truncated": added_truncated,
        "removed_total": removed_total,
        "removed": removed_items,
        "removed_truncated": removed_truncated,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--path", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        repo = Path(checked(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
        if Path.cwd().resolve() != repo:
            raise ComparisonError("run the helper from the repository Git toplevel")
        base = full_commit(repo, args.base, "base")
        candidate = full_commit(repo, args.candidate, "candidate")
        if checked(repo, "rev-parse", "HEAD") != candidate:
            raise ComparisonError("candidate must be HEAD in the invoking repository")
        if run(repo, "merge-base", "--is-ancestor", base, candidate).returncode:
            raise ComparisonError("base must be an ancestor of candidate")
        paths = [validate_path(path) for path in args.path]
        if len(paths) != len(set(paths)):
            raise ComparisonError("each selected path must be supplied once")
        provenance = scanner_provenance(repo, base, candidate)
        with tempfile.TemporaryDirectory(prefix="check-errors-cache-") as cache_dir:
            cache_root = Path(cache_dir)
            environment = os.environ.copy()
            environment["XDG_CACHE_HOME"] = str(cache_root / "xdg")
            environment["GOCACHE"] = str(cache_root / "go-build")
            comparisons = [
                compare_path(repo, base, candidate, path, environment) for path in paths
            ]
    except (ComparisonError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = {
        "schema_version": 1,
        "base": base,
        "candidate": candidate,
        "paths": comparisons,
        "scanner": provenance,
    }
    print(json.dumps(payload, sort_keys=True))
    return 1 if any(path["added_total"] for path in comparisons) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
