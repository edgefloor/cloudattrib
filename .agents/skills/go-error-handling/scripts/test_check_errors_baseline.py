#!/usr/bin/env python3
"""Behavioral tests for check-errors-baseline.py."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HELPER = HERE / "check-errors-baseline.py"
WRAPPER = HERE / "check-errors.sh"
AST = HERE / "check-errors-ast.go"
spec = importlib.util.spec_from_file_location("check_errors_baseline", HELPER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class BaselineComparatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        self.write_scanner()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True, check=True
        ).stdout.strip()

    def write(self, path: str, content: str) -> None:
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")

    def write_scanner(self) -> None:
        scanner_dir = self.repo / ".agents/skills/go-error-handling/scripts"
        scanner_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(WRAPPER, scanner_dir / WRAPPER.name)
        shutil.copy2(AST, scanner_dir / AST.name)

    def commit(self, message: str) -> str:
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def invoke(
        self, base: str, candidate: str, *paths: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "python3", "-B", str(HELPER), "--base", base, "--candidate", candidate,
        ]
        for path in paths:
            command.extend(("--path", path))
        return subprocess.run(
            command, cwd=self.repo, text=True, capture_output=True, check=False, env=environment
        )

    def seed(self, source: str) -> str:
        self.write("pkg/example.go", source)
        return self.commit("base")

    def test_shifted_baseline_is_not_added(self) -> None:
        base = self.seed("package pkg\nfunc f() error {\n var err error\n return err\n}\n")
        self.write("pkg/example.go", "// shifted\npackage pkg\nfunc f() error {\n var err error\n return err\n}\n")
        candidate = self.commit("shift")
        result = self.invoke(base, candidate, "pkg/example.go")
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(1, payload["paths"][0]["matched_count"])
        self.assertEqual(0, payload["paths"][0]["added_total"])

    def test_same_count_replacement_is_added(self) -> None:
        base = self.seed("package pkg\nfunc f() error {\n var err error\n return err\n}\n")
        self.write("pkg/example.go", "package pkg\nfunc f() error {\n var err error\n if err.Error() == \"bad\" { return nil }\n return nil\n}\n")
        candidate = self.commit("replace")
        result = self.invoke(base, candidate, "pkg/example.go")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(1, json.loads(result.stdout)["paths"][0]["added_total"])

    def test_added_and_clean_results(self) -> None:
        base = self.seed("package pkg\nfunc f() error { return nil }\n")
        self.write("pkg/example.go", "package pkg\nfunc f() error {\n var err error\n return err\n}\n")
        candidate = self.commit("add")
        self.assertEqual(1, self.invoke(base, candidate, "pkg/example.go").returncode)
        self.write("pkg/example.go", "package pkg\nfunc f() error { return nil }\n")
        clean = self.commit("clean")
        self.assertEqual(0, self.invoke(base, clean, "pkg/example.go").returncode)

    def test_scope_errors(self) -> None:
        base = self.seed("package pkg\nfunc f() error { return nil }\n")
        for path in ("pkg/example_test.go", "vendor/pkg/example.go", ".git/config.go", "pkg/missing.go"):
            with self.subTest(path=path):
                self.assertEqual(2, self.invoke(base, base, path).returncode)

    def test_different_scanner_is_rejected(self) -> None:
        base = self.seed("package pkg\nfunc f() error { return nil }\n")
        scanner = self.repo / ".agents/skills/go-error-handling/scripts/check-errors-ast.go"
        scanner.write_text(scanner.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        candidate = self.commit("scanner change")
        self.assertEqual(2, self.invoke(base, candidate, "pkg/example.go").returncode)

    def test_ambient_scanner_cache_cannot_replace_real_scan(self) -> None:
        base = self.seed("package pkg\nfunc f() error {\n var err error\n return err\n}\n")
        poison_root = self.repo / "poison"
        stamp = subprocess.run(
            ["cksum", str(WRAPPER.with_name("check-errors-ast.go"))],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.split()
        poisoned = poison_root / "golang-skills" / f"check-errors-ast-{stamp[0]}-{stamp[1]}"
        poisoned.parent.mkdir(parents=True)
        marker = self.repo / "poison-executed"
        poisoned.write_text(
            "#!/usr/bin/env bash\ntouch \"$POISON_MARKER\"\necho '{\"findings\":[],\"total\":0,\"truncated\":false}'\n",
            encoding="utf-8",
        )
        poisoned.chmod(0o755)
        environment = os.environ.copy()
        environment["XDG_CACHE_HOME"] = str(poison_root)
        environment["GOCACHE"] = str(poison_root / "go-build")
        environment["POISON_MARKER"] = str(marker)
        result = self.invoke(base, base, "pkg/example.go", environment=environment)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(marker.exists())
        payload = json.loads(result.stdout)["paths"][0]
        self.assertEqual(1, payload["base_scan"]["exit_status"])
        self.assertEqual(1, payload["candidate_scan"]["exit_status"])

    def test_scan_rejects_malformed_truncated_and_bad_exit(self) -> None:
        root = self.repo / "fixture"
        selected = root / "pkg/example.go"
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_text("package pkg\n", encoding="utf-8")
        wrapper = root / ".agents/skills/go-error-handling/scripts/check-errors.sh"
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        for body in (
            "echo not-json; exit 0",
            "echo '{\"findings\":[],\"total\":1,\"truncated\":true}'; exit 1",
            "echo '{\"findings\":[],\"total\":0,\"truncated\":false}'; exit 7",
            "echo '{\"findings\":[],\"total\":1,\"truncated\":false}'; exit 1",
        ):
            with self.subTest(body=body):
                wrapper.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
                wrapper.chmod(0o755)
                with self.assertRaises(module.ComparisonError):
                    module.scan(self.repo, root, selected, os.environ.copy())

    def test_scan_rejects_wrong_file_and_line(self) -> None:
        root = self.repo / "fixture"
        selected = root / "pkg/example.go"
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_text("package pkg\n", encoding="utf-8")
        wrapper = root / ".agents/skills/go-error-handling/scripts/check-errors.sh"
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        for item in (
            '{"file":"wrong.go","line":1,"rule":"r","message":"m"}',
            f'{{"file":"{selected}","line":2,"rule":"r","message":"m"}}',
        ):
            with self.subTest(item=item):
                wrapper.write_text(
                    "#!/usr/bin/env bash\n"
                    f"echo '{{\"findings\":[{item}],\"total\":1,\"truncated\":false}}'; exit 1\n",
                    encoding="utf-8",
                )
                wrapper.chmod(0o755)
                with self.assertRaises(module.ComparisonError):
                    module.scan(self.repo, root, selected, os.environ.copy())


if __name__ == "__main__":
    unittest.main()
