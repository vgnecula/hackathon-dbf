"""In-memory sandbox.

The decoupler: attackers (Track B) and detectors (Track C) can be built and unit-tested
against this with no Docker, no network and no API keys, in milliseconds.

`exec` cannot really run anything, so it delegates to a pluggable handler. The default
handler is a small pytest simulator: it collects ``def test_*`` from the targeted test
files and reports them as passing unless listed in :attr:`FakeSandbox.failing_tests`.
That is enough to exercise the whole harness — including the "tests were deleted so
nothing ran" path, which is the interesting one — without a container.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from typing import ClassVar

from rlint.models import EnvSpec
from rlint.sandbox.base import (
    BaseSandbox,
    ExecResult,
    build_layout,
    is_excluded,
    matches_any,
    normalize_path,
)

ExecHandler = Callable[["FakeSandbox", str, "int | None"], ExecResult]

_TEST_FN = re.compile(r"^\s*(?:async\s+)?def\s+(test_\w*)", re.MULTILINE)


def _target_dir(cmd: str) -> str | None:
    """The test path a grader command points at, if any."""
    for token in reversed(cmd.split()):
        if token.startswith("-"):
            continue
        if "test" in token and "/" in token or token.startswith("tests"):
            return normalize_path(token)
    return None


def simulate_pytest(sb: FakeSandbox, cmd: str, timeout_s: int | None = None) -> ExecResult:
    """Produce pytest-shaped output from the in-memory file tree."""
    target = _target_dir(cmd)
    collected: list[str] = []
    for path in sorted(sb.list_files()):
        if not (path.endswith(".py") and ("test" in path.rsplit("/", 1)[-1])):
            continue
        if target and not (path == target or path.startswith(target.rstrip("/") + "/")):
            continue
        for name in _TEST_FN.findall(sb.files[path]):
            collected.append(f"{path}::{name}")

    if not collected:
        # pytest exits 5 when it collects nothing. Whether that counts as success is
        # exactly the naive-grader bug E1 relies on.
        return ExecResult(exit_code=5, stdout="no tests ran in 0.01s")

    failed = [t for t in collected if t in sb.failing_tests]
    passed = len(collected) - len(failed)
    lines = ["." * passed + "F" * len(failed), ""]
    if failed:
        lines.append(f"{len(failed)} failed, {passed} passed in 0.05s")
    else:
        lines.append(f"{passed} passed in 0.05s")
    return ExecResult(exit_code=1 if failed else 0, stdout="\n".join(lines))


class FakeSandbox(BaseSandbox):
    #: Test ids ("path::test_name") that should report as failing.
    failing_tests: ClassVar[set[str]] = set()
    #: Swap in your own to script arbitrary command behaviour in a test.
    default_exec_handler: ClassVar[ExecHandler] = simulate_pytest

    def __init__(self, spec: EnvSpec, with_tests: bool, sandbox_id: str = "") -> None:
        super().__init__(spec, with_tests, sandbox_id or f"fake-{uuid.uuid4().hex[:8]}")
        self.files: dict[str, str] = {}
        self.outside_files: dict[str, str] = {}
        self.exec_log: list[str] = []
        self.exec_handler: ExecHandler | None = None

    @classmethod
    def create(cls, spec: EnvSpec, *, with_tests: bool) -> FakeSandbox:
        sb = cls(spec, with_tests)
        sb.write_files(build_layout(spec, with_tests=with_tests))
        return sb

    def exec(self, cmd: str, timeout_s: int | None = None) -> ExecResult:
        self.exec_log.append(cmd)
        handler = self.exec_handler or type(self).default_exec_handler
        return handler(self, cmd, timeout_s)

    def write_file(self, path: str, content: str) -> None:
        key = normalize_path(path)
        if key.startswith("../") or path.startswith("/") and not path.startswith("/workspace"):
            self.outside_files[path] = content
            return
        self.files[key] = content

    def read_file(self, path: str) -> str:
        key = normalize_path(path)
        if key in self.files:
            return self.files[key]
        raise FileNotFoundError(path)

    def read_file_absolute(self, path: str) -> str:
        if path in self.outside_files:
            return self.outside_files[path]
        raise FileNotFoundError(path)

    def delete_file(self, path: str) -> None:
        self.files.pop(normalize_path(path), None)

    def list_files(self, glob: str = "**/*") -> list[str]:
        return sorted(
            path
            for path in self.files
            if not is_excluded(path) and matches_any(path, [glob])
        )

    def destroy(self) -> None:
        self.destroyed = True
        self.files.clear()
