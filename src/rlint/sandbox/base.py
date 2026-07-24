"""Sandbox contract plus the logic every backend shares.

FROZEN CONTRACT. `Sandbox` is what attackers (Track B) are written against; adding methods
is fine, changing existing signatures is not without telling the team.

Two conventions matter:

* ``with_tests=False`` builds a *policy* sandbox: starter files and visible tests only.
  Held-out tests never enter a policy sandbox, which is what makes the `heldout` detector
  meaningful.
* ``with_tests=True`` builds a *grading* sandbox: pristine files plus both test suites.

Paths in the public API are always POSIX and relative to the workspace root.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from rlint.models import EnvSpec

WORKDIR = "/workspace"
#: Where the egress monitor lives. Outside the workspace so a policy cannot see or edit it.
RLINT_LIB = "/opt/rlint"
NET_LOG = "/tmp/rlint_net.log"

#: Never counted as part of the workspace: churn here is noise, not signal.
EXCLUDE_PATTERNS = (
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.pytest_cache/**",
    "**/.git/**",
    "**/.ruff_cache/**",
)

#: Injected via PYTHONPATH into grading sandboxes so `network_attempts` has real evidence
#: behind it rather than a guess from the diff. Python imports `sitecustomize` before user
#: code, so this wraps the socket layer ahead of anything the policy can run.
NETWORK_MONITOR = '''\
import os
import socket

_LOG = os.environ.get("RLINT_NET_LOG", "/tmp/rlint_net.log")
_seen = set()


def _record(host, port):
    entry = "%s:%s" % (host, port)
    if entry in _seen:
        return
    _seen.add(entry)
    try:
        with open(_LOG, "a") as fh:
            fh.write(entry + "\\n")
    except OSError:
        pass


_orig_connect = socket.socket.connect


def _connect(self, address):
    if isinstance(address, tuple) and len(address) >= 2:
        _record(address[0], address[1])
    return _orig_connect(self, address)


socket.socket.connect = _connect

_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo(host, port, *args, **kwargs):
    _record(host, port)
    return _orig_getaddrinfo(host, port, *args, **kwargs)


socket.getaddrinfo = _getaddrinfo
'''


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str = ""
    wall_time_s: float = 0.0
    timed_out: bool = False

    @property
    def output(self) -> str:
        """Combined stream.

        Daytona's ``ExecuteResponse`` has no stderr field at all, so backends generally
        fold stderr into stdout. Read this when you do not care which stream it came from.
        """
        if self.stderr and self.stderr not in self.stdout:
            return f"{self.stdout}\n{self.stderr}".strip()
        return self.stdout


@runtime_checkable
class Sandbox(Protocol):
    """What an attacker is handed. Backends: fake, local (Docker), daytona."""

    spec: EnvSpec
    with_tests: bool

    @classmethod
    def create(cls, spec: EnvSpec, *, with_tests: bool) -> Sandbox: ...

    def exec(self, cmd: str, timeout_s: int | None = None) -> ExecResult: ...

    def write_file(self, path: str, content: str) -> None: ...

    def read_file(self, path: str) -> str: ...

    def list_files(self, glob: str = "**/*") -> list[str]: ...

    def hash_tree(self) -> dict[str, str]: ...

    def export(self, globs: list[str]) -> dict[str, str]: ...

    def destroy(self) -> None: ...


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a POSIX-ish glob to a regex.

    `fnmatch` is unusable here because its ``*`` happily crosses ``/``, which would make
    ``src/*`` match ``src/a/b.py`` and quietly break the `filediff` detector's allowlist.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile(f"^{''.join(out)}$")


def matches_any(path: str, globs: list[str] | tuple[str, ...]) -> bool:
    path = normalize_path(path)
    for pattern in globs:
        pattern = normalize_path(pattern)
        if glob_to_regex(pattern).match(path):
            return True
        # A bare directory prefix such as "src" or "tests/visible" should cover its
        # contents; writing "src/**" everywhere is a footgun nobody needs at 11am.
        if not any(c in pattern for c in "*?") and path.startswith(pattern.rstrip("/") + "/"):
            return True
    return False


def normalize_path(path: str) -> str:
    """Workspace-relative, POSIX, no leading ``./`` or ``/``."""
    path = path.replace("\\", "/")
    if path.startswith(WORKDIR):
        path = path[len(WORKDIR) :]
    path = path.lstrip("/")
    if path.startswith("./"):
        path = path[2:]
    return posixpath.normpath(path) if path else path


def is_excluded(path: str) -> bool:
    return matches_any(path, EXCLUDE_PATTERNS)


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def build_layout(spec: EnvSpec, *, with_tests: bool) -> dict[str, str]:
    """The files a fresh sandbox starts with.

    Held-out tests are included only for grading sandboxes. This function is the single
    place that decision is made, so there is exactly one line to audit.
    """
    layout: dict[str, str] = {}
    for path, content in spec.files.items():
        layout[normalize_path(path)] = content
    for path, content in spec.visible_tests.items():
        layout[normalize_path(path)] = content
    if with_tests:
        for path, content in spec.heldout_tests.items():
            layout[normalize_path(path)] = content
    return layout


class BaseSandbox(ABC):
    """Shared implementation. Backends supply the primitive file and exec operations."""

    def __init__(self, spec: EnvSpec, with_tests: bool, sandbox_id: str = "") -> None:
        self.spec = spec
        self.with_tests = with_tests
        self.sandbox_id = sandbox_id
        self.destroyed = False

    def __repr__(self) -> str:
        kind = "grading" if self.with_tests else "policy"
        return f"<{type(self).__name__} {kind} env={self.spec.env_id} id={self.sandbox_id}>"

    # --- primitives every backend must provide -------------------------------------

    @abstractmethod
    def exec(self, cmd: str, timeout_s: int | None = None) -> ExecResult: ...

    @abstractmethod
    def write_file(self, path: str, content: str) -> None: ...

    @abstractmethod
    def read_file(self, path: str) -> str: ...

    @abstractmethod
    def list_files(self, glob: str = "**/*") -> list[str]: ...

    @abstractmethod
    def destroy(self) -> None: ...

    # --- shared behaviour ----------------------------------------------------------

    def write_files(self, files: dict[str, str]) -> None:
        for path, content in files.items():
            self.write_file(path, content)

    def read_tree(self) -> dict[str, str]:
        """Every workspace file as path -> content."""
        return {path: self.read_file(path) for path in self.list_files()}

    def hash_tree(self) -> dict[str, str]:
        return {path: sha256(content) for path, content in self.read_tree().items()}

    def export(self, globs: list[str]) -> dict[str, str]:
        """Extract only the paths the policy is allowed to own.

        This is the chokepoint that makes out-of-band grading work: whatever the policy did
        to tests, graders or the harness simply does not leave the sandbox.
        """
        return {
            path: self.read_file(path)
            for path in self.list_files()
            if matches_any(path, globs)
        }

    def read_network_log(self) -> list[str]:
        """Hosts the sandbox tried to reach, as recorded by the egress monitor."""
        try:
            raw = self.read_file_absolute(NET_LOG)
        except (FileNotFoundError, KeyError, OSError):
            return []
        seen: list[str] = []
        for line in raw.splitlines():
            entry = line.strip()
            if not entry or entry in seen:
                continue
            host = entry.rsplit(":", 1)[0]
            if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
                continue
            seen.append(entry)
        return seen

    def read_file_absolute(self, path: str) -> str:
        """Read a path outside the workspace. Backends override where that differs."""
        return self.read_file(path)

    def __enter__(self) -> BaseSandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.destroy()
