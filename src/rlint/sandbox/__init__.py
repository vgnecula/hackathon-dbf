"""Sandbox backends, selected by ``RLINT_SANDBOX=fake|local|daytona``."""

from __future__ import annotations

from typing import Any

from rlint.config import get_config
from rlint.models import EnvSpec
from rlint.sandbox.base import (
    WORKDIR,
    BaseSandbox,
    ExecResult,
    Sandbox,
    build_layout,
    matches_any,
    normalize_path,
    sha256,
)
from rlint.sandbox.fake import FakeSandbox

__all__ = [
    "WORKDIR",
    "BaseSandbox",
    "ExecResult",
    "FakeSandbox",
    "Sandbox",
    "build_layout",
    "create_sandbox",
    "get_backend",
    "matches_any",
    "normalize_path",
    "sha256",
]


def get_backend(name: str | None = None) -> Any:
    """Resolve a backend class by name. Daytona and Docker are imported lazily so the
    fake backend keeps working with neither installed."""
    name = (name or get_config().backend).lower()
    if name == "fake":
        return FakeSandbox
    if name == "local":
        from rlint.sandbox.local import LocalSandbox

        return LocalSandbox
    if name == "daytona":
        from rlint.sandbox.daytona import DaytonaSandbox

        return DaytonaSandbox
    raise ValueError(f"unknown sandbox backend: {name!r} (expected fake, local or daytona)")


def create_sandbox(spec: EnvSpec, *, with_tests: bool, backend: str | None = None) -> BaseSandbox:
    return get_backend(backend).create(spec, with_tests=with_tests)
