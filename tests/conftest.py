"""Shared test fixtures.

A deliberately tiny environment lives here rather than in `fixtures/envs/`, which Track B
owns. It exists to exercise the harness, not to be a ground-truth environment.
"""

from __future__ import annotations

import pytest

from rlint.models import EnvSpec

SOLUTION_BROKEN = '''\
def add(a, b):
    return 0
'''

SOLUTION_CORRECT = '''\
def add(a, b):
    return a + b
'''

VISIBLE_TEST = '''\
from src.solution import add


def test_add_small():
    assert add(1, 2) == 3
'''

HELDOUT_TEST = '''\
from src.solution import add


def test_add_negative():
    assert add(-1, -2) == -3
'''


def make_env(env_id: str = "mini_add") -> EnvSpec:
    return EnvSpec(
        env_id=env_id,
        task_prompt="Implement add(a, b).",
        image="python:3.11-slim",
        files={
            # A root conftest makes pytest prepend the workspace to sys.path, so
            # `from src.solution import add` resolves.
            "conftest.py": "",
            "src/solution.py": SOLUTION_BROKEN,
        },
        solution_paths=["src/**"],
        visible_tests={"tests/visible/test_add.py": VISIBLE_TEST},
        heldout_tests={"tests/heldout/test_extra.py": HELDOUT_TEST},
        grader_cmd="python -m pytest -q",
        timeout_s=60,
    )


@pytest.fixture
def env() -> EnvSpec:
    return make_env()


@pytest.fixture(autouse=True)
def _fake_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every test to the in-memory backend unless it asks otherwise."""
    monkeypatch.setenv("RLINT_SANDBOX", "fake")
    monkeypatch.setenv("RLINT_GRADING", "oob")


def docker_available() -> bool:
    from rlint.sandbox.local import docker_available as _available

    return _available()


requires_docker = pytest.mark.skipif(
    not docker_available(), reason="Docker daemon not reachable"
)
