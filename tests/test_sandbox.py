"""Backend contract tests.

Every backend runs the same suite. Parity is the point: a rollout must produce the same
`Rollout` whether it ran on the fake, on Docker or on Daytona, so that dropping to the
fallback backend does not change the number we report.
"""

from __future__ import annotations

import pytest
from conftest import make_env, requires_docker

from rlint.models import EnvSpec
from rlint.sandbox import get_backend
from rlint.sandbox.base import glob_to_regex, matches_any, normalize_path

BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param("local", id="local", marks=[requires_docker, pytest.mark.docker]),
]


@pytest.fixture(params=BACKENDS)
def backend(request: pytest.FixtureRequest) -> str:
    return request.param


def _make(backend: str, spec: EnvSpec, *, with_tests: bool):
    return get_backend(backend).create(spec, with_tests=with_tests)


class TestLayout:
    def test_policy_sandbox_never_sees_heldout_tests(self, backend: str, env: EnvSpec) -> None:
        """The single most important invariant in the project.

        If held-out tests leak into the policy sandbox, the strongest detector is worthless.
        """
        sb = _make(backend, env, with_tests=False)
        try:
            files = sb.list_files()
            assert "src/solution.py" in files
            assert "tests/visible/test_add.py" in files
            assert "tests/heldout/test_extra.py" not in files
            assert not any(path.startswith("tests/heldout") for path in files)
        finally:
            sb.destroy()

    def test_grading_sandbox_has_both_suites(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=True)
        try:
            files = sb.list_files()
            assert "tests/visible/test_add.py" in files
            assert "tests/heldout/test_extra.py" in files
        finally:
            sb.destroy()


class TestFileOps:
    def test_write_read_round_trip(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=False)
        try:
            sb.write_file("src/new_module.py", "VALUE = 42\n")
            assert sb.read_file("src/new_module.py") == "VALUE = 42\n"
            assert "src/new_module.py" in sb.list_files()
        finally:
            sb.destroy()

    def test_write_creates_nested_directories(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=False)
        try:
            sb.write_file("src/deep/nested/mod.py", "x = 1\n")
            assert sb.read_file("src/deep/nested/mod.py") == "x = 1\n"
        finally:
            sb.destroy()

    def test_list_files_accepts_a_glob(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=False)
        try:
            assert sb.list_files("tests/**/*.py") == ["tests/visible/test_add.py"]
        finally:
            sb.destroy()

    def test_hash_tree_tracks_edits(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=False)
        try:
            before = sb.hash_tree()
            sb.write_file("src/solution.py", "def add(a, b):\n    return a + b\n")
            after = sb.hash_tree()
            assert before["src/solution.py"] != after["src/solution.py"]
            assert before["tests/visible/test_add.py"] == after["tests/visible/test_add.py"]
        finally:
            sb.destroy()

    def test_export_honours_the_allowlist(self, backend: str, env: EnvSpec) -> None:
        """Export is the chokepoint out-of-band grading depends on."""
        sb = _make(backend, env, with_tests=False)
        try:
            sb.write_file("tests/visible/test_add.py", "")  # E1, in miniature
            sb.write_file("conftest.py", "# tampered")
            exported = sb.export(env.solution_paths)
            assert set(exported) == {"src/solution.py"}
        finally:
            sb.destroy()

    def test_destroy_is_idempotent(self, backend: str, env: EnvSpec) -> None:
        sb = _make(backend, env, with_tests=False)
        sb.destroy()
        sb.destroy()
        assert sb.destroyed


class TestExec:
    @requires_docker
    @pytest.mark.docker
    def test_exec_reports_exit_code_and_output(self, env: EnvSpec) -> None:
        sb = _make("local", env, with_tests=False)
        try:
            ok = sb.exec("echo hello")
            assert ok.exit_code == 0
            assert "hello" in ok.stdout
            bad = sb.exec("exit 3")
            assert bad.exit_code == 3
        finally:
            sb.destroy()

    @requires_docker
    @pytest.mark.docker
    def test_network_is_blocked_when_the_spec_says_so(self, env: EnvSpec) -> None:
        """E7's precondition: `network: false` must actually mean no egress."""
        assert env.network is False
        sb = _make("local", env, with_tests=False)
        try:
            result = sb.exec(
                "python -c \"import socket; socket.create_connection(('1.1.1.1', 80), 3)\"",
                timeout_s=20,
            )
            assert result.exit_code != 0
        finally:
            sb.destroy()

    @requires_docker
    @pytest.mark.docker
    def test_egress_attempts_are_recorded(self, env: EnvSpec) -> None:
        sb = _make("local", env, with_tests=False)
        try:
            sb.exec(
                "python -c \"import socket;\n"
                "try: socket.create_connection(('example.com', 80), 2)\n"
                "except Exception: pass\" || true",
                timeout_s=20,
            )
            assert any("example.com" in entry for entry in sb.read_network_log())
        finally:
            sb.destroy()


class TestGlobs:
    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            ("src/**", "src/solution.py", True),
            ("src/**", "src/deep/nested.py", True),
            ("src/**", "tests/test_a.py", False),
            ("src/*", "src/deep/nested.py", False),
            ("src/*.py", "src/solution.py", True),
            ("**/*.py", "a/b/c.py", True),
            ("tests/**/*.py", "tests/visible/test_add.py", True),
            ("tests/**/*.py", "src/solution.py", False),
        ],
    )
    def test_star_does_not_cross_a_slash(self, pattern: str, path: str, expected: bool) -> None:
        """`fnmatch` gets this wrong, which would silently widen the allowlist."""
        assert bool(glob_to_regex(pattern).match(path)) is expected

    def test_bare_directory_covers_its_contents(self) -> None:
        assert matches_any("src/a/b.py", ["src"])

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("./src/a.py", "src/a.py"),
            ("/workspace/src/a.py", "src/a.py"),
            ("src//a.py", "src/a.py"),
            ("src/a.py", "src/a.py"),
        ],
    )
    def test_paths_normalise_to_workspace_relative(self, raw: str, expected: str) -> None:
        assert normalize_path(raw) == expected


def test_unknown_backend_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown sandbox backend"):
        get_backend("kubernetes")


def test_env_var_selects_the_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    from rlint.sandbox.fake import FakeSandbox

    monkeypatch.setenv("RLINT_SANDBOX", "fake")
    assert get_backend() is FakeSandbox


def test_fake_sandbox_simulates_pytest(env: EnvSpec) -> None:
    sb = get_backend("fake").create(make_env(), with_tests=True)
    try:
        assert sb.exec("python -m pytest -q tests/visible").exit_code == 0
        sb.write_file("tests/visible/test_add.py", "")
        sb.write_file("tests/heldout/test_extra.py", "")
        emptied = sb.exec("python -m pytest -q")
        assert emptied.exit_code == 5
        assert "no tests ran" in emptied.stdout
    finally:
        sb.destroy()
