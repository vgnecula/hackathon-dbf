"""Daytona adapter, against a stub SDK.

The adapter cannot be exercised without an API key, and it is the file most likely to
break under time pressure, so the SDK is stubbed and the adapter's own logic is tested:
snapshot reuse, keyword filtering, stream folding, rate-limit backoff and teardown.

The stub deliberately omits `ttl_minutes` from the create params, because tolerating an
SDK that does not know a keyword is the specific behaviour worth pinning down.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from typing import Any

import pytest
from conftest import make_env

import rlint.sandbox.daytona as adapter


class RateLimitError(Exception):
    def __init__(self, message: str = "429", headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.headers = headers or {}


@dataclass
class StubResources:
    cpu: int = 1
    memory: int = 1
    disk: int = 3


@dataclass
class StubImage:
    base_image: str
    packages: list[str] = field(default_factory=list)

    @classmethod
    def base(cls, image: str) -> StubImage:
        return cls(base_image=image)

    def pip_install(self, packages: list[str]) -> StubImage:
        self.packages = list(packages)
        return self


@dataclass
class StubFileUpload:
    source: bytes
    destination: str


@dataclass
class StubCreateSnapshotParams:
    name: str
    image: Any
    resources: Any = None


@dataclass
class StubCreateParams:
    """Note the absent `ttl_minutes` and `env_vars`: an older SDK than we expect."""

    snapshot: str | None = None
    ephemeral: bool = False
    auto_stop_interval: int = 15
    labels: dict[str, str] = field(default_factory=dict)
    network_block_all: bool = False


@dataclass
class StubConfig:
    api_key: str | None = None
    api_url: str | None = None
    target: str | None = None
    connection_pool_maxsize: int | None = None


class StubFs:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.folders: list[str] = []

    def create_folder(self, path: str, mode: str) -> None:
        self.folders.append(path)

    def upload_file(self, content: bytes, destination: str) -> None:
        self.files[destination] = content

    def upload_files(self, uploads: list[StubFileUpload]) -> None:
        for upload in uploads:
            self.files[upload.destination] = upload.source

    def download_file(self, path: str) -> bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]


@dataclass
class StubExecResponse:
    exit_code: int
    result: str


class StubProcess:
    def __init__(self, owner: StubSandboxHandle) -> None:
        self.owner = owner

    def exec(self, command: str, cwd: str | None = None, timeout: int | None = None):
        self.owner.commands.append(command)
        if "find ." in command:
            listing = sorted(
                path[len("/workspace/") :]
                for path in self.owner.fs.files
                if path.startswith("/workspace/")
            )
            return StubExecResponse(0, "\n".join(listing))
        if command.startswith("cat "):
            target = command.split()[1]
            data = self.owner.fs.files.get(target)
            if data is None:
                return StubExecResponse(1, "no such file")
            return StubExecResponse(0, data.decode())
        return StubExecResponse(0, "ok")


class StubSandboxHandle:
    def __init__(self, sandbox_id: str, params: StubCreateParams) -> None:
        self.id = sandbox_id
        self.params = params
        self.fs = StubFs({})
        self.process = StubProcess(self)
        self.commands: list[str] = []


class StubSnapshotService:
    def __init__(self) -> None:
        self.existing: set[str] = set()
        self.created: list[StubCreateSnapshotParams] = []

    def get(self, name: str) -> str:
        if name not in self.existing:
            raise LookupError(name)
        return name

    def create(self, params: StubCreateSnapshotParams, on_logs: Any = None) -> None:
        self.created.append(params)
        self.existing.add(params.name)


class StubClient:
    def __init__(self, config: StubConfig | None = None) -> None:
        self.config = config
        self.snapshot = StubSnapshotService()
        self.created: list[StubCreateParams] = []
        self.deleted: list[str] = []
        self.fail_with: list[Exception] = []

    def create(self, params: StubCreateParams, timeout: int | None = None) -> StubSandboxHandle:
        if self.fail_with:
            raise self.fail_with.pop(0)
        self.created.append(params)
        return StubSandboxHandle(f"sb-{len(self.created)}", params)

    def delete(self, handle: StubSandboxHandle) -> None:
        self.deleted.append(handle.id)


def build_stub_module() -> types.ModuleType:
    module = types.ModuleType("daytona")
    module.Daytona = StubClient
    module.DaytonaConfig = StubConfig
    module.CreateSandboxFromSnapshotParams = StubCreateParams
    module.CreateSnapshotParams = StubCreateSnapshotParams
    module.Image = StubImage
    module.Resources = StubResources
    module.FileUpload = StubFileUpload
    module.DaytonaRateLimitError = RateLimitError
    return module


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    module = build_stub_module()
    monkeypatch.setitem(sys.modules, "daytona", module)
    monkeypatch.setenv("DAYTONA_API_KEY", "test-key")
    monkeypatch.setattr(adapter, "_client", None)
    monkeypatch.setattr(adapter, "_snapshot_cache", {})
    return module


@pytest.fixture
def client(sdk: types.ModuleType) -> StubClient:
    return adapter.get_client()


class TestSnapshots:
    def test_name_is_stable_for_the_same_dependencies(self) -> None:
        assert adapter.snapshot_name(make_env()) == adapter.snapshot_name(make_env())

    def test_name_changes_when_dependencies_change(self) -> None:
        base = make_env()
        other = make_env()
        other.install = ["pytest", "numpy"]
        assert adapter.snapshot_name(base) != adapter.snapshot_name(other)

    def test_name_is_a_legal_identifier(self) -> None:
        env = make_env("Weird Env/Name!")
        assert adapter.snapshot_name(env).replace("-", "").isalnum()

    def test_dependencies_are_baked_in_once(self, client: StubClient) -> None:
        """Twenty concurrent rollouts must trigger exactly one build."""
        env = make_env()
        for _ in range(3):
            adapter.ensure_snapshot(env)
        assert len(client.snapshot.created) == 1
        assert client.snapshot.created[0].image.packages == ["pytest"]

    def test_an_existing_snapshot_is_reused(self, client: StubClient) -> None:
        env = make_env()
        client.snapshot.existing.add(adapter.snapshot_name(env))
        adapter.ensure_snapshot(env)
        assert client.snapshot.created == []


class TestCreate:
    def test_sandbox_is_ephemeral_and_never_auto_stops(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        params = client.created[0]
        assert params.ephemeral is True
        # Background compute does not reset Daytona's inactivity timer, so a non-zero
        # auto-stop would kill a long grading run mid-flight.
        assert params.auto_stop_interval == 0
        assert sb.sandbox_id == "sb-1"

    def test_unknown_keywords_are_dropped_rather_than_raising(self, client: StubClient) -> None:
        """`ttl_minutes` is missing from this SDK; creation must still succeed."""
        adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        assert not hasattr(client.created[0], "ttl_minutes")

    def test_network_is_blocked_unless_the_spec_allows_it(self, client: StubClient) -> None:
        blocked = make_env()
        assert blocked.network is False
        adapter.DaytonaSandbox.create(blocked, with_tests=False)
        assert client.created[0].network_block_all is True

        allowed = make_env()
        allowed.network = True
        adapter.DaytonaSandbox.create(allowed, with_tests=False)
        assert client.created[1].network_block_all is False

    def test_policy_sandbox_never_receives_heldout_tests(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        uploaded = set(sb._sb.fs.files)
        assert "/workspace/tests/visible/test_add.py" in uploaded
        assert "/workspace/tests/heldout/test_extra.py" not in uploaded

    def test_egress_monitor_lands_outside_the_workspace(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        assert "/opt/rlint/sitecustomize.py" in sb._sb.fs.files


class TestRateLimits:
    def test_creation_retries_and_then_succeeds(
        self, client: StubClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(adapter.time, "sleep", lambda _s: None)
        client.fail_with = [RateLimitError(headers={"retry-after-sandbox-create": "0"})]
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        assert sb.sandbox_id == "sb-1"

    def test_persistent_rate_limiting_raises_a_clear_error(
        self, client: StubClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(adapter.time, "sleep", lambda _s: None)
        client.fail_with = [RateLimitError() for _ in range(6)]
        with pytest.raises(adapter.DaytonaUnavailableError, match="rate limited"):
            adapter.DaytonaSandbox.create(make_env(), with_tests=False)

    def test_other_errors_are_not_retried(self, client: StubClient) -> None:
        client.fail_with = [RuntimeError("quota exhausted")]
        with pytest.raises(RuntimeError, match="quota exhausted"):
            adapter.DaytonaSandbox.create(make_env(), with_tests=False)


class TestOperations:
    def test_exec_folds_stderr_into_stdout(self, client: StubClient) -> None:
        """ExecuteResponse has no stderr field, so the shell has to merge the streams."""
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        sb.exec("python -m pytest -q")
        assert sb._sb.commands[-1].endswith("2>&1")

    def test_file_round_trip(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        sb.write_file("src/new.py", "VALUE = 1\n")
        assert sb.read_file("src/new.py") == "VALUE = 1\n"

    def test_paths_cannot_escape_the_workspace(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        with pytest.raises(ValueError, match="escapes workspace"):
            sb.write_file("../../etc/passwd", "nope")

    def test_export_honours_the_allowlist(self, client: StubClient) -> None:
        env = make_env()
        sb = adapter.DaytonaSandbox.create(env, with_tests=False)
        assert set(sb.export(env.solution_paths)) == {"src/solution.py"}

    def test_destroy_is_idempotent(self, client: StubClient) -> None:
        sb = adapter.DaytonaSandbox.create(make_env(), with_tests=False)
        sb.destroy()
        sb.destroy()
        assert client.deleted == ["sb-1"]


class TestClientConfiguration:
    def test_missing_api_key_fails_loudly(
        self, sdk: types.ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DAYTONA_API_KEY", raising=False)
        with pytest.raises(adapter.DaytonaUnavailableError, match="DAYTONA_API_KEY"):
            adapter.get_client()

    def test_connection_pool_is_uncapped_for_concurrent_execs(self, client: StubClient) -> None:
        assert client.config.connection_pool_maxsize is None

    def test_client_is_shared_across_threads(self, client: StubClient) -> None:
        assert adapter.get_client() is client


def test_missing_sdk_points_at_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "daytona", None)
    monkeypatch.setattr(adapter, "_client", None)
    with pytest.raises(adapter.DaytonaUnavailableError, match="RLINT_SANDBOX=local"):
        adapter.get_client()
