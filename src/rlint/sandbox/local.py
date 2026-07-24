"""Docker sandbox — the de-risking backend.

Built before the Daytona adapter on purpose: a Daytona API problem at 11:00 must not kill
the day. Semantics are deliberately identical to the Daytona backend so a rollout produces
the same `Rollout` on either.

The workspace is a host temp directory bind-mounted at /workspace, so file operations are
plain filesystem calls and only `exec` pays the container round-trip.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid

from rlint.config import get_config
from rlint.models import EnvSpec
from rlint.sandbox.base import (
    NET_LOG,
    NETWORK_MONITOR,
    RLINT_LIB,
    WORKDIR,
    BaseSandbox,
    ExecResult,
    build_layout,
    is_excluded,
    matches_any,
    normalize_path,
)

MAX_FILE_BYTES = 256 * 1024


class DockerUnavailableError(RuntimeError):
    pass


def _docker(*args: str, timeout: int = 120, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        input=stdin,
        check=False,
    )


def docker_available() -> bool:
    try:
        return _docker("info", timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class LocalSandbox(BaseSandbox):
    def __init__(self, spec: EnvSpec, with_tests: bool, container: str, host_dir: str) -> None:
        super().__init__(spec, with_tests, sandbox_id=container)
        self.container = container
        self.host_dir = host_dir

    @classmethod
    def create(cls, spec: EnvSpec, *, with_tests: bool) -> LocalSandbox:
        if not docker_available():
            raise DockerUnavailableError(
                "Docker daemon is not reachable. Set RLINT_SANDBOX=fake or start Docker."
            )
        cfg = get_config()
        host_dir = tempfile.mkdtemp(prefix="rlint-ws-")
        os.chmod(host_dir, 0o777)
        container = f"rlint-{uuid.uuid4().hex[:10]}"

        run_args = [
            "run", "-d", "--name", container,
            "-w", WORKDIR,
            "-v", f"{host_dir}:{WORKDIR}",
            "--memory", "1g", "--cpus", "1",
        ]
        run_args += [spec.image, "sleep", "infinity"]
        result = _docker(*run_args, timeout=600 if cfg.docker_image_pull else 60)
        if result.returncode != 0:
            shutil.rmtree(host_dir, ignore_errors=True)
            raise DockerUnavailableError(f"docker run failed: {result.stderr.strip()}")

        sb = cls(spec, with_tests, container, host_dir)
        try:
            sb.write_files(build_layout(spec, with_tests=with_tests))
            sb._install_network_monitor()
            sb._install_packages()
            if not spec.network:
                # Installs need egress, so the container starts connected and is cut off
                # afterwards. E7 must be able to succeed pre-patch and fail post-patch.
                _docker("network", "disconnect", "bridge", container, timeout=30)
        except Exception:
            sb.destroy()
            raise
        return sb

    # --- primitives ------------------------------------------------------------------

    def exec(self, cmd: str, timeout_s: int | None = None) -> ExecResult:
        timeout = timeout_s or self.spec.timeout_s
        started = time.monotonic()
        try:
            proc = _docker(
                "exec",
                "-w", WORKDIR,
                "-e", f"PYTHONPATH={RLINT_LIB}",
                "-e", f"RLINT_NET_LOG={NET_LOG}",
                self.container,
                "sh", "-c", cmd,
                timeout=timeout + 10,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                exit_code=124,
                stdout="",
                stderr=f"timed out after {timeout}s",
                wall_time_s=time.monotonic() - started,
                timed_out=True,
            )
        return ExecResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            wall_time_s=time.monotonic() - started,
        )

    def write_file(self, path: str, content: str) -> None:
        target = self._host_path(path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)

    def read_file(self, path: str) -> str:
        target = self._host_path(path)
        try:
            with open(target, encoding="utf-8", errors="replace") as fh:
                return fh.read(MAX_FILE_BYTES)
        except IsADirectoryError as exc:
            raise FileNotFoundError(path) from exc

    def read_file_absolute(self, path: str) -> str:
        proc = _docker("exec", self.container, "cat", path, timeout=30)
        if proc.returncode != 0:
            raise FileNotFoundError(path)
        return proc.stdout

    def list_files(self, glob: str = "**/*") -> list[str]:
        found: list[str] = []
        for root, _dirs, names in os.walk(self.host_dir):
            for name in names:
                rel = normalize_path(os.path.relpath(os.path.join(root, name), self.host_dir))
                if not is_excluded(rel) and matches_any(rel, [glob]):
                    found.append(rel)
        return sorted(found)

    def destroy(self) -> None:
        if self.destroyed:
            return
        self.destroyed = True
        # The container runs as root, so anything it created is root-owned and the host
        # user cannot clean it up until ownership comes back.
        _docker(
            "exec", self.container,
            "chown", "-R", f"{os.getuid()}:{os.getgid()}", WORKDIR,
            timeout=30,
        )
        _docker("rm", "-f", self.container, timeout=60)
        shutil.rmtree(self.host_dir, ignore_errors=True)

    # --- helpers ---------------------------------------------------------------------

    def _host_path(self, path: str) -> str:
        rel = normalize_path(path)
        if rel.startswith(".."):
            raise ValueError(f"path escapes workspace: {path}")
        return os.path.join(self.host_dir, rel)

    def _install_network_monitor(self) -> None:
        _docker(
            "exec", "-i", self.container,
            "sh", "-c", f"mkdir -p {RLINT_LIB} && cat > {RLINT_LIB}/sitecustomize.py",
            stdin=NETWORK_MONITOR,
            timeout=60,
        )

    def _install_packages(self) -> None:
        if not self.spec.install:
            return
        packages = " ".join(self.spec.install)
        result = self.exec(f"pip install --quiet --no-input {packages} 2>&1", timeout_s=300)
        if result.exit_code != 0:
            raise RuntimeError(f"pip install failed in {self.container}: {result.output[-2000:]}")
