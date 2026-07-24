"""Daytona sandbox.

Notes that cost time to discover, so they are written down here:

* Quotas are vCPU pools, not sandbox counts. Tier 1 is 10 vCPU total, which is ~10
  concurrent `daytona-small`. Size `RLINT_MAX_PARALLEL` to the tier you actually have.
* `_experimental_fork` is VM-only; container sandboxes cannot fork. So instead of forking a
  warmed-up parent we bake `install` into a snapshot once and create every sandbox from it.
  Same win (no per-rollout pip install), and it stays on the fast container path.
* `ExecuteResponse` has no stderr field, so commands are run with `2>&1`.
* `network_block_all` is honoured at create time. Below Tier 3 `update_network_settings`
  on a running sandbox is rejected, so network policy is decided at creation and never
  changed afterwards.

Every SDK call lives in this file. The SDK surface moves fast, hence `_supported`, which
drops keyword arguments the installed version does not know about rather than exploding.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import re
import threading
import time
import uuid
from typing import Any

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

_LIST_CMD = (
    "find . -type f "
    "-not -path './.git/*' -not -path '*/__pycache__/*' "
    "-not -path '*/.pytest_cache/*' -not -name '*.pyc' "
    "| sed 's|^\\./||' | sort"
)

_client: Any = None
_client_lock = threading.Lock()
_snapshot_cache: dict[str, str] = {}
_snapshot_lock = threading.Lock()


class DaytonaUnavailableError(RuntimeError):
    pass


def _sdk() -> Any:
    try:
        import daytona
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise DaytonaUnavailableError(
            "The daytona SDK is not installed. `pip install -e '.[daytona]'` "
            "or set RLINT_SANDBOX=local."
        ) from exc
    return daytona


def get_client() -> Any:
    """Process-wide Daytona client. Shared across worker threads by design."""
    global _client
    with _client_lock:
        if _client is not None:
            return _client
        daytona = _sdk()
        if not os.environ.get("DAYTONA_API_KEY"):
            raise DaytonaUnavailableError("DAYTONA_API_KEY is not set.")
        config_kwargs = _supported(
            daytona.DaytonaConfig,
            api_key=os.environ["DAYTONA_API_KEY"],
            api_url=os.environ.get("DAYTONA_API_URL"),
            target=os.environ.get("DAYTONA_TARGET"),
            # Many concurrent execs share this client; the default pool will throttle us.
            connection_pool_maxsize=None,
        )
        config_kwargs = {k: v for k, v in config_kwargs.items() if v is not None or k == "connection_pool_maxsize"}
        _client = daytona.Daytona(daytona.DaytonaConfig(**config_kwargs))
        return _client


def _supported(callee: Any, /, **kwargs: Any) -> dict[str, Any]:
    """Keep only the kwargs the installed SDK actually accepts.

    `callee` is positional-only: `target` is one of Daytona's own config keys, and a
    normal parameter here would collide with it.
    """
    try:
        params = inspect.signature(callee).parameters
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return kwargs
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return kwargs
    return {k: v for k, v in kwargs.items() if k in params}


def _is_rate_limit(exc: Exception) -> bool:
    daytona = _sdk()
    err_cls = getattr(daytona, "DaytonaRateLimitError", None)
    if err_cls is not None and isinstance(exc, err_cls):
        return True
    return "429" in str(exc) or "rate limit" in str(exc).lower()


def _retry_after(exc: Exception) -> float | None:
    headers = getattr(exc, "headers", None)
    if not headers:
        return None
    for key in ("retry-after-sandbox-create", "retry-after"):
        value = headers.get(key) if hasattr(headers, "get") else None
        if value:
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
    return None


def snapshot_name(spec: EnvSpec) -> str:
    """Stable name per (image, install set) so identical environments share a snapshot."""
    digest = hashlib.sha256(
        (spec.image + "|" + ",".join(sorted(spec.install))).encode()
    ).hexdigest()[:12]
    prefix = get_config().snapshot_prefix
    base = re.sub(r"[^a-z0-9-]+", "-", f"{prefix}-{spec.env_id}".lower()).strip("-")
    return f"{base[:40]}-{digest}"


def ensure_snapshot(spec: EnvSpec, *, on_logs: Any = None) -> str:
    """Build (once) a snapshot with the environment's dependencies baked in.

    This replaces the fork-from-warm-parent idea in the spec, which does not work on
    container sandboxes. Cached per process and guarded by a lock so 20 concurrent
    rollouts trigger exactly one build.
    """
    name = snapshot_name(spec)
    with _snapshot_lock:
        if name in _snapshot_cache:
            return name
        daytona = _sdk()
        client = get_client()
        try:
            client.snapshot.get(name)
            _snapshot_cache[name] = name
            return name
        except Exception:  # noqa: BLE001 - SDK raises a variety of not-found errors
            pass

        image = daytona.Image.base(spec.image)
        if spec.install:
            image = image.pip_install(list(spec.install))
        params_kwargs = _supported(
            daytona.CreateSnapshotParams,
            name=name,
            image=image,
            resources=daytona.Resources(cpu=1, memory=1, disk=3),
        )
        client.snapshot.create(
            daytona.CreateSnapshotParams(**params_kwargs),
            **_supported(client.snapshot.create, on_logs=on_logs),
        )
        _snapshot_cache[name] = name
        return name


class DaytonaSandbox(BaseSandbox):
    def __init__(self, spec: EnvSpec, with_tests: bool, handle: Any) -> None:
        super().__init__(spec, with_tests, sandbox_id=getattr(handle, "id", str(uuid.uuid4())))
        self._sb = handle

    @classmethod
    def create(cls, spec: EnvSpec, *, with_tests: bool) -> DaytonaSandbox:
        daytona = _sdk()
        client = get_client()
        cfg = get_config()
        snapshot = ensure_snapshot(spec)

        params = daytona.CreateSandboxFromSnapshotParams(
            **_supported(
                daytona.CreateSandboxFromSnapshotParams,
                snapshot=snapshot,
                ephemeral=True,
                ttl_minutes=cfg.sandbox_ttl_minutes,
                # Background compute does not reset the inactivity timer, so a default
                # auto-stop would kill a long grading run mid-flight.
                auto_stop_interval=0,
                labels={"rlint": "1", "env": spec.env_id[:40]},
                env_vars={"RLINT_NET_LOG": NET_LOG, "PYTHONPATH": RLINT_LIB},
                # Dependencies are baked into the snapshot, so the sandbox itself never
                # needs egress unless the environment explicitly allows it.
                network_block_all=not spec.network,
            )
        )
        handle = cls._create_with_backoff(client, params)
        sb = cls(spec, with_tests, handle)
        try:
            sb._install_network_monitor()
            sb.write_files(build_layout(spec, with_tests=with_tests))
        except Exception:
            sb.destroy()
            raise
        return sb

    @staticmethod
    def _create_with_backoff(client: Any, params: Any, attempts: int = 5) -> Any:
        delay = 1.0
        last: Exception | None = None
        for _ in range(attempts):
            try:
                return client.create(params, timeout=90)
            except Exception as exc:  # noqa: BLE001 - retry only on rate limits
                if not _is_rate_limit(exc):
                    raise
                last = exc
                time.sleep(_retry_after(exc) or delay)
                delay = min(delay * 2, 8.0)
        raise DaytonaUnavailableError(f"sandbox creation rate limited after {attempts} attempts: {last}")

    # --- primitives ------------------------------------------------------------------

    def exec(self, cmd: str, timeout_s: int | None = None) -> ExecResult:
        timeout = timeout_s or self.spec.timeout_s
        started = time.monotonic()
        try:
            # No stderr field on ExecuteResponse, so fold the streams in the shell.
            response = self._sb.process.exec(f"{cmd} 2>&1", cwd=WORKDIR, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - a failed exec is data, not a crash
            elapsed = time.monotonic() - started
            timed_out = "timeout" in str(exc).lower()
            return ExecResult(
                exit_code=124 if timed_out else 1,
                stdout="",
                stderr=str(exc),
                wall_time_s=elapsed,
                timed_out=timed_out,
            )
        return ExecResult(
            exit_code=getattr(response, "exit_code", 1),
            stdout=getattr(response, "result", "") or "",
            wall_time_s=time.monotonic() - started,
        )

    def write_file(self, path: str, content: str) -> None:
        target = self._abs(path)
        parent = os.path.dirname(target)
        if parent and parent != WORKDIR:
            try:
                self._sb.fs.create_folder(parent, "755")
            except Exception:  # noqa: BLE001 - already exists is the common case
                pass
        self._sb.fs.upload_file(content.encode("utf-8"), target)

    def write_files(self, files: dict[str, str]) -> None:
        """Batch the initial layout into one upload instead of one call per file."""
        daytona = _sdk()
        if not files:
            return
        parents = {os.path.dirname(self._abs(p)) for p in files}
        for parent in sorted(parents):
            if parent and parent != WORKDIR:
                try:
                    self._sb.fs.create_folder(parent, "755")
                except Exception:  # noqa: BLE001
                    pass
        uploads = [
            daytona.FileUpload(source=content.encode("utf-8"), destination=self._abs(path))
            for path, content in files.items()
        ]
        self._sb.fs.upload_files(uploads)

    def read_file(self, path: str) -> str:
        data = self._sb.fs.download_file(self._abs(path))
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    def read_file_absolute(self, path: str) -> str:
        result = self.exec(f"cat {path}")
        if result.exit_code != 0:
            raise FileNotFoundError(path)
        return result.stdout

    def list_files(self, glob: str = "**/*") -> list[str]:
        result = self.exec(_LIST_CMD, timeout_s=30)
        if result.exit_code != 0:
            return []
        paths = [normalize_path(line) for line in result.stdout.splitlines() if line.strip()]
        return sorted(p for p in paths if not is_excluded(p) and matches_any(p, [glob]))

    def destroy(self) -> None:
        if self.destroyed:
            return
        self.destroyed = True
        try:
            get_client().delete(self._sb)
        except Exception:  # noqa: BLE001 - ephemeral+ttl_minutes is the safety net
            pass

    # --- helpers ---------------------------------------------------------------------

    def _abs(self, path: str) -> str:
        rel = normalize_path(path)
        if rel.startswith(".."):
            raise ValueError(f"path escapes workspace: {path}")
        return f"{WORKDIR}/{rel}"

    def _install_network_monitor(self) -> None:
        try:
            self._sb.fs.create_folder(RLINT_LIB, "755")
        except Exception:  # noqa: BLE001
            pass
        self._sb.fs.upload_file(
            NETWORK_MONITOR.encode("utf-8"), f"{RLINT_LIB}/sitecustomize.py"
        )
