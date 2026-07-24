"""Environment-driven configuration.

Kept tiny on purpose: every knob is an env var with a sane default, so a demo can be
reconfigured from the shell without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

BackendName = str  # "fake" | "local" | "daytona"
GradingMode = str  # "inband" | "oob"


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    backend: BackendName = "fake"
    grading: GradingMode = "oob"
    # Daytona quotas are vCPU pools, not sandbox counts: Tier 1 is 10 vCPU total, so ~10
    # concurrent daytona-small. Size this to the tier you actually have.
    max_parallel: int = 8
    default_timeout_s: int = 120
    # Sandboxes are torn down by us, but belt-and-braces in case the orchestrator dies.
    sandbox_ttl_minutes: int = 15
    snapshot_prefix: str = "rlint"
    docker_image_pull: bool = True

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            backend=os.environ.get("RLINT_SANDBOX", "fake"),
            grading=os.environ.get("RLINT_GRADING", "oob"),
            max_parallel=_int("RLINT_MAX_PARALLEL", 8),
            default_timeout_s=_int("RLINT_TIMEOUT_S", 120),
            sandbox_ttl_minutes=_int("RLINT_SANDBOX_TTL_MIN", 15),
            snapshot_prefix=os.environ.get("RLINT_SNAPSHOT_PREFIX", "rlint"),
            docker_image_pull=os.environ.get("RLINT_DOCKER_PULL", "1") != "0",
        )


def get_config() -> Config:
    return Config.from_env()
