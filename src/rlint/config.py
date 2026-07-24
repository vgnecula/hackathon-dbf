"""Environment-driven configuration. VG owns this file.

`Config`/`get_config()` is GDk's Track A shape (harness.py, grading.py, sandbox/* already
depend on it) — extended with the Daytona/Braintrust/Fireworks API settings VG's
generator.py, patcher.py and attackers/llm.py need. Every knob is an env var with a sane
default, so a demo can be reconfigured from the shell without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

BackendName = str  # "fake" | "local" | "daytona"
GradingMode = str  # "inband" | "oob"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader — no python-dotenv dependency in pyproject.toml.

    Strips inline ``# comment`` suffixes on unquoted values (e.g. ``RLINT_SANDBOX=fake  #
    fake | local | daytona``, straight out of the old .env.example template) so they don't
    leak into the value itself.
    """
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            if end != -1:
                value = value[1:end]
        else:
            value = value.split("#", 1)[0].strip()
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(REPO_ROOT / ".env")


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
    # sandbox / harness knobs (Track A)
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

    # Daytona (only needed if backend == "daytona"; daytona.py itself reads os.environ
    # directly, these are for VG's own call sites)
    daytona_api_key: str = ""
    daytona_api_url: str = "https://app.daytona.io/api"

    # Braintrust
    braintrust_api_key: str = ""
    braintrust_project: str = "rlint"

    # Fireworks (OpenAI-compatible) — generator.py, patcher.py, attackers/llm.py
    fireworks_api_key: str = ""
    fireworks_base_url: str = "https://api.fireworks.ai/inference/v1"
    fireworks_model: str = "accounts/fireworks/models/glm-5p2"

    envs_dir: Path = REPO_ROOT / "fixtures" / "envs"

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
            daytona_api_key=os.environ.get("DAYTONA_API_KEY", ""),
            daytona_api_url=os.environ.get("DAYTONA_API_URL", "https://app.daytona.io/api"),
            braintrust_api_key=os.environ.get("BRAINTRUST_API_KEY", ""),
            braintrust_project=os.environ.get("BRAINTRUST_PROJECT", "rlint"),
            fireworks_api_key=os.environ.get("FIREWORKS_API_KEY", ""),
            fireworks_base_url=os.environ.get(
                "FIREWORKS_BASE_URL", "https://api.fireworks.ai/inference/v1"
            ),
            fireworks_model=os.environ.get(
                "FIREWORKS_MODEL", "accounts/fireworks/models/glm-5p2"
            ),
        )


def get_config() -> Config:
    return Config.from_env()
