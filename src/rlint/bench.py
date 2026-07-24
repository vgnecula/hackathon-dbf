"""Parallel rollout benchmark.

Produces the number quoted on stage: N rollouts across 2N sandboxes in M seconds, against
the serial equivalent. Run it once before the demo and once during, on whichever backend
is live::

    python -m rlint.bench --backend daytona --count 20 --parallel 20

The warm-up rollout is not counted. The first sandbox on a given environment pays for the
snapshot or image build, and folding that one-off cost into a concurrency claim would
overstate the result.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass

from rlint.harness import AttackerSpec, run_suite
from rlint.models import EnvSpec
from rlint.sandbox import BaseSandbox

BENCH_ENV = EnvSpec(
    env_id="bench",
    task_prompt="Benchmark environment. Not a ground-truth fixture.",
    install=["pytest"],
    files={"conftest.py": "", "src/solution.py": "def add(a, b):\n    return a + b\n"},
    visible_tests={
        "tests/visible/test_add.py": (
            "from src.solution import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
        )
    },
    heldout_tests={
        "tests/heldout/test_more.py": (
            "from src.solution import add\n\n\ndef test_more():\n    assert add(2, 2) == 4\n"
        )
    },
    timeout_s=60,
)


def noop(sb: BaseSandbox, spec: EnvSpec) -> None:
    """Stand-in policy: this measures the harness, not an attacker."""


@dataclass
class BenchReport:
    backend: str
    rollouts: int
    sandboxes: int
    parallel: int
    wall_time_s: float
    serial_time_s: float
    failures: int
    warmup_s: float

    @property
    def speedup(self) -> float:
        return self.serial_time_s / self.wall_time_s if self.wall_time_s else 1.0

    def render(self) -> str:
        lines = [
            f"backend            {self.backend}",
            f"rollouts           {self.rollouts}",
            f"sandboxes created  {self.sandboxes}",
            f"max parallel       {self.parallel}",
            f"warm-up            {self.warmup_s:.1f}s (excluded)",
            f"wall clock         {self.wall_time_s:.1f}s",
            f"serial equivalent  {self.serial_time_s:.1f}s",
            f"speedup            {self.speedup:.1f}x",
        ]
        if self.failures:
            lines.append(f"FAILURES           {self.failures}")
        width = max(len(line) for line in lines)
        return "\n".join(["-" * width, *lines, "-" * width])


def warm_up(backend: str) -> float:
    """Pay the snapshot or image build once, before the clock starts."""
    from rlint.sandbox import create_sandbox

    started = time.monotonic()
    sandbox = create_sandbox(BENCH_ENV, with_tests=True, backend=backend)
    sandbox.destroy()
    return time.monotonic() - started


def benchmark(backend: str, count: int, parallel: int) -> BenchReport:
    warmup_s = warm_up(backend)
    attackers = [AttackerSpec(id=f"rollout_{i:02d}", fn=noop) for i in range(count)]
    result = run_suite(
        BENCH_ENV, attackers, grading="oob", backend=backend, max_parallel=parallel
    )
    return BenchReport(
        backend=backend,
        rollouts=len(result.rollouts),
        sandboxes=result.sandboxes_created,
        parallel=result.max_parallel,
        wall_time_s=result.wall_time_s,
        serial_time_s=result.serial_time_s,
        failures=sum(1 for r in result.rollouts if r.exit_code == -1),
        warmup_s=warmup_s,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="local", choices=["fake", "local", "daytona"])
    parser.add_argument("--count", type=int, default=20, help="number of rollouts")
    parser.add_argument(
        "--parallel",
        type=int,
        default=20,
        help="concurrency; size to your vCPU pool, not the creation rate limit",
    )
    args = parser.parse_args(argv)
    print(benchmark(args.backend, args.count, args.parallel).render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
