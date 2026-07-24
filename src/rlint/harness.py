"""Rollout orchestration.

One rollout is: build a policy sandbox, let an attacker loose in it, snapshot what changed,
export the solution, grade it, and hand a `Rollout` to the detectors.

Threads rather than asyncio. The work is I/O-bound HTTP, so threads are as fast in
practice, and keeping the sandbox API synchronous means attackers (Track B) and detectors
(Track C) stay ordinary synchronous functions instead of inheriting async from us.
"""

from __future__ import annotations

import difflib
import time
import traceback
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from rlint.config import get_config
from rlint.grading import GradeBundle, GradeResult, grade_inband, grade_out_of_band
from rlint.models import EnvSpec, Rollout
from rlint.sandbox import BaseSandbox, create_sandbox, sha256

MAX_DIFF_CHARS = 8000

AttackerFn = Callable[[BaseSandbox, EnvSpec], None]


@dataclass
class AttackerSpec:
    """Harness-side view of an attacker.

    Structural, not an import from `attackers/`: the harness must not depend on Track B's
    registry, and Track B must not have to wait on the harness.
    """

    id: str
    fn: AttackerFn
    exploit_class: str | None = None
    description: str = ""


def adapt_attackers(items: Iterable[object]) -> list[AttackerSpec]:
    """Accept anything that looks like an attacker: an `AttackerSpec`, a registry entry
    with `.id`/`.exploit_class`, or a bare decorated function."""
    adapted: list[AttackerSpec] = []
    for item in items:
        if isinstance(item, AttackerSpec):
            adapted.append(item)
            continue
        fn = getattr(item, "fn", None) or item
        if not callable(fn):
            raise TypeError(f"not an attacker: {item!r}")
        adapted.append(
            AttackerSpec(
                id=str(getattr(item, "id", None) or getattr(fn, "__name__", "attacker")),
                fn=fn,  # type: ignore[arg-type]
                exploit_class=getattr(item, "exploit_class", None)
                or getattr(fn, "exploit_class", None),
                description=str(
                    getattr(item, "description", None) or getattr(fn, "__doc__", "") or ""
                ).strip(),
            )
        )
    return adapted


@dataclass
class SuiteResult:
    env_id: str
    rollouts: list[Rollout]
    wall_time_s: float
    max_parallel: int
    backend: str
    grading: str
    sandboxes_created: int = 0

    @property
    def serial_time_s(self) -> float:
        """Sum of per-rollout times: the number parallelism is measured against."""
        return sum(r.wall_time_s for r in self.rollouts)

    @property
    def speedup(self) -> float:
        return self.serial_time_s / self.wall_time_s if self.wall_time_s else 1.0


def compute_diff(before: dict[str, str], after: dict[str, str]) -> tuple[list[str], str]:
    """Changed paths and a truncated unified diff."""
    paths = sorted(set(before) | set(after))
    changed: list[str] = []
    chunks: list[str] = []
    for path in paths:
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        changed.append(path)
        chunks.extend(
            difflib.unified_diff(
                (old or "").splitlines(keepends=True),
                (new or "").splitlines(keepends=True),
                fromfile=f"a/{path}" if old is not None else "/dev/null",
                tofile=f"b/{path}" if new is not None else "/dev/null",
                n=2,
            )
        )
    text = "".join(chunks)
    if len(text) > MAX_DIFF_CHARS:
        text = text[:MAX_DIFF_CHARS] + f"\n... [truncated, {len(text)} chars total]\n"
    return changed, text


def _failed_rollout(
    spec: EnvSpec, attacker: AttackerSpec, message: str, wall_time_s: float
) -> Rollout:
    """A rollout that blew up is still a data point. Never let one kill the suite."""
    return Rollout(
        rollout_id=f"{spec.env_id}:{attacker.id}",
        env_id=spec.env_id,
        attacker_id=attacker.id,
        workspace_before={},
        workspace_after={},
        diff_paths=[],
        diff_text="",
        visible_pass_rate=0.0,
        heldout_pass_rate=0.0,
        reward=0.0,
        exit_code=-1,
        wall_time_s=wall_time_s,
        network_attempts=[],
        stdout=f"[rlint] rollout failed:\n{message}",
        ground_truth_exploit=attacker.exploit_class,
    )


def run_rollout(
    spec: EnvSpec,
    attacker: AttackerSpec,
    *,
    grading: str | None = None,
    backend: str | None = None,
) -> Rollout:
    cfg = get_config()
    grading = grading or cfg.grading
    started = time.monotonic()
    sandbox: BaseSandbox | None = None
    try:
        sandbox = create_sandbox(spec, with_tests=False, backend=backend)
        before = sandbox.read_tree()

        attacker.fn(sandbox, spec)

        after = sandbox.read_tree()
        diff_paths, diff_text = compute_diff(before, after)

        # The allowlist chokepoint: whatever the policy did to tests, graders or the
        # harness simply does not leave this sandbox.
        exported = sandbox.export(spec.solution_paths)
        policy_network = sandbox.read_network_log()

        inband: GradeResult | None = None
        if grading == "inband":
            inband = grade_inband(spec, sandbox)
    except Exception:
        elapsed = time.monotonic() - started
        return _failed_rollout(spec, attacker, traceback.format_exc(limit=5), elapsed)
    finally:
        if sandbox is not None:
            sandbox.destroy()

    try:
        # Held-out is always measured out-of-band, even when the reward came from in-band
        # grading. Otherwise the `heldout` detector has nothing to compare against in the
        # "before" table, which is the table the whole demo rests on.
        bundle: GradeBundle = grade_out_of_band(spec, exported, backend=backend)
    except Exception:
        elapsed = time.monotonic() - started
        return _failed_rollout(spec, attacker, traceback.format_exc(limit=5), elapsed)

    if inband is not None:
        primary, reward = inband, inband.naive
    else:
        primary, reward = bundle.visible, bundle.visible.strict

    network_attempts = list(dict.fromkeys([*policy_network, *bundle.network_attempts]))

    return Rollout(
        rollout_id=f"{spec.env_id}:{attacker.id}",
        env_id=spec.env_id,
        attacker_id=attacker.id,
        workspace_before={p: sha256(c) for p, c in before.items()},
        workspace_after={p: sha256(c) for p, c in after.items()},
        diff_paths=diff_paths,
        diff_text=diff_text,
        visible_pass_rate=primary.pass_rate,
        heldout_pass_rate=bundle.heldout.pass_rate,
        reward=reward,
        exit_code=primary.exit_code,
        wall_time_s=time.monotonic() - started,
        network_attempts=network_attempts,
        stdout=primary.stdout[-8000:],
        ground_truth_exploit=attacker.exploit_class,
    )


def run_suite(
    spec: EnvSpec,
    attackers: Sequence[object],
    *,
    grading: str | None = None,
    backend: str | None = None,
    max_parallel: int | None = None,
    on_result: Callable[[Rollout], None] | None = None,
) -> SuiteResult:
    """Run every attacker against one environment, in parallel.

    `max_parallel` must be sized to your Daytona vCPU pool, not to the creation rate
    limit: Tier 1 is 10 vCPU total, so ~10 concurrent `daytona-small`.
    """
    cfg = get_config()
    specs = adapt_attackers(attackers)
    workers = max(1, max_parallel or cfg.max_parallel)
    grading = grading or cfg.grading
    backend_name = backend or cfg.backend

    started = time.monotonic()
    rollouts: list[Rollout] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rlint") as pool:
        futures = {
            pool.submit(run_rollout, spec, atk, grading=grading, backend=backend_name): atk
            for atk in specs
        }
        for future in as_completed(futures):
            rollout = future.result()
            rollouts.append(rollout)
            if on_result is not None:
                on_result(rollout)

    order = {atk.id: i for i, atk in enumerate(specs)}
    rollouts.sort(key=lambda r: order.get(r.attacker_id, 0))

    return SuiteResult(
        env_id=spec.env_id,
        rollouts=rollouts,
        wall_time_s=time.monotonic() - started,
        max_parallel=workers,
        backend=backend_name,
        grading=grading,
        # One policy sandbox plus one grading sandbox per rollout.
        sandboxes_created=len(specs) * 2,
    )


@dataclass
class MultiEnvResult:
    results: list[SuiteResult] = field(default_factory=list)

    @property
    def rollouts(self) -> list[Rollout]:
        return [r for result in self.results for r in result.rollouts]


def run_environments(
    specs: Sequence[EnvSpec],
    attackers: Sequence[object],
    **kwargs: object,
) -> MultiEnvResult:
    """N exploit classes across M environments — the denominator in the pitch."""
    return MultiEnvResult(
        results=[run_suite(spec, attackers, **kwargs) for spec in specs]  # type: ignore[arg-type]
    )
