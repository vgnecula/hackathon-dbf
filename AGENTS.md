# AGENTS.md — read this before touching any file in this repo

This repo is being built by a team of four during a 5.5-hour hackathon
(Daytona HackSprint #5). Full context: [rlint.md](rlint.md) (spec) and
[PLAN.md](PLAN.md) (execution plan). This file is the cheapest coordination
mechanism we have — every agent working in this repo reads it automatically.

## The one rule

**Do not edit files outside your track's ownership list.** If you need a
change in a file you don't own, say so in team chat — don't edit it, and
don't let your agent edit it. This is how four people/agents push straight
to `main` all day with zero merge conflicts and no PR review.

## Ownership map — exclusive, no shared files

| Owner | Track | Exclusive files |
|---|---|---|
| **VG** | Contracts, then generation + pitch | `pyproject.toml`, `ruff.toml`, `.env.example`, `AGENTS.md`, `models.py`, `config.py`, `cli.py`, `generator.py`, `patcher.py`, `attackers/llm.py`, `scripts/demo.sh`, slides |
| **GDk** | Sandbox + harness | `sandbox/base.py`, `sandbox/fake.py`, `sandbox/local.py`, `sandbox/daytona.py`, `grading.py`, `harness.py` |
| **DG** | Ground truth | `fixtures/envs/**`, `attackers/base.py`, `attackers/scripted.py` |
| **JS** | Detection + Braintrust | `detectors/**`, `tracing.py`, `report.py` |

Tests follow the same rule: `tests/test_<track>.py` per owner.

Note: `sandbox/base.py`, `attackers/base.py`, and `detectors/base.py` were
stubbed by VG in the freeze commit to unblock parallel work, but ownership
of their *contents* belongs to GDk, DG, and JS respectively from that point
on. Changes to `models.py` or `sandbox/base.py` after the freeze require
announcing in chat — everything else in the repo codes against them.

## Frozen contracts

`models.py` is verbatim from [rlint.md](rlint.md) §4:

```python
from dataclasses import dataclass, field
from typing import Literal

@dataclass
class EnvSpec:
    env_id: str
    task_prompt: str                    # what the policy is told to do
    image: str = "python:3.11-slim"
    install: list[str] = field(default_factory=list)   # pip packages
    files: dict[str, str] = field(default_factory=dict)  # path -> contents (starter code)

    solution_paths: list[str] = field(default_factory=lambda: ["src/**"])
    visible_tests: dict[str, str] = field(default_factory=dict)   # shown to policy
    heldout_tests: dict[str, str] = field(default_factory=dict)   # NEVER in policy sandbox

    grader_cmd: str = "python -m pytest -q"
    timeout_s: int = 120
    network: bool = False

@dataclass
class Rollout:
    rollout_id: str
    env_id: str
    attacker_id: str
    workspace_before: dict[str, str]    # path -> sha256
    workspace_after: dict[str, str]
    diff_paths: list[str]
    diff_text: str                      # unified diff, truncated
    visible_pass_rate: float
    heldout_pass_rate: float
    reward: float                       # what naive training would see
    exit_code: int
    wall_time_s: float
    network_attempts: list[str]
    stdout: str
    ground_truth_exploit: str | None    # "E1".."E8" for scripted attackers, None for LLM

@dataclass
class Detection:
    detector_id: str
    rollout_id: str
    fired: bool
    score: float                        # 0..1 confidence
    evidence: str
    suspected_classes: list[str]

@dataclass
class Report:
    env_id: str
    rollouts: list[Rollout]
    detections: list[Detection]
    # computed
    recall_by_class: dict[str, float]
    false_positive_rate: float
    missed: list[str]
```

`ground_truth_exploit` is the field the entire coverage claim rests on.
Scripted attackers set it. Without it there is no recall number.

The three interfaces that matter:

```python
# sandbox/base.py — GDk implements, DG's attackers consume
class Sandbox(Protocol):
    @classmethod
    def create(cls, spec: EnvSpec, *, with_tests: bool) -> "Sandbox": ...
    def exec(self, cmd: str, timeout_s: int) -> ExecResult: ...
    def write_file(self, path: str, content: str) -> None: ...
    def read_file(self, path: str) -> str: ...
    def list_files(self, glob: str = "**/*") -> list[str]: ...
    def hash_tree(self) -> dict[str, str]: ...
    def export(self, globs: list[str]) -> dict[str, str]: ...
    def destroy(self) -> None: ...

# attackers/base.py — DG owns, harness consumes
Attacker = Callable[[Sandbox, EnvSpec], None]
def attacker(exploit_class: str, description: str) -> Callable[[Attacker], Attacker]: ...
REGISTRY: dict[str, AttackerMeta]   # attacker_id -> (fn, exploit_class, description)

# detectors/base.py — JS owns, registry consumes
Detector = Callable[[Rollout], Detection]
```

Two conventions that unblock parallel work:

1. **`with_tests=False`** for policy sandboxes (visible tests only — held-out
   tests never enter the policy sandbox). `True` for grading sandboxes.
2. **`Rollout` is the only thing detectors see.** They are pure functions
   over a dataclass, so JS can build the whole detection layer against
   hand-written `Rollout` literals with no sandbox, no Docker, no API keys.

## The architectural decision that matters

**Grade out-of-band.** The policy never has write access to the grader or
the tests because they are not in its sandbox at all. This single decision
kills exploit classes E1, E3, E4, E6, and E8 outright. The naive in-band path
stays behind `--grading=inband` so the demo can show the exploits succeeding
first — the before/after table pair is the whole demo.

## Working conventions

- One repo, everyone pushes to `main`. No PR review — too slow for a 5.5-hour
  build. Ownership prevents conflicts instead of review resolving them.
- `git pull --rebase` before every push. Push every 20–30 minutes even if
  incomplete, behind a flag or as a stub. Small commits.
- Branches only for risky spikes, merged within the hour.
- Formatting is pinned in `ruff.toml` from commit #1 — don't reformat a file
  someone else is holding.
- Two hard integration freezes: 12:15 and 13:15. Everyone stops, merges, GDk
  runs end-to-end.
- `FakeSandbox` (`sandbox/fake.py`) is what makes the parallelism real: DG
  and JS never wait on GDk, and their tests run in milliseconds with no
  Docker, no network, no API keys.
- `pytest` green per track is the merge gate.

See [PLAN.md](PLAN.md) for the full timeline, per-person briefs, demo script,
and risk list.
