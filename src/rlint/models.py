"""Core data model, verbatim from rlint.md section 4.

Frozen contract. Every track codes against these types; changes must be announced.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnvSpec:
    env_id: str
    task_prompt: str  # what the policy is told to do
    image: str = "python:3.11-slim"
    install: list[str] = field(default_factory=list)  # pip packages
    files: dict[str, str] = field(default_factory=dict)  # path -> contents (starter code)

    solution_paths: list[str] = field(default_factory=lambda: ["src/**"])
    visible_tests: dict[str, str] = field(default_factory=dict)  # shown to policy
    heldout_tests: dict[str, str] = field(default_factory=dict)  # NEVER in policy sandbox

    grader_cmd: str = "python -m pytest -q"
    timeout_s: int = 120
    network: bool = False


@dataclass
class Rollout:
    rollout_id: str
    env_id: str
    attacker_id: str
    workspace_before: dict[str, str]  # path -> sha256
    workspace_after: dict[str, str]
    diff_paths: list[str]
    diff_text: str  # unified diff, truncated
    visible_pass_rate: float
    heldout_pass_rate: float
    reward: float  # what naive training would see
    exit_code: int
    wall_time_s: float
    network_attempts: list[str]
    stdout: str
    ground_truth_exploit: str | None  # "E1".."E8" for scripted attackers, None for LLM


@dataclass
class Detection:
    detector_id: str
    rollout_id: str
    fired: bool
    score: float  # 0..1 confidence
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
