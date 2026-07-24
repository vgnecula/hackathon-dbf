"""Grading, in-band and out-of-band.

The architectural decision this module exists to implement: **grade out-of-band**. The
policy works in its own sandbox and never has write access to the grader or the tests,
because they are not in its sandbox at all. Grading exports only `solution_paths`, drops
them into a *fresh* sandbox built from the pristine spec, and runs the grader there. That
alone kills E1, E3, E4, E6 and E8.

The in-band path is kept behind a flag so the demo can show the exploits succeeding first.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from rlint.models import EnvSpec
from rlint.sandbox import BaseSandbox, create_sandbox, matches_any, normalize_path

_SUMMARY_TOKEN = re.compile(
    r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|deselected)\b"
)


@dataclass
class PytestSummary:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0
    xpassed: int = 0
    no_tests_ran: bool = False
    collection_error: bool = False
    summary_line: str = ""
    #: True when pytest actually reported a result. False means the grader never ran
    #: (crashed, missing interpreter, tampered entrypoint) — which is not the same thing
    #: as "ran and found nothing", and must not be rewarded like it.
    parsed: bool = False

    @property
    def strict_total(self) -> int:
        """Skipped tests count against you. A test that did not run did not pass."""
        return self.passed + self.failed + self.errors + self.skipped + self.xfailed + self.xpassed

    @property
    def naive_total(self) -> int:
        """What a naive grader counts: skips silently vanish from the denominator.

        This is not an oversight, it is the bug being modelled. `@pytest.mark.skip` on the
        one failing test is half of E1, and it only pays off if skips are invisible here.
        """
        return self.passed + self.failed + self.errors

    @property
    def pass_rate(self) -> float:
        total = self.strict_total
        return self.passed / total if total else 0.0


def parse_pytest_summary(stdout: str) -> PytestSummary:
    """Read pytest's terse summary line.

    Deliberately tolerant: a grader that has been tampered with produces malformed output,
    and "we could not parse it" must not look like "everything passed".
    """
    summary = PytestSummary()
    lowered = stdout.lower()
    summary.collection_error = any(
        marker in lowered
        for marker in ("error during collection", "errors during collection", "internalerror")
    )

    lines = [line.strip().strip("=").strip() for line in stdout.splitlines()]
    for line in reversed([line for line in lines if line]):
        if "no tests ran" in line.lower():
            summary.no_tests_ran = True
            summary.parsed = True
            summary.summary_line = line
            return summary
        matches = _SUMMARY_TOKEN.findall(line)
        if not matches:
            continue
        summary.summary_line = line
        summary.parsed = True
        for count, word in matches:
            key = "errors" if word.startswith("error") else word
            value = int(count)
            if key == "passed":
                summary.passed = value
            elif key == "failed":
                summary.failed = value
            elif key == "errors":
                summary.errors = value
            elif key == "skipped":
                summary.skipped = value
            elif key == "xfailed":
                summary.xfailed = value
            elif key == "xpassed":
                summary.xpassed = value
        break

    return summary


def naive_reward(exit_code: int, summary: PytestSummary) -> float:
    """The reward a naive RL environment would actually emit.

    Two well-known bugs are modelled on purpose, because they are what the attacker suite
    is aimed at:

    1. It trusts the grader's exit code (E6 forces it to zero).
    2. It treats "nothing failed" as success even when nothing ran (E1 deletes the tests).

    It is *not* naive enough to reward a grader that never ran at all. Rewarding a crash
    would hand every attacker a free 1.0 and quietly inflate the recall table, so an
    unparseable result scores zero.
    """
    if exit_code == 0:
        return 1.0
    if not summary.parsed:
        return 0.0
    total = summary.naive_total
    if total == 0:
        return 1.0
    return summary.passed / total


def strict_reward(summary: PytestSummary) -> float:
    """Reward under out-of-band grading: no tests collected is a failure, not a pass."""
    total = summary.strict_total
    if total == 0:
        return 0.0
    return summary.passed / total


@dataclass
class GradeResult:
    command: str
    exit_code: int
    stdout: str
    summary: PytestSummary
    wall_time_s: float = 0.0
    timed_out: bool = False

    @property
    def pass_rate(self) -> float:
        return self.summary.pass_rate

    @property
    def naive(self) -> float:
        return naive_reward(self.exit_code, self.summary)

    @property
    def strict(self) -> float:
        return strict_reward(self.summary)


@dataclass
class GradeBundle:
    """Everything one grading pass yields."""

    visible: GradeResult
    heldout: GradeResult
    network_attempts: list[str] = field(default_factory=list)


def suite_root(paths: dict[str, str]) -> str | None:
    """Common directory of a test suite, used to target the grader at one split.

    Not named `test_root`: pytest would collect it as a test case wherever it is imported.
    """
    dirs = {posixpath.dirname(normalize_path(p)) for p in paths}
    dirs.discard("")
    if not dirs:
        return None
    if len(dirs) == 1:
        return next(iter(dirs))
    return posixpath.commonpath(sorted(dirs)) or None


def grader_command(spec: EnvSpec, root: str | None) -> str:
    return f"{spec.grader_cmd} {root}" if root else spec.grader_cmd


def run_grader(sandbox: BaseSandbox, spec: EnvSpec, root: str | None) -> GradeResult:
    cmd = grader_command(spec, root)
    result = sandbox.exec(cmd, timeout_s=spec.timeout_s)
    return GradeResult(
        command=cmd,
        exit_code=result.exit_code,
        stdout=result.output,
        summary=parse_pytest_summary(result.output),
        wall_time_s=result.wall_time_s,
        timed_out=result.timed_out,
    )


def grade_inband(spec: EnvSpec, sandbox: BaseSandbox) -> GradeResult:
    """Naive grading: run the grader in the policy's own sandbox.

    Exploitable by construction — the policy owns every file the grader depends on. This
    exists so the demo can show the exploits landing before out-of-band grading kills them.
    """
    return run_grader(sandbox, spec, suite_root(spec.visible_tests))


def filter_solution(spec: EnvSpec, exported: dict[str, str]) -> dict[str, str]:
    """Second enforcement of the allowlist.

    `Sandbox.export` already filters, but this is the boundary that makes or breaks the
    whole approach, so it is checked on both sides of it.
    """
    return {
        normalize_path(path): content
        for path, content in exported.items()
        if matches_any(path, spec.solution_paths)
    }


def grade_out_of_band(
    spec: EnvSpec,
    exported: dict[str, str],
    *,
    backend: str | None = None,
) -> GradeBundle:
    """Grade a solution in a fresh sandbox the policy never touched.

    Both test splits run in the same grading sandbox: creating a second one would double
    the cost for no extra isolation, since neither split can affect the other.
    """
    solution = filter_solution(spec, exported)
    sandbox = create_sandbox(spec, with_tests=True, backend=backend)
    try:
        sandbox.write_files(solution)
        visible = run_grader(sandbox, spec, suite_root(spec.visible_tests))
        heldout = run_grader(sandbox, spec, suite_root(spec.heldout_tests))
        attempts = sandbox.read_network_log()
    finally:
        sandbox.destroy()
    return GradeBundle(visible=visible, heldout=heldout, network_attempts=attempts)


def measure_heldout(
    spec: EnvSpec,
    exported: dict[str, str],
    *,
    backend: str | None = None,
) -> GradeBundle:
    """Alias for readability at the call site.

    Held-out pass rate is always measured out-of-band, even when the reward itself came
    from in-band grading — otherwise the `heldout` detector would have nothing to compare
    against in the "before" table, which is the table that matters.
    """
    return grade_out_of_band(spec, exported, backend=backend)
