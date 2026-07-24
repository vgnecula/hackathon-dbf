"""Report -> hardened EnvSpec. VG owns this file.

Hardening applied, per rlint.md §5.6:
  - network disabled outright
  - solution_paths tightened to exclude test/grader-adjacent paths, so those
    files are never in-scope for the policy's export in the first place
  - held-out test set expanded if the `heldout` detector fired
  - grading is switched to out-of-band by *convention*: a patched env's
    env_id carries a "-patched" suffix, and callers (cli.py, demo.sh) are
    expected to run it with `--grading oob`. EnvSpec itself has no grading
    field (frozen contract, models.py) so this is not stored on the spec.

Then re-run the same attacker suite and show the second table — the
before/after pair is the demo.
"""

from rlint.generator import _client, _generate_tests
from rlint.models import EnvSpec, Report

_GRADER_ADJACENT_PREFIXES = (
    "tests/",
    "test_",
    "conftest.py",
    "pytest.ini",
    "pyproject.toml",
    "setup.cfg",
    "tox.ini",
)


def _tighten_solution_paths(spec: EnvSpec) -> list[str]:
    tightened = [
        p
        for p in spec.solution_paths
        if not any(p.startswith(prefix) for prefix in _GRADER_ADJACENT_PREFIXES)
    ]
    return tightened or ["src/**"]


def _expand_heldout(spec: EnvSpec) -> dict[str, str]:
    client = _client()
    prompt = (
        f"{spec.task_prompt}\n\nGenerate ADDITIONAL held-out edge-case tests, distinct from "
        "any test suite that might already exist for this task."
    )
    extra = _generate_tests(client, prompt, spec.files, "heldout")
    return extra.get("tests", {})


def patch_env(spec: EnvSpec, report: Report) -> EnvSpec:
    """Given a Report with fired detections, emit a hardened EnvSpec."""
    fired = {d.detector_id for d in report.detections if d.fired}

    heldout_tests = dict(spec.heldout_tests)
    if "heldout" in fired:
        heldout_tests.update(_expand_heldout(spec))

    return EnvSpec(
        env_id=f"{spec.env_id}-patched",
        task_prompt=spec.task_prompt,
        image=spec.image,
        install=list(spec.install),
        files=dict(spec.files),
        solution_paths=_tighten_solution_paths(spec),
        visible_tests=dict(spec.visible_tests),
        heldout_tests=heldout_tests,
        grader_cmd=spec.grader_cmd,
        timeout_s=spec.timeout_s,
        network=False,
    )
