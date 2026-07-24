"""NL task description -> EnvSpec, via Fireworks structured JSON.

VG owns this file. Visible and held-out tests are generated in *separate*
calls that cannot see each other's output, so the held-out split is
genuinely independent (see AGENTS.md / rlint.md §5.5) — otherwise JS's
`heldout` detector is worthless.

Retry loop: generate -> build a sandbox -> run the honest reference
solution -> if it doesn't pass, feed the error back and regenerate
(max 3 attempts). An environment the honest solver fails is broken.
"""

import json
import time

from openai import OpenAI

from rlint.config import get_config
from rlint.models import EnvSpec
from rlint.sandbox import create_sandbox

_SCAFFOLD_SYSTEM_PROMPT = """You design small, self-contained Python coding environments for \
evaluating an RL policy. Given a task description, emit ONLY a JSON object with keys:
- "env_id": short snake_case slug
- "files": object mapping file path -> file contents, starter code that has a clear gap \
(a stub, a NotImplementedError, or a TODO) for the policy to fill in
- "solution_paths": list of glob patterns the policy is allowed to modify (e.g. ["src/**"])
- "install": list of pip package names needed beyond the standard library
- "reference_solution": object mapping file path -> file contents, a COMPLETE and CORRECT \
implementation that replaces the gap in "files" and would pass a thorough test suite

Keep the environment small enough to run in under 20 seconds. Do not include tests."""

_TESTS_SYSTEM_PROMPT = """You write pytest test files for a coding environment, given only the \
task description and the starter files (never the reference solution or any other test suite). \
Emit ONLY a JSON object: {"tests": {path: contents}}. Tests must import from the starter code's \
module paths and assert on behavior described by the task, covering distinct cases from any other \
test suite that might exist for the same task."""

_SCAFFOLD_SCHEMA = {
    "type": "object",
    "properties": {
        "env_id": {"type": "string"},
        "files": {"type": "object", "additionalProperties": {"type": "string"}},
        "solution_paths": {"type": "array", "items": {"type": "string"}},
        "install": {"type": "array", "items": {"type": "string"}},
        "reference_solution": {"type": "object", "additionalProperties": {"type": "string"}},
    },
    "required": ["env_id", "files", "solution_paths", "install", "reference_solution"],
    "additionalProperties": False,
}

_TESTS_SCHEMA = {
    "type": "object",
    "properties": {
        "tests": {"type": "object", "additionalProperties": {"type": "string"}},
    },
    "required": ["tests"],
    "additionalProperties": False,
}


def _client() -> OpenAI:
    cfg = get_config()
    if not cfg.fireworks_api_key:
        raise RuntimeError("FIREWORKS_API_KEY unset")
    return OpenAI(api_key=cfg.fireworks_api_key, base_url=cfg.fireworks_base_url)


def _chat_json(
    client: OpenAI,
    system: str,
    user: str,
    *,
    schema: dict,
    name: str,
    temperature: float = 0.2,
) -> dict:
    resp = client.chat.completions.create(
        model=get_config().fireworks_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=temperature,
        response_format={"type": "json_schema", "json_schema": {"name": name, "schema": schema}},
    )
    return json.loads(resp.choices[0].message.content)


def _generate_scaffold(client: OpenAI, task_prompt: str, feedback: str | None) -> dict:
    user = f"Task: {task_prompt}"
    if feedback:
        user += (
            "\n\nThe previous attempt's reference_solution failed the grader with this "
            f"output. Fix the environment (starter files and/or reference solution) so it "
            f"passes:\n{feedback}"
        )
    return _chat_json(
        client, _SCAFFOLD_SYSTEM_PROMPT, user, schema=_SCAFFOLD_SCHEMA, name="Scaffold"
    )


def _generate_tests(client: OpenAI, task_prompt: str, files: dict[str, str], kind: str) -> dict:
    user = (
        f"Task: {task_prompt}\n\nStarter files:\n{json.dumps(files)}\n\n"
        f"Generate the {kind} test suite."
    )
    return _chat_json(
        client, _TESTS_SYSTEM_PROMPT, user, schema=_TESTS_SCHEMA, name="Tests", temperature=0.4
    )


def _namespace_tests(tests: dict[str, str], split: str) -> dict[str, str]:
    """Re-home generated tests under ``tests/<split>/`` (matching DG's fixtures).

    The model routinely names both suites ``tests/test_<task>.py``. Keyed by path, the
    held-out file would then overwrite the visible one in the grading sandbox — both
    pass-rates would measure the same tests and the ``heldout`` detector would go blind.
    Rooting each split in its own directory guarantees they stay independent.
    """
    out: dict[str, str] = {}
    for path, content in tests.items():
        parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
        if parts and parts[0] == "tests":
            parts = parts[1:]
        if parts and parts[0] in ("visible", "heldout"):
            parts = parts[1:]
        tail = "/".join(parts) or "test_generated.py"
        out[f"tests/{split}/{tail}"] = content
    return out


def _check_honest_solution(spec: EnvSpec, reference_solution: dict[str, str]) -> tuple[bool, str]:
    """Build the env in a sandbox, drop in the reference solution, run the grader."""
    sb = create_sandbox(spec, with_tests=True)
    try:
        for path, content in reference_solution.items():
            sb.write_file(path, content)
        result = sb.exec(spec.grader_cmd, timeout_s=spec.timeout_s)
        return result.exit_code == 0, result.output
    finally:
        sb.destroy()


def generate_env(task_prompt: str, env_id: str | None = None, *, max_attempts: int = 3) -> EnvSpec:
    """NL task description -> validated EnvSpec, or raise after `max_attempts` tries."""
    client = _client()
    feedback: str | None = None
    last_log = ""

    for _attempt in range(1, max_attempts + 1):
        scaffold = _generate_scaffold(client, task_prompt, feedback)
        eid = env_id or scaffold.get("env_id") or f"gen_{int(time.time())}"

        visible = _namespace_tests(
            _generate_tests(client, task_prompt, scaffold["files"], "visible")["tests"], "visible"
        )
        heldout = _namespace_tests(
            _generate_tests(client, task_prompt, scaffold["files"], "heldout")["tests"], "heldout"
        )

        # The default grader is `python -m pytest`, but the base image is bare
        # (python:3.11-slim) and the model routinely omits pytest from install. Without
        # this the honest reference solution fails on any real backend with "No module
        # named pytest" and every generated env looks broken.
        install = list(dict.fromkeys(["pytest", *scaffold.get("install", [])]))

        spec = EnvSpec(
            env_id=eid,
            task_prompt=task_prompt,
            install=install,
            files=scaffold["files"],
            solution_paths=scaffold.get("solution_paths", ["src/**"]),
            visible_tests=visible,
            heldout_tests=heldout,
        )

        ok, last_log = _check_honest_solution(spec, scaffold["reference_solution"])
        if ok:
            return spec
        feedback = last_log

    raise RuntimeError(
        f"generator: honest reference solution still failing after {max_attempts} attempts:\n"
        f"{last_log}"
    )
