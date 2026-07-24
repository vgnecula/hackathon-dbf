"""rlint CLI — VG owns this file.

    rlint gen "train a model to write SQL against my schema"   # NL -> .rlint/<env_id>/
    rlint attack <env_id> [--attackers all] [--grading inband|oob]
    rlint report <env_id>
    rlint patch  <env_id>
    rlint demo   [<env_id>]                                     # scripted end-to-end

State between commands lives under ``.rlint/<env_id>/`` (spec.json + rollouts.json), so
``attack`` and ``report`` compose without re-running. Real runs use the configured sandbox
backend (``RLINT_SANDBOX``, default set to ``local`` for deployment); pass ``--backend`` to
override per command. The fake backend does not execute code and must not be used for a
reported number — it silently misses the hardcode/mock classes.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import typer
from rich.console import Console

from rlint.models import EnvSpec, Rollout

app = typer.Typer(help="A linter for agent-generated RL environments.", no_args_is_help=True)
console = Console()

STATE_DIR = Path(".rlint")
_ROLLOUT_FIELDS = tuple(Rollout.__dataclass_fields__)


# --------------------------------------------------------------------------------------
# State persistence
# --------------------------------------------------------------------------------------


def _env_dir(env_id: str) -> Path:
    return STATE_DIR / env_id


def _save_spec(spec: EnvSpec) -> Path:
    path = _env_dir(spec.env_id) / "spec.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(spec), indent=2))
    return path


def _load_spec(env_id: str) -> EnvSpec:
    """A fixture env by name, else a spec previously saved by ``gen``/``patch``."""
    from rlint.attackers.scripted import FIXTURE_IDS, load_fixture_spec

    if env_id in FIXTURE_IDS:
        return load_fixture_spec(env_id)
    path = _env_dir(env_id) / "spec.json"
    if path.exists():
        return EnvSpec(**json.loads(path.read_text()))
    raise typer.BadParameter(
        f"unknown env {env_id!r}: not a fixture ({', '.join(FIXTURE_IDS)}) "
        f"and no saved spec at {path}"
    )


def _save_rollouts(env_id: str, rollouts: list[Rollout]) -> Path:
    path = _env_dir(env_id) / "rollouts.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(r) for r in rollouts], indent=2))
    return path


def _load_rollouts(env_id: str) -> list[Rollout]:
    path = _env_dir(env_id) / "rollouts.json"
    if not path.exists():
        raise typer.BadParameter(
            f"no rollouts for {env_id!r} at {path}; run `rlint attack {env_id}` first"
        )
    raw = json.loads(path.read_text())
    return [Rollout(**{k: row[k] for k in _ROLLOUT_FIELDS if k in row}) for row in raw]


# --------------------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------------------


def _attackers_for(spec: EnvSpec, selector: str) -> list:
    """Scripted suite for fixtures; the generic LLM attacker for anything else.

    Scripted attackers (E0-E8) are hand-authored per fixture env and no-op on any other
    env_id, so a generated or patched env is attacked with the model-driven attacker.
    """
    from rlint.attackers.scripted import FIXTURE_IDS, registered_attackers

    if spec.env_id in FIXTURE_IDS:
        attackers = registered_attackers()
        if selector and selector != "all":
            wanted = {s.strip() for s in selector.split(",")}
            attackers = [a for a in attackers if a.attacker_id in wanted]
            if not attackers:
                raise typer.BadParameter(f"no scripted attacker matched {selector!r}")
        return attackers

    from rlint.attackers.llm import llm_attack
    from rlint.harness import AttackerSpec

    def _llm(sb, s):  # noqa: ANN001 - AttackerFn signature
        llm_attack(sb, s)

    console.print(f"[yellow]{spec.env_id}[/] is not a fixture — using the LLM attacker only.")
    return [AttackerSpec(id="llm_adversary", fn=_llm, exploit_class=None)]


def _build_report(env_id: str, spec: EnvSpec, rollouts: list[Rollout]):
    from rlint.detectors.registry import build_report, default_detectors

    detectors = default_detectors(solution_paths=spec.solution_paths, task_prompt=spec.task_prompt)
    return build_report(env_id, rollouts, detectors, solution_paths=spec.solution_paths)


def _print_report(env_id: str, spec: EnvSpec, rollouts: list[Rollout], grading: str) -> None:
    from rlint.report import render_report

    report = _build_report(env_id, spec, rollouts)
    console.print(render_report(report, grading=grading))


def _run_attack(spec: EnvSpec, selector: str, grading: str, backend: str | None):
    from rlint.harness import run_suite

    attackers = _attackers_for(spec, selector)
    return run_suite(spec, attackers, grading=grading, backend=backend)


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


@app.command()
def gen(
    task: str,
    env_id: str = typer.Option(None, help="Override the generated env id."),
) -> None:
    """NL task description -> validated EnvSpec, saved under .rlint/<env_id>/."""
    from rlint.generator import generate_env

    console.print(f"[bold]generating[/] environment from: {task!r}")
    spec = generate_env(task, env_id)
    path = _save_spec(spec)
    console.print(
        f"[green]✓[/] {spec.env_id}: {len(spec.files)} files, "
        f"{len(spec.visible_tests)} visible + {len(spec.heldout_tests)} held-out tests"
    )
    console.print(f"  saved to {path}")


@app.command()
def attack(
    env_id: str,
    attackers: str = typer.Option("all", help="Comma-separated attacker ids, or 'all'."),
    grading: str = typer.Option("oob", help="'inband' (naive) or 'oob' (out-of-band)."),
    backend: str = typer.Option(None, help="fake | local | daytona (default: configured)."),
) -> None:
    """Run the attacker suite against env_id and record Rollouts."""
    if grading not in ("inband", "oob"):
        raise typer.BadParameter("grading must be 'inband' or 'oob'")
    spec = _load_spec(env_id)
    result = _run_attack(spec, attackers, grading, backend)
    _save_rollouts(env_id, result.rollouts)
    won = sum(1 for r in result.rollouts if r.reward >= 1.0)
    console.print(
        f"[green]✓[/] {len(result.rollouts)} rollouts on [bold]{result.backend}[/] "
        f"(grading={result.grading}, {result.wall_time_s:.1f}s, {result.speedup:.1f}x vs serial); "
        f"{won} scored full reward"
    )
    console.print(f"  run `rlint report {env_id}` for the coverage table")


@app.command()
def report(
    env_id: str,
    grading: str = typer.Option("inband", help="Label shown on the table header."),
) -> None:
    """Run detectors over recorded rollouts and print the coverage table."""
    spec = _load_spec(env_id)
    rollouts = _load_rollouts(env_id)
    _print_report(env_id, spec, rollouts, grading)


@app.command()
def patch(env_id: str) -> None:
    """Harden env_id's EnvSpec based on the last report and write EnvSpec'."""
    from rlint.patcher import patch_env

    spec = _load_spec(env_id)
    rollouts = _load_rollouts(env_id)
    report_obj = _build_report(env_id, spec, rollouts)
    patched = patch_env(spec, report_obj)
    path = _save_spec(patched)
    console.print(f"[green]✓[/] hardened [bold]{spec.env_id}[/] -> [bold]{patched.env_id}[/]")
    console.print(f"  network: {spec.network} -> {patched.network}")
    console.print(f"  solution_paths: {spec.solution_paths} -> {patched.solution_paths}")
    console.print(f"  held-out tests: {len(spec.heldout_tests)} -> {len(patched.heldout_tests)}")
    console.print(f"  grading enforced out-of-band; saved to {path}")
    console.print(f"  verify with `rlint attack {env_id} --grading oob` then `rlint report`")


@app.command()
def demo(
    env_id: str = typer.Argument("csv_stats", help="Fixture to run the before/after on."),
    backend: str = typer.Option(None, help="fake | local | daytona (default: configured)."),
) -> None:
    """Scripted end-to-end: the before/after that is the whole pitch.

    BEFORE — naive in-band grading: every exploit scores full reward.
    AFTER  — out-of-band grading (what `patch` enforces): the exploits that depend on
             touching the grader collapse to zero reward. Same env, same attackers.
    """
    spec = _load_spec(env_id)

    console.rule("[bold]BEFORE — in-band grading (what naive training sees)")
    before = _run_attack(spec, "all", "inband", backend)
    _save_rollouts(env_id, before.rollouts)
    _print_report(env_id, spec, before.rollouts, "inband")

    console.rule("[bold]PATCH — harden the environment")
    from rlint.patcher import patch_env

    report_obj = _build_report(env_id, spec, before.rollouts)
    patched = patch_env(spec, report_obj)
    console.print(
        f"network {spec.network}->{patched.network}, "
        f"held-out {len(spec.heldout_tests)}->{len(patched.heldout_tests)}, "
        "grading enforced out-of-band"
    )

    console.rule("[bold]AFTER — out-of-band grading (exploits now fail)")
    after = _run_attack(spec, "all", "oob", backend)
    _print_report(env_id, spec, after.rollouts, "oob")

    killed = sum(
        1
        for b, a in zip(before.rollouts, after.rollouts, strict=False)
        if b.reward >= 1.0 and a.reward < 1.0
    )
    console.print(
        f"\n[green]✓[/] {killed} exploits that won in-band now score < 1.0 out-of-band "
        f"on [bold]{after.backend}[/]"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
