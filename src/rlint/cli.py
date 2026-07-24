"""rlint CLI — VG owns this file.

rlint gen "train a model to write SQL against my schema"   # NL -> fixtures/envs/<id>/
rlint attack <env_id> [--attackers all] [--grading inband|oob]
rlint report <env_id>
rlint patch  <env_id>
rlint demo                                                  # scripted end-to-end
"""

import typer

app = typer.Typer(help="A linter for agent-generated RL environments.")


@app.command()
def gen(task: str) -> None:
    """NL task description -> EnvSpec, written to fixtures/envs/<env_id>/."""
    raise NotImplementedError


@app.command()
def attack(
    env_id: str,
    attackers: str = typer.Option("all", help="Comma-separated attacker ids, or 'all'."),
    grading: str = typer.Option("oob", help="'inband' or 'oob'."),
) -> None:
    """Run the attacker suite against env_id and record Rollouts."""
    raise NotImplementedError


@app.command()
def report(env_id: str) -> None:
    """Run detectors over recorded rollouts and print the coverage table."""
    raise NotImplementedError


@app.command()
def patch(env_id: str) -> None:
    """Harden env_id's EnvSpec based on the last Report and write EnvSpec'."""
    raise NotImplementedError


@app.command()
def demo() -> None:
    """Scripted end-to-end: gen -> attack -> report -> patch -> attack -> report."""
    raise NotImplementedError


def main() -> None:
    app()


if __name__ == "__main__":
    main()
