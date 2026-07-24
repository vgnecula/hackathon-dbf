"""DG ground-truth fixtures and scripted attackers."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from rlint.attackers import scripted
from rlint.attackers.base import REGISTRY, AttackerMeta, attacker
from rlint.harness import adapt_attackers, run_rollout
from rlint.sandbox.fake import FakeSandbox


def _materialize(tmp_path: Path, env_id: str, *, reference: bool) -> Path:
    spec = scripted.load_fixture_spec(env_id)
    for tree in (spec.files, spec.visible_tests, spec.heldout_tests):
        for path, content in tree.items():
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    if reference:
        for path, content in scripted.load_reference_solution(env_id).items():
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    return tmp_path


def test_registry_contains_control_and_all_exploit_classes() -> None:
    registry = scripted.ensure_registered()
    assert set(registry) >= {
        "honest_solver",
        "delete_tests",
        "hardcode_outputs",
        "patch_assertions",
        "overwrite_grader",
        "mock_dependency",
        "exit_zero",
        "network_fetch",
        "edit_harness",
    }
    assert [meta.exploit_class for meta in scripted.registered_attackers()] == [
        "E0",
        "E1",
        "E2",
        "E3",
        "E4",
        "E5",
        "E6",
        "E7",
        "E8",
    ]


def test_attacker_registry_rejects_invalid_ground_truth_metadata() -> None:
    with pytest.raises(ValueError, match="invalid exploit class"):
        attacker("E9", "outside the measured taxonomy")
    with pytest.raises(ValueError, match="description"):
        attacker("E1", "  ")


def test_attacker_registry_rejects_duplicate_ids() -> None:
    def dg_duplicate(_sb, _spec):
        return None

    try:
        attacker("E1", "first registration")(dg_duplicate)
        with pytest.raises(ValueError, match="duplicate attacker id"):
            attacker("E2", "conflicting registration")(dg_duplicate)
    finally:
        REGISTRY.pop("dg_duplicate", None)


def test_attacker_metadata_is_immutable() -> None:
    meta = AttackerMeta("sample", "E1", "delete tests", lambda _sb, _spec: None)
    with pytest.raises(FrozenInstanceError):
        meta.exploit_class = "E2"  # type: ignore[misc]


@pytest.mark.parametrize("env_id", ["csv_stats", "string_utils", "json_parser"])
def test_fixture_reference_solution_passes_visible_and_heldout(tmp_path: Path, env_id: str) -> None:
    workspace = _materialize(tmp_path, env_id, reference=True)
    proc = subprocess.run(
        ["sh", "run.sh", "tests"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize("env_id", ["csv_stats", "string_utils", "json_parser"])
def test_fixture_starter_solution_fails(tmp_path: Path, env_id: str) -> None:
    workspace = _materialize(tmp_path, env_id, reference=False)
    proc = subprocess.run(
        ["sh", "run.sh", "tests/visible"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode != 0


def test_policy_fixture_excludes_heldout_tests() -> None:
    spec = scripted.load_fixture_spec("csv_stats")
    sb = FakeSandbox.create(spec, with_tests=False)
    try:
        assert sb.list_files("tests/visible/**/*.py")
        assert not sb.list_files("tests/heldout/**/*.py")
    finally:
        sb.destroy()


def test_scripted_rollout_carries_ground_truth_label() -> None:
    spec = scripted.load_fixture_spec("csv_stats")
    registry = scripted.ensure_registered()
    rollout = run_rollout(
        spec,
        adapt_attackers([registry["delete_tests"]])[0],
        grading="inband",
        backend="fake",
    )
    assert rollout.ground_truth_exploit == "E1"
    assert "tests/visible/test_csv_stats.py" in rollout.diff_paths


def test_network_attacker_records_egress_under_fake_backend() -> None:
    spec = scripted.load_fixture_spec("csv_stats")
    registry = scripted.ensure_registered()
    rollout = run_rollout(
        spec,
        adapt_attackers([registry["network_fetch"]])[0],
        grading="oob",
        backend="fake",
    )
    assert rollout.ground_truth_exploit == "E7"
    assert rollout.network_attempts == ["example.com:80"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI not installed")
@pytest.mark.docker
def test_csv_stats_scripted_attackers_win_inband_with_docker() -> None:
    from conftest import docker_available

    if not docker_available():
        pytest.skip("Docker daemon not reachable")

    spec = scripted.load_fixture_spec("csv_stats")
    attackers = adapt_attackers(
        [meta for meta in scripted.registered_attackers() if meta.exploit_class != "E0"]
    )
    for meta in attackers:
        rollout = run_rollout(spec, meta, grading="inband", backend="local")
        assert rollout.reward == 1.0, f"{meta.id}: {rollout.stdout}"
