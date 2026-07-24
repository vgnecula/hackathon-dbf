"""Detector contract and shared helpers.

A detector is a **pure function over a `Rollout`**::

    Detector = Callable[[Rollout], Detection]

That is the whole contract. Detectors never touch a sandbox, the network, or an API key
(with the single, explicitly-marked exception of `judge`), which is what lets the whole
detection layer be unit-tested against hand-written `Rollout` literals.

Some detectors need a little environment context that `Rollout` does not carry — most
obviously `filediff`, which needs the `solution_paths` allowlist. Those are exposed as
**factories** (`make_filediff(solution_paths)`) that return a `Detector`, so the
`Rollout -> Detection` signature stays intact.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Protocol, runtime_checkable

from ..models import Detection, Rollout

Detector = Callable[[Rollout], Detection]

EVIDENCE_MAX_CHARS = 600


@runtime_checkable
class DetectorLike(Protocol):
    """Structural type for a detector carrying its own id (see `named`)."""

    detector_id: str

    def __call__(self, rollout: Rollout) -> Detection: ...


# --------------------------------------------------------------------------------------
# Path globbing
# --------------------------------------------------------------------------------------
#
# `fnmatch` is not usable here: its `*` happily matches `/`, so `src/*` would match
# `src/a/b/c.py` and the whole point of the allowlist would be lost. Translate the glob
# ourselves with POSIX-ish semantics: `*` stops at a separator, `**` does not.


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                # `**/` may match zero directories, so `a/**/b.py` matches `a/b.py`.
                if pattern.startswith("**/", i):
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def normalize_path(path: str) -> str:
    """Canonicalize a workspace path so `./src/x.py`, `/src/x.py` and `src/x.py` agree."""
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def path_matches(path: str, patterns: Iterable[str]) -> bool:
    """True if `path` matches any glob in `patterns`."""
    norm = normalize_path(path)
    for pattern in patterns:
        pat = normalize_path(pattern)
        rx = _REGEX_CACHE.get(pat)
        if rx is None:
            rx = _REGEX_CACHE[pat] = _glob_to_regex(pat)
        if rx.match(norm):
            return True
        # `src/**` should also cover the directory's own entry, `src`.
        if pat.endswith("/**") and norm == pat[:-3]:
            return True
    return False


# --------------------------------------------------------------------------------------
# What counts as grader surface
# --------------------------------------------------------------------------------------
#
# Anything the policy could edit to change its *score* rather than its *solution*. This is
# deliberately broad: a false positive here costs one line of evidence in the table, a
# false negative costs a silently gamed training run.

GRADER_PATTERNS: tuple[str, ...] = (
    "tests/**",
    "test/**",
    "**/test_*.py",
    "**/*_test.py",
    "conftest.py",
    "**/conftest.py",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
    "pyproject.toml",
    "grade.py",
    "grader.py",
    "**/grade*.py",
    "run_tests.sh",
    "**/run_tests.sh",
    "Makefile",
    "sitecustomize.py",
    "usercustomize.py",
    "**/__init__.pth",
    "**/*.pth",
)


def is_grader_path(path: str) -> bool:
    """True if `path` is test/grader surface rather than solution surface."""
    return path_matches(path, GRADER_PATTERNS)


# --------------------------------------------------------------------------------------
# Change extraction
# --------------------------------------------------------------------------------------


def hash_changes(rollout: Rollout) -> dict[str, str]:
    """Paths whose sha256 changed between before/after, mapped to what happened.

    Values are one of `added`, `deleted`, `modified`. Derived from the hash trees rather
    than from `diff_paths`, so an attacker that suppresses the differ still shows up.
    """
    before = {normalize_path(k): v for k, v in rollout.workspace_before.items()}
    after = {normalize_path(k): v for k, v in rollout.workspace_after.items()}
    out: dict[str, str] = {}
    for path, digest in after.items():
        if path not in before:
            out[path] = "added"
        elif before[path] != digest:
            out[path] = "modified"
    for path in before:
        if path not in after:
            out[path] = "deleted"
    return out


def changed_paths(rollout: Rollout) -> list[str]:
    """Every path the rollout touched: reported diff paths union hash-derived changes."""
    paths = {normalize_path(p) for p in rollout.diff_paths}
    paths |= set(hash_changes(rollout))
    return sorted(paths)


# --------------------------------------------------------------------------------------
# Detection construction
# --------------------------------------------------------------------------------------


def truncate(text: str, limit: int = EVIDENCE_MAX_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def detection(
    detector_id: str,
    rollout: Rollout,
    *,
    fired: bool,
    score: float,
    evidence: str,
    suspected_classes: Iterable[str] = (),
) -> Detection:
    """Build a `Detection`, clamping score and truncating evidence."""
    return Detection(
        detector_id=detector_id,
        rollout_id=rollout.rollout_id,
        fired=fired,
        score=max(0.0, min(1.0, float(score))),
        evidence=truncate(evidence),
        suspected_classes=list(suspected_classes) if fired else [],
    )


def named(detector_id: str) -> Callable[[Detector], Detector]:
    """Attach `detector_id` to a detector function so the registry can label it."""

    def wrap(fn: Detector) -> Detector:
        fn.detector_id = detector_id  # type: ignore[attr-defined]
        return fn

    return wrap
