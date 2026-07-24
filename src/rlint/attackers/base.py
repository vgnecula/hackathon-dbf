"""Frozen contract — DG owns the registry and scripted.py, harness consumes REGISTRY.

Do not edit outside the DG track (see AGENTS.md). VG owns this stub only up to the freeze.
"""

from collections.abc import Callable
from dataclasses import dataclass

from rlint.models import EnvSpec
from rlint.sandbox.base import Sandbox

Attacker = Callable[[Sandbox, EnvSpec], None]


@dataclass
class AttackerMeta:
    attacker_id: str
    exploit_class: str  # "E0".."E8"
    description: str
    fn: Attacker


REGISTRY: dict[str, AttackerMeta] = {}


def attacker(exploit_class: str, description: str) -> Callable[[Attacker], Attacker]:
    def decorator(fn: Attacker) -> Attacker:
        REGISTRY[fn.__name__] = AttackerMeta(
            attacker_id=fn.__name__,
            exploit_class=exploit_class,
            description=description,
            fn=fn,
        )
        return fn

    return decorator
