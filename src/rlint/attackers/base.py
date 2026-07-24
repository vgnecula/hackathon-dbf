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
        attacker_id = fn.__name__
        if attacker_id in REGISTRY:
            raise ValueError(f"duplicate attacker id: {attacker_id}")
        REGISTRY[attacker_id] = AttackerMeta(
            attacker_id=attacker_id,
            exploit_class=exploit_class,
            description=description,
            fn=fn,
        )
        return fn

    return decorator


__all__ = ["Attacker", "AttackerMeta", "REGISTRY", "attacker"]
