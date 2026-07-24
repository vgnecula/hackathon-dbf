"""Ground-truth attacker metadata and registration."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from rlint.models import EnvSpec
from rlint.sandbox.base import Sandbox

Attacker = Callable[[Sandbox, EnvSpec], None]
EXPLOIT_CLASSES: Final = frozenset(f"E{i}" for i in range(9))


@dataclass(frozen=True, slots=True)
class AttackerMeta:
    attacker_id: str
    exploit_class: str  # "E0".."E8"
    description: str
    fn: Attacker


REGISTRY: dict[str, AttackerMeta] = {}


def attacker(exploit_class: str, description: str) -> Callable[[Attacker], Attacker]:
    """Register one deterministic attacker with immutable ground-truth metadata."""
    if exploit_class not in EXPLOIT_CLASSES:
        raise ValueError(
            f"invalid exploit class {exploit_class!r}; "
            f"expected one of {sorted(EXPLOIT_CLASSES)}"
        )
    description = description.strip()
    if not description:
        raise ValueError("attacker description must not be empty")

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


__all__ = ["EXPLOIT_CLASSES", "Attacker", "AttackerMeta", "REGISTRY", "attacker"]
