"""Frozen contract — JS owns detectors/** and registry.py, which consumes Detector.

Do not edit outside the JS track (see AGENTS.md). VG owns this stub only up to the freeze.
"""

from collections.abc import Callable

from rlint.models import Detection, Rollout

Detector = Callable[[Rollout], Detection]
