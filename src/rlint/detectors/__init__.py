"""Detection layer: pure `Rollout -> Detection` functions plus the aggregating registry."""

from .base import Detector, detection, is_grader_path, named, path_matches

__all__ = ["Detector", "detection", "is_grader_path", "named", "path_matches"]
