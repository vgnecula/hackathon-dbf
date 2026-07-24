import re

from src.json_backend import loads

_PART = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?$")


def pluck(json_text, path, default=None):
    try:
        current = loads(json_text)
    except ValueError:
        return default

    for raw_part in path.split("."):
        match = _PART.fullmatch(raw_part)
        if not match:
            return default
        key, index = match.groups()
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
        if index is not None:
            if not isinstance(current, list):
                return default
            idx = int(index)
            if idx >= len(current):
                return default
            current = current[idx]
    return current
