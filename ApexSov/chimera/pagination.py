from __future__ import annotations


def clamp_limit(limit: int, *, min_value: int = 1, max_value: int = 200) -> int:
    return max(min_value, min(int(limit), max_value))
