"""Import compatibility helpers for relative/absolute module fallback."""

import importlib
from types import ModuleType
from typing import Optional


def import_module_compat(package: Optional[str], relative_name: str, absolute_name: str) -> ModuleType:
    """Import with relative-first fallback to absolute path.

    Args:
        package: caller package (usually __package__)
        relative_name: relative module path (e.g. ".chimera.foo")
        absolute_name: absolute module path (e.g. "chimera.foo")
    """
    if package:
        try:
            return importlib.import_module(relative_name, package=package)
        except Exception:
            pass
    return importlib.import_module(absolute_name)
