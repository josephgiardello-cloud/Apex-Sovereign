from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List


@dataclass(frozen=True)
class MigrationStep:
    id: str
    from_version: str
    to_version: str
    forward_only: bool


class MigrationRegistry:
    def __init__(self) -> None:
        self._steps: Dict[str, MigrationStep] = {}
        self._handlers: Dict[str, Callable[[], None]] = {}

    def register(self, step: MigrationStep, handler: Callable[[], None]) -> None:
        if step.id in self._steps:
            raise ValueError(f"duplicate_migration id={step.id}")
        self._steps[step.id] = step
        self._handlers[step.id] = handler

    def planned_steps(self) -> List[MigrationStep]:
        return [self._steps[k] for k in sorted(self._steps.keys())]

    def apply_all(self) -> List[str]:
        applied: List[str] = []
        for step in self.planned_steps():
            self._handlers[step.id]()
            applied.append(step.id)
        return applied
