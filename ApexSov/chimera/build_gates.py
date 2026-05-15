from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .domain import BuildGate


@dataclass(frozen=True)
class GateResult:
    gate: BuildGate
    passed: bool
    details: str


def evaluate_gate_set(results: List[GateResult]) -> Dict[str, object]:
    failures = [r for r in results if not r.passed]
    return {
        "passed": len(failures) == 0,
        "failure_count": len(failures),
        "failures": [f"{r.gate}:{r.details}" for r in failures],
    }
