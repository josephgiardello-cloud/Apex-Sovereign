from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DecisionKind(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    RETRY = "retry"
    ERROR = "error"


class DecisionAuthority(str, Enum):
    POLICY = "policy"
    SAFETY = "safety"
    ORCHESTRATOR = "orchestrator"
    PROVIDER = "provider"


class BuildGate(str, Enum):
    TIER0 = "tier0"
    TIER1 = "tier1"
    TIER2 = "tier2"


@dataclass(frozen=True)
class DecisionRecord:
    authority: DecisionAuthority
    decision: DecisionKind
    reason: str
    confidence: Optional[float] = None
