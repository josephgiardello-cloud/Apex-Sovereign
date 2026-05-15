from __future__ import annotations

from typing import Iterable, List, Optional

from .domain import DecisionAuthority, DecisionKind, DecisionRecord


# Highest precedence first.
_AUTHORITY_ORDER = [
    DecisionAuthority.POLICY,
    DecisionAuthority.SAFETY,
    DecisionAuthority.ORCHESTRATOR,
    DecisionAuthority.PROVIDER,
]


def _sort_by_authority(records: Iterable[DecisionRecord]) -> List[DecisionRecord]:
    rank = {authority: idx for idx, authority in enumerate(_AUTHORITY_ORDER)}
    return sorted(records, key=lambda r: rank.get(r.authority, 999))


def resolve_final_decision(records: Iterable[DecisionRecord]) -> Optional[DecisionRecord]:
    """Resolve final decision using explicit authority precedence.

    First record in highest-precedence authority wins.
    """
    ordered = _sort_by_authority(records)
    return ordered[0] if ordered else None


def is_hard_block(decision: Optional[DecisionRecord]) -> bool:
    if decision is None:
        return False
    return decision.decision == DecisionKind.BLOCK
