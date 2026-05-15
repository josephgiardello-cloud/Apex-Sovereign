"""Failure taxonomy helpers for consistent runtime error classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class FailureType(StrEnum):
    RETRYABLE = "retryable"
    NON_RETRYABLE = "non_retryable"
    POISON = "poison"
    PARTIAL_COMMIT = "partial_commit"
    UNKNOWN_STATE = "unknown_state"


class FailureAction(StrEnum):
    MANUAL_RETRY = "manual_retry"
    FAIL_FAST = "fail_fast"
    QUARANTINE = "quarantine"
    RECONCILE = "reconcile"


@dataclass(frozen=True, slots=True)
class FailurePolicy:
    failure_type: FailureType
    failure_class: str
    failure_source: str
    retryable: bool
    action: FailureAction
    auto_retry: bool


_POLICY_BY_FAILURE_TYPE: dict[FailureType, FailurePolicy] = {
    FailureType.RETRYABLE: FailurePolicy(
        failure_type=FailureType.RETRYABLE,
        failure_class="timeout",
        failure_source="infrastructure",
        retryable=True,
        action=FailureAction.MANUAL_RETRY,
        auto_retry=False,
    ),
    FailureType.NON_RETRYABLE: FailurePolicy(
        failure_type=FailureType.NON_RETRYABLE,
        failure_class="contract_violation",
        failure_source="input",
        retryable=False,
        action=FailureAction.FAIL_FAST,
        auto_retry=False,
    ),
    FailureType.POISON: FailurePolicy(
        failure_type=FailureType.POISON,
        failure_class="poison_message",
        failure_source="policy",
        retryable=False,
        action=FailureAction.QUARANTINE,
        auto_retry=False,
    ),
    FailureType.PARTIAL_COMMIT: FailurePolicy(
        failure_type=FailureType.PARTIAL_COMMIT,
        failure_class="partial_commit",
        failure_source="durability",
        retryable=False,
        action=FailureAction.RECONCILE,
        auto_retry=False,
    ),
    FailureType.UNKNOWN_STATE: FailurePolicy(
        failure_type=FailureType.UNKNOWN_STATE,
        failure_class="runtime_exception",
        failure_source="execution",
        retryable=False,
        action=FailureAction.RECONCILE,
        auto_retry=False,
    ),
}


def _failure_type_for_exception(exc: BaseException) -> FailureType:
    if isinstance(exc, TimeoutError):
        return FailureType.RETRYABLE

    try:
        import asyncio

        if isinstance(exc, (asyncio.TimeoutError, asyncio.CancelledError)):
            return FailureType.RETRYABLE
    except Exception:
        pass

    if isinstance(exc, (ValueError, TypeError, AssertionError, PermissionError)):
        return FailureType.NON_RETRYABLE

    return FailureType.UNKNOWN_STATE


def classify_failure(exc: BaseException) -> dict[str, Any]:
    failure_type = _failure_type_for_exception(exc)
    policy = _POLICY_BY_FAILURE_TYPE[failure_type]
    return {
        "failure_type": policy.failure_type.value,
        "failure_class": policy.failure_class,
        "failure_source": policy.failure_source,
        "retryable": bool(policy.retryable),
        "failure_action": policy.action.value,
        "auto_retry": bool(policy.auto_retry),
        "exception_type": type(exc).__name__,
    }


__all__ = ["FailureType", "FailureAction", "FailurePolicy", "classify_failure"]
