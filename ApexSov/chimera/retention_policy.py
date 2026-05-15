from __future__ import annotations

from typing import Any, Dict, List, Optional


def coerce_positive_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            int_value = int(value)
        else:
            int_value = int(str(value).strip())
        if int_value <= 0:
            return None
        return int_value
    except Exception:
        return None


def effective_retention_seconds(
    policy: Dict[str, Any],
    key: str,
    *,
    baseline_retention: Dict[str, Any],
    compliance_mode: bool,
    compliance_require_ttls: bool,
    max_session_prompts_ttl_seconds: int,
    max_adversarial_corpus_ttl_seconds: int,
    max_content_store_ttl_seconds: int,
) -> int:
    retention = policy.get("retention")
    if not isinstance(retention, dict):
        retention = {}

    ttl = coerce_positive_int(retention.get(key))
    if ttl is None:
        ttl = coerce_positive_int(baseline_retention.get(key)) or 0

    if compliance_mode and compliance_require_ttls and ttl <= 0:
        ttl = coerce_positive_int(baseline_retention.get(key)) or 0

    cap = 0
    if key == "session_prompts_ttl_seconds":
        cap = int(max_session_prompts_ttl_seconds or 0)
    elif key == "adversarial_corpus_ttl_seconds":
        cap = int(max_adversarial_corpus_ttl_seconds or 0)
    elif key == "content_store_ttl_seconds":
        cap = int(max_content_store_ttl_seconds or 0)

    if cap > 0 and ttl > cap:
        ttl = cap

    return int(ttl or 0)


def missing_required_retention_fields(
    policy: Dict[str, Any],
    *,
    compliance_mode: bool,
    compliance_require_ttls: bool,
) -> List[str]:
    if not compliance_mode or not compliance_require_ttls:
        return []

    retention = policy.get("retention")
    if not isinstance(retention, dict):
        return [
            "session_prompts_ttl_seconds",
            "adversarial_corpus_ttl_seconds",
            "content_store_ttl_seconds",
        ]

    required = [
        "session_prompts_ttl_seconds",
        "adversarial_corpus_ttl_seconds",
        "content_store_ttl_seconds",
    ]

    missing: List[str] = []
    for key in required:
        if coerce_positive_int(retention.get(key)) is None:
            missing.append(key)
    return missing
