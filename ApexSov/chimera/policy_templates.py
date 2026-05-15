from __future__ import annotations

import json
from typing import Any, Dict, List


# Domain-specific PII augmentations per industry template
FINANCE_SPECIFIC_PATTERNS: List[str] = [
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
    r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
]

HEALTHCARE_SPECIFIC_PATTERNS: List[str] = [
    r"\bMRN[:\s]*[A-Za-z0-9\-]{4,20}\b",
    r"\b(patient|member)\s*id[:\s]*[A-Za-z0-9\-]{4,20}\b",
]

GOVERNMENT_SPECIFIC_PATTERNS: List[str] = [
    r"\bpassport\s*no[:\s]*[A-Za-z0-9]{6,15}\b",
    r"\bnational\s*id[:\s]*[A-Za-z0-9\-]{4,20}\b",
]

DEFAULT_POLICY_BASELINE: Dict[str, Any] = {
    "unified_thresh": 0.65,
    "axis_thresholds": {
        "pii": 0.2,
        "jailbreak": 0.3,
        "grooming": 0.3,
        # Optional high-risk/DLP axis. Default is disabled (0.0).
        "dlp": 0.0,
        # Optional semantic DLP axis (embedding similarity to exemplars). Default disabled.
        "dlp_semantic": 0.0,
    },
    "risk_weights": {
        "pii": 1.0,
        "jailbreak": 1.2,
        "grooming": 0.8,
        "toxicity": 0.5,
        "drift": 0.3,
        "dlp": 0.9,
        "dlp_semantic": 1.0,
    },
    "pii_patterns": [
        # email
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}\b",
        # SSN
        r"\b\d{3}-\d{2}-\d{4}\b",
        # phone
        r"\b(?:\+1[\s\-_.]*)?(?:\(?\d{3}\)?|\d{3})[\s\-_.]?\d{3}[\s\-_.]?\d{4}\b",
        # generic card-like
        r"\b(?:\d[\s\-_.]?){13,19}\b",
        # address-ish
        r"\b\d{1,5}\s+\w+\s+(street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr)\b",
    ],
    "pii_mode": "block",  # or "redact"
    # Multimodal guardrail: this gateway only supports text inspection.
    # If false, any non-text message content will be rejected.
    "allow_multimodal": False,
    "usage_quotas": {
        "requests_per_minute": 0,
        "tokens_per_minute": 0,
        "tokens_per_day": 0,
        "tokens_per_month": 0,
    },
    "tool_scoping": {
        "enabled": False,
        "mode": "allowlist",
        "allowed_tools": [],
        "denied_tools": [],
        "audit_allowed": True,
    },
    # Retention applies only to non-ledger state in Redis.
    # Ledger is append-only and is never deleted by retention.
    "retention": {
        "session_prompts_ttl_seconds": 180 * 24 * 3600,
        "adversarial_corpus_ttl_seconds": 365 * 24 * 3600,
        "content_store_ttl_seconds": 365 * 24 * 3600,
    },
    # Data minimization controls (tenant-configurable).
    # - no_content_retention: disables storing raw prompts and any deduped content derived from prompts.
    # - audit_mode: controls how identifiers/context are recorded to the append-only audit ledger.
    #   Supported: full | hash_only | redacted_only
    "data_minimization": {
        "no_content_retention": False,
        "audit_mode": "full",
        "include_subject": True,
        "include_session_id": True,
        "include_request_context": True,
    },
}

DEFAULT_POLICY_RETENTION: Dict[str, Any] = DEFAULT_POLICY_BASELINE["retention"]
DEFAULT_POLICY_DATA_MINIMIZATION: Dict[str, Any] = DEFAULT_POLICY_BASELINE["data_minimization"]
DEFAULT_POLICY_TOOL_SCOPING: Dict[str, Any] = DEFAULT_POLICY_BASELINE["tool_scoping"]

POLICY_TEMPLATE_MAP: Dict[str, Dict[str, Any]] = {
    "default": DEFAULT_POLICY_BASELINE,
    "finance": {
        "unified_thresh": 0.75,
        "axis_thresholds": {
            "pii": 0.1,
            "jailbreak": 0.2,
            "grooming": 0.3,
            # Finance: enable a stricter high-risk/DLP threshold.
            "dlp": 0.25,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + FINANCE_SPECIFIC_PATTERNS,
        # Finance: per-tenant model allowlist and retention defaults.
        # Note: ledger is append-only; these TTLs apply only to non-ledger stores.
        "model_allowlist": ["safe-small", "default-mid", "reasoning-pro"],
        "retention": {
            # Typical finance evidence retention is 5-7y for immutable audit logs.
            # Prompt/session stores are usually much shorter to reduce sensitive-data exposure.
            "session_prompts_ttl_seconds": 180 * 24 * 3600,
            "adversarial_corpus_ttl_seconds": 365 * 24 * 3600,
            "content_store_ttl_seconds": 365 * 24 * 3600,
        },
        "data_minimization": DEFAULT_POLICY_DATA_MINIMIZATION,
        "evidence_retention_years": 7,
    },
    "healthcare": {
        "unified_thresh": 0.7,
        "axis_thresholds": {
            "pii": 0.15,
            "jailbreak": 0.25,
            "grooming": 0.3,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + HEALTHCARE_SPECIFIC_PATTERNS,
        "retention": DEFAULT_POLICY_RETENTION,
        "data_minimization": DEFAULT_POLICY_DATA_MINIMIZATION,
    },
    "government": {
        "unified_thresh": 0.8,
        "axis_thresholds": {
            "pii": 0.1,
            "jailbreak": 0.2,
            "grooming": 0.25,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + GOVERNMENT_SPECIFIC_PATTERNS,
        "retention": DEFAULT_POLICY_RETENTION,
        "data_minimization": DEFAULT_POLICY_DATA_MINIMIZATION,
    },
}


def clone_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(policy))


def get_policy_template(policy_group: str) -> Dict[str, Any]:
    return POLICY_TEMPLATE_MAP.get(policy_group, DEFAULT_POLICY_BASELINE)


def build_seed_policy_for_group(policy_group: str) -> Dict[str, Any]:
    return clone_policy(get_policy_template(policy_group))
