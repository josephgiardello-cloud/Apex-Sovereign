from typing import Any, Dict, List, Optional


def threat_intel_admin_audit_payload(
    *,
    ts: str,
    tenant_id: str,
    subject: str,
    roles: List[str],
    action: str,
    meta: Dict[str, Any],
    region: str,
    chain_id: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "ts": ts,
        "tenant_id": tenant_id,
        "subject": subject,
        "roles": roles,
        "decision": "ADMIN_ACTION",
        "action": action,
        "active_feed_version": meta.get("active_feed_version"),
        "previous_feed_version": meta.get("previous_feed_version"),
        "region": region,
        "ledger_chain_id": chain_id,
    }
    if isinstance(extra, dict) and extra:
        payload.update(extra)
    return payload


def signing_audit_config_payload(*, enabled: bool, stream_key: str, ttl_seconds: int) -> Dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "stream_key": stream_key,
        "ttl_seconds": int(ttl_seconds or 0),
    }


def signing_audit_summary_payload(
    *,
    ts: str,
    env: str,
    sign_audit: Dict[str, Any],
    events: List[Dict[str, Any]],
    tenant_id_filter: Optional[str],
    include_tenant_id: bool,
    include_filter: bool,
    counters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "ts": ts,
        "env": env,
        "sign_audit": sign_audit,
        "recent_events": events,
    }
    if include_tenant_id and tenant_id_filter is not None:
        payload["tenant_id"] = tenant_id_filter
    if include_filter:
        payload["filter"] = {"tenant_id": tenant_id_filter}
    if isinstance(counters, dict):
        payload["counters"] = counters
    return payload


def threat_intel_status_payload(*, tenant_id: str, cached: Dict[str, Any], versions: List[Any]) -> Dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "active_feed_version": cached.get("feed_version"),
        "previous_feed_version": cached.get("previous_feed_version"),
        "updated_at": cached.get("updated_at"),
        "rule_count": len(cached.get("rules") or []),
        "recent_versions": versions,
    }


def dlp_semantic_status_payload(
    *,
    tenant_id: str,
    meta: Dict[str, Any],
    items: List[Any],
    enabled: bool,
    embedding_model: str,
    max_exemplars: int,
    include_comment: bool = True,
    include_tenant_id: bool = True,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "enabled": bool(enabled),
        "embedding_model": embedding_model,
        "max_exemplars": int(max_exemplars),
        "updated_at": meta.get("updated_at"),
        "count": meta.get("count", len(items)),
    }
    if include_tenant_id:
        payload["tenant_id"] = tenant_id
    if include_comment:
        payload["comment"] = meta.get("comment")
    return payload


def ledger_backlog_state_label(*, is_warning: bool, is_critical: bool) -> str:
    if is_critical:
        return "CRITICAL"
    if is_warning:
        return "WARNING"
    return "OK"


def model_allowlist_payload(*, tenant_id: str, policy_version: str, allowlist: List[str], known_models: List[str]) -> Dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "policy_version": policy_version,
        "model_allowlist": allowlist,
        "known_models": known_models,
    }


def effective_retention_view(
    *,
    tenant_id: str,
    policy_version: Optional[str],
    configured: Dict[str, Any],
    effective: Dict[str, int],
    compliance_mode: bool,
    compliance_require_ttls: bool,
    max_session_prompts_ttl_seconds: int,
    max_adversarial_corpus_ttl_seconds: int,
    max_content_store_ttl_seconds: int,
) -> Dict[str, Any]:
    keys = [
        "session_prompts_ttl_seconds",
        "adversarial_corpus_ttl_seconds",
        "content_store_ttl_seconds",
    ]
    return {
        "tenant_id": tenant_id,
        "policy_version": policy_version,
        "compliance": {
            "mode": bool(compliance_mode),
            "require_ttls": bool(compliance_require_ttls),
            "max_ttls_seconds": {
                "session_prompts_ttl_seconds": int(max_session_prompts_ttl_seconds or 0),
                "adversarial_corpus_ttl_seconds": int(max_adversarial_corpus_ttl_seconds or 0),
                "content_store_ttl_seconds": int(max_content_store_ttl_seconds or 0),
            },
        },
        "retention": {
            "configured": {k: configured.get(k) for k in keys},
            "effective_seconds": effective,
            "applies_to": [
                "session:{tenant}:{session}:prompts",
                "apex:adversarial_corpus:{tenant}",
                "apex:content:{tenant}:{kind}:{sha256}",
            ],
            "never_deleted": ["apex:audit_ledger"],
        },
    }
