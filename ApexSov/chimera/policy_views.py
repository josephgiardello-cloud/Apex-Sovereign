from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as redis


async def policy_current_for_tenant(
    r: redis.Redis,
    *,
    tenant_id: str,
    store_factory,
    seed_policy: Dict[str, Any],
):
    store = store_factory(r)
    return await store.get_policy_or_seed(tenant_id, seed_policy=seed_policy)


async def policy_versions_for_tenant(
    r: redis.Redis,
    *,
    tenant_id: str,
    store_factory,
):
    store = store_factory(r)
    return await store.list_versions(tenant_id)


def effective_retention_view(
    *,
    tenant_id: str,
    policy: Dict[str, Any],
    policy_version: Optional[str],
    effective_retention_seconds: Callable[[Dict[str, Any], str], int],
    payload_builder,
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
    configured: Dict[str, Any] = {}
    try:
        configured = (policy.get("retention") or {}) if isinstance(policy, dict) else {}
    except Exception:
        configured = {}

    effective: Dict[str, int] = {k: int(effective_retention_seconds(policy, k) or 0) for k in keys}
    return payload_builder(
        tenant_id=tenant_id,
        policy_version=policy_version,
        configured=configured,
        effective=effective,
        compliance_mode=compliance_mode,
        compliance_require_ttls=compliance_require_ttls,
        max_session_prompts_ttl_seconds=max_session_prompts_ttl_seconds,
        max_adversarial_corpus_ttl_seconds=max_adversarial_corpus_ttl_seconds,
        max_content_store_ttl_seconds=max_content_store_ttl_seconds,
    )


async def build_policy_current_with_history_view(
    r: redis.Redis,
    *,
    tenant_id: str,
    store_factory,
    current,
) -> Dict[str, Any]:
    store = store_factory(r)
    history_records = await store.list_versions(tenant_id)

    history: List[Dict[str, Any]] = []
    for rec in history_records:
        if rec.version == current.version and rec.created_at == current.created_at:
            continue
        history.append(
            {
                "version": rec.version,
                "comment": rec.comment,
                "date": rec.created_at,
            }
        )

    return {
        "version": current.version,
        "created_at": current.created_at,
        "policy": current.policy,
        "history": history,
    }
