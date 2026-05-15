from typing import Any, Dict, List, Optional

import redis.asyncio as redis
from fastapi import HTTPException

from . import control_plane_payloads
from . import env_config_governance
from . import pagination
from . import policy_governance
from . import redis_json_views


async def list_indexed_json_objects(
    r: redis.Redis,
    *,
    index_key: str,
    hash_key: str,
    limit: int,
) -> List[Dict[str, Any]]:
    lim = pagination.clamp_limit(limit)
    ids = await r.lrange(index_key, 0, lim - 1)
    if not ids:
        return []
    raw_map = await r.hmget(hash_key, *ids)
    return redis_json_views.decode_json_items_skip_invalid(raw_map)


async def load_policy_proposal(
    r: redis.Redis,
    *,
    proposals_hash_key: str,
    proposal_id: str,
    require_pending: bool = False,
) -> Dict[str, Any]:
    raw = await r.hget(proposals_hash_key, proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = redis_json_views.decode_required_json_object(raw)
    if require_pending and not policy_governance.is_pending(proposal):
        raise HTTPException(status_code=409, detail="Proposal is not pending")
    return proposal


async def load_env_config_proposal(
    r: redis.Redis,
    *,
    proposals_hash_key: str,
    proposal_id: str,
    require_pending: bool = False,
) -> Dict[str, Any]:
    raw = await r.hget(proposals_hash_key, proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = redis_json_views.decode_required_json_object(raw)
    if require_pending and not env_config_governance.is_pending(proposal):
        raise HTTPException(status_code=409, detail="Proposal is not pending")
    return proposal


async def build_signing_audit_summary_payload(
    r: redis.Redis,
    *,
    limit: int,
    tenant_id_filter: Optional[str],
    include_tenant_id: bool,
    include_filter: bool,
    include_counters: bool,
    read_signing_audit_stream,
    ts: str,
    env: str,
    sign_audit: Dict[str, Any],
) -> Dict[str, Any]:
    events = await read_signing_audit_stream(r, limit=limit, tenant_id_filter=tenant_id_filter)
    counters = None
    if include_counters:
        try:
            counters = {
                "success": int(await r.get("apex:signing:ops:success") or 0),
                "failure": int(await r.get("apex:signing:ops:failure") or 0),
                "last_error": await r.get("apex:signing:ops:last_error"),
                "last_error_at": await r.get("apex:signing:ops:last_error_at"),
            }
        except Exception:
            counters = {}
    return control_plane_payloads.signing_audit_summary_payload(
        ts=ts,
        env=env,
        sign_audit=sign_audit,
        events=events,
        tenant_id_filter=tenant_id_filter,
        include_tenant_id=include_tenant_id,
        include_filter=include_filter,
        counters=counters,
    )


async def dlp_semantic_status_for_tenant(
    r: redis.Redis,
    *,
    tenant_id: str,
    store_factory,
    enabled: bool,
    embedding_model: str,
    max_exemplars: int,
    include_comment: bool = True,
    include_tenant_id: bool = True,
) -> Dict[str, Any]:
    loaded = await store_factory(r).load(tenant_id)
    meta = loaded.get("meta") or {}
    items = loaded.get("items") or []
    return control_plane_payloads.dlp_semantic_status_payload(
        tenant_id=tenant_id,
        meta=meta,
        items=items,
        enabled=enabled,
        embedding_model=embedding_model,
        max_exemplars=max_exemplars,
        include_comment=include_comment,
        include_tenant_id=include_tenant_id,
    )
