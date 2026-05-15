from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as redis
from fastapi import HTTPException
from pydantic import BaseModel

try:
    from . import redis_json_views as chimera_redis_json_views
except Exception:
    import chimera.redis_json_views as chimera_redis_json_views  # type: ignore[no-redef]


_policy_version: str = ""
_seed_policy_for_group_fn: Optional[Callable[[str], Dict[str, Any]]] = None
_seed_from_template_fields_fn: Optional[Callable[..., Dict[str, Any]]] = None
_seed_from_policy_group_fields_fn: Optional[Callable[..., Dict[str, Any]]] = None
_effective_retention_seconds_fn: Optional[Callable[[Dict[str, Any], str], int]] = None


def configure_tenant_policy_store(
    *,
    policy_version: str,
    seed_policy_for_group_fn: Callable[[str], Dict[str, Any]],
    seed_from_template_fields_fn: Callable[..., Dict[str, Any]],
    seed_from_policy_group_fields_fn: Callable[..., Dict[str, Any]],
    effective_retention_seconds_fn: Callable[[Dict[str, Any], str], int],
) -> None:
    global _policy_version
    global _seed_policy_for_group_fn
    global _seed_from_template_fields_fn
    global _seed_from_policy_group_fields_fn
    global _effective_retention_seconds_fn

    _policy_version = policy_version
    _seed_policy_for_group_fn = seed_policy_for_group_fn
    _seed_from_template_fields_fn = seed_from_template_fields_fn
    _seed_from_policy_group_fields_fn = seed_from_policy_group_fields_fn
    _effective_retention_seconds_fn = effective_retention_seconds_fn


class PolicyRecord(BaseModel):
    version: str
    policy: Dict[str, Any]
    created_at: str
    created_by: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None
    change_request_id: Optional[str] = None
    proposal_id: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None


class PolicyStore:
    """Per-tenant policy store on Redis with current + history."""

    def __init__(self, r: redis.Redis):
        self.r = r

    def _current_key(self, tenant_id: str) -> str:
        return f"apex:policy:{tenant_id}:current"

    def _history_key(self, tenant_id: str) -> str:
        return f"apex:policy:{tenant_id}:history"

    async def get_policy_record(self, tenant_id: str) -> PolicyRecord:
        raw = await self.r.get(self._current_key(tenant_id))
        if not raw:
            raise HTTPException(status_code=404, detail="Policy not found for tenant")
        data = chimera_redis_json_views.decode_required_json_object(raw)
        return PolicyRecord(**data)

    async def get_policy_or_seed(self, tenant_id: str, seed_policy: Dict[str, Any]) -> PolicyRecord:
        raw = await self.r.get(self._current_key(tenant_id))
        if raw:
            data = chimera_redis_json_views.decode_required_json_object(raw)
            return PolicyRecord(**data)

        if _seed_from_template_fields_fn is None:
            raise RuntimeError("tenant_policy_store not configured")
        record = PolicyRecord(
            **_seed_from_template_fields_fn(
                policy_version=_policy_version,
                seed_policy=seed_policy,
            )
        )
        await self.set_policy(tenant_id, record, is_new=True)
        return record

    async def set_policy(self, tenant_id: str, record: PolicyRecord, is_new: bool = False) -> None:
        key = self._current_key(tenant_id)
        hist_key = self._history_key(tenant_id)

        async with self.r.pipeline(transaction=True) as pipe:
            if not is_new:
                current_raw = await self.r.get(key)
                if current_raw:
                    await pipe.rpush(hist_key, current_raw)
            await pipe.set(key, record.model_dump_json())
            await pipe.execute()

    async def list_versions(self, tenant_id: str) -> List[PolicyRecord]:
        history = await self.r.lrange(self._history_key(tenant_id), 0, -1)
        out: List[PolicyRecord] = []
        for obj in chimera_redis_json_views.decode_json_items_skip_invalid(history):
            try:
                out.append(PolicyRecord(**obj))
            except Exception:
                continue
        try:
            current = await self.get_policy_record(tenant_id)
            out.append(current)
        except Exception:
            pass
        return out

    async def rollback_to_version(self, tenant_id: str, version: str, actor: str) -> PolicyRecord:
        history = await self.r.lrange(self._history_key(tenant_id), 0, -1)
        for h in reversed(history):
            data = chimera_redis_json_views.decode_required_json_object(h)
            if data.get("version") == version:
                record = PolicyRecord(**data)
                record.comment = f"rollback_by_{actor}"
                await self.set_policy(tenant_id, record, is_new=False)
                return record
        raise HTTPException(status_code=404, detail="Policy version not found for tenant")


def policy_retention_seconds(policy: Dict[str, Any], key: str) -> int:
    try:
        if _effective_retention_seconds_fn is None:
            return 0
        return int(_effective_retention_seconds_fn(policy, key) or 0)
    except Exception:
        return 0


class TenantMetadata(BaseModel):
    tenant_id: str
    organization_name: str
    tier: str
    industry: str
    contact_email: str
    active: bool = True
    created_at: str
    policy_group: str = "default"


class TenantStore:
    """Tenant metadata store and policy seeding."""

    def __init__(self, r: redis.Redis):
        self.r = r
        self.policy_store = PolicyStore(r)

    def _meta_key(self, tenant_id: str) -> str:
        return f"apex:tenant:{tenant_id}:meta"

    async def onboard_tenant(self, metadata: TenantMetadata) -> None:
        await self.r.set(self._meta_key(metadata.tenant_id), metadata.model_dump_json())

        if _seed_policy_for_group_fn is None or _seed_from_policy_group_fields_fn is None:
            raise RuntimeError("tenant_policy_store not configured")

        seed_policy = _seed_policy_for_group_fn(metadata.policy_group)
        record = PolicyRecord(
            **_seed_from_policy_group_fields_fn(
                policy_version=_policy_version,
                seed_policy=seed_policy,
                tenant_id=metadata.tenant_id,
                policy_group=metadata.policy_group,
            )
        )
        await self.policy_store.set_policy(metadata.tenant_id, record, is_new=True)

    async def upsert_metadata(self, metadata: TenantMetadata) -> None:
        await self.r.set(self._meta_key(metadata.tenant_id), metadata.model_dump_json())

    async def get_metadata(self, tenant_id: str) -> TenantMetadata:
        raw = await self.r.get(self._meta_key(tenant_id))
        if not raw:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return TenantMetadata(**chimera_redis_json_views.decode_required_json_object(raw))

    async def list_all(self) -> List[TenantMetadata]:
        keys = await self.r.keys("apex:tenant:*:meta")
        out: List[TenantMetadata] = []
        for k in keys:
            raw = await self.r.get(k)
            if raw:
                decoded = chimera_redis_json_views.decode_single_json_skip_invalid(raw)
                if decoded is None:
                    continue
                try:
                    out.append(TenantMetadata(**decoded))
                except Exception:
                    continue
        return out
