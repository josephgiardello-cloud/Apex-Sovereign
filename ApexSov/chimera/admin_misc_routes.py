from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from fastapi import Depends, HTTPException


def register_admin_misc_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    tenant_store_factory: Callable[[Any], Any],
    control_plane_reads: Any,
    dlp_semantic_store_factory: Callable[[Any], Any],
    dlp_semantic_enabled: bool,
    embedding_model: str,
    dlp_semantic_max_exemplars: int,
    drift_engine_factory: Callable[..., Any],
    drift_backend: Any,
    vector_backend_cls: Any,
    redis_bow_backend_cls: Any,
) -> None:
    @app.get("/admin/tenants")
    async def list_tenants(identity=Depends(get_identity)):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = tenant_store_factory(r)
        return await store.list_all()

    @app.post("/admin/tenants/{tenant_id}")
    async def upsert_tenant(
        tenant_id: str,
        metadata: Any,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        if tenant_id != getattr(metadata, "tenant_id", None):
            raise HTTPException(status_code=400, detail="tenant_id mismatch")
        r = await get_redis_client()
        store = tenant_store_factory(r)
        existing_meta_raw = await r.get(store._meta_key(tenant_id))
        if existing_meta_raw:
            await store.upsert_metadata(metadata)
        else:
            await store.onboard_tenant(metadata)
        return metadata

    @app.get("/api/v1/audit/dlp_semantic/status")
    async def audit_get_dlp_semantic_status(identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await control_plane_reads.dlp_semantic_status_for_tenant(
            r,
            tenant_id=identity.tenant_id,
            store_factory=dlp_semantic_store_factory,
            enabled=dlp_semantic_enabled,
            embedding_model=embedding_model,
            max_exemplars=dlp_semantic_max_exemplars,
        )

    @app.post("/admin/sessions/{session_id}/anchor/reset")
    async def reset_session_anchor(
        session_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        engine = drift_engine_factory(r_client=r, drift_backend=drift_backend)

        if isinstance(engine.drift_backend, vector_backend_cls):
            await engine.drift_backend.reset_anchor(session_id)
        elif isinstance(engine.drift_backend, redis_bow_backend_cls):
            await engine.drift_backend.reset_anchor(session_id)
        else:
            raise HTTPException(status_code=400, detail="Unsupported drift backend for anchor reset")

        return {"status": "ok", "session_id": session_id, "action": "anchor_reset"}
