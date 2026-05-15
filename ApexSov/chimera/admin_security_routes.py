from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel


class ThreatIntelRule(BaseModel):
    rule_id: Optional[str] = None
    indicator: Optional[str] = None
    indicator_hash: Optional[str] = None
    indicator_token_count: Optional[int] = None
    indicator_hash_alg: Optional[str] = None
    tactic: str = "prompt_injection"
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    source: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


class ThreatIntelIngestRequest(BaseModel):
    feed_version: Optional[str] = None
    mode: Literal["replace", "append"] = "replace"
    activate: bool = True
    comment: Optional[str] = None
    hash_indicators: bool = False
    rules: List[ThreatIntelRule]


class ThreatIntelActivateRequest(BaseModel):
    feed_version: str


class DlpSemanticExemplar(BaseModel):
    exemplar_id: Optional[str] = None
    text: str
    label: Optional[str] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    created_at: Optional[str] = None


class DlpSemanticIngestRequest(BaseModel):
    mode: Literal["replace", "append"] = "replace"
    comment: Optional[str] = None
    exemplars: List[DlpSemanticExemplar]


def register_admin_security_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    threat_intel_store_factory: Callable[..., Any],
    create_unsigned_ledger_entry: Callable[..., Awaitable[Any]],
    ledger_backpressure_error_cls: Any,
    control_plane_payloads: Any,
    policy_records: Any,
    region: str,
    chain_id: str,
    control_plane_reads: Any,
    read_signing_audit_stream: Callable[..., Awaitable[List[Dict[str, Any]]]],
    get_apex_env: Callable[[], Any],
    sign_audit_enabled: bool,
    sign_audit_stream_key: str,
    sign_audit_ttl_seconds: int,
    threat_intel_versions_key: Callable[[str], str],
    dlp_semantic_store_factory: Callable[..., Any],
    policy_store_factory: Callable[..., Any],
    seed_policy_for_group: Callable[[str], Dict[str, Any]],
    no_content_retention_enabled: Callable[[Dict[str, Any]], bool],
    policy_retention_seconds: Callable[[Dict[str, Any], str], int],
    dlp_semantic_enabled: bool,
    embedding_model: str,
    dlp_semantic_max_exemplars: int,
    load_signer_for_worker: Callable[[], Any],
    signer_health: Dict[str, Any],
) -> None:
    async def _threat_intel_status_payload(r: Any, *, tenant_id: str) -> Dict[str, Any]:
        cached = await threat_intel_store_factory(r).load_rules(tenant_id, force_reload=True)
        try:
            versions = await r.lrange(threat_intel_versions_key(tenant_id), 0, 9)
        except Exception:
            versions = []
        return control_plane_payloads.threat_intel_status_payload(
            tenant_id=tenant_id,
            cached=cached,
            versions=versions,
        )

    @app.post("/admin/threat_intel/{tenant_id}/ingest")
    async def admin_threat_intel_ingest(
        tenant_id: str,
        req: ThreatIntelIngestRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = threat_intel_store_factory(r)
        meta = await store.ingest(tenant_id, req)

        audit_payload = control_plane_payloads.threat_intel_admin_audit_payload(
            ts=policy_records.utc_now_z(),
            tenant_id=tenant_id,
            subject=identity.subject,
            roles=identity.roles,
            action="THREAT_INTEL_INGEST",
            meta=meta,
            region=region,
            chain_id=chain_id,
            extra={
                "staged_feed_version": meta.get("staged_feed_version"),
                "mode": meta.get("mode"),
                "rule_count": meta.get("rule_count"),
                "activate": bool(req.activate),
                "comment": req.comment,
            },
        )
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
        except ledger_backpressure_error_cls:
            pass
        except Exception:
            pass

        return {"ok": True, "meta": meta}

    @app.post("/admin/threat_intel/{tenant_id}/activate")
    async def admin_threat_intel_activate(
        tenant_id: str,
        req: ThreatIntelActivateRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = threat_intel_store_factory(r)
        meta = await store.activate(tenant_id, req.feed_version)

        audit_payload = control_plane_payloads.threat_intel_admin_audit_payload(
            ts=policy_records.utc_now_z(),
            tenant_id=tenant_id,
            subject=identity.subject,
            roles=identity.roles,
            action="THREAT_INTEL_ACTIVATE",
            meta=meta,
            region=region,
            chain_id=chain_id,
        )
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
        except Exception:
            pass

        return {"ok": True, "meta": meta}

    @app.post("/admin/threat_intel/{tenant_id}/rollback")
    async def admin_threat_intel_rollback(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = threat_intel_store_factory(r)
        meta = await store.rollback(tenant_id)

        audit_payload = control_plane_payloads.threat_intel_admin_audit_payload(
            ts=policy_records.utc_now_z(),
            tenant_id=tenant_id,
            subject=identity.subject,
            roles=identity.roles,
            action="THREAT_INTEL_ROLLBACK",
            meta=meta,
            region=region,
            chain_id=chain_id,
        )
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
        except Exception:
            pass

        return {"ok": True, "meta": meta}

    @app.get("/admin/signing/audit/summary")
    async def admin_signing_audit_summary(
        limit: int = 50,
        tenant_id: Optional[str] = None,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.build_signing_audit_summary_payload(
            r,
            limit=limit,
            tenant_id_filter=tenant_id,
            include_tenant_id=False,
            include_filter=True,
            include_counters=True,
            read_signing_audit_stream=read_signing_audit_stream,
            ts=policy_records.utc_now_z(),
            env=get_apex_env().value,
            sign_audit=control_plane_payloads.signing_audit_config_payload(
                enabled=sign_audit_enabled,
                stream_key=sign_audit_stream_key,
                ttl_seconds=sign_audit_ttl_seconds,
            ),
        )

    @app.get("/api/v1/audit/signing/audit/summary")
    async def audit_signing_audit_summary(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await control_plane_reads.build_signing_audit_summary_payload(
            r,
            limit=limit,
            tenant_id_filter=identity.tenant_id,
            include_tenant_id=True,
            include_filter=False,
            include_counters=False,
            read_signing_audit_stream=read_signing_audit_stream,
            ts=policy_records.utc_now_z(),
            env=get_apex_env().value,
            sign_audit=control_plane_payloads.signing_audit_config_payload(
                enabled=sign_audit_enabled,
                stream_key=sign_audit_stream_key,
                ttl_seconds=sign_audit_ttl_seconds,
            ),
        )

    @app.get("/admin/threat_intel/{tenant_id}/status")
    async def admin_threat_intel_status(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await _threat_intel_status_payload(r, tenant_id=tenant_id)

    @app.post("/admin/dlp_semantic/{tenant_id}/ingest")
    async def admin_dlp_semantic_ingest(
        tenant_id: str,
        req: DlpSemanticIngestRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()

        content_ttl = 0
        try:
            policy_record = await policy_store_factory(r).get_policy_or_seed(
                tenant_id,
                seed_policy=seed_policy_for_group("default"),
            )
            pol = policy_record.policy or {}
            if no_content_retention_enabled(pol):
                raise HTTPException(status_code=409, detail="Tenant policy forbids content retention (semantic DLP ingest disabled)")
            content_ttl = policy_retention_seconds(pol, "content_store_ttl_seconds")
        except HTTPException:
            raise
        except Exception:
            pass

        store = dlp_semantic_store_factory(r)
        meta = await store.ingest(tenant_id, req, content_ttl_seconds=content_ttl)

        audit_payload = {
            "ts": policy_records.utc_now_z(),
            "tenant_id": tenant_id,
            "subject": identity.subject,
            "roles": identity.roles,
            "decision": "ADMIN_ACTION",
            "action": "DLP_SEMANTIC_INGEST",
            "mode": meta.get("mode"),
            "count": meta.get("count"),
            "comment": req.comment,
            "enabled": bool(dlp_semantic_enabled),
            "embedding_model": embedding_model,
            "region": region,
            "ledger_chain_id": chain_id,
        }
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
        except ledger_backpressure_error_cls:
            pass
        except Exception:
            pass

        return {"ok": True, "meta": meta}

    @app.get("/admin/dlp_semantic/{tenant_id}/status")
    async def admin_dlp_semantic_status(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.dlp_semantic_status_for_tenant(
            r,
            tenant_id=tenant_id,
            store_factory=dlp_semantic_store_factory,
            enabled=dlp_semantic_enabled,
            embedding_model=embedding_model,
            max_exemplars=dlp_semantic_max_exemplars,
        )

    @app.post("/admin/failsafe/zeroize")
    async def admin_failsafe_zeroize(identity=Depends(get_identity)):
        authz_engine.require_admin(identity)
        r = await get_redis_client()

        signer = load_signer_for_worker()
        did_zeroize = False
        if hasattr(signer, "zeroize"):
            try:
                signer.zeroize()  # type: ignore[attr-defined]
                did_zeroize = True
            except Exception:
                did_zeroize = False

        signer_health["ok"] = False
        signer_health["last_error"] = "zeroized_by_admin" if did_zeroize else "zeroize_attempt_failed"
        signer_health["last_error_at"] = policy_records.utc_now_z()

        audit_payload = {
            "ts": policy_records.utc_now_z(),
            "tenant_id": identity.tenant_id,
            "subject": identity.subject,
            "roles": identity.roles,
            "decision": "ADMIN_ACTION",
            "action": "SIGNER_ZEROIZE",
            "did_zeroize": did_zeroize,
            "region": region,
            "ledger_chain_id": chain_id,
        }
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
        except ledger_backpressure_error_cls:
            pass
        except Exception:
            pass

        return {"ok": True, "did_zeroize": did_zeroize, "signer_health": signer_health}
