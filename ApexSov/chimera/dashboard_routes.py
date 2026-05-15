from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

from fastapi import Depends


def register_dashboard_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    get_apex_env: Callable[[], Any],
    get_unsigned_backlog_status: Callable[[Any], Awaitable[Any]],
    ledger_backlog_state_label: Callable[..., str],
    fips_mode: bool,
    policy_version: str,
    region: str,
    chain_id: str,
    egress_check_url: Callable[[str], Any],
    compile_egress_allowlist_patterns: Callable[[], Any],
    utc_now_z: Callable[[], str],
    block_ip_literals: bool,
    allowlist_regex: str,
    audit_blocks: bool,
    model_catalog: Dict[str, Any],
    dashboard_views: Any,
    control_plane_reads: Any,
    policy_views: Any,
    max_unsigned_queue: int,
    decode_single_json_skip_invalid: Callable[[Any], Any],
    compute_entry_hash: Callable[[Dict[str, Any], Any], str],
    metrics_hour_key: Callable[[Any], str],
    metrics_total_key: Callable[[str], str],
    metrics_blocked_key: Callable[[str], str],
    metrics_highrisk_key: Callable[[str], str],
    metrics_axis_hash_key: Callable[[str], str],
    verify_ledger_chain_for_api: Callable[[Any], Awaitable[Any]],
    seed_policy_for_group: Callable[[str], Dict[str, Any]],
    effective_retention_seconds: Callable[[Dict[str, Any], str], int],
    retention_payload_builder: Callable[..., Dict[str, Any]],
    compliance_mode: bool,
    compliance_require_ttls: bool,
    max_session_prompts_ttl_seconds: int,
    max_adversarial_corpus_ttl_seconds: int,
    max_content_store_ttl_seconds: int,
    dlp_semantic_store_factory: Callable[..., Any],
    dlp_semantic_enabled: bool,
    dlp_embedding_model: str,
    dlp_max_exemplars: int,
    policy_store_factory: Callable[..., Any],
) -> None:
    async def _policy_current_default(r: Any, *, tenant_id: str):
        return await policy_views.policy_current_for_tenant(
            r,
            tenant_id=tenant_id,
            store_factory=policy_store_factory,
            seed_policy=seed_policy_for_group("default"),
        )

    def _retention_view_for_current(*, tenant_id: str, current: Any) -> Dict[str, Any]:
        return policy_views.effective_retention_view(
            tenant_id=tenant_id,
            policy=current.policy or {},
            policy_version=current.version,
            effective_retention_seconds=effective_retention_seconds,
            payload_builder=retention_payload_builder,
            compliance_mode=compliance_mode,
            compliance_require_ttls=compliance_require_ttls,
            max_session_prompts_ttl_seconds=max_session_prompts_ttl_seconds,
            max_adversarial_corpus_ttl_seconds=max_adversarial_corpus_ttl_seconds,
            max_content_store_ttl_seconds=max_content_store_ttl_seconds,
        )

    def _egress_validate_payload(url: str) -> Dict[str, Any]:
        return dashboard_views.build_egress_validate_payload(
            url,
            egress_check_url=egress_check_url,
            compile_egress_allowlist_patterns=compile_egress_allowlist_patterns,
            utc_now_z=utc_now_z,
            block_ip_literals=block_ip_literals,
            allowlist_regex=allowlist_regex,
            audit_blocks=audit_blocks,
        )

    async def _dashboard_integrity_metrics(r: Any) -> Dict[str, Any]:
        return await dashboard_views.system_integrity_metrics(
            r,
            get_unsigned_backlog_status=get_unsigned_backlog_status,
            max_unsigned_queue=max_unsigned_queue,
            get_last_kms_signed_at_fn=lambda client: dashboard_views.get_last_kms_signed_at(
                client,
                decode_single_json_skip_invalid=decode_single_json_skip_invalid,
            ),
        )

    async def _dashboard_risk_overview(r: Any) -> Dict[str, Any]:
        return await dashboard_views.get_24h_risk_stats(
            r,
            metrics_hour_key=metrics_hour_key,
            metrics_total_key=metrics_total_key,
            metrics_blocked_key=metrics_blocked_key,
            metrics_highrisk_key=metrics_highrisk_key,
            metrics_axis_hash_key=metrics_axis_hash_key,
        )

    @app.get("/admin/governance/summary")
    async def governance_summary(identity=Depends(get_identity)):
        """High-level governance summary for operators."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
        return {
            "env": get_apex_env().value,
            "ledger_backlog_len": queue_len,
            "ledger_backlog_state": ledger_backlog_state_label(
                is_warning=is_warning,
                is_critical=is_critical,
            ),
            "fips_mode": fips_mode,
            "policy_version": policy_version,
            "region": region,
            "chain_id": chain_id,
        }

    @app.get("/admin/egress/validate")
    async def admin_egress_validate(
        url: str,
        identity=Depends(get_identity),
    ):
        """Admin-only helper to test sovereign egress policy decisions."""
        authz_engine.require_admin(identity)
        return _egress_validate_payload(url)

    @app.get("/api/v1/audit/egress/validate")
    async def audit_egress_validate(
        url: str,
        identity=Depends(get_identity),
    ):
        """Auditor read-only helper to test sovereign egress policy decisions."""
        authz_engine.require_audit_read(identity)
        return _egress_validate_payload(url)

    @app.get("/sdk/config")
    async def sdk_config():
        """Simple configuration endpoint for SDKs or clients to auto-configure proxy access."""
        return {
            "stream_endpoint": "/v1/stream",
            "auth_scheme": "Bearer",
            "required_headers": ["Authorization", "x-tenant-id", "x-session-id"],
            "models": list(model_catalog.keys()),
        }

    @app.get("/api/v1/dashboard/summary")
    async def dashboard_summary(identity=Depends(get_identity)):
        """CISO dashboard summary for integrity, backpressure, and recent risk stats."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()

        metrics = await _dashboard_integrity_metrics(r)
        backpressure_level = float(metrics.get("backpressure_level") or 0.0)
        last_kms_signed_at = metrics.get("last_kms_signed_at")

        ledger_status = await dashboard_views.recent_ledger_status(
            r,
            decode_single_json_skip_invalid=decode_single_json_skip_invalid,
            compute_entry_hash=compute_entry_hash,
        )

        risk_overview = await _dashboard_risk_overview(r)

        return {
            "system_integrity": {
                "ledger_status": ledger_status,
                "last_kms_signed_at": last_kms_signed_at,
                "backpressure_level": backpressure_level,
                "fips_mode": fips_mode,
            },
            "risk_overview": risk_overview,
        }

    @app.get("/api/v1/audit/dashboard/summary")
    async def audit_dashboard_summary(identity=Depends(get_identity)):
        """Auditor-facing compliance dashboard summary (read-only)."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()

        metrics = await _dashboard_integrity_metrics(r)
        backpressure_level = float(metrics.get("backpressure_level") or 0.0)
        last_kms_signed_at = metrics.get("last_kms_signed_at")

        ok, count, last_checkpoint = await verify_ledger_chain_for_api(r)
        risk_overview = await _dashboard_risk_overview(r)

        current = await _policy_current_default(r, tenant_id=identity.tenant_id)
        policy = current.policy or {}
        retention_view = _retention_view_for_current(tenant_id=identity.tenant_id, current=current)

        dlp_status = await control_plane_reads.dlp_semantic_status_for_tenant(
            r,
            tenant_id=identity.tenant_id,
            store_factory=dlp_semantic_store_factory,
            enabled=dlp_semantic_enabled,
            embedding_model=dlp_embedding_model,
            max_exemplars=dlp_max_exemplars,
            include_comment=False,
            include_tenant_id=False,
        )
        return {
            "system_integrity": {
                "ledger_chain_verified": bool(ok),
                "ledger_entry_count": int(count),
                "last_checkpoint": last_checkpoint,
                "last_kms_signed_at": last_kms_signed_at,
                "backpressure_level": backpressure_level,
                "fips_mode": fips_mode,
                "region": region,
                "chain_id": chain_id,
            },
            "risk_overview": risk_overview,
            "tenant_controls": {
                "tenant_id": identity.tenant_id,
                "model_allowlist": policy.get("model_allowlist") or [],
                "retention": policy.get("retention") or {},
                "retention_effective": retention_view,
                "retention_governed": retention_view,
                "dlp_semantic": dlp_status,
            },
            "platform": {
                "models": list(model_catalog.keys()),
            },
        }

    @app.get("/api/v1/policy/{tenant_id}/current")
    async def dashboard_policy_current(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        """CISO dashboard view of per-tenant policy and its history."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        current = await _policy_current_default(r, tenant_id=tenant_id)
        return await policy_views.build_policy_current_with_history_view(
            r,
            tenant_id=tenant_id,
            store_factory=policy_store_factory,
            current=current,
        )
