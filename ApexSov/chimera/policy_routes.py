from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel


class PolicyUpdateRequest(BaseModel):
    policy: Dict[str, Any]
    version: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None


class PolicyProposalRequest(BaseModel):
    policy: Dict[str, Any]
    change_request_id: Optional[str] = None
    requested_version: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None


class PolicyProposalApprovalRequest(BaseModel):
    version: Optional[str] = None
    approval_comment: Optional[str] = None


class PolicyProposalRejectRequest(BaseModel):
    rejection_comment: Optional[str] = None


class ModelAllowlistUpdateRequest(BaseModel):
    models: List[str]
    version: Optional[str] = None
    comment: Optional[str] = None


def register_policy_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    two_person_policy: bool,
    policy_version: str,
    seed_policy_for_group: Callable[[str], Dict[str, Any]],
    policy_store_factory: Callable[..., Any],
    policy_record_cls: Any,
    policy_records: Any,
    policy_governance: Any,
    policy_views: Any,
    control_plane_reads: Any,
    control_plane_payloads: Any,
    model_allowlist: Any,
    external_model_map: Dict[str, str],
    model_catalog: Dict[str, Any],
    validate_retention_policy_or_raise: Callable[[Dict[str, Any]], None],
    effective_retention_seconds: Callable[[Dict[str, Any], str], int],
    compliance_mode: bool,
    compliance_require_ttls: bool,
    max_session_prompts_ttl_seconds: int,
    max_adversarial_corpus_ttl_seconds: int,
    max_content_store_ttl_seconds: int,
    best_effort_governance_ledger_event: Callable[..., Awaitable[None]],
) -> None:
    def _policy_proposals_hash_key(tenant_id: str) -> str:
        return policy_governance.policy_proposals_hash_key(tenant_id)

    def _policy_proposals_index_key(tenant_id: str) -> str:
        return policy_governance.policy_proposals_index_key(tenant_id)

    async def _policy_current_default(r: Any, *, tenant_id: str):
        return await policy_views.policy_current_for_tenant(
            r,
            tenant_id=tenant_id,
            store_factory=policy_store_factory,
            seed_policy=seed_policy_for_group("default"),
        )

    def _model_allowlist_payload_for_current(*, tenant_id: str, current: Any) -> Dict[str, Any]:
        policy = current.policy or {}
        allowlist = model_allowlist.read_policy_allowlist(policy)
        return control_plane_payloads.model_allowlist_payload(
            tenant_id=tenant_id,
            policy_version=current.version,
            allowlist=allowlist,
            known_models=list(model_catalog.keys()),
        )

    def _retention_view_for_current(*, tenant_id: str, current: Any) -> Dict[str, Any]:
        return policy_views.effective_retention_view(
            tenant_id=tenant_id,
            policy=current.policy or {},
            policy_version=current.version,
            effective_retention_seconds=effective_retention_seconds,
            payload_builder=control_plane_payloads.effective_retention_view,
            compliance_mode=compliance_mode,
            compliance_require_ttls=compliance_require_ttls,
            max_session_prompts_ttl_seconds=max_session_prompts_ttl_seconds,
            max_adversarial_corpus_ttl_seconds=max_adversarial_corpus_ttl_seconds,
            max_content_store_ttl_seconds=max_content_store_ttl_seconds,
        )

    async def _effective_retention_for_tenant(r: Any, *, tenant_id: str) -> Dict[str, Any]:
        current = await _policy_current_default(r, tenant_id=tenant_id)
        return _retention_view_for_current(tenant_id=tenant_id, current=current)

    @app.get("/admin/policies/{tenant_id}")
    async def get_policy_for_tenant(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = policy_store_factory(r)
        return await store.get_policy_record(tenant_id)

    @app.post("/admin/policies/{tenant_id}")
    async def update_policy_for_tenant(
        tenant_id: str,
        req: PolicyUpdateRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        if two_person_policy:
            raise HTTPException(
                status_code=409,
                detail="Two-person policy control enabled; use /admin/policies/{tenant_id}/proposals and approve with a second admin.",
            )
        if not isinstance(req.justification, str) or not req.justification.strip():
            raise HTTPException(status_code=400, detail="Policy change requires justification")
        r = await get_redis_client()
        store = policy_store_factory(r)
        validate_retention_policy_or_raise(req.policy)
        new_version = req.version or policy_records.generated_version(policy_version=policy_version)
        record = policy_record_cls(
            **policy_records.policy_update_fields(
                version=new_version,
                policy=req.policy,
                created_by=identity.subject,
                comment=req.comment,
                justification=req.justification,
                change_ticket=req.change_ticket,
            )
        )
        await store.set_policy(tenant_id, record, is_new=False)

        await best_effort_governance_ledger_event(
            r,
            tenant_id=tenant_id,
            actor=identity.subject,
            event_type="POLICY_UPDATED",
            extra={"version": record.version, "change_ticket": req.change_ticket},
        )

        return record

    @app.post("/admin/policies/{tenant_id}/proposals")
    async def propose_policy_change(
        tenant_id: str,
        req: PolicyProposalRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()

        if not isinstance(req.justification, str) or not req.justification.strip():
            raise HTTPException(status_code=400, detail="Policy change requires justification")

        validate_retention_policy_or_raise(req.policy)

        record = policy_governance.build_policy_proposal_record(
            tenant_id=tenant_id,
            policy=req.policy,
            change_request_id=req.change_request_id,
            requested_version=req.requested_version,
            comment=req.comment,
            justification=req.justification,
            change_ticket=req.change_ticket,
            created_by=identity.subject,
            created_at=policy_records.utc_now_z(),
        )
        proposal_id = str(record.get("proposal_id") or "")

        async with r.pipeline(transaction=True) as pipe:
            pipe.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(record))
            pipe.lpush(_policy_proposals_index_key(tenant_id), proposal_id)
            pipe.ltrim(_policy_proposals_index_key(tenant_id), 0, 499)
            await pipe.execute()

        await best_effort_governance_ledger_event(
            r,
            tenant_id=tenant_id,
            actor=identity.subject,
            event_type="POLICY_PROPOSED",
            extra={"proposal_id": proposal_id, "change_request_id": req.change_request_id, "change_ticket": req.change_ticket},
        )

        return record

    @app.get("/admin/policies/{tenant_id}/proposals")
    async def list_policy_proposals(
        tenant_id: str,
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.list_indexed_json_objects(
            r,
            index_key=_policy_proposals_index_key(tenant_id),
            hash_key=_policy_proposals_hash_key(tenant_id),
            limit=limit,
        )

    @app.get("/admin/policies/{tenant_id}/proposals/{proposal_id}")
    async def get_policy_proposal(
        tenant_id: str,
        proposal_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.load_policy_proposal(
            r,
            proposals_hash_key=_policy_proposals_hash_key(tenant_id),
            proposal_id=proposal_id,
        )

    @app.post("/admin/policies/{tenant_id}/proposals/{proposal_id}/approve")
    async def approve_policy_proposal(
        tenant_id: str,
        proposal_id: str,
        req: PolicyProposalApprovalRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        store = policy_store_factory(r)
        proposal = await control_plane_reads.load_policy_proposal(
            r,
            proposals_hash_key=_policy_proposals_hash_key(tenant_id),
            proposal_id=proposal_id,
            require_pending=True,
        )

        proposer = proposal.get("created_by")
        if policy_governance.violates_two_person_rule(proposer=proposer, approver=identity.subject):
            raise HTTPException(status_code=403, detail="Two-person rule: proposer cannot approve their own proposal")

        approved_at = policy_records.utc_now_z()
        proposal = policy_governance.approve_proposal(
            proposal,
            approver=identity.subject,
            approved_at=approved_at,
            approval_comment=req.approval_comment,
        )

        new_version = policy_records.approved_version(
            provided_version=req.version,
            requested_version=proposal.get("requested_version"),
            policy_version=policy_version,
        )

        record = policy_record_cls(
            **policy_records.approved_proposal_fields(
                version=new_version,
                policy=proposal.get("policy") or {},
                proposal_created_at=proposal.get("created_at"),
                approved_at=approved_at,
                proposer=proposer,
                proposal_comment=proposal.get("comment"),
                proposal_justification=proposal.get("justification"),
                proposal_change_ticket=proposal.get("change_ticket"),
                change_request_id=proposal.get("change_request_id"),
                proposal_id=proposal_id,
                approved_by=identity.subject,
            )
        )

        async with r.pipeline(transaction=True) as pipe:
            pipe.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(proposal))
            await pipe.execute()

        await store.set_policy(tenant_id, record, is_new=False)

        await best_effort_governance_ledger_event(
            r,
            tenant_id=tenant_id,
            actor=identity.subject,
            event_type="POLICY_APPROVED",
            extra={"proposal_id": proposal_id, "change_request_id": proposal.get("change_request_id"), "version": new_version},
        )

        return {
            "proposal": proposal,
            "applied_policy_record": record,
        }

    @app.post("/admin/policies/{tenant_id}/proposals/{proposal_id}/reject")
    async def reject_policy_proposal(
        tenant_id: str,
        proposal_id: str,
        req: PolicyProposalRejectRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        proposal = await control_plane_reads.load_policy_proposal(
            r,
            proposals_hash_key=_policy_proposals_hash_key(tenant_id),
            proposal_id=proposal_id,
            require_pending=True,
        )

        proposal = policy_governance.reject_proposal(
            proposal,
            rejector=identity.subject,
            rejected_at=policy_records.utc_now_z(),
            rejection_comment=req.rejection_comment,
        )

        await r.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(proposal))

        await best_effort_governance_ledger_event(
            r,
            tenant_id=tenant_id,
            actor=identity.subject,
            event_type="POLICY_REJECTED",
            extra={"proposal_id": proposal_id, "change_request_id": proposal.get("change_request_id")},
        )

        return proposal

    @app.post("/admin/policies/{tenant_id}/model_allowlist")
    async def update_model_allowlist_for_tenant(
        tenant_id: str,
        req: ModelAllowlistUpdateRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        if two_person_policy:
            raise HTTPException(
                status_code=409,
                detail="Two-person policy control enabled; update allowlist via a proposal and approval.",
            )
        r = await get_redis_client()
        current = await _policy_current_default(r, tenant_id=tenant_id)
        policy = dict(current.policy or {})

        try:
            normalized = model_allowlist.normalize_requested_models(
                req.models,
                external_model_map=external_model_map,
                model_catalog=model_catalog,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        policy["model_allowlist"] = normalized

        validate_retention_policy_or_raise(policy)

        new_version = req.version or policy_records.generated_version(
            policy_version=policy_version,
            suffix="allowlist",
        )
        record = policy_record_cls(
            **policy_records.policy_update_fields(
                version=new_version,
                policy=policy,
                created_by=identity.subject,
                comment=req.comment or "update_model_allowlist",
            )
        )
        store = policy_store_factory(r)
        await store.set_policy(tenant_id, record, is_new=False)
        return record

    @app.get("/admin/policies/{tenant_id}/model_allowlist")
    async def get_model_allowlist_for_tenant(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        current = await _policy_current_default(r, tenant_id=tenant_id)
        return _model_allowlist_payload_for_current(tenant_id=tenant_id, current=current)

    @app.get("/api/v1/audit/model_allowlist")
    async def audit_get_model_allowlist(identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        current = await _policy_current_default(r, tenant_id=identity.tenant_id)
        return _model_allowlist_payload_for_current(tenant_id=identity.tenant_id, current=current)

    @app.get("/api/v1/audit/retention/effective")
    async def audit_retention_effective(identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await _effective_retention_for_tenant(r, tenant_id=identity.tenant_id)

    @app.get("/admin/retention/{tenant_id}/effective")
    async def admin_retention_effective(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await _effective_retention_for_tenant(r, tenant_id=tenant_id)

    @app.get("/admin/policies/{tenant_id}/versions")
    async def list_policy_versions(
        tenant_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await policy_views.policy_versions_for_tenant(
            r,
            tenant_id=tenant_id,
            store_factory=policy_store_factory,
        )

    @app.post("/admin/policies/{tenant_id}/rollback/{version}")
    async def rollback_policy(
        tenant_id: str,
        version: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        if two_person_policy:
            raise HTTPException(
                status_code=409,
                detail="Two-person policy control enabled; perform rollback via a proposal and approval.",
            )
        r = await get_redis_client()
        store = policy_store_factory(r)
        return await store.rollback_to_version(tenant_id, version, actor=identity.subject)
