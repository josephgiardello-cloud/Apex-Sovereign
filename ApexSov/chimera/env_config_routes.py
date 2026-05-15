from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel

from . import control_plane_reads
from . import env_config_changes
from . import env_config_governance
from . import env_config_views
from . import policy_records


class EnvConfigProposalRequest(BaseModel):
    changes: Dict[str, Optional[str]]
    change_request_id: Optional[str] = None
    change_ticket: Optional[str] = None
    justification: str
    comment: Optional[str] = None


class EnvConfigProposalApprovalRequest(BaseModel):
    approval_comment: Optional[str] = None


class EnvConfigProposalRejectRequest(BaseModel):
    rejection_comment: Optional[str] = None


def register_env_config_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    get_apex_env: Callable[[], Any],
    runtime_snapshot: Dict[str, Any],
    is_sensitive_env_key: Callable[[str], bool],
    redact_env_value: Callable[[str], str],
    best_effort_governance_ledger_event: Callable[..., Awaitable[None]],
) -> None:
    def _envcfg_proposals_hash_key() -> str:
        return env_config_governance.envcfg_proposals_hash_key(get_apex_env().value)

    def _envcfg_proposals_index_key() -> str:
        return env_config_governance.envcfg_proposals_index_key(get_apex_env().value)

    def _envcfg_desired_current_key() -> str:
        return env_config_governance.envcfg_desired_current_key(get_apex_env().value)

    def _envcfg_desired_history_key() -> str:
        return env_config_governance.envcfg_desired_history_key(get_apex_env().value)

    def _sanitize_env_changes(changes: Dict[str, Optional[str]]) -> Dict[str, Any]:
        return env_config_changes.sanitize_env_changes(
            changes,
            is_sensitive_env_key=is_sensitive_env_key,
            redact_env_value=redact_env_value,
        )

    def _env_changes_version(changes_redacted: Dict[str, Any]) -> str:
        return env_config_changes.env_changes_version(changes_redacted)

    @app.get("/admin/env_config/current")
    async def admin_env_config_current(identity=Depends(get_identity)):
        """Admin/operator view of the current runtime env snapshot and approved desired config."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_current_payload(
            r,
            env_value=get_apex_env().value,
            runtime_snapshot=runtime_snapshot,
            desired_current_key=_envcfg_desired_current_key(),
        )

    @app.get("/api/v1/audit/env_config/current")
    async def audit_env_config_current(identity=Depends(get_identity)):
        """Auditor read-only view of env config (redacted) and desired config (redacted)."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_current_payload(
            r,
            env_value=get_apex_env().value,
            runtime_snapshot=runtime_snapshot,
            desired_current_key=_envcfg_desired_current_key(),
        )

    @app.get("/admin/env_config/history")
    async def admin_env_config_history(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        """Admin/operator view of approved desired env config history (redacted).

        Notes:
        - Most recent approvals are returned first.
        - This does not include pending proposals; see /admin/env_config/proposals.
        """
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_history_payload(
            r,
            env_value=get_apex_env().value,
            desired_history_key=_envcfg_desired_history_key(),
            limit=limit,
        )

    @app.get("/api/v1/audit/env_config/history")
    async def audit_env_config_history(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        """Auditor read-only view of approved desired env config history (redacted)."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_history_payload(
            r,
            env_value=get_apex_env().value,
            desired_history_key=_envcfg_desired_history_key(),
            limit=limit,
        )

    @app.get("/admin/env_config/overview")
    async def admin_env_config_overview(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        """Admin/operator view of env config: snapshot + desired config + approved history (redacted)."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_overview_payload(
            r,
            env_value=get_apex_env().value,
            runtime_snapshot=runtime_snapshot,
            desired_current_key=_envcfg_desired_current_key(),
            desired_history_key=_envcfg_desired_history_key(),
            limit=limit,
        )

    @app.get("/api/v1/audit/env_config/overview")
    async def audit_env_config_overview(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        """Auditor read-only view of env config: snapshot + desired config + approved history (redacted)."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await env_config_views.build_env_config_overview_payload(
            r,
            env_value=get_apex_env().value,
            runtime_snapshot=runtime_snapshot,
            desired_current_key=_envcfg_desired_current_key(),
            desired_history_key=_envcfg_desired_history_key(),
            limit=limit,
        )

    @app.post("/admin/env_config/proposals")
    async def propose_env_config_change(
        req: EnvConfigProposalRequest,
        identity=Depends(get_identity),
    ):
        """Propose a desired env var change (two-person approval; does not mutate runtime env)."""
        authz_engine.require_admin(identity)
        if not isinstance(req.justification, str) or not req.justification.strip():
            raise HTTPException(status_code=400, detail="justification is required")

        changes_redacted = _sanitize_env_changes(req.changes or {})
        if not changes_redacted:
            raise HTTPException(status_code=400, detail="no valid env var changes provided")

        version = _env_changes_version(changes_redacted)
        record = env_config_governance.build_env_config_proposal_record(
            env_value=get_apex_env().value,
            version=version,
            changes=changes_redacted,
            change_request_id=req.change_request_id,
            change_ticket=req.change_ticket,
            justification=req.justification,
            comment=req.comment,
            created_by=identity.subject,
            created_by_tenant=identity.tenant_id,
            created_at=policy_records.utc_now_z(),
        )
        proposal_id = str(record.get("proposal_id") or "")

        r = await get_redis_client()
        async with r.pipeline(transaction=True) as pipe:
            pipe.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(record, separators=(",", ":"), sort_keys=True))
            pipe.lpush(_envcfg_proposals_index_key(), proposal_id)
            pipe.ltrim(_envcfg_proposals_index_key(), 0, 499)
            await pipe.execute()

        await best_effort_governance_ledger_event(
            r,
            tenant_id=identity.tenant_id,
            actor=identity.subject,
            event_type="ENV_CONFIG_PROPOSED",
            extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": version, "change_request_id": req.change_request_id},
        )

        return record

    @app.get("/admin/env_config/proposals")
    async def list_env_config_proposals(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.list_indexed_json_objects(
            r,
            index_key=_envcfg_proposals_index_key(),
            hash_key=_envcfg_proposals_hash_key(),
            limit=limit,
        )

    @app.get("/admin/env_config/proposals/{proposal_id}")
    async def get_env_config_proposal(
        proposal_id: str,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await control_plane_reads.load_env_config_proposal(
            r,
            proposals_hash_key=_envcfg_proposals_hash_key(),
            proposal_id=proposal_id,
        )

    @app.post("/admin/env_config/proposals/{proposal_id}/approve")
    async def approve_env_config_proposal(
        proposal_id: str,
        req: EnvConfigProposalApprovalRequest,
        identity=Depends(get_identity),
    ):
        """Approve an env config proposal; approver must be different from proposer."""
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        proposal = await control_plane_reads.load_env_config_proposal(
            r,
            proposals_hash_key=_envcfg_proposals_hash_key(),
            proposal_id=proposal_id,
            require_pending=True,
        )

        proposer = proposal.get("created_by")
        if env_config_governance.violates_two_person_rule(proposer=proposer, approver=identity.subject):
            raise HTTPException(status_code=403, detail="Two-person rule: proposer cannot approve their own proposal")

        approved_at = policy_records.utc_now_z()
        proposal = env_config_governance.approve_env_config_proposal(
            proposal,
            approved_by=identity.subject,
            approved_at=approved_at,
            approval_comment=req.approval_comment,
        )

        desired_record = env_config_governance.build_desired_config_record(
            env_value=get_apex_env().value,
            proposal=proposal,
            proposal_id=proposal_id,
            approved_by=identity.subject,
            approved_at=approved_at,
        )

        async with r.pipeline(transaction=True) as pipe:
            pipe.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(proposal, separators=(",", ":"), sort_keys=True))
            pipe.set(_envcfg_desired_current_key(), json.dumps(desired_record, separators=(",", ":"), sort_keys=True))
            pipe.lpush(_envcfg_desired_history_key(), json.dumps(desired_record, separators=(",", ":"), sort_keys=True))
            pipe.ltrim(_envcfg_desired_history_key(), 0, 199)
            await pipe.execute()

        await best_effort_governance_ledger_event(
            r,
            tenant_id=identity.tenant_id,
            actor=identity.subject,
            event_type="ENV_CONFIG_APPROVED",
            extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": proposal.get("version")},
        )

        return {"proposal": proposal, "desired_config": desired_record}

    @app.post("/admin/env_config/proposals/{proposal_id}/reject")
    async def reject_env_config_proposal(
        proposal_id: str,
        req: EnvConfigProposalRejectRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        proposal = await control_plane_reads.load_env_config_proposal(
            r,
            proposals_hash_key=_envcfg_proposals_hash_key(),
            proposal_id=proposal_id,
            require_pending=True,
        )

        proposal = env_config_governance.reject_env_config_proposal(
            proposal,
            rejected_by=identity.subject,
            rejected_at=policy_records.utc_now_z(),
            rejection_comment=req.rejection_comment,
        )

        await r.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(proposal, separators=(",", ":"), sort_keys=True))

        await best_effort_governance_ledger_event(
            r,
            tenant_id=identity.tenant_id,
            actor=identity.subject,
            event_type="ENV_CONFIG_REJECTED",
            extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": proposal.get("version")},
        )

        return proposal

    @app.get("/api/v1/audit/env_config/proposals")
    async def audit_list_env_config_proposals(
        limit: int = 50,
        identity=Depends(get_identity),
    ):
        """Auditor read-only view of env config proposals (redacted)."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await control_plane_reads.list_indexed_json_objects(
            r,
            index_key=_envcfg_proposals_index_key(),
            hash_key=_envcfg_proposals_hash_key(),
            limit=limit,
        )
