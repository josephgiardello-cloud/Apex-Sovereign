from __future__ import annotations

from typing import Any, Dict, Optional
import uuid


def policy_proposals_hash_key(tenant_id: str) -> str:
    return f"apex:policy:{tenant_id}:proposals"


def policy_proposals_index_key(tenant_id: str) -> str:
    return f"apex:policy:{tenant_id}:proposals:index"


def build_policy_proposal_record(
    *,
    tenant_id: str,
    policy: Dict[str, Any],
    change_request_id: Optional[str],
    requested_version: Optional[str],
    comment: Optional[str],
    justification: Optional[str],
    change_ticket: Optional[str],
    created_by: Optional[str],
    created_at: str,
) -> Dict[str, Any]:
    proposal_id = str(uuid.uuid4())
    return {
        "proposal_id": proposal_id,
        "tenant_id": tenant_id,
        "policy": policy,
        "change_request_id": change_request_id,
        "requested_version": requested_version,
        "comment": comment,
        "justification": justification,
        "change_ticket": change_ticket,
        "status": "PENDING",
        "created_by": created_by,
        "created_at": created_at,
        "approved_by": None,
        "approved_at": None,
        "approval_comment": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_comment": None,
    }


def is_pending(proposal: Dict[str, Any]) -> bool:
    return proposal.get("status") == "PENDING"


def approve_proposal(
    proposal: Dict[str, Any],
    *,
    approver: Optional[str],
    approved_at: str,
    approval_comment: Optional[str],
) -> Dict[str, Any]:
    out = dict(proposal)
    out["status"] = "APPROVED"
    out["approved_by"] = approver
    out["approved_at"] = approved_at
    out["approval_comment"] = approval_comment
    return out


def reject_proposal(
    proposal: Dict[str, Any],
    *,
    rejector: Optional[str],
    rejected_at: str,
    rejection_comment: Optional[str],
) -> Dict[str, Any]:
    out = dict(proposal)
    out["status"] = "REJECTED"
    out["rejected_by"] = rejector
    out["rejected_at"] = rejected_at
    out["rejection_comment"] = rejection_comment
    return out


def violates_two_person_rule(*, proposer: Optional[str], approver: Optional[str]) -> bool:
    return bool(proposer and approver and proposer == approver)
