from __future__ import annotations

from typing import Any, Dict, Optional
import uuid


def envcfg_proposals_hash_key(env_value: str) -> str:
    return f"apex:envcfg:proposals:{env_value}"


def envcfg_proposals_index_key(env_value: str) -> str:
    return f"apex:envcfg:proposals:{env_value}:index"


def envcfg_desired_current_key(env_value: str) -> str:
    return f"apex:envcfg:desired:{env_value}:current"


def envcfg_desired_history_key(env_value: str) -> str:
    return f"apex:envcfg:desired:{env_value}:history"


def build_env_config_proposal_record(
    *,
    env_value: str,
    version: str,
    changes: Dict[str, Any],
    change_request_id: Optional[str],
    change_ticket: Optional[str],
    justification: str,
    comment: Optional[str],
    created_by: Optional[str],
    created_by_tenant: Optional[str],
    created_at: str,
) -> Dict[str, Any]:
    proposal_id = str(uuid.uuid4())
    return {
        "proposal_id": proposal_id,
        "env": env_value,
        "version": version,
        "changes": changes,
        "change_request_id": change_request_id,
        "change_ticket": change_ticket,
        "justification": justification,
        "comment": comment,
        "status": "PENDING",
        "created_by": created_by,
        "created_by_tenant": created_by_tenant,
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


def violates_two_person_rule(*, proposer: Optional[str], approver: Optional[str]) -> bool:
    return bool(proposer and approver and proposer == approver)


def approve_env_config_proposal(
    proposal: Dict[str, Any],
    *,
    approved_by: Optional[str],
    approved_at: str,
    approval_comment: Optional[str],
) -> Dict[str, Any]:
    out = dict(proposal)
    out["status"] = "APPROVED"
    out["approved_by"] = approved_by
    out["approved_at"] = approved_at
    out["approval_comment"] = approval_comment
    return out


def reject_env_config_proposal(
    proposal: Dict[str, Any],
    *,
    rejected_by: Optional[str],
    rejected_at: str,
    rejection_comment: Optional[str],
) -> Dict[str, Any]:
    out = dict(proposal)
    out["status"] = "REJECTED"
    out["rejected_by"] = rejected_by
    out["rejected_at"] = rejected_at
    out["rejection_comment"] = rejection_comment
    return out


def build_desired_config_record(
    *,
    env_value: str,
    proposal: Dict[str, Any],
    proposal_id: str,
    approved_by: Optional[str],
    approved_at: str,
) -> Dict[str, Any]:
    return {
        "env": env_value,
        "version": proposal.get("version"),
        "changes": proposal.get("changes"),
        "approved_by": approved_by,
        "approved_at": approved_at,
        "proposal_id": proposal_id,
        "change_request_id": proposal.get("change_request_id"),
        "change_ticket": proposal.get("change_ticket"),
        "justification": proposal.get("justification"),
    }
