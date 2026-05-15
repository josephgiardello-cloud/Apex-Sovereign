from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import time


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generated_version(*, policy_version: str, suffix: Optional[str] = None) -> str:
    base = f"{policy_version}:{int(time.time())}"
    if not suffix:
        return base
    return f"{base}:{suffix}"


def approved_version(*, provided_version: Optional[str], requested_version: Optional[str], policy_version: str) -> str:
    if isinstance(provided_version, str) and provided_version.strip():
        return provided_version
    if isinstance(requested_version, str) and requested_version.strip():
        return requested_version
    return generated_version(policy_version=policy_version, suffix="approved")


def seed_from_template_fields(*, policy_version: str, seed_policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": policy_version,
        "policy": seed_policy,
        "created_at": utc_now_z(),
        "created_by": "system",
        "comment": "seed_from_template",
    }


def seed_from_policy_group_fields(
    *,
    policy_version: str,
    seed_policy: Dict[str, Any],
    tenant_id: str,
    policy_group: str,
) -> Dict[str, Any]:
    return {
        "version": policy_version,
        "policy": seed_policy,
        "created_at": utc_now_z(),
        "created_by": tenant_id,
        "comment": f"seed_from_policy_group:{policy_group}",
    }


def policy_update_fields(
    *,
    version: str,
    policy: Dict[str, Any],
    created_by: Optional[str],
    comment: Optional[str],
    justification: Optional[str] = None,
    change_ticket: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "version": version,
        "policy": policy,
        "created_at": created_at or utc_now_z(),
        "created_by": created_by,
        "comment": comment,
        "justification": justification,
        "change_ticket": change_ticket,
    }


def approved_proposal_fields(
    *,
    version: str,
    policy: Dict[str, Any],
    proposal_created_at: Optional[str],
    approved_at: str,
    proposer: Optional[str],
    proposal_comment: Optional[str],
    proposal_justification: Optional[str],
    proposal_change_ticket: Optional[str],
    change_request_id: Optional[str],
    proposal_id: str,
    approved_by: Optional[str],
) -> Dict[str, Any]:
    return {
        "version": version,
        "policy": policy,
        "created_at": proposal_created_at or approved_at,
        "created_by": proposer,
        "comment": proposal_comment or "approved_policy_change",
        "justification": proposal_justification,
        "change_ticket": proposal_change_ticket,
        "change_request_id": change_request_id,
        "proposal_id": proposal_id,
        "approved_by": approved_by,
        "approved_at": approved_at,
    }
