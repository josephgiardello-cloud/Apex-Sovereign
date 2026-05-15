from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_governance_event_payload(
    *,
    tenant_id: str,
    actor: str,
    event_type: str,
    region: str,
    chain_id: str,
    extra: Optional[Dict[str, Any]] = None,
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "ts": ts or utc_now_z(),
        "tenant_id": tenant_id,
        "decision": event_type,
        "subject": actor,
        "region": region,
        "ledger_chain_id": chain_id,
    }
    if extra:
        payload.update(extra)
    return payload
