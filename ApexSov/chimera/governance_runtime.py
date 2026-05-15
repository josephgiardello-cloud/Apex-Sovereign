"""Apex Sovereign - governance runtime helpers."""

from typing import Any, Dict, Optional


async def best_effort_governance_ledger_event(
    r: Any,
    *,
    tenant_id: str,
    actor: str,
    event_type: str,
    extra: Optional[Dict[str, Any]] = None,
    region: str,
    chain_id: str,
    build_governance_event_payload_fn: Any,
    create_unsigned_ledger_entry_fn: Any,
    ledger_backpressure_error_cls: Any,
) -> None:
    payload = build_governance_event_payload_fn(
        tenant_id=tenant_id,
        actor=actor,
        event_type=event_type,
        region=region,
        chain_id=chain_id,
        extra=extra,
    )
    try:
        await create_unsigned_ledger_entry_fn(r, payload)
    except ledger_backpressure_error_cls:
        print("[apex-admin] Dropping governance ledger entry due to backlog")
    except Exception:
        pass
