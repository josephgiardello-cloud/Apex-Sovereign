import json
from typing import Any, Dict, Optional

import redis.asyncio as redis
from fastapi import HTTPException

from . import redis_json_views


async def load_rtbf_proof_from_ledger(
    r: redis.Redis,
    *,
    tenant_id: str,
    request_id: str,
    max_scan: int = 5000,
    ignore_mapping: bool = False,
    write_back: bool = True,
) -> Optional[Dict[str, Any]]:
    """Best-effort RTBF proof retrieval from the canonical ledger.

    Strategy:
    1) Use request_id -> entry_id/index mapping if present.
    2) Fallback: bounded reverse scan of the ledger tail.
    """

    ledger_key = "apex:audit_ledger"
    mapping_key = f"apex:rtbf:proof_ledger_entry:{tenant_id}:{request_id}"

    if not ignore_mapping:
        try:
            raw_map = await r.get(mapping_key)
            if raw_map:
                try:
                    m = redis_json_views.decode_required_json_object(raw_map)
                    idx = m.get("index")
                    entry_id = m.get("entry_id")
                    if idx is not None:
                        raw = await r.lindex(ledger_key, int(idx))
                        if raw:
                            decoded = redis_json_views.decode_single_json_skip_invalid(raw)
                            if decoded is None:
                                return None
                            e = decoded
                            payload = e.get("payload") or {}
                            if payload.get("tenant_id") == tenant_id and payload.get("request_id") == request_id and payload.get("decision") == "RTBF_PROOF":
                                return {"source": "ledger_index", "index": int(idx), "entry_id": entry_id, "payload": payload}
                except Exception:
                    pass
        except Exception:
            pass

    try:
        length = int(await r.llen(ledger_key) or 0)
        if length <= 0:
            return None
        start = max(0, length - int(max_scan))
        for idx in range(length - 1, start - 1, -1):
            raw = await r.lindex(ledger_key, idx)
            if not raw:
                continue
            decoded = redis_json_views.decode_single_json_skip_invalid(raw)
            if decoded is None:
                continue
            e = decoded
            payload = e.get("payload") or {}
            if payload.get("decision") != "RTBF_PROOF":
                continue
            if payload.get("tenant_id") != tenant_id:
                continue
            if payload.get("request_id") != request_id:
                continue
            entry_id = payload.get("entry_id")
            try:
                if write_back and entry_id:
                    await r.set(mapping_key, json.dumps({"entry_id": entry_id, "index": int(idx)}))
            except Exception:
                pass
            return {"source": "ledger_scan", "index": int(idx), "entry_id": entry_id, "payload": payload}
    except Exception:
        return None

    return None


async def get_rtbf_proof_payload(
    r: redis.Redis,
    *,
    tenant_id: str,
    request_id: str,
    zero_cache: bool,
) -> Dict[str, Any]:
    key = f"apex:rtbf:proof:{tenant_id}:{request_id}"
    raw = None if zero_cache else await r.get(key)
    if not raw:
        from_ledger = await load_rtbf_proof_from_ledger(
            r,
            tenant_id=tenant_id,
            request_id=request_id,
            ignore_mapping=bool(zero_cache),
            write_back=not bool(zero_cache),
        )
        if not from_ledger:
            raise HTTPException(status_code=404, detail="RTBF proof not found; retrieve via ledger export")
        return {
            "source": from_ledger.get("source"),
            "ledger_index": from_ledger.get("index"),
            "ledger_entry_id": from_ledger.get("entry_id"),
            "payload": from_ledger.get("payload"),
        }
    return redis_json_views.decode_optional_json_with_raw_fallback(raw) or {"raw": raw}
