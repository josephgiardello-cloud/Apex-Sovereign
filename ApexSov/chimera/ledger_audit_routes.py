from __future__ import annotations

import json
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, Optional

from fastapi import Depends
from fastapi.responses import StreamingResponse


def register_ledger_audit_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    verify_ledger_chain_for_api: Callable[[Any], Awaitable[Any]],
    region: str,
    chain_id: str,
    policy_version: str,
    utc_now_z: Callable[[], str],
    decode_single_json_skip_invalid: Callable[[Any], Optional[Dict[str, Any]]],
) -> None:
    @app.get("/api/v1/audit/ledger/verify")
    async def audit_ledger_verify(identity=Depends(get_identity)):
        """API-based ledger integrity verification for auditors."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        ok, count, last_checkpoint = await verify_ledger_chain_for_api(r)
        return {
            "verification_status": "verified" if ok else "failed",
            "entry_count": count,
            "chain_integrity_score": 1.0 if ok else 0.0,
            "last_checkpoint": last_checkpoint,
            "region": region,
            "chain_id": chain_id,
        }

    @app.get("/api/v1/audit/ledger/export")
    async def audit_ledger_export(
        tenant_id: Optional[str] = None,
        start_index: int = 0,
        end_index: int = -1,
        identity=Depends(get_identity),
    ):
        """Evidence export for discovery as JSONL."""
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        length = int(await r.llen("apex:audit_ledger") or 0)

        s = max(0, int(start_index))
        e = int(end_index)
        if e < 0:
            e = length - 1
        e = min(e, length - 1)

        async def _gen() -> AsyncGenerator[bytes, None]:
            meta = {
                "type": "EXPORT_META",
                "ts": utc_now_z(),
                "region": region,
                "chain_id": chain_id,
                "tenant_filter": tenant_id,
                "start_index": s,
                "end_index": e,
                "policy_version": policy_version,
                "entry_count": 0 if length == 0 or s > e else (e - s + 1),
            }
            yield (json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

            if length == 0 or s > e:
                return

            for idx in range(s, e + 1):
                raw = await r.lindex("apex:audit_ledger", idx)
                if not raw:
                    continue
                if tenant_id:
                    decoded = decode_single_json_skip_invalid(raw)
                    if decoded is None:
                        continue
                    payload = (decoded or {}).get("payload") or {}
                    if payload.get("tenant_id") != tenant_id:
                        continue
                    yield (json.dumps(decoded, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
                else:
                    yield (raw + "\n").encode("utf-8")

        return StreamingResponse(_gen(), media_type="application/jsonl")
