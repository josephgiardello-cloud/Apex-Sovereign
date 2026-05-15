from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import boto3
import redis.asyncio as redis

_get_redis_client_fn: Optional[Callable[[], Awaitable[redis.Redis]]] = None
_decode_single_json_skip_invalid_fn: Optional[Callable[[Any], Optional[Dict[str, Any]]]] = None
_decode_optional_json_object_or_default_fn: Optional[Callable[[Any], Dict[str, Any]]] = None
_decode_required_json_object_fn: Optional[Callable[[Any], Dict[str, Any]]] = None
_compute_entry_hash_fn: Optional[Callable[[Dict[str, Any], Optional[str]], str]] = None
_apex_region: str = ""
_apex_chain_id: str = ""


def configure_ledger_verify_helpers(
    *,
    get_redis_client_fn: Callable[[], Awaitable[redis.Redis]],
    decode_single_json_skip_invalid_fn: Callable[[Any], Optional[Dict[str, Any]]],
    decode_optional_json_object_or_default_fn: Callable[[Any], Dict[str, Any]],
    decode_required_json_object_fn: Callable[[Any], Dict[str, Any]],
    compute_entry_hash_fn: Callable[[Dict[str, Any], Optional[str]], str],
    apex_region: str,
    apex_chain_id: str,
) -> None:
    global _get_redis_client_fn
    global _decode_single_json_skip_invalid_fn
    global _decode_optional_json_object_or_default_fn
    global _decode_required_json_object_fn
    global _compute_entry_hash_fn
    global _apex_region
    global _apex_chain_id

    _get_redis_client_fn = get_redis_client_fn
    _decode_single_json_skip_invalid_fn = decode_single_json_skip_invalid_fn
    _decode_optional_json_object_or_default_fn = decode_optional_json_object_or_default_fn
    _decode_required_json_object_fn = decode_required_json_object_fn
    _compute_entry_hash_fn = compute_entry_hash_fn
    _apex_region = str(apex_region or "")
    _apex_chain_id = str(apex_chain_id or "")


def _require_cfg() -> None:
    if (
        _get_redis_client_fn is None
        or _decode_single_json_skip_invalid_fn is None
        or _decode_optional_json_object_or_default_fn is None
        or _decode_required_json_object_fn is None
        or _compute_entry_hash_fn is None
    ):
        raise RuntimeError("ledger_verify_helpers not configured")


async def verify_ledger_chain_for_api(r: redis.Redis) -> Tuple[bool, int, Optional[str]]:
    _require_cfg()
    length = await r.llen("apex:audit_ledger")
    prev_hash: Optional[str] = None
    ok = True

    for idx in range(length):
        raw = await r.lindex("apex:audit_ledger", idx)
        if not raw:
            ok = False
            break
        decoded = _decode_single_json_skip_invalid_fn(raw)
        if decoded is None:
            ok = False
            break

        payload = decoded.get("payload", {})
        expected_prev = decoded.get("prev_hash")
        entry_hash = decoded.get("entry_hash")
        recomputed = _compute_entry_hash_fn(payload, prev_hash)
        if expected_prev != prev_hash or entry_hash != recomputed:
            ok = False
            break
        prev_hash = entry_hash

    last_checkpoint_ts: Optional[str] = None
    cl = await r.llen("apex:audit_checkpoints")
    if cl and cl > 0:
        last_cp_raw = await r.lindex("apex:audit_checkpoints", cl - 1)
        if last_cp_raw:
            cp = _decode_optional_json_object_or_default_fn(last_cp_raw)
            last_checkpoint_ts = cp.get("ts")

    return ok, length, last_checkpoint_ts


def verify_ledger_chain_from_redis() -> None:
    _require_cfg()

    async def _inner() -> None:
        r = await _get_redis_client_fn()
        length = await r.llen("apex:audit_ledger")
        print(f"[apex] Verifying ledger chain, length={length}, region={_apex_region}, chain_id={_apex_chain_id}")

        prev_hash: Optional[str] = None
        for idx in range(length):
            raw = await r.lindex("apex:audit_ledger", idx)
            if not raw:
                print(f"[apex] Missing entry at index={idx}")
                return
            decoded = _decode_single_json_skip_invalid_fn(raw)
            if decoded is None:
                print(f"[apex] Invalid JSON entry at index={idx}")
                return

            payload = decoded.get("payload", {})
            expected_prev = decoded.get("prev_hash")
            entry_hash = decoded.get("entry_hash")
            recomputed = _compute_entry_hash_fn(payload, prev_hash)

            if expected_prev != prev_hash:
                print(
                    f"[apex] prev_hash mismatch at index={idx}, "
                    f"expected={prev_hash}, stored={expected_prev}"
                )
                return
            if entry_hash != recomputed:
                print(
                    f"[apex] entry_hash mismatch at index={idx}, "
                    f"stored={entry_hash}, recomputed={recomputed}"
                )
                return

            prev_hash = entry_hash

        print("[apex] Ledger chain OK")

    asyncio.run(_inner())


def verify_ledger_from_s3(
    bucket: str,
    prefix: str = "ledger/",
    region: Optional[str] = None,
) -> None:
    _require_cfg()

    session_kwargs: Dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    s3 = boto3.client("s3", **session_kwargs)

    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    prev_hash: Optional[str] = None
    total_entries = 0

    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            for line in body.splitlines():
                if not line.strip():
                    continue
                entry = _decode_required_json_object_fn(line)
                payload = entry.get("payload", {})
                expected_prev = entry.get("prev_hash")
                entry_hash = entry.get("entry_hash")
                recomputed = _compute_entry_hash_fn(payload, prev_hash)

                if expected_prev != prev_hash:
                    print(
                        f"[apex] S3 prev_hash mismatch at entry={total_entries}, "
                        f"key={key}, expected={prev_hash}, stored={expected_prev}"
                    )
                    return
                if entry_hash != recomputed:
                    print(
                        f"[apex] S3 entry_hash mismatch at entry={total_entries}, "
                        f"key={key}, stored={entry_hash}, recomputed={recomputed}"
                    )
                    return

                prev_hash = entry_hash
                total_entries += 1

    print(f"[apex] S3 ledger chain OK, entries={total_entries}")
