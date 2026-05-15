"""Apex Sovereign - low-level Redis ledger primitives.

Call configure_ledger_primitives() before using these helpers.
"""

import asyncio
import json
from typing import Any, Callable, Dict, Optional

import boto3
import redis.asyncio as redis


_SIGNING_QUEUE_KEY: str = ""
_LEDGER_CHECKPOINT_BUCKET: str = ""
_decode_required_json_object_fn: Optional[Callable[[Any], Dict[str, Any]]] = None


def configure_ledger_primitives(
    *,
    signing_queue_key: str,
    ledger_checkpoint_bucket: str,
    decode_required_json_object_fn: Callable[[Any], Dict[str, Any]],
) -> None:
    global _SIGNING_QUEUE_KEY, _LEDGER_CHECKPOINT_BUCKET, _decode_required_json_object_fn
    _SIGNING_QUEUE_KEY = str(signing_queue_key or "")
    _LEDGER_CHECKPOINT_BUCKET = str(ledger_checkpoint_bucket or "")
    _decode_required_json_object_fn = decode_required_json_object_fn


async def write_raw_ledger_entry(r: redis.Redis, entry: Dict[str, Any]) -> int:
    encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    length = await r.rpush("apex:audit_ledger", encoded)
    return int(length)


async def read_raw_ledger_entry(r: redis.Redis, index: int) -> Optional[Dict[str, Any]]:
    raw = await r.lindex("apex:audit_ledger", index)
    if not raw:
        return None
    return _decode_required_json_object_fn(raw)


async def update_raw_ledger_entry(r: redis.Redis, index: int, entry: Dict[str, Any]) -> None:
    encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    await r.lset("apex:audit_ledger", index, encoded)


async def enqueue_for_signing(r: redis.Redis, index: int) -> None:
    await r.rpush(_SIGNING_QUEUE_KEY, str(index))


async def write_checkpoint(r: redis.Redis, checkpoint: Dict[str, Any]) -> None:
    """Write a checkpoint into Redis and optionally S3 for independent verification."""
    encoded = json.dumps(checkpoint, separators=(",", ":"), sort_keys=True)
    await r.rpush("apex:audit_checkpoints", encoded)

    bucket = _LEDGER_CHECKPOINT_BUCKET
    if bucket:

        def _put() -> None:
            s3 = boto3.client("s3")
            key = f"checkpoints/{checkpoint['chain_id']}/{checkpoint['ts']}.json"
            s3.put_object(Bucket=bucket, Key=key, Body=encoded.encode("utf-8"))

        await asyncio.to_thread(_put)
