from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

import boto3
import redis.asyncio as redis

_ledger_s3_bucket: str = ""
_ledger_s3_prefix: str = "ledger"
_apex_region: str = ""
_get_redis_client_fn: Optional[Callable[[], Awaitable[redis.Redis]]] = None
_decode_single_json_skip_invalid_fn: Optional[Callable[[Any], Optional[Dict[str, Any]]]] = None


def configure_ledger_s3_sync(
    *,
    ledger_s3_bucket: str,
    ledger_s3_prefix: str,
    apex_region: str,
    get_redis_client_fn: Callable[[], Awaitable[redis.Redis]],
    decode_single_json_skip_invalid_fn: Callable[[Any], Optional[Dict[str, Any]]],
) -> None:
    global _ledger_s3_bucket
    global _ledger_s3_prefix
    global _apex_region
    global _get_redis_client_fn
    global _decode_single_json_skip_invalid_fn

    _ledger_s3_bucket = str(ledger_s3_bucket or "")
    _ledger_s3_prefix = str(ledger_s3_prefix or "ledger")
    _apex_region = str(apex_region or "")
    _get_redis_client_fn = get_redis_client_fn
    _decode_single_json_skip_invalid_fn = decode_single_json_skip_invalid_fn


def _require_cfg() -> None:
    if _get_redis_client_fn is None or _decode_single_json_skip_invalid_fn is None:
        raise RuntimeError("ledger_s3_sync not configured")


async def upload_to_s3(key: str, content: str) -> None:
    bucket = _ledger_s3_bucket
    if not bucket:
        return

    def _put() -> None:
        s3 = boto3.client("s3")
        try:
            try:
                existing = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            except s3.exceptions.NoSuchKey:
                existing = b""
            new_body = existing + content.encode("utf-8")
            s3.put_object(Bucket=bucket, Key=key, Body=new_body)
        except Exception as exc:
            print(f"[apex-s3-ledger] upload_to_s3 error: {exc}")

    await asyncio.to_thread(_put)


async def s3_ledger_sync_loop(stop_event: asyncio.Event) -> None:
    _require_cfg()

    r = await _get_redis_client_fn()
    buffer: List[Dict[str, Any]] = []
    max_batch = 100
    last_flush = time.time()

    while not stop_event.is_set():
        try:
            raw = await r.lpop("apex:signed_ledger_buffer")
            now = time.time()
            if raw:
                decoded = _decode_single_json_skip_invalid_fn(raw)
                if decoded is not None:
                    buffer.append(decoded)

            time_since_last_flush = now - last_flush
            should_flush = len(buffer) >= max_batch or (buffer and time_since_last_flush >= 60)

            if should_flush:
                region = _apex_region
                date_str = datetime.utcnow().strftime("%Y-%m-%d")
                prefix = _ledger_s3_prefix.rstrip("/") or "ledger"
                s3_key = f"{prefix}/{region}/{date_str}/audit.jsonl"

                jsonl_content = "\n".join(
                    json.dumps(e, separators=(",", ":"), sort_keys=True) for e in buffer
                ) + "\n"

                await upload_to_s3(s3_key, jsonl_content)

                buffer = []
                last_flush = now

            if not raw:
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[apex-s3-ledger] sync loop error: {exc}")
            await asyncio.sleep(2.0)
