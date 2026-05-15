"""Redis runtime helpers for connection and worker lease coordination."""

import asyncio
import os
from enum import Enum
from typing import Any, Callable, Optional

import redis.asyncio as redis

_GLOBAL_REDIS_CLIENT: Optional[redis.Redis] = None
_APEX_REDIS_URL_ENV: Optional[str] = None
_GET_APEX_ENV_FN: Optional[Callable[[], Any]] = None
_APEX_ENV_PROD: Optional[Enum] = None

MAX_WORKER_ID = 1023
WORKER_LEASE_TTL = 60
WORKER_ID_RETRIES = 16


def configure_redis_runtime(
    *,
    redis_url_env: str,
    get_apex_env_fn: Callable[[], Any],
    apex_env_prod: Enum,
) -> None:
    global _APEX_REDIS_URL_ENV, _GET_APEX_ENV_FN, _APEX_ENV_PROD
    _APEX_REDIS_URL_ENV = redis_url_env
    _GET_APEX_ENV_FN = get_apex_env_fn
    _APEX_ENV_PROD = apex_env_prod


def build_redis_url() -> str:
    if not _APEX_REDIS_URL_ENV or not _GET_APEX_ENV_FN or _APEX_ENV_PROD is None:
        raise RuntimeError("redis runtime is not configured")

    base = os.getenv(_APEX_REDIS_URL_ENV, "")
    if not base:
        raise RuntimeError(f"{_APEX_REDIS_URL_ENV} must be set")

    env = _GET_APEX_ENV_FN()
    if env == _APEX_ENV_PROD:
        if not base.startswith("rediss://"):
            raise RuntimeError("Redis in PROD must use TLS (rediss://)")
        if "@" not in base:
            raise RuntimeError("Redis in PROD must include authentication in URL or be ACL-secured")
    return base


async def get_redis_client() -> redis.Redis:
    global _GLOBAL_REDIS_CLIENT
    if _GLOBAL_REDIS_CLIENT is not None:
        return _GLOBAL_REDIS_CLIENT

    url = build_redis_url()
    use_ssl = url.startswith("rediss://")
    _GLOBAL_REDIS_CLIENT = redis.from_url(url, decode_responses=True, ssl=use_ssl)
    return _GLOBAL_REDIS_CLIENT


async def get_worker_id(r: redis.Redis) -> int:
    for attempt in range(WORKER_ID_RETRIES):
        val = await r.incr("snowflake:next_worker_id")
        candidate = int(val) & MAX_WORKER_ID
        lease_key = f"snowflake:lease:{candidate}"
        ok = await r.set(lease_key, "1", ex=WORKER_LEASE_TTL, nx=True)
        if ok:
            return candidate
        await asyncio.sleep(0.05 * (attempt + 1))
    raise RuntimeError("Unable to allocate worker_id: all IDs appear leased (possible DoS or misconfig)")
