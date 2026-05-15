from __future__ import annotations

import asyncio
import hashlib
import os
import time
from typing import Any, Awaitable, Callable, Dict, Optional

import redis.asyncio as redis
from fastapi import HTTPException

_get_redis_client_fn: Optional[Callable[[], Awaitable[redis.Redis]]] = None
_policy_store_factory: Optional[Callable[[redis.Redis], Any]] = None
_seed_policy_for_group_fn: Optional[Callable[[str], Dict[str, Any]]] = None
_policy_retention_seconds_fn: Optional[Callable[[Dict[str, Any], str], int]] = None
_utc_now_z_fn: Optional[Callable[[], str]] = None
_apex_self_test_interval_seconds: int = 300
_apex_failsafe_gov: bool = False
_apex_ledger_capacity_fail_pct: float = 0.95


def configure_runtime_health(
    *,
    get_redis_client_fn: Callable[[], Awaitable[redis.Redis]],
    policy_store_factory: Callable[[redis.Redis], Any],
    seed_policy_for_group_fn: Callable[[str], Dict[str, Any]],
    policy_retention_seconds_fn: Callable[[Dict[str, Any], str], int],
    utc_now_z_fn: Callable[[], str],
    apex_self_test_interval_seconds: int,
    apex_failsafe_gov: bool,
    apex_ledger_capacity_fail_pct: float,
) -> None:
    global _get_redis_client_fn
    global _policy_store_factory
    global _seed_policy_for_group_fn
    global _policy_retention_seconds_fn
    global _utc_now_z_fn
    global _apex_self_test_interval_seconds
    global _apex_failsafe_gov
    global _apex_ledger_capacity_fail_pct

    _get_redis_client_fn = get_redis_client_fn
    _policy_store_factory = policy_store_factory
    _seed_policy_for_group_fn = seed_policy_for_group_fn
    _policy_retention_seconds_fn = policy_retention_seconds_fn
    _utc_now_z_fn = utc_now_z_fn
    _apex_self_test_interval_seconds = int(apex_self_test_interval_seconds)
    _apex_failsafe_gov = bool(apex_failsafe_gov)
    _apex_ledger_capacity_fail_pct = float(apex_ledger_capacity_fail_pct)


SIGNER_HEALTH: Dict[str, Any] = {
    "ok": True,
    "last_ok_at": None,
    "last_error": None,
    "last_error_at": None,
}

SELF_TEST: Dict[str, Any] = {
    "ok": True,
    "started_at": None,
    "base_file_sha256": None,
    "last_run_at": None,
    "last_error": None,
}


def _ensure_started_at() -> None:
    if SELF_TEST.get("started_at") is None and _utc_now_z_fn is not None:
        SELF_TEST["started_at"] = _utc_now_z_fn()


def _sha256_file_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


async def periodic_self_test_loop() -> None:
    _ensure_started_at()
    base_path = os.path.abspath(__file__)
    if SELF_TEST.get("base_file_sha256") is None:
        try:
            SELF_TEST["base_file_sha256"] = _sha256_file_hex(base_path)
        except Exception as exc:
            SELF_TEST["ok"] = False
            SELF_TEST["last_error"] = f"initial_self_test_failed:{exc}"

    while True:
        try:
            if _utc_now_z_fn is not None:
                SELF_TEST["last_run_at"] = _utc_now_z_fn()
            expected = SELF_TEST.get("base_file_sha256")
            if expected:
                current = _sha256_file_hex(base_path)
                if current != expected:
                    SELF_TEST["ok"] = False
                    SELF_TEST["last_error"] = "base_file_hash_changed"
        except Exception as exc:
            SELF_TEST["ok"] = False
            SELF_TEST["last_error"] = f"self_test_error:{exc}"

        await asyncio.sleep(max(60, int(_apex_self_test_interval_seconds)))


async def retention_enforcer_loop() -> None:
    await asyncio.sleep(5.0)
    while True:
        try:
            if (
                _get_redis_client_fn is None
                or _policy_store_factory is None
                or _seed_policy_for_group_fn is None
                or _policy_retention_seconds_fn is None
            ):
                raise RuntimeError("runtime_health not configured")

            r = await _get_redis_client_fn()
            store = _policy_store_factory(r)

            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="session:*:prompts", count=200)
                for k in keys or []:
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        parts = str(k).split(":")
                        tenant_id = parts[1] if len(parts) >= 3 else None
                        if not tenant_id:
                            continue
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=_seed_policy_for_group_fn("default"),
                        )
                        policy = current.policy or {}
                        prompts_ttl = _policy_retention_seconds_fn(policy, "session_prompts_ttl_seconds")
                        if prompts_ttl > 0:
                            await r.expire(k, prompts_ttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="apex:adversarial_corpus:*", count=200)
                for k in keys or []:
                    if str(k) == "apex:adversarial_corpus":
                        continue
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        tenant_id = str(k).split(":", 2)[2]
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=_seed_policy_for_group_fn("default"),
                        )
                        policy = current.policy or {}
                        adv_ttl = _policy_retention_seconds_fn(policy, "adversarial_corpus_ttl_seconds")
                        if adv_ttl > 0:
                            await r.expire(k, adv_ttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="apex:content:*:*:*", count=200)
                for k in keys or []:
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        tenant_id = str(k).split(":", 3)[2]
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=_seed_policy_for_group_fn("default"),
                        )
                        policy = current.policy or {}
                        cttl = _policy_retention_seconds_fn(policy, "content_store_ttl_seconds")
                        if cttl > 0:
                            await r.expire(k, cttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

        except Exception:
            pass

        await asyncio.sleep(300)


async def get_redis_memory_pressure(r: redis.Redis) -> Dict[str, Any]:
    try:
        info = await r.info(section="memory")
        used = int(info.get("used_memory", 0) or 0)
        maxmem = int(info.get("maxmemory", 0) or 0)
        if maxmem <= 0:
            return {"supported": False, "used_memory": used, "maxmemory": maxmem, "pressure": None}
        pressure = float(used) / float(maxmem)
        return {"supported": True, "used_memory": used, "maxmemory": maxmem, "pressure": pressure}
    except Exception:
        return {"supported": False, "used_memory": None, "maxmemory": None, "pressure": None}


async def enforce_failsafe_or_raise(r: redis.Redis) -> None:
    if not _apex_failsafe_gov:
        return

    if not bool(SELF_TEST.get("ok", True)):
        raise HTTPException(status_code=503, detail="Fail-safe: self-test failed")

    if not bool(SIGNER_HEALTH.get("ok", True)):
        raise HTTPException(status_code=503, detail="Fail-safe: signer unhealthy")

    mem = await get_redis_memory_pressure(r)
    pressure = mem.get("pressure")
    if mem.get("supported") and isinstance(pressure, float) and pressure >= float(_apex_ledger_capacity_fail_pct):
        raise HTTPException(status_code=503, detail=f"Fail-safe: Redis memory pressure high ({pressure:.2%})")
