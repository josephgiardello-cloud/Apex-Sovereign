from typing import Any, Dict, List, Optional

import redis.asyncio as redis

from . import pagination
from . import redis_json_views


async def read_env_config_desired(r: redis.Redis, *, desired_current_key: str) -> Optional[Dict[str, Any]]:
    desired_raw = None
    try:
        desired_raw = await r.get(desired_current_key)
    except Exception:
        desired_raw = None
    return redis_json_views.decode_optional_json_with_raw_fallback(desired_raw)


async def read_env_config_history(
    r: redis.Redis,
    *,
    desired_history_key: str,
    limit: int,
) -> List[Dict[str, Any]]:
    lim = pagination.clamp_limit(limit)
    raw_items = await r.lrange(desired_history_key, 0, lim - 1)
    return redis_json_views.decode_json_items_with_raw_fallback(raw_items)


async def build_env_config_history_payload(
    r: redis.Redis,
    *,
    env_value: str,
    desired_history_key: str,
    limit: int,
) -> Dict[str, Any]:
    out = await read_env_config_history(r, desired_history_key=desired_history_key, limit=limit)
    return {"env": env_value, "items": out}


async def build_env_config_current_payload(
    r: redis.Redis,
    *,
    env_value: str,
    runtime_snapshot: Dict[str, Any],
    desired_current_key: str,
) -> Dict[str, Any]:
    desired = await read_env_config_desired(r, desired_current_key=desired_current_key)
    return {
        "env": env_value,
        "runtime_snapshot": runtime_snapshot,
        "desired_config": desired,
    }


async def build_env_config_overview_payload(
    r: redis.Redis,
    *,
    env_value: str,
    runtime_snapshot: Dict[str, Any],
    desired_current_key: str,
    desired_history_key: str,
    limit: int,
) -> Dict[str, Any]:
    desired = await read_env_config_desired(r, desired_current_key=desired_current_key)
    history = await read_env_config_history(r, desired_history_key=desired_history_key, limit=limit)
    return {
        "env": env_value,
        "runtime_snapshot": runtime_snapshot,
        "desired_config": desired,
        "approved_history": history,
    }
