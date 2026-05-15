from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

import redis.asyncio as redis

_alert_min_tony_score: float = 0.8


def configure_metrics_runtime(*, alert_min_tony_score: float) -> None:
    global _alert_min_tony_score
    _alert_min_tony_score = float(alert_min_tony_score)


def metrics_hour_key(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H")


def metrics_total_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:total"


def metrics_blocked_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:blocked"


def metrics_highrisk_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:highrisk"


def metrics_axis_hash_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:axis_counts"


async def record_metrics_for_audit(r: redis.Redis, payload: Dict[str, Any]) -> None:
    ts_str = payload.get("ts")
    if not ts_str:
        return
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", ""))
    except Exception:
        return

    hour_key = metrics_hour_key(ts)

    total_key = metrics_total_key(hour_key)
    blocked_key = metrics_blocked_key(hour_key)
    highrisk_key = metrics_highrisk_key(hour_key)
    axis_hash = metrics_axis_hash_key(hour_key)

    decision = payload.get("decision")
    risk_axes = payload.get("risk_axes", {})
    tony_score = float(risk_axes.get("tony", 0.0))

    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(total_key, 1)
        if decision == "BLOCK":
            pipe.incr(blocked_key, 1)
        if tony_score >= _alert_min_tony_score:
            pipe.incr(highrisk_key, 1)

        for axis, val in risk_axes.items():
            if axis in ("tony", "context"):
                continue
            try:
                v = float(val)
            except Exception:
                continue
            if v > 0.0:
                pipe.hincrby(axis_hash, axis, 1)

        expire_seconds = 7 * 24 * 3600
        pipe.expire(total_key, expire_seconds)
        pipe.expire(blocked_key, expire_seconds)
        pipe.expire(highrisk_key, expire_seconds)
        pipe.expire(axis_hash, expire_seconds)

        await pipe.execute()
