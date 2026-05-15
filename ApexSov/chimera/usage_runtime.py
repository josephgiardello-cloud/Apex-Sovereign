from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from fastapi import HTTPException


def get_usage_quotas(policy: Dict[str, Any], default_policy_baseline: Dict[str, Any]) -> Dict[str, int]:
    base = (default_policy_baseline or {}).get("usage_quotas") or {}
    from_policy = (policy or {}).get("usage_quotas") or {}
    merged = {**base, **from_policy}

    def _as_non_negative_int(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except Exception:
            return 0

    return {
        "requests_per_minute": _as_non_negative_int(merged.get("requests_per_minute")),
        "tokens_per_minute": _as_non_negative_int(merged.get("tokens_per_minute")),
        "tokens_per_day": _as_non_negative_int(merged.get("tokens_per_day")),
        "tokens_per_month": _as_non_negative_int(merged.get("tokens_per_month")),
    }


def estimate_text_tokens(text: str) -> int:
    """Cheap, deterministic approximation without a tokenizer dependency."""
    t = str(text or "")
    if not t:
        return 0
    return max(1, (len(t) + 3) // 4)


def estimate_messages_tokens(messages: List[Dict[str, Any]]) -> int:
    total = 0
    for msg in messages or []:
        content = msg.get("content") if isinstance(msg, dict) else None
        if isinstance(content, str):
            total += estimate_text_tokens(content)
            continue
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    total += estimate_text_tokens(part.get("text") or "")
    return total


def _keys(tenant_id: str, now: datetime) -> Dict[str, str]:
    minute_bucket = now.strftime("%Y%m%d%H%M")
    day_bucket = now.strftime("%Y%m%d")
    month_bucket = now.strftime("%Y%m")
    return {
        "rpm": f"apex:usage:{tenant_id}:rpm:{minute_bucket}",
        "tpm": f"apex:usage:{tenant_id}:tpm:{minute_bucket}",
        "day": f"apex:usage:{tenant_id}:tokens:day:{day_bucket}",
        "month": f"apex:usage:{tenant_id}:tokens:month:{month_bucket}",
    }


async def reserve_usage_or_raise(
    r: Any,
    *,
    tenant_id: str,
    quotas: Dict[str, int],
    prompt_tokens_estimate: int,
    now: datetime,
) -> Dict[str, Any]:
    keys = _keys(tenant_id, now)

    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(keys["rpm"], 1)
        pipe.expire(keys["rpm"], 120)
        pipe.incr(keys["tpm"], int(prompt_tokens_estimate or 0))
        pipe.expire(keys["tpm"], 120)
        pipe.incr(keys["day"], int(prompt_tokens_estimate or 0))
        pipe.expire(keys["day"], 2 * 24 * 3600)
        pipe.incr(keys["month"], int(prompt_tokens_estimate or 0))
        pipe.expire(keys["month"], 35 * 24 * 3600)
        result = await pipe.execute()

    rpm = int(result[0] or 0)
    tpm = int(result[2] or 0)
    day = int(result[4] or 0)
    month = int(result[6] or 0)

    rpm_limit = int(quotas.get("requests_per_minute") or 0)
    tpm_limit = int(quotas.get("tokens_per_minute") or 0)
    day_limit = int(quotas.get("tokens_per_day") or 0)
    month_limit = int(quotas.get("tokens_per_month") or 0)

    if rpm_limit > 0 and rpm > rpm_limit:
        raise HTTPException(status_code=429, detail="Quota exceeded: requests_per_minute")
    if tpm_limit > 0 and tpm > tpm_limit:
        raise HTTPException(status_code=429, detail="Quota exceeded: tokens_per_minute")
    if day_limit > 0 and day > day_limit:
        raise HTTPException(status_code=429, detail="Quota exceeded: tokens_per_day")
    if month_limit > 0 and month > month_limit:
        raise HTTPException(status_code=429, detail="Quota exceeded: tokens_per_month")

    return {
        "keys": keys,
        "requests_per_minute": rpm,
        "tokens_per_minute": tpm,
        "tokens_per_day": day,
        "tokens_per_month": month,
        "prompt_tokens": int(prompt_tokens_estimate or 0),
    }


async def add_completion_usage(
    r: Any,
    *,
    keys: Dict[str, str],
    completion_tokens: int,
) -> Dict[str, int]:
    completion_tokens = int(completion_tokens or 0)
    if completion_tokens <= 0:
        return {
            "tokens_per_minute": 0,
            "tokens_per_day": 0,
            "tokens_per_month": 0,
        }

    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(keys["tpm"], completion_tokens)
        pipe.incr(keys["day"], completion_tokens)
        pipe.incr(keys["month"], completion_tokens)
        result = await pipe.execute()

    return {
        "tokens_per_minute": int(result[0] or 0),
        "tokens_per_day": int(result[1] or 0),
        "tokens_per_month": int(result[2] or 0),
    }


def estimate_cost_usd(
    *,
    internal_model: str,
    internal_to_external_model: Dict[str, str],
    model_prices_usd_per_1k: Dict[str, Dict[str, float]],
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    external = internal_to_external_model.get(internal_model, internal_model)
    pricing = model_prices_usd_per_1k.get(external) or model_prices_usd_per_1k.get(internal_model) or {}
    prompt_price = float(pricing.get("prompt") or 0.0)
    completion_price = float(pricing.get("completion") or 0.0)

    return ((prompt_tokens / 1000.0) * prompt_price) + ((completion_tokens / 1000.0) * completion_price)
