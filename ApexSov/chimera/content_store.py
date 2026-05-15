"""Apex Sovereign - content dedup storage helpers."""

import unicodedata
from typing import Any, Callable, Dict, Optional

import redis.asyncio as redis


_APEX_CONTENT_TTL_SECONDS: int = 0
_sha256_hex_fn: Optional[Callable[[bytes], str]] = None


def configure_content_store(*, apex_content_ttl_seconds: int, sha256_hex_fn: Callable[[bytes], str]) -> None:
    global _APEX_CONTENT_TTL_SECONDS, _sha256_hex_fn
    _APEX_CONTENT_TTL_SECONDS = int(apex_content_ttl_seconds or 0)
    _sha256_hex_fn = sha256_hex_fn


async def store_deduped_content(
    r: redis.Redis,
    *,
    tenant_id: Optional[str] = None,
    kind: str,
    content: str,
    ttl_seconds: int = 0,
) -> Dict[str, Any]:
    """Store large content once and refer to it by hash."""
    normalized = unicodedata.normalize("NFC", content)
    digest = _sha256_hex_fn(f"{kind}\0{normalized}".encode("utf-8"))
    if tenant_id:
        key = f"apex:content:{tenant_id}:{kind}:{digest}"
    else:
        key = f"apex:content:{kind}:{digest}"

    try:
        was_set = await r.set(key, normalized, nx=True)
        effective_ttl = int(ttl_seconds or 0) or _APEX_CONTENT_TTL_SECONDS
        if effective_ttl > 0:
            try:
                current_ttl = await r.ttl(key)
            except Exception:
                current_ttl = None

            should_shorten = (
                isinstance(current_ttl, int)
                and current_ttl >= 0
                and int(current_ttl) > int(effective_ttl)
            )
            should_set = ((was_set is True) or (current_ttl == -1) or should_shorten)
            if should_set:
                await r.expire(key, int(effective_ttl))
    except Exception:
        pass

    out: Dict[str, Any] = {"ref": f"{kind}:{digest}", "sha256": digest, "len": len(normalized)}
    if tenant_id:
        out["tenant_id"] = tenant_id
        out["tenant_ref"] = f"{tenant_id}:{kind}:{digest}"
    return out
