from __future__ import annotations

import unicodedata
import uuid
import json
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional

import numpy as np
import redis.asyncio as redis
from fastapi import HTTPException
from pydantic import BaseModel

try:
    from . import policy_records as chimera_policy_records
except Exception:
    import chimera.policy_records as chimera_policy_records  # type: ignore[no-redef]

try:
    from . import redis_json_views as chimera_redis_json_views
except Exception:
    import chimera.redis_json_views as chimera_redis_json_views  # type: ignore[no-redef]


_DLP_EMBEDDER_CACHE: Dict[str, Any] = {"key": None, "embedder": None}
_secret_provider: Any = None
_openai_embedding_provider_cls: Any = None
_embedding_model: str = ""
_dlp_semantic_enabled: bool = False
_dlp_semantic_max_exemplars: int = 0
_store_deduped_content_fn: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None
_severity_weight_fn: Callable[[str], float] = lambda _: 0.0
_clamp01_fn: Callable[[float], float] = lambda x: max(0.0, min(float(x), 1.0))


def configure_dlp_semantic_store(
    *,
    secret_provider: Any,
    openai_embedding_provider_cls: Any,
    embedding_model: str,
    dlp_semantic_enabled: bool,
    dlp_semantic_max_exemplars: int,
    store_deduped_content_fn: Callable[..., Awaitable[Dict[str, Any]]],
    severity_weight_fn: Callable[[str], float],
    clamp01_fn: Callable[[float], float],
) -> None:
    global _secret_provider
    global _openai_embedding_provider_cls
    global _embedding_model
    global _dlp_semantic_enabled
    global _dlp_semantic_max_exemplars
    global _store_deduped_content_fn
    global _severity_weight_fn
    global _clamp01_fn

    _secret_provider = secret_provider
    _openai_embedding_provider_cls = openai_embedding_provider_cls
    _embedding_model = embedding_model
    _dlp_semantic_enabled = bool(dlp_semantic_enabled)
    _dlp_semantic_max_exemplars = int(dlp_semantic_max_exemplars)
    _store_deduped_content_fn = store_deduped_content_fn
    _severity_weight_fn = severity_weight_fn
    _clamp01_fn = clamp01_fn


def _dlp_semantic_items_key(tenant_id: str) -> str:
    return f"apex:dlp_semantic:{tenant_id}:items"


def _dlp_semantic_meta_key(tenant_id: str) -> str:
    return f"apex:dlp_semantic:{tenant_id}:meta"


class DlpSemanticExemplar(BaseModel):
    exemplar_id: Optional[str] = None
    text: str
    label: Optional[str] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    created_at: Optional[str] = None


class DlpSemanticIngestRequest(BaseModel):
    mode: Literal["replace", "append"] = "replace"
    comment: Optional[str] = None
    exemplars: List[DlpSemanticExemplar]


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    if a.shape != b.shape:
        return 0.0
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


async def _get_dlp_embedder() -> Optional[Any]:
    if _secret_provider is None or _openai_embedding_provider_cls is None:
        return None

    try:
        key = await _secret_provider.get_openai_key()
    except Exception:
        key = ""
    if not key:
        return None

    cached_key = _DLP_EMBEDDER_CACHE.get("key")
    if cached_key == key and _DLP_EMBEDDER_CACHE.get("embedder") is not None:
        return _DLP_EMBEDDER_CACHE["embedder"]

    embedder = _openai_embedding_provider_cls(api_key=key, model=_embedding_model)
    _DLP_EMBEDDER_CACHE["key"] = key
    _DLP_EMBEDDER_CACHE["embedder"] = embedder
    return embedder


class DlpSemanticStore:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def load(self, tenant_id: str) -> Dict[str, Any]:
        meta_raw = await self.r.get(_dlp_semantic_meta_key(tenant_id))
        items_raw = await self.r.get(_dlp_semantic_items_key(tenant_id))
        meta = chimera_redis_json_views.decode_optional_json_object_or_default(meta_raw)
        items = chimera_redis_json_views.decode_optional_json_list_or_default(items_raw)
        return {"meta": meta, "items": items}

    async def ingest(
        self,
        tenant_id: str,
        req: DlpSemanticIngestRequest,
        *,
        content_ttl_seconds: int = 0,
    ) -> Dict[str, Any]:
        if not req.exemplars:
            raise HTTPException(status_code=400, detail="exemplars must be non-empty")

        existing_items: List[Dict[str, Any]] = []
        if req.mode == "append":
            loaded = await self.load(tenant_id)
            existing_items = list(loaded.get("items") or [])

        embedder = await _get_dlp_embedder()
        if embedder is None:
            raise HTTPException(status_code=400, detail="Semantic DLP requires OPENAI_API_KEY")
        if _store_deduped_content_fn is None:
            raise HTTPException(status_code=500, detail="semantic dlp storage not configured")

        compiled: List[Dict[str, Any]] = existing_items
        for ex in req.exemplars:
            txt = (ex.text or "").strip()
            if not txt:
                continue
            if len(txt) > 4000:
                raise HTTPException(status_code=400, detail="exemplar text too long (max 4000 chars)")

            ex_id = ex.exemplar_id or f"dlp_{uuid.uuid4().hex}"
            norm = unicodedata.normalize("NFC", txt)
            vec = await embedder.embed(norm)
            compiled.append(
                {
                    "exemplar_id": ex_id,
                    "label": ex.label,
                    "severity": ex.severity,
                    "confidence": float(ex.confidence),
                    "created_at": ex.created_at or chimera_policy_records.utc_now_z(),
                    "text_ref": await _store_deduped_content_fn(
                        self.r,
                        tenant_id=tenant_id,
                        kind="dlp_exemplar",
                        content=norm,
                        ttl_seconds=int(content_ttl_seconds or 0),
                    ),
                    "embedding": vec.tolist(),
                }
            )

        if len(compiled) > _dlp_semantic_max_exemplars:
            compiled = compiled[:_dlp_semantic_max_exemplars]

        meta = {
            "updated_at": chimera_policy_records.utc_now_z(),
            "mode": req.mode,
            "count": len(compiled),
            "comment": req.comment,
        }

        await self.r.set(_dlp_semantic_items_key(tenant_id), json.dumps(compiled, separators=(",", ":")))
        await self.r.set(_dlp_semantic_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))
        return meta


async def score_semantic_dlp(
    r: redis.Redis,
    *,
    tenant_id: str,
    text: str,
    max_hits: int = 5,
) -> Dict[str, Any]:
    if not _dlp_semantic_enabled:
        return {"score": 0.0, "hits": []}
    embedder = await _get_dlp_embedder()
    if embedder is None:
        return {"score": 0.0, "hits": []}

    store = DlpSemanticStore(r)
    loaded = await store.load(tenant_id)
    items: List[Dict[str, Any]] = list(loaded.get("items") or [])
    if not items:
        return {"score": 0.0, "hits": []}

    norm = unicodedata.normalize("NFC", text or "")
    vec = await embedder.embed(norm)
    v = np.array(vec, dtype=float)

    best = 0.0
    hits: List[Dict[str, Any]] = []
    for it in items[:_dlp_semantic_max_exemplars]:
        try:
            ev = np.array(it.get("embedding") or [], dtype=float)
            sim = _cosine_similarity(v, ev)
            sev = str(it.get("severity") or "medium")
            conf = float(it.get("confidence") or 0.0)
            score = _clamp01_fn(max(0.0, sim) * conf * _severity_weight_fn(sev))
            if score > best:
                best = score
            if score > 0.0:
                hits.append(
                    {
                        "exemplar_id": it.get("exemplar_id"),
                        "label": it.get("label"),
                        "severity": sev,
                        "confidence": conf,
                        "similarity": sim,
                        "score": score,
                    }
                )
        except Exception:
            continue

    hits = sorted(hits, key=lambda h: float(h.get("score") or 0.0), reverse=True)[:max_hits]
    return {"score": float(best), "hits": hits, "count": len(items)}
