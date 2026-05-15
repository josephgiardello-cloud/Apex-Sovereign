from __future__ import annotations

import time
from collections import Counter
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol

import httpx
import numpy as np
import redis.asyncio as redis
from fastapi import HTTPException

_apex_embedding_model: str = ""
_openai_base_url: str = ""
_global_policy_text: str = ""
_utc_now_z_fn: Optional[Callable[[], str]] = None


def configure_drift_runtime(
    *,
    apex_embedding_model: str,
    openai_base_url: str,
    global_policy_text: str,
    utc_now_z_fn: Callable[[], str],
) -> None:
    global _apex_embedding_model
    global _openai_base_url
    global _global_policy_text
    global _utc_now_z_fn

    _apex_embedding_model = apex_embedding_model
    _openai_base_url = openai_base_url
    _global_policy_text = global_policy_text
    _utc_now_z_fn = utc_now_z_fn


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class HalfOpenCircuitBreaker:
    """Simple per-process half-open circuit breaker."""

    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 30, half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_attempts = 0

    def before_call(self) -> None:
        now = time.time()
        if self.state == CircuitState.OPEN:
            if self._opened_at is None or now - self._opened_at > self.reset_timeout:
                self.state = CircuitState.HALF_OPEN
                self._half_open_attempts = 0
            else:
                raise HTTPException(status_code=503, detail="Upstream circuit open")

        if self.state == CircuitState.HALF_OPEN:
            self._half_open_attempts += 1
            if self._half_open_attempts > self.half_open_max_calls:
                self.state = CircuitState.OPEN
                self._opened_at = now
                raise HTTPException(status_code=503, detail="Upstream circuit re-opened")

    def after_call_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._half_open_attempts = 0
        self.state = CircuitState.CLOSED

    def after_call_failure(self) -> None:
        self._failures += 1
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self._opened_at = time.time()
            return
        if self._failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self._opened_at = time.time()


LLM_CIRCUIT = HalfOpenCircuitBreaker(failure_threshold=5, reset_timeout=30, half_open_max_calls=3)
EMBEDDER_CIRCUIT = HalfOpenCircuitBreaker(failure_threshold=3, reset_timeout=15, half_open_max_calls=2)


class DriftBackend(Protocol):
    async def get_anchor(self, session_id: str) -> np.ndarray:
        ...

    async def get_history_prompts(self, session_id: str) -> List[str]:
        ...


class EmbeddingProvider(Protocol):
    async def embed(self, text: str) -> np.ndarray:
        ...


class OpenAIEmbeddingProvider:
    """Minimal OpenAI embedding client for drift backend."""

    def __init__(self, api_key: str = "", model: str = "", base_url: str = ""):
        self.api_key = api_key
        self.model = model or _apex_embedding_model
        effective_base = base_url or _openai_base_url or "https://api.openai.com/v1"
        self.base_url = effective_base
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=15.0,
            headers=headers,
        )
        self._dim: Optional[int] = None

    async def _ensure_dim(self) -> int:
        if self._dim is not None:
            return self._dim
        payload = {"input": "apex-dim-probe", "model": self.model}
        resp = await self._client.post("/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
        vec = data["data"][0]["embedding"]
        self._dim = len(vec)
        return self._dim

    async def embed(self, text: str) -> np.ndarray:
        if not text.strip():
            dim = await self._ensure_dim()
            return np.zeros(dim, dtype=float)
        payload = {"input": text, "model": self.model}
        resp = await self._client.post("/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
        vec = data["data"][0]["embedding"]
        return np.array(vec, dtype=float)


class VectorIndex(Protocol):
    async def upsert(self, items: List[Dict[str, Any]]) -> None:
        ...

    async def query(self, session_id: str, top_k: int) -> List[np.ndarray]:
        ...

    async def delete_session(self, session_id: str) -> None:
        ...


class QdrantIndex:
    """Qdrant-backed vector index for drift history."""

    def __init__(
        self,
        client: Any,
        collection: str,
        vector_dim: int,
        distance: Any = None,
    ):
        self.client = client
        self.collection = collection
        self.vector_dim = vector_dim
        self.distance = distance

    @staticmethod
    def build_client(*, url: str, api_key: Optional[str]) -> Any:
        from qdrant_client import AsyncQdrantClient

        return AsyncQdrantClient(url=url, api_key=api_key)

    async def ensure_collection(self) -> None:
        from qdrant_client.models import Distance, VectorParams

        distance = self.distance or Distance.COSINE
        collections = await self.client.get_collections()
        names = [c.name for c in collections.collections]
        if self.collection not in names:
            await self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(
                    size=self.vector_dim,
                    distance=distance,
                ),
            )

    async def upsert(self, items: List[Dict[str, Any]]) -> None:
        from qdrant_client.models import PointStruct

        points = []
        for it in items:
            points.append(
                PointStruct(
                    id=it["id"],
                    vector=it["vector"],
                    payload=it.get("metadata", {}),
                )
            )

        await self.client.upsert(
            collection_name=self.collection,
            points=points,
        )

    async def query(self, session_id: str, top_k: int) -> List[np.ndarray]:
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        flt = Filter(
            must=[
                FieldCondition(
                    key="session_id",
                    match=MatchValue(value=session_id),
                )
            ]
        )
        limit = top_k
        offset = None
        vectors: List[np.ndarray] = []
        while True:
            res, next_offset = await self.client.scroll(
                collection_name=self.collection,
                scroll_filter=flt,
                limit=min(limit, 100),
                with_vectors=True,
                with_payload=False,
                offset=offset,
            )
            for p in res:
                if p.vector is not None:
                    vectors.append(np.array(p.vector, dtype=float))
                    if len(vectors) >= top_k:
                        return vectors
            if not next_offset:
                break
            offset = next_offset
        return vectors

    async def delete_session(self, session_id: str) -> None:
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        flt = Filter(
            must=[
                FieldCondition(
                    key="session_id",
                    match=MatchValue(value=session_id),
                )
            ]
        )
        await self.client.delete(
            collection_name=self.collection,
            wait=True,
            filter=flt,
        )


class RedisBowDriftBackend:
    """Baseline, Redis-backed, Bag-of-Words drift backend."""

    def __init__(self, r_client: redis.Redis, history_limit: int = 20):
        self.r = r_client
        self.history_limit = history_limit

    async def get_history_prompts(self, session_id: str) -> List[str]:
        return await self.r.lrange(f"session:{session_id}:prompts", -self.history_limit, -1)

    async def get_anchor(self, session_id: str) -> np.ndarray:
        prior_prompts = await self.get_history_prompts(session_id)
        if not prior_prompts:
            return np.zeros(1)

        all_text = " ".join(prior_prompts)
        words = all_text.split()
        if not words:
            return np.zeros(1)

        word_counts = Counter(words)
        vocab = sorted(set(words))
        vec = np.array([word_counts.get(w, 0) for w in vocab], dtype=float)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else np.zeros_like(vec)

    async def reset_anchor(self, session_id: str) -> None:
        await self.r.delete(f"session:{session_id}:prompts")


class VectorDbDriftBackend:
    """Vector DB-backed drift backend."""

    def __init__(
        self,
        index: QdrantIndex,
        embedder: EmbeddingProvider,
        history_limit: int = 50,
        global_policy_text: str = "",
    ):
        self.index = index
        self.embedder = embedder
        self.history_limit = history_limit
        self.global_policy_text = global_policy_text or _global_policy_text
        self._global_anchor_vec: Optional[np.ndarray] = None

    async def ensure_global_anchor(self) -> np.ndarray:
        if self._global_anchor_vec is not None:
            return self._global_anchor_vec
        vec = await self.embedder.embed(self.global_policy_text)
        norm = np.linalg.norm(vec)
        self._global_anchor_vec = vec / norm if norm > 0 else vec
        return self._global_anchor_vec

    async def get_history_prompts(self, session_id: str) -> List[str]:
        return []

    async def get_anchor(self, session_id: str) -> np.ndarray:
        vectors = await self.index.query(session_id=session_id, top_k=self.history_limit)
        if not vectors:
            return np.zeros(0, dtype=float)
        mat = np.stack(vectors, axis=0)
        mean_vec = mat.mean(axis=0)
        norm = np.linalg.norm(mean_vec)
        return mean_vec / norm if norm > 0 else np.zeros_like(mean_vec)

    async def add_prompt_embedding(self, session_id: str, prompt: str) -> None:
        vec = await self.embedder.embed(prompt)
        if _utc_now_z_fn is None:
            raise RuntimeError("drift_runtime not configured")
        item = {
            "id": f"{session_id}:{int(time.time() * 1000)}",
            "vector": vec.tolist(),
            "metadata": {
                "session_id": session_id,
                "ts": _utc_now_z_fn(),
            },
        }
        await self.index.upsert([item])

    async def reset_anchor(self, session_id: str) -> None:
        await self.index.delete_session(session_id)
