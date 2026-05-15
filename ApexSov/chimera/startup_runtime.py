"""Apex Sovereign - startup runtime initialization helpers."""

import asyncio
import os
from typing import Any


async def initialize_runtime_on_startup(
    *,
    get_apex_env_fn: Any,
    apex_env_prod: Any,
    tracing_available_fn: Any,
    periodic_self_test_loop_fn: Any,
    retention_enforcer_loop_fn: Any,
    get_redis_client_fn: Any,
    apex_drift_backend: str,
    require_vector_backend_api_key_or_raise_fn: Any,
    openai_base_url: str,
    openai_embedding_model: str,
    openai_embedding_provider_cls: Any,
    qdrant_index_cls: Any,
    vector_db_drift_backend_cls: Any,
    redis_bow_drift_backend_cls: Any,
    qdrant_url: str,
    qdrant_api_key: str,
    qdrant_collection: str,
) -> Any:
    """Run startup checks/tasks and return configured drift backend instance."""
    env = get_apex_env_fn()
    if env == apex_env_prod and not tracing_available_fn():
        raise RuntimeError("Tracing is required in PROD but OpenTelemetry is not available/configured")

    asyncio.create_task(periodic_self_test_loop_fn())
    asyncio.create_task(retention_enforcer_loop_fn())

    r = await get_redis_client_fn()

    if apex_drift_backend == "vector":
        openai_key = os.getenv("OPENAI_API_KEY", "")
        try:
            require_vector_backend_api_key_or_raise_fn(
                api_key=openai_key,
                endpoint_url=openai_base_url,
            )
        except ValueError as exc:
            raise RuntimeError(str(exc))

        embedder = openai_embedding_provider_cls(
            api_key=openai_key,
            model=openai_embedding_model,
            base_url=openai_base_url,
        )
        qdrant = qdrant_index_cls.build_client(
            url=qdrant_url,
            api_key=qdrant_api_key or None,
        )

        dim = await embedder._ensure_dim()
        drift_index = qdrant_index_cls(
            client=qdrant,
            collection=qdrant_collection,
            vector_dim=dim,
        )
        await drift_index.ensure_collection()

        backend = vector_db_drift_backend_cls(index=drift_index, embedder=embedder)
        await backend.ensure_global_anchor()
        return backend

    return redis_bow_drift_backend_cls(r)
