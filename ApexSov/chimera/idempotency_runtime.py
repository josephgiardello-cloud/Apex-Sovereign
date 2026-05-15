"""Idempotency boundary helpers for streaming request deduplication."""

from __future__ import annotations

import asyncio
import time
from threading import RLock
from typing import Any


class IdempotencyBoundary:
    """Stores completed results keyed by (session_id, request_id)."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._completed: dict[tuple[str, str], dict[str, Any]] = {}
        self._inflight: dict[tuple[str, str], dict[str, Any]] = {}

    def _key(self, *, session_id: str, request_id: str) -> tuple[str, str]:
        return (str(session_id or "").strip(), str(request_id or "").strip())

    def get_cached(self, *, session_id: str, request_id: str) -> Any | None:
        key = self._key(session_id=session_id, request_id=request_id)
        if not key[0] or not key[1]:
            return None
        with self._lock:
            entry = self._completed.get(key)
            if not entry:
                return None
            return entry.get("result")

    def acquire_or_get(
        self,
        *,
        session_id: str,
        request_id: str,
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[str, Any | None, asyncio.Future | None]:
        key = self._key(session_id=session_id, request_id=request_id)
        if not key[0] or not key[1]:
            return ("no-key", None, None)

        with self._lock:
            if key in self._completed:
                return ("cached", self._completed[key].get("result"), None)
            if key in self._inflight:
                return ("inflight", None, self._inflight[key].get("future"))
            shared_future: asyncio.Future = loop.create_future()
            self._inflight[key] = {
                "future": shared_future,
                "started_at_unix": float(time.time()),
            }
            return ("acquired", None, shared_future)

    def store_result(self, *, session_id: str, request_id: str, result: Any) -> None:
        key = self._key(session_id=session_id, request_id=request_id)
        if not key[0] or not key[1]:
            return
        with self._lock:
            self._completed[key] = {
                "result": result,
                "completed_at_unix": float(time.time()),
            }
            inflight_entry = self._inflight.pop(key, None)
        inflight = inflight_entry.get("future") if isinstance(inflight_entry, dict) else None
        if inflight is not None and not inflight.done():
            inflight.set_result(result)

    def store_error(self, *, session_id: str, request_id: str, error: Exception) -> None:
        key = self._key(session_id=session_id, request_id=request_id)
        if not key[0] or not key[1]:
            return
        with self._lock:
            inflight_entry = self._inflight.pop(key, None)
        inflight = inflight_entry.get("future") if isinstance(inflight_entry, dict) else None
        if inflight is not None and not inflight.done():
            inflight.set_exception(error)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "completed": {
                    f"{session_id}:{request_id}": value.get("result")
                    for (session_id, request_id), value in self._completed.items()
                },
                "inflight_count": len(self._inflight),
            }

    def snapshot_for_tenant(
        self,
        *,
        tenant_id: str,
        max_keys: int = 100,
        session_id_filter: str | None = None,
    ) -> dict[str, Any]:
        tenant = str(tenant_id or "").strip()
        prefix = f"{tenant}:"
        now_ts = float(time.time())
        session_filter = str(session_id_filter or "").strip()
        full_session_filter = f"{prefix}{session_filter}" if session_filter else ""
        with self._lock:
            completed_entries = [
                {
                    "session_id": session_id,
                    "request_id": request_id,
                    "age_seconds": max(0.0, now_ts - float((entry or {}).get("completed_at_unix") or now_ts)),
                }
                for (session_id, request_id), entry in self._completed.items()
                if session_id.startswith(prefix)
                and (not full_session_filter or session_id == full_session_filter)
            ]
            inflight_entries = [
                {
                    "session_id": session_id,
                    "request_id": request_id,
                    "age_seconds": max(0.0, now_ts - float((entry or {}).get("started_at_unix") or now_ts)),
                }
                for (session_id, request_id), entry in self._inflight.items()
                if session_id.startswith(prefix)
                and (not full_session_filter or session_id == full_session_filter)
            ]

        completed_entries = completed_entries[: max(0, int(max_keys))]
        inflight_entries = inflight_entries[: max(0, int(max_keys))]

        return {
            "tenant_id": tenant,
            "session_id_filter": session_filter or None,
            "completed_count": len(completed_entries),
            "inflight_count": len(inflight_entries),
            "completed_entries": completed_entries,
            "inflight_entries": inflight_entries,
        }
