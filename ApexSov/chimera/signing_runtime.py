from __future__ import annotations

import asyncio
import base64
import json
from typing import Any, Awaitable, Callable, Dict, Optional

import redis.asyncio as redis

_load_signer_for_worker_fn: Optional[Callable[[], Any]] = None
_signer_health: Optional[Dict[str, Any]] = None
_utc_now_z_fn: Optional[Callable[[], str]] = None
_get_redis_client_fn: Optional[Callable[[], Awaitable[redis.Redis]]] = None
_signing_queue_key: str = "apex:signing_queue"
_read_raw_ledger_entry_fn: Optional[Callable[[redis.Redis, int], Awaitable[Optional[Dict[str, Any]]]]] = None
_update_raw_ledger_entry_fn: Optional[Callable[[redis.Redis, int, Dict[str, Any]], Awaitable[None]]] = None
_compute_entry_hash_fn: Optional[Callable[[Dict[str, Any], Optional[str]], str]] = None
_enforce_kms_dual_control_or_raise_fn: Optional[Callable[[Optional[redis.Redis]], Awaitable[None]]] = None
_emit_signing_access_log_fn: Optional[Callable[..., Awaitable[None]]] = None
_enqueue_for_signing_fn: Optional[Callable[[redis.Redis, int], Awaitable[None]]] = None


MAX_SIGNING_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 2.0


def configure_signing_runtime(
    *,
    load_signer_for_worker_fn: Callable[[], Any],
    signer_health: Dict[str, Any],
    utc_now_z_fn: Callable[[], str],
    get_redis_client_fn: Callable[[], Awaitable[redis.Redis]],
    signing_queue_key: str,
    read_raw_ledger_entry_fn: Callable[[redis.Redis, int], Awaitable[Optional[Dict[str, Any]]]],
    update_raw_ledger_entry_fn: Callable[[redis.Redis, int, Dict[str, Any]], Awaitable[None]],
    compute_entry_hash_fn: Callable[[Dict[str, Any], Optional[str]], str],
    enforce_kms_dual_control_or_raise_fn: Callable[[Optional[redis.Redis]], Awaitable[None]],
    emit_signing_access_log_fn: Callable[..., Awaitable[None]],
    enqueue_for_signing_fn: Callable[[redis.Redis, int], Awaitable[None]],
) -> None:
    global _load_signer_for_worker_fn
    global _signer_health
    global _utc_now_z_fn
    global _get_redis_client_fn
    global _signing_queue_key
    global _read_raw_ledger_entry_fn
    global _update_raw_ledger_entry_fn
    global _compute_entry_hash_fn
    global _enforce_kms_dual_control_or_raise_fn
    global _emit_signing_access_log_fn
    global _enqueue_for_signing_fn

    _load_signer_for_worker_fn = load_signer_for_worker_fn
    _signer_health = signer_health
    _utc_now_z_fn = utc_now_z_fn
    _get_redis_client_fn = get_redis_client_fn
    _signing_queue_key = signing_queue_key
    _read_raw_ledger_entry_fn = read_raw_ledger_entry_fn
    _update_raw_ledger_entry_fn = update_raw_ledger_entry_fn
    _compute_entry_hash_fn = compute_entry_hash_fn
    _enforce_kms_dual_control_or_raise_fn = enforce_kms_dual_control_or_raise_fn
    _emit_signing_access_log_fn = emit_signing_access_log_fn
    _enqueue_for_signing_fn = enqueue_for_signing_fn


def _require_cfg() -> None:
    if (
        _load_signer_for_worker_fn is None
        or _signer_health is None
        or _utc_now_z_fn is None
        or _get_redis_client_fn is None
        or _read_raw_ledger_entry_fn is None
        or _update_raw_ledger_entry_fn is None
        or _compute_entry_hash_fn is None
        or _enforce_kms_dual_control_or_raise_fn is None
        or _emit_signing_access_log_fn is None
        or _enqueue_for_signing_fn is None
    ):
        raise RuntimeError("signing_runtime not configured")


async def signing_worker_loop(stop_event: asyncio.Event) -> None:
    _require_cfg()

    try:
        signer = _load_signer_for_worker_fn()
        _signer_health["ok"] = True
        _signer_health["last_ok_at"] = _utc_now_z_fn()
        _signer_health["last_error"] = None
    except Exception as exc:
        signer = None
        _signer_health["ok"] = False
        _signer_health["last_error"] = f"signer_load_failed:{exc}"
        _signer_health["last_error_at"] = _utc_now_z_fn()

    r = await _get_redis_client_fn()

    while not stop_event.is_set():
        try:
            if signer is None:
                try:
                    signer = _load_signer_for_worker_fn()
                    _signer_health["ok"] = True
                    _signer_health["last_ok_at"] = _utc_now_z_fn()
                    _signer_health["last_error"] = None
                except Exception as exc:
                    _signer_health["ok"] = False
                    _signer_health["last_error"] = f"signer_load_failed:{exc}"
                    _signer_health["last_error_at"] = _utc_now_z_fn()
                    await asyncio.sleep(2.0)
                    continue

            item = await r.blpop(_signing_queue_key, timeout=5)
            if not item:
                continue
            _, index_str = item
            index = int(index_str)

            entry = await _read_raw_ledger_entry_fn(r, index)
            if not entry:
                continue

            if entry.get("signing_status") == "kms_signed":
                continue

            attempts = int(entry.get("signing_attempts", 0))
            if attempts >= MAX_SIGNING_ATTEMPTS:
                entry["signing_status"] = "kms_failed"
                entry["kms_signed_at"] = entry.get("kms_signed_at") or _utc_now_z_fn()
                await _update_raw_ledger_entry_fn(r, index, entry)
                continue

            payload = entry.get("payload", {})
            prev_hash = entry.get("prev_hash")
            entry_hash = _compute_entry_hash_fn(payload, prev_hash)

            if entry_hash != entry.get("entry_hash"):
                entry["signing_status"] = "hash_mismatch"
                entry["kms_signed_at"] = _utc_now_z_fn()
                await _update_raw_ledger_entry_fn(r, index, entry)
                continue

            try:
                await _enforce_kms_dual_control_or_raise_fn(r)
            except Exception as exc:
                _signer_health["ok"] = False
                _signer_health["last_error"] = f"dual_control_failed:{exc}"
                _signer_health["last_error_at"] = _utc_now_z_fn()
                try:
                    await _emit_signing_access_log_fn(
                        r,
                        tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                        status="failure",
                        ledger_index=index,
                        entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                        kid=(entry.get("kid") if isinstance(entry, dict) else None),
                        alg=(entry.get("alg") if isinstance(entry, dict) else None),
                        signing_status=str(entry.get("signing_status") or "pending_kms"),
                        error=f"dual_control:{str(exc)}",
                    )
                except Exception:
                    pass
                try:
                    await _enqueue_for_signing_fn(r, index)
                except Exception:
                    pass
                await asyncio.sleep(2.0)
                continue

            message_bytes = json.dumps(
                {
                    "payload": payload,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

            def _sign() -> bytes:
                return signer.sign(message_bytes)

            try:
                signature = await asyncio.to_thread(_sign)
            except Exception as exc:
                _signer_health["ok"] = False
                _signer_health["last_error"] = "sign_failed"
                _signer_health["last_error_at"] = _utc_now_z_fn()
                try:
                    await _emit_signing_access_log_fn(
                        r,
                        tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                        status="failure",
                        ledger_index=index,
                        entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                        kid=(entry.get("kid") if isinstance(entry, dict) else None),
                        alg=(entry.get("alg") if isinstance(entry, dict) else None),
                        signing_status=str(entry.get("signing_status") or "pending_kms"),
                        error=f"sign_failed:{str(exc)}",
                    )
                except Exception:
                    pass
                attempts += 1
                entry["signing_attempts"] = attempts
                if attempts >= MAX_SIGNING_ATTEMPTS:
                    entry["signing_status"] = "kms_failed"
                    entry["kms_signed_at"] = _utc_now_z_fn()
                    await _update_raw_ledger_entry_fn(r, index, entry)
                else:
                    await _update_raw_ledger_entry_fn(r, index, entry)
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                    await _enqueue_for_signing_fn(r, index)
                continue

            entry["kms_signature"] = base64.b64encode(signature).decode("ascii")
            entry["kms_signed_at"] = _utc_now_z_fn()
            entry["signing_status"] = "kms_signed"
            entry["signing_attempts"] = attempts

            try:
                signer_kid = getattr(signer, "key_id", None)
                if isinstance(signer_kid, str) and signer_kid.strip():
                    entry["kid"] = signer_kid.strip()
            except Exception:
                pass
            await _update_raw_ledger_entry_fn(r, index, entry)

            try:
                await _emit_signing_access_log_fn(
                    r,
                    tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                    status="success",
                    ledger_index=index,
                    entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                    kid=(entry.get("kid") if isinstance(entry, dict) else None),
                    alg=(entry.get("alg") if isinstance(entry, dict) else None),
                    signing_status=str(entry.get("signing_status") or "kms_signed"),
                    error=None,
                )
            except Exception:
                pass

            _signer_health["ok"] = True
            _signer_health["last_ok_at"] = _utc_now_z_fn()
            _signer_health["last_error"] = None

            try:
                await r.rpush(
                    "apex:signed_ledger_buffer",
                    json.dumps(entry, separators=(",", ":"), sort_keys=True),
                )
            except Exception:
                pass

        except Exception as exc:
            _signer_health["ok"] = False
            _signer_health["last_error"] = f"signing_loop_error:{exc}"
            _signer_health["last_error_at"] = _utc_now_z_fn()
            await asyncio.sleep(1.0)
