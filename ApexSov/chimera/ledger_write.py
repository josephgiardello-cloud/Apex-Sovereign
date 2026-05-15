"""Apex Sovereign – Ledger write path: audit minimization, backlog status, and create_unsigned_ledger_entry.

Extracted from BaseT8.py.  Call configure_ledger_write() before using any
public function here.
"""

import asyncio
import base64
import json
import random
import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

import redis.asyncio as redis
from fastapi import HTTPException


class LedgerBackpressureError(RuntimeError):
    """
    Raised when unsigned ledger queue exceeds configured safety threshold.
    """


# ── Module-level config (set by configure_ledger_write) ───────────────────────
_APEX_AUDIT_HASH_SALT: str = ""
_APEX_REGION: str = ""
_APEX_CHAIN_ID: str = ""
_LEDGER_CHAIN_ID: str = ""
_KMS_KEY_ID: str = ""
_POLICY_VERSION: str = ""
_MAX_UNSIGNED_QUEUE: int = 0
_UNSIGNED_WARN_FRACTION: float = 0.8
_SIGNING_QUEUE_KEY: str = ""
_LEDGER_CHECKPOINT_INTERVAL: int = 0
_APEX_ENABLE_MERKLE_CHECKPOINTS: bool = False
_APEX_SIGN_CHECKPOINTS: bool = False
_APEX_ENABLE_ANCHOR_ENTRIES: bool = False
_DEFAULT_POLICY_BASELINE: Dict[str, Any] = {}

_get_apex_env_fn: Optional[Callable] = None
_policy_store_factory: Optional[Callable] = None
_utc_now_z_fn: Optional[Callable] = None
_compute_entry_hash_fn: Optional[Callable] = None
_compute_merkle_root_hex_fn: Optional[Callable] = None
_load_signer_for_worker_fn: Optional[Callable] = None
_decode_required_json_object_fn: Optional[Callable] = None
_extract_entry_hash_leaves_fn: Optional[Callable] = None
_enqueue_for_signing_fn: Optional[Callable] = None
_write_checkpoint_fn: Optional[Callable] = None

_AUDIT_MINIMIZATION_CACHE: Dict[str, Dict[str, Any]] = {}


def configure_ledger_write(
    *,
    apex_audit_hash_salt: str,
    apex_region: str,
    apex_chain_id: str,
    ledger_chain_id: str,
    kms_key_id: str,
    policy_version: str,
    max_unsigned_queue: int,
    unsigned_warn_fraction: float,
    signing_queue_key: str,
    ledger_checkpoint_interval: int,
    apex_enable_merkle_checkpoints: bool,
    apex_sign_checkpoints: bool,
    apex_enable_anchor_entries: bool,
    default_policy_baseline: Dict[str, Any],
    get_apex_env_fn: Callable,
    policy_store_factory: Callable,
    utc_now_z_fn: Callable,
    compute_entry_hash_fn: Callable,
    compute_merkle_root_hex_fn: Callable,
    load_signer_for_worker_fn: Callable,
    decode_required_json_object_fn: Callable,
    extract_entry_hash_leaves_fn: Callable,
    enqueue_for_signing_fn: Callable,
    write_checkpoint_fn: Callable,
) -> None:
    global _APEX_AUDIT_HASH_SALT, _APEX_REGION, _APEX_CHAIN_ID, _LEDGER_CHAIN_ID
    global _KMS_KEY_ID, _POLICY_VERSION, _MAX_UNSIGNED_QUEUE, _UNSIGNED_WARN_FRACTION
    global _SIGNING_QUEUE_KEY, _LEDGER_CHECKPOINT_INTERVAL
    global _APEX_ENABLE_MERKLE_CHECKPOINTS, _APEX_SIGN_CHECKPOINTS, _APEX_ENABLE_ANCHOR_ENTRIES
    global _DEFAULT_POLICY_BASELINE
    global _get_apex_env_fn, _policy_store_factory, _utc_now_z_fn
    global _compute_entry_hash_fn, _compute_merkle_root_hex_fn, _load_signer_for_worker_fn
    global _decode_required_json_object_fn, _extract_entry_hash_leaves_fn
    global _enqueue_for_signing_fn, _write_checkpoint_fn

    _APEX_AUDIT_HASH_SALT = str(apex_audit_hash_salt or "")
    _APEX_REGION = str(apex_region or "")
    _APEX_CHAIN_ID = str(apex_chain_id or "")
    _LEDGER_CHAIN_ID = str(ledger_chain_id or "")
    _KMS_KEY_ID = str(kms_key_id or "")
    _POLICY_VERSION = str(policy_version or "")
    _MAX_UNSIGNED_QUEUE = int(max_unsigned_queue)
    _UNSIGNED_WARN_FRACTION = float(unsigned_warn_fraction)
    _SIGNING_QUEUE_KEY = str(signing_queue_key or "")
    _LEDGER_CHECKPOINT_INTERVAL = int(ledger_checkpoint_interval)
    _APEX_ENABLE_MERKLE_CHECKPOINTS = bool(apex_enable_merkle_checkpoints)
    _APEX_SIGN_CHECKPOINTS = bool(apex_sign_checkpoints)
    _APEX_ENABLE_ANCHOR_ENTRIES = bool(apex_enable_anchor_entries)
    _DEFAULT_POLICY_BASELINE = dict(default_policy_baseline or {})
    _get_apex_env_fn = get_apex_env_fn
    _policy_store_factory = policy_store_factory
    _utc_now_z_fn = utc_now_z_fn
    _compute_entry_hash_fn = compute_entry_hash_fn
    _compute_merkle_root_hex_fn = compute_merkle_root_hex_fn
    _load_signer_for_worker_fn = load_signer_for_worker_fn
    _decode_required_json_object_fn = decode_required_json_object_fn
    _extract_entry_hash_leaves_fn = extract_entry_hash_leaves_fn
    _enqueue_for_signing_fn = enqueue_for_signing_fn
    _write_checkpoint_fn = write_checkpoint_fn


# ── Audit minimization helpers ─────────────────────────────────────────────────

import hashlib
import unicodedata


def get_data_minimization(policy: Dict[str, Any]) -> Dict[str, Any]:
    base = _DEFAULT_POLICY_BASELINE.get("data_minimization") or {}
    dm = policy.get("data_minimization") if isinstance(policy, dict) else None
    if not isinstance(dm, dict):
        dm = {}
    out = dict(base)
    out.update(dm)
    return out


def no_content_retention_enabled(policy: Dict[str, Any]) -> bool:
    dm = get_data_minimization(policy)
    return bool(dm.get("no_content_retention", False))


def _audit_hash_value(*, tenant_id: str, value: Any) -> str:
    s = str(value) if value is not None else ""
    material = f"{_APEX_AUDIT_HASH_SALT}\0{tenant_id}\0{s}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def apply_audit_minimization_to_payload(*, tenant_id: str, payload: Dict[str, Any], dm: Dict[str, Any]) -> Dict[str, Any]:
    """Return a minimized copy of payload based on tenant data minimization policy."""
    mode = str(dm.get("audit_mode", "full") or "full").strip().lower()
    include_subject = bool(dm.get("include_subject", True))
    include_session_id = bool(dm.get("include_session_id", True))
    include_request_context = bool(dm.get("include_request_context", True))

    out = dict(payload)

    # Drop fields based on inclusion flags.
    if not include_subject:
        out.pop("subject", None)
    if not include_session_id:
        out.pop("session_id", None)
    if not include_request_context:
        for k in ("ip", "user_agent", "device_id"):
            out.pop(k, None)

    # Transform fields by audit mode.
    if mode == "full":
        return out

    hash_keys = ("subject", "session_id", "ip", "user_agent", "device_id")
    redact_keys = ("subject", "session_id", "ip", "user_agent", "device_id", "reason", "comment")

    if mode == "hash_only":
        for k in hash_keys:
            if k in out and out.get(k) is not None:
                out[k] = _audit_hash_value(tenant_id=tenant_id, value=out.get(k))
        out["audit_mode"] = "hash_only"
        return out

    if mode == "redacted_only":
        for k in redact_keys:
            if k in out and out.get(k) is not None:
                out[k] = "[REDACTED]"
        out["audit_mode"] = "redacted_only"
        return out

    # Unknown mode -> safest fallback.
    for k in hash_keys:
        if k in out and out.get(k) is not None:
            out[k] = _audit_hash_value(tenant_id=tenant_id, value=out.get(k))
    out["audit_mode"] = "hash_only"
    return out


async def get_cached_tenant_minimization(r: redis.Redis, tenant_id: str) -> Dict[str, Any]:
    now = time.time()
    cached = _AUDIT_MINIMIZATION_CACHE.get(tenant_id)
    if isinstance(cached, dict) and float(cached.get("expires_at", 0)) > now:
        return cached.get("data_minimization") or (_DEFAULT_POLICY_BASELINE.get("data_minimization") or {})

    dm = _DEFAULT_POLICY_BASELINE.get("data_minimization") or {}
    try:
        store = _policy_store_factory(r)
        try:
            record = await store.get_policy_record(tenant_id)
        except HTTPException:
            record = None
        if record is not None:
            dm = get_data_minimization(record.policy or {})
    except Exception:
        dm = _DEFAULT_POLICY_BASELINE.get("data_minimization") or {}

    _AUDIT_MINIMIZATION_CACHE[tenant_id] = {
        "expires_at": now + 60.0,
        "data_minimization": dm,
    }
    return dm


# ── Backlog status & ledger entry creation ─────────────────────────────────────

async def get_unsigned_backlog_status(r: redis.Redis) -> Tuple[int, bool, bool]:
    queue_len = await r.llen(_SIGNING_QUEUE_KEY) or 0
    warn_threshold = int(_UNSIGNED_WARN_FRACTION * _MAX_UNSIGNED_QUEUE)
    is_critical = queue_len >= _MAX_UNSIGNED_QUEUE
    is_warning = queue_len >= warn_threshold and not is_critical
    return queue_len, is_warning, is_critical


async def create_unsigned_ledger_entry(
    r: redis.Redis,
    payload: Dict[str, Any],
    max_retries: int = 8,
    allow_checkpoint: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    """
    Atomically append a new ledger entry with backpressure and jittered retries:
    - Reject if unsigned queue too large (to preserve integrity).
    - WATCH tail, recompute prev_hash inside transaction, RPUSH.
    - Use randomized backoff to avoid thundering herd.

    Enriched schema:
    - entry_id: UUID per logical event
    - region: deployment region (APEX_REGION or KMS_REGION)
    - ledger_chain_id: logical chain identifier
    - ts: canonical event timestamp (UTC ISO8601)
    """
    queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
    if is_warning:
        print(f"[apex-ledger] WARNING: unsigned backlog high ({queue_len}/{_MAX_UNSIGNED_QUEUE})")
    if is_critical:
        print(f"[apex-ledger] CRITICAL: unsigned backlog >= limit ({queue_len}/{_MAX_UNSIGNED_QUEUE})")
        raise LedgerBackpressureError(
            f"Unsigned ledger queue too large ({queue_len} >= {_MAX_UNSIGNED_QUEUE}); "
            f"refusing new entries to preserve audit integrity."
        )

    region = _APEX_REGION
    chain_id = _APEX_CHAIN_ID or _LEDGER_CHAIN_ID

    # Apply tenant-configurable audit minimization before committing to the immutable ledger.
    tenant_id = payload.get("tenant_id") if isinstance(payload, dict) else None
    minimized_payload = dict(payload)
    if isinstance(tenant_id, str) and tenant_id.strip():
        try:
            dm = await get_cached_tenant_minimization(r, tenant_id.strip())
            minimized_payload = apply_audit_minimization_to_payload(
                tenant_id=tenant_id.strip(),
                payload=minimized_payload,
                dm=dm,
            )
        except Exception:
            minimized_payload = dict(payload)

    for attempt in range(max_retries):
        async with r.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch("apex:audit_ledger")
                last = await pipe.lindex("apex:audit_ledger", -1)
                if last:
                    last_entry = _decode_required_json_object_fn(last)
                    prev_hash = last_entry.get("entry_hash")
                else:
                    prev_hash = None

                enriched_payload = dict(minimized_payload)
                enriched_payload.setdefault("entry_id", str(uuid.uuid4()))
                enriched_payload.setdefault("region", region)
                enriched_payload.setdefault("ledger_chain_id", chain_id)
                enriched_payload.setdefault("ts", _utc_now_z_fn())

                entry_hash = _compute_entry_hash_fn(enriched_payload, prev_hash)

                entry = {
                    "payload": enriched_payload,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                    "kms_signature": None,
                    "kms_signed_at": None,
                    "signing_status": "pending_kms",
                    "signing_attempts": 0,
                    "alg": "ECDSA_SHA256",
                    "kid": _KMS_KEY_ID or "dev-ledger-key",
                    "flushed_to_s3": False,
                }

                encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)

                pipe.multi()
                pipe.rpush("apex:audit_ledger", encoded)
                result = await pipe.execute()
                new_len = int(result[0])
                index = new_len - 1

                # Best-effort index for auditor workflows (fast lookup by entry_id).
                try:
                    entry_id = enriched_payload.get("entry_id")
                    if entry_id:
                        await r.set(f"apex:ledger:index:{entry_id}", str(index), nx=True)
                except Exception:
                    pass

                if allow_checkpoint and _LEDGER_CHECKPOINT_INTERVAL > 0 and new_len % _LEDGER_CHECKPOINT_INTERVAL == 0:
                    merkle_root: Optional[str] = None
                    merkle_start_index: Optional[int] = None
                    merkle_end_index: Optional[int] = None
                    merkle_leaf_count: Optional[int] = None

                    if _APEX_ENABLE_MERKLE_CHECKPOINTS:
                        try:
                            merkle_end_index = index
                            merkle_start_index = max(0, merkle_end_index - _LEDGER_CHECKPOINT_INTERVAL + 1)
                            raw_entries = await r.lrange("apex:audit_ledger", merkle_start_index, merkle_end_index)
                            leaves = _extract_entry_hash_leaves_fn(raw_entries)
                            merkle_leaf_count = len(leaves)
                            merkle_root = _compute_merkle_root_hex_fn(leaves)
                        except Exception:
                            merkle_root = None

                    checkpoint_payload = {
                        "ts": _utc_now_z_fn(),
                        "chain_id": chain_id,
                        "last_index": index,
                        "last_entry_hash": entry_hash,
                        "entry_count": new_len,
                        "policy_version": _POLICY_VERSION,
                        "env": _get_apex_env_fn().value,
                        "region": region,
                        "merkle_alg": "sha256",
                        "merkle_start_index": merkle_start_index,
                        "merkle_end_index": merkle_end_index,
                        "merkle_leaf_count": merkle_leaf_count,
                        "merkle_root": merkle_root,
                    }

                    if _APEX_SIGN_CHECKPOINTS and merkle_root:
                        try:
                            signer = _load_signer_for_worker_fn()
                            sig = signer.sign(merkle_root.encode("utf-8"))
                            checkpoint_payload["checkpoint_signature_b64"] = base64.b64encode(sig).decode("ascii")
                            checkpoint_payload["checkpoint_sig_alg"] = "ECDSA_SHA256"
                            checkpoint_payload["checkpoint_sig_kid"] = _KMS_KEY_ID or "dev-ledger-key"
                        except Exception:
                            pass
                    await _write_checkpoint_fn(r, checkpoint_payload)

                    if _APEX_ENABLE_ANCHOR_ENTRIES and merkle_root and merkle_start_index is not None and merkle_end_index is not None:
                        anchor_payload = {
                            "decision": "MERKLE_ANCHOR",
                            "chain_id": chain_id,
                            "merkle_alg": "sha256",
                            "merkle_root": merkle_root,
                            "anchored_start_index": merkle_start_index,
                            "anchored_end_index": merkle_end_index,
                            "anchored_leaf_count": merkle_leaf_count,
                            "anchored_last_entry_hash": entry_hash,
                            "checkpoint_interval": _LEDGER_CHECKPOINT_INTERVAL,
                        }
                        try:
                            await create_unsigned_ledger_entry(
                                r,
                                anchor_payload,
                                max_retries=max_retries,
                                allow_checkpoint=False,
                            )
                        except LedgerBackpressureError:
                            print("[apex-ledger] Dropping MERKLE_ANCHOR due to backlog")
                        except Exception:
                            pass

                await _enqueue_for_signing_fn(r, index)
                return index, entry
            except redis.WatchError:
                base = 0.01 * (attempt + 1)
                jitter = random.uniform(0.5, 1.5)
                await asyncio.sleep(base * jitter)
                continue

    raise RuntimeError("Failed to append ledger entry after retries (concurrent modifications too frequent)")
