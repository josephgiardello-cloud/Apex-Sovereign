"""Apex Sovereign – KMS dual-control enforcement, signing access log, and signing audit stream reader.

Extracted from BaseT8.py.  Call configure_signing_audit() before use.
"""

import hashlib
import time
from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as redis

# ── Module-level config (set by configure_signing_audit) ─────────────────────
_APEX_KMS_DUAL_CONTROL: bool = False
_APEX_FIPS_MODE: bool = False
_KMS_KEY_ID: str = ""
_get_apex_env_fn: Optional[Callable] = None
_APEX_ENV_PROD: Any = None
_APEX_SIGN_AUDIT_ENABLED: bool = False
_APEX_SIGN_AUDIT_STREAM_KEY: str = ""
_APEX_SIGN_AUDIT_TTL_SECONDS: int = 0
_APEX_REGION: str = ""
_APEX_CHAIN_ID: str = ""
_utc_now_z_fn: Optional[Callable] = None
_envcfg_desired_current_key_fn: Optional[Callable] = None
_decode_required_json_object_fn: Optional[Callable] = None
_clamp_limit_fn: Optional[Callable] = None

_KMS_DUAL_CONTROL_CACHE: Dict[str, Any] = {"expires_at": 0.0, "ok": True, "reason": None}


def configure_signing_audit(
    *,
    apex_kms_dual_control: bool,
    apex_fips_mode: bool,
    kms_key_id: str,
    get_apex_env_fn: Callable,
    apex_env_prod: Any,
    apex_sign_audit_enabled: bool,
    apex_sign_audit_stream_key: str,
    apex_sign_audit_ttl_seconds: int,
    apex_region: str,
    apex_chain_id: str,
    utc_now_z_fn: Callable,
    envcfg_desired_current_key_fn: Callable,
    decode_required_json_object_fn: Callable,
    clamp_limit_fn: Callable,
) -> None:
    global _APEX_KMS_DUAL_CONTROL, _APEX_FIPS_MODE, _KMS_KEY_ID
    global _get_apex_env_fn, _APEX_ENV_PROD
    global _APEX_SIGN_AUDIT_ENABLED, _APEX_SIGN_AUDIT_STREAM_KEY, _APEX_SIGN_AUDIT_TTL_SECONDS
    global _APEX_REGION, _APEX_CHAIN_ID, _utc_now_z_fn
    global _envcfg_desired_current_key_fn, _decode_required_json_object_fn, _clamp_limit_fn

    _APEX_KMS_DUAL_CONTROL = bool(apex_kms_dual_control)
    _APEX_FIPS_MODE = bool(apex_fips_mode)
    _KMS_KEY_ID = str(kms_key_id or "")
    _get_apex_env_fn = get_apex_env_fn
    _APEX_ENV_PROD = apex_env_prod
    _APEX_SIGN_AUDIT_ENABLED = bool(apex_sign_audit_enabled)
    _APEX_SIGN_AUDIT_STREAM_KEY = str(apex_sign_audit_stream_key or "")
    _APEX_SIGN_AUDIT_TTL_SECONDS = int(apex_sign_audit_ttl_seconds or 0)
    _APEX_REGION = str(apex_region or "")
    _APEX_CHAIN_ID = str(apex_chain_id or "")
    _utc_now_z_fn = utc_now_z_fn
    _envcfg_desired_current_key_fn = envcfg_desired_current_key_fn
    _decode_required_json_object_fn = decode_required_json_object_fn
    _clamp_limit_fn = clamp_limit_fn


async def enforce_kms_dual_control_or_raise(r: Optional[redis.Redis]) -> None:
    """Enforce dual-control for which KMS key id the signer may use.

    This is an application-level governance guardrail (defense-in-depth).

    Mechanism:
    - When enabled, require that the currently running `APEX_KMS_KEY_ID` matches
      the *approved* desired env-config stored in Redis.
    - The desired config stores values redacted; for sensitive keys we compare
      the sha256 of the runtime value against the stored sha256.

    Notes:
    - This does not provide per-signature human approval (AWS KMS does not offer
      per-request quorum approvals). It provides dual-control over key *selection*
      and therefore key usage by the service.
    """
    if not _APEX_KMS_DUAL_CONTROL:
        return
    if r is None:
        raise RuntimeError("dual_control_requires_redis")

    try:
        env = _get_apex_env_fn()
    except Exception:
        env = None

    # Only enforce in high-assurance modes.
    if not (_APEX_FIPS_MODE or env == _APEX_ENV_PROD):
        return

    now = time.time()
    cached = dict(_KMS_DUAL_CONTROL_CACHE)
    if float(cached.get("expires_at") or 0.0) > now:
        if not bool(cached.get("ok", True)):
            raise RuntimeError(str(cached.get("reason") or "dual_control_failed"))
        return

    if not _KMS_KEY_ID:
        raise RuntimeError("dual_control_missing_runtime_kms_key_id")

    desired_raw = await r.get(_envcfg_desired_current_key_fn(_get_apex_env_fn().value))
    if not desired_raw:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_desired_config"})
        raise RuntimeError("dual_control_missing_desired_config")

    try:
        desired = _decode_required_json_object_fn(desired_raw)
    except Exception:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_invalid_desired_config"})
        raise RuntimeError("dual_control_invalid_desired_config")

    if not isinstance(desired, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_invalid_desired_config"})
        raise RuntimeError("dual_control_invalid_desired_config")

    # Ensure the record is an approved desired config.
    if not (desired.get("approved_by") and desired.get("approved_at")):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_desired_config_not_approved"})
        raise RuntimeError("dual_control_desired_config_not_approved")

    changes = desired.get("changes")
    if not isinstance(changes, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_changes"})
        raise RuntimeError("dual_control_missing_changes")

    kms_change = changes.get("APEX_KMS_KEY_ID")
    if not isinstance(kms_change, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_approved_kms_key"})
        raise RuntimeError("dual_control_missing_approved_kms_key")
    if kms_change.get("unset") is True:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_kms_key_unset"})
        raise RuntimeError("dual_control_kms_key_unset")

    desired_sha = kms_change.get("sha256")
    if not (isinstance(desired_sha, str) and desired_sha):
        # If not redacted, fall back to direct compare.
        desired_val = kms_change.get("value")
        if isinstance(desired_val, str) and desired_val:
            desired_sha = hashlib.sha256(desired_val.encode("utf-8")).hexdigest()

    runtime_sha = hashlib.sha256(str(_KMS_KEY_ID).encode("utf-8")).hexdigest()
    if not (isinstance(desired_sha, str) and desired_sha == runtime_sha):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_kms_key_mismatch"})
        raise RuntimeError("dual_control_kms_key_mismatch")

    _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 30.0, "ok": True, "reason": None})


async def emit_signing_access_log(
    r: Optional[redis.Redis],
    *,
    tenant_id: Optional[str],
    status: str,
    ledger_index: int,
    entry_id: Optional[str],
    kid: Optional[str],
    alg: Optional[str],
    signing_status: Optional[str],
    error: Optional[str] = None,
) -> None:
    """Best-effort signing access log.

    This is intentionally NOT written to the audit ledger to avoid recursion.
    Use AWS CloudTrail as the authoritative KMS access log.
    """
    if not _APEX_SIGN_AUDIT_ENABLED:
        return
    if r is None:
        return

    try:
        fields: Dict[str, str] = {
            "ts": _utc_now_z_fn(),
            "env": _get_apex_env_fn().value,
            "region": str(_APEX_REGION or ""),
            "chain_id": str(_APEX_CHAIN_ID or ""),
            "tenant_id": str((tenant_id or "").strip() or ""),
            "status": str(status or "unknown"),
            "ledger_index": str(int(ledger_index)),
            "entry_id": str(entry_id or ""),
            "kid": str(kid or ""),
            "alg": str(alg or ""),
            "signing_status": str(signing_status or ""),
        }
        if error:
            fields["error"] = str(error)[:256]

        # Stream of signing events (bounded, best-effort). Operators can sink this to SIEM.
        await r.xadd(_APEX_SIGN_AUDIT_STREAM_KEY, fields, maxlen=10000, approximate=True)
        if int(_APEX_SIGN_AUDIT_TTL_SECONDS or 0) > 0:
            await r.expire(_APEX_SIGN_AUDIT_STREAM_KEY, int(_APEX_SIGN_AUDIT_TTL_SECONDS))

        # Minimal counters for dashboards.
        if str(status).lower() == "success":
            await r.incr("apex:signing:ops:success", 1)
        else:
            await r.incr("apex:signing:ops:failure", 1)
            if error:
                await r.set("apex:signing:ops:last_error", str(error)[:256])
                await r.set("apex:signing:ops:last_error_at", _utc_now_z_fn())
        await r.expire("apex:signing:ops:success", int(_APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:failure", int(_APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:last_error", int(_APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:last_error_at", int(_APEX_SIGN_AUDIT_TTL_SECONDS))
    except Exception:
        return


async def read_signing_audit_stream(
    r: redis.Redis,
    *,
    limit: int,
    tenant_id_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Read recent signing audit events from Redis stream.

    Notes:
    - Uses XREVRANGE to fetch most recent events.
    - Optional in-memory filtering by tenant_id.
    """
    lim = _clamp_limit_fn(limit, max_value=500)
    tenant_filter = (tenant_id_filter or "").strip() or None

    # Fetch a little more when filtering to increase odds of returning `lim` events.
    fetch = lim
    if tenant_filter:
        fetch = min(2000, lim * 10)

    events: List[Dict[str, Any]] = []
    try:
        raw = await r.xrevrange(_APEX_SIGN_AUDIT_STREAM_KEY, max="+", min="-", count=fetch)
    except Exception:
        raw = []

    for stream_id, fields in raw or []:
        try:
            f = dict(fields or {})
            f["stream_id"] = stream_id
            if tenant_filter:
                t = str(f.get("tenant_id") or "").strip() or None
                if t != tenant_filter:
                    continue
            events.append(f)
            if len(events) >= lim:
                break
        except Exception:
            continue
    return events
