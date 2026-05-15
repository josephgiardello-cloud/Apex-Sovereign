from __future__ import annotations

import asyncio
import os
import ssl
import sys
from typing import Any, Awaitable, Callable, Dict

from fastapi import Depends, HTTPException


def register_runtime_status_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    utc_now_z: Callable[[], str],
    ir_timelines_fn: Callable[[], Dict[str, Any]],
    runbooks: Dict[str, Any],
    incident_record_key: Callable[[str], str],
    decode_optional_json_with_raw_fallback: Callable[[Any], Dict[str, Any]],
    get_apex_env: Callable[[], Any],
    apex_env_prod: Any,
    tracing_available: Callable[[], bool],
    apex_fips_mode: bool,
    apex_region: str,
    apex_chain_id: str,
    signer_health: Dict[str, Any],
    self_test: Dict[str, Any],
    enforce_failsafe_or_raise: Callable[[Any], Awaitable[None]],
    enforce_kms_dual_control_or_raise: Callable[[Any], Awaitable[None]],
    load_signer_for_worker: Callable[[], Any],
    get_unsigned_backlog_status: Callable[[Any], Awaitable[Any]],
    max_unsigned_queue: int,
    unsigned_warn_fraction: float,
    ledger_backlog_state_label: Callable[..., str],
) -> None:
    @app.get("/api/v1/ir/timelines")
    async def ir_timelines(identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        return {
            "ts": utc_now_z(),
            "timelines": ir_timelines_fn(),
        }

    @app.get("/api/v1/ir/runbooks")
    async def ir_runbooks(identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        return {
            "ts": utc_now_z(),
            "runbooks": sorted(runbooks.keys()),
        }

    @app.get("/api/v1/ir/runbooks/{reason_code}")
    async def ir_runbook(reason_code: str, identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        code = (reason_code or "").strip()
        rb = runbooks.get(code)
        if not rb:
            raise HTTPException(status_code=404, detail="Runbook not found")
        return {
            "ts": utc_now_z(),
            "reason_code": code,
            "runbook": rb,
            "timelines": ir_timelines_fn(),
        }

    @app.get("/api/v1/ir/incidents/{incident_id}")
    async def ir_get_incident(incident_id: str, identity=Depends(get_identity)):
        authz_engine.require_audit_read(identity)
        inc_id = (incident_id or "").strip()
        if not inc_id:
            raise HTTPException(status_code=400, detail="incident_id is required")

        r = await get_redis_client()
        raw = await r.get(incident_record_key(inc_id))
        if not raw:
            raise HTTPException(status_code=404, detail="Incident not found")
        obj = decode_optional_json_with_raw_fallback(raw)

        if str(obj.get("tenant_id") or "").strip() != identity.tenant_id:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {
            "ts": utc_now_z(),
            "incident": obj,
        }

    @app.get("/healthz")
    async def healthz():
        return {
            "status": "ok",
            "env": get_apex_env().value,
            "pid": os.getpid(),
            "fips_mode": apex_fips_mode,
            "region": apex_region,
            "chain_id": apex_chain_id,
        }

    @app.get("/fips_status")
    async def fips_status():
        return {
            "apex_fips_mode": bool(apex_fips_mode),
            "python_version": sys.version,
            "openssl_version": getattr(ssl, "OPENSSL_VERSION", None),
            "ssl_has_sni": getattr(ssl, "HAS_SNI", None),
            "signer_health": signer_health,
            "self_test": self_test,
        }

    @app.get("/readyz")
    async def readyz():
        env = get_apex_env()

        if env == apex_env_prod and not tracing_available():
            raise HTTPException(status_code=503, detail="Tracing not configured")

        try:
            r = await get_redis_client()
            pong = await r.ping()
            if pong is not True:
                raise RuntimeError("Redis did not respond with PONG")

            await enforce_failsafe_or_raise(r)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Redis not ready: {str(exc)}")

        if env == apex_env_prod and os.getenv("APEX_KMS_HEALTH_CHECK", "true").lower() == "true":
            try:
                try:
                    await enforce_kms_dual_control_or_raise(r)
                except Exception as exc:
                    signer_health["ok"] = False
                    signer_health["last_error"] = f"dual_control_failed:{exc}"
                    signer_health["last_error_at"] = utc_now_z()
                    raise HTTPException(status_code=503, detail=f"KMS dual-control failed: {str(exc)}")

                signer = load_signer_for_worker()

                def _sign():
                    return signer.sign(b"apex-kms-health-check")

                await asyncio.to_thread(_sign)

                signer_health["ok"] = True
                signer_health["last_ok_at"] = utc_now_z()
                signer_health["last_error"] = None
            except Exception as exc:
                signer_health["ok"] = False
                signer_health["last_error"] = f"kms_health_check_failed:{exc}"
                signer_health["last_error_at"] = utc_now_z()
                raise HTTPException(status_code=503, detail=f"KMS not ready: {str(exc)}")

        try:
            r = await get_redis_client()
            queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
            if is_critical:
                raise HTTPException(
                    status_code=503,
                    detail=f"Ledger backlog too large ({queue_len} >= {max_unsigned_queue})",
                )
            if is_warning:
                print(f"[apex-readyz] WARNING: unsigned backlog high ({queue_len}/{max_unsigned_queue})")
        except HTTPException:
            raise
        except Exception:
            pass

        return {
            "status": "ready",
            "env": env.value,
        }

    @app.get("/governance_status")
    async def governance_status():
        r = await get_redis_client()
        queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)

        status = ledger_backlog_state_label(
            is_warning=is_warning,
            is_critical=is_critical,
        )
        http_status = 503 if is_critical else 200

        body = {
            "status": status,
            "unsigned_backlog_len": queue_len,
            "max_unsigned_queue": max_unsigned_queue,
            "warning_threshold": int(unsigned_warn_fraction * max_unsigned_queue),
            "env": get_apex_env().value,
            "fips_mode": apex_fips_mode,
            "region": apex_region,
            "chain_id": apex_chain_id,
        }

        if http_status != 200:
            raise HTTPException(status_code=http_status, detail=body)
        return body
