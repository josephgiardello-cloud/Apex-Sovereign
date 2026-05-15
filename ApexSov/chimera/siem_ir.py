from __future__ import annotations

import asyncio
import copy
import json
import os
import uuid
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional

import httpx
import redis.asyncio as redis
from fastapi import HTTPException

try:
    from . import redis_json_views as chimera_redis_json_views
except Exception:
    import chimera.redis_json_views as chimera_redis_json_views  # type: ignore[no-redef]


_alert_webhook_url: str = ""
_apex_siem_webhook_url: str = ""
_apex_siem_send_all: bool = False
_alert_min_tony_score: float = 0.0
_apex_siem_timeout_seconds: float = 5.0
_apex_siem_webhook_headers_json: str = ""
_apex_alert_correlation_window_seconds: int = 900
_apex_region: str = ""
_apex_chain_id: str = ""
_get_apex_env_fn: Optional[Callable[[], Any]] = None
_utc_now_z_fn: Optional[Callable[[], str]] = None
_sha256_hex_fn: Optional[Callable[[bytes], str]] = None
_enforce_sovereign_egress_or_raise_fn: Optional[Callable[..., Awaitable[None]]] = None


def configure_siem_ir(
    *,
    alert_webhook_url: str,
    apex_siem_webhook_url: str,
    apex_siem_send_all: bool,
    alert_min_tony_score: float,
    apex_siem_timeout_seconds: float,
    apex_siem_webhook_headers_json: str,
    apex_alert_correlation_window_seconds: int,
    apex_region: str,
    apex_chain_id: str,
    get_apex_env_fn: Callable[[], Any],
    utc_now_z_fn: Callable[[], str],
    sha256_hex_fn: Callable[[bytes], str],
    enforce_sovereign_egress_or_raise_fn: Callable[..., Awaitable[None]],
) -> None:
    global _alert_webhook_url
    global _apex_siem_webhook_url
    global _apex_siem_send_all
    global _alert_min_tony_score
    global _apex_siem_timeout_seconds
    global _apex_siem_webhook_headers_json
    global _apex_alert_correlation_window_seconds
    global _apex_region
    global _apex_chain_id
    global _get_apex_env_fn
    global _utc_now_z_fn
    global _sha256_hex_fn
    global _enforce_sovereign_egress_or_raise_fn

    _alert_webhook_url = alert_webhook_url
    _apex_siem_webhook_url = apex_siem_webhook_url
    _apex_siem_send_all = bool(apex_siem_send_all)
    _alert_min_tony_score = float(alert_min_tony_score)
    _apex_siem_timeout_seconds = float(apex_siem_timeout_seconds or 5.0)
    _apex_siem_webhook_headers_json = apex_siem_webhook_headers_json
    _apex_alert_correlation_window_seconds = int(apex_alert_correlation_window_seconds or 900)
    _apex_region = apex_region
    _apex_chain_id = apex_chain_id
    _get_apex_env_fn = get_apex_env_fn
    _utc_now_z_fn = utc_now_z_fn
    _sha256_hex_fn = sha256_hex_fn
    _enforce_sovereign_egress_or_raise_fn = enforce_sovereign_egress_or_raise_fn


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def classify_severity(payload: Dict[str, Any]) -> Severity:
    decision = str(payload.get("decision") or "").upper()
    violation = str(payload.get("violation") or "").lower()

    try:
        tony = float((payload.get("risk_axes") or {}).get("tony") or payload.get("score") or 0.0)
    except Exception:
        tony = 0.0

    if decision in {"BLOCK"}:
        if violation in {"axis_pii_threshold", "axis_dlp_threshold"}:
            return Severity.HIGH
        if violation in {"axis_jailbreak_threshold"}:
            return Severity.MEDIUM
        if tony >= 0.95:
            return Severity.HIGH
        return Severity.MEDIUM

    if decision in {"DENY"}:
        return Severity.MEDIUM

    if decision in {"INCIDENT_OPENED", "INCIDENT_ESCALATED"}:
        return Severity.HIGH

    if tony >= max(_alert_min_tony_score, 0.90):
        return Severity.MEDIUM
    return Severity.INFO


IR_TIMELINES_DEFAULT: Dict[str, Dict[str, Any]] = {
    Severity.INFO.value: {"ack_minutes": 240, "contain_minutes": 1440, "update_minutes": 1440},
    Severity.LOW.value: {"ack_minutes": 120, "contain_minutes": 720, "update_minutes": 720},
    Severity.MEDIUM.value: {"ack_minutes": 60, "contain_minutes": 240, "update_minutes": 240},
    Severity.HIGH.value: {"ack_minutes": 15, "contain_minutes": 60, "update_minutes": 60},
    Severity.CRITICAL.value: {"ack_minutes": 5, "contain_minutes": 30, "update_minutes": 30},
}


def ir_timelines() -> Dict[str, Any]:
    raw = os.getenv("APEX_IR_TIMELINES_JSON", "")
    if raw:
        try:
            obj = chimera_redis_json_views.decode_required_json_object(raw)
            if isinstance(obj, dict):
                merged = copy.deepcopy(IR_TIMELINES_DEFAULT)
                for k, v in obj.items():
                    if isinstance(k, str) and isinstance(v, dict):
                        merged[k] = v
                return merged
        except Exception:
            pass
    return IR_TIMELINES_DEFAULT


def incident_active_key(*, tenant_id: str, correlation_key: str) -> str:
    if _sha256_hex_fn is None:
        raise RuntimeError("siem_ir not configured")
    digest = _sha256_hex_fn(f"{tenant_id}\0{correlation_key}".encode("utf-8"))
    return f"apex:incidents:active:{tenant_id}:{digest}"


def incident_record_key(incident_id: str) -> str:
    return f"apex:incidents:record:{incident_id}"


async def _correlate_alert(
    r: redis.Redis,
    *,
    payload: Dict[str, Any],
    severity: Severity,
) -> Dict[str, Any]:
    tenant_id = str(payload.get("tenant_id") or "").strip() or "unknown"
    session_id = str(payload.get("session_id") or "").strip()
    decision = str(payload.get("decision") or "").strip()
    violation = str(payload.get("violation") or payload.get("action") or "").strip() or "unknown"

    correlation_key = f"{decision}:{violation}:{session_id}" if session_id else f"{decision}:{violation}"
    active_key = incident_active_key(tenant_id=tenant_id, correlation_key=correlation_key)

    incident_id = None
    opened = False
    if _utc_now_z_fn is None:
        raise RuntimeError("siem_ir not configured")
    now_iso = _utc_now_z_fn()
    ttl = max(60, int(_apex_alert_correlation_window_seconds or 900))

    try:
        existing = await r.get(active_key)
        if existing:
            incident_id = str(existing)
    except Exception:
        incident_id = None

    if not incident_id:
        incident_id = f"inc_{uuid.uuid4().hex}"
        try:
            ok = await r.set(active_key, incident_id, ex=ttl, nx=True)
            if ok:
                opened = True
            else:
                try:
                    winner = await r.get(active_key)
                    if winner:
                        incident_id = str(winner)
                        opened = False
                except Exception:
                    pass
        except Exception:
            pass

    record = {
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "decision": decision,
        "violation": violation,
        "correlation_key": correlation_key,
        "severity": severity.value,
        "opened": bool(opened),
        "first_seen_at": now_iso,
        "last_seen_at": now_iso,
        "count": 1,
    }

    try:
        rk = incident_record_key(incident_id)
        existing_raw = await r.get(rk)
        if existing_raw:
            existing_obj = chimera_redis_json_views.decode_optional_json_object_or_default(existing_raw)
            record["first_seen_at"] = existing_obj.get("first_seen_at") or record["first_seen_at"]
            record["count"] = int(existing_obj.get("count") or 0) + 1
            opened = False
            record["opened"] = False
        await r.set(rk, json.dumps(record, separators=(",", ":"), sort_keys=True), ex=30 * 24 * 3600)
    except Exception:
        pass

    return record


def _siem_headers() -> Dict[str, str]:
    if not _apex_siem_webhook_headers_json:
        return {}
    try:
        obj = chimera_redis_json_views.decode_required_json_object(_apex_siem_webhook_headers_json)
        if isinstance(obj, dict):
            out: Dict[str, str] = {}
            for k, v in obj.items():
                if isinstance(k, str) and isinstance(v, str):
                    out[k] = v
            return out
    except Exception:
        pass
    return {}


async def _send_to_siem(event: Dict[str, Any], *, r: Optional[redis.Redis] = None) -> None:
    if not _apex_siem_webhook_url:
        return
    try:
        try:
            if _enforce_sovereign_egress_or_raise_fn is None:
                raise RuntimeError("siem_ir not configured")
            await _enforce_sovereign_egress_or_raise_fn(
                r,
                tenant_id=str((event.get("payload") or {}).get("tenant_id") or "").strip() or None,
                session_id=str((event.get("payload") or {}).get("session_id") or "").strip() or None,
                subject=str((event.get("payload") or {}).get("subject") or "").strip() or None,
                roles=(event.get("payload") or {}).get("roles") if isinstance((event.get("payload") or {}).get("roles"), list) else None,
                purpose="SIEM_WEBHOOK",
                url=_apex_siem_webhook_url,
            )
        except HTTPException:
            return
        headers = {"Content-Type": "application/json", **_siem_headers()}
        async with httpx.AsyncClient(timeout=float(_apex_siem_timeout_seconds or 5.0)) as client:
            await client.post(_apex_siem_webhook_url, headers=headers, json=event)
    except Exception:
        return


RUNBOOKS: Dict[str, Dict[str, Any]] = {
    "axis_pii_threshold": {
        "title": "PII detected and blocked",
        "default_severity": Severity.HIGH.value,
        "steps": [
            "Confirm tenant/session scope and whether the content was user-supplied.",
            "Verify PII mode (block/redact) and thresholds in the tenant policy.",
            "If policy permits, advise user to remove PII and retry.",
            "If repeated, consider tightening allowlists and enabling additional DLP controls.",
        ],
    },
    "axis_jailbreak_threshold": {
        "title": "Prompt injection / jailbreak attempt",
        "default_severity": Severity.MEDIUM.value,
        "steps": [
            "Review threat intel feed version/hits for this tenant.",
            "Check whether the request attempted to override system/developer messages.",
            "Consider adding/activating threat intel indicators for the pattern.",
        ],
    },
    "axis_dlp_threshold": {
        "title": "High-risk/DLP intent blocked",
        "default_severity": Severity.HIGH.value,
        "steps": [
            "Confirm whether the request involved funds movement, credentials, or trade surveillance triggers.",
            "Ensure finance policy template thresholds/weights match governance expectations.",
            "Escalate to compliance if this appears to be a real user attempt.",
        ],
    },
    "tony_threshold": {
        "title": "Unified risk threshold exceeded",
        "default_severity": Severity.MEDIUM.value,
        "steps": [
            "Inspect which axes contributed most to TONY and whether thresholds are too strict.",
            "Check recent policy changes and two-person approvals.",
        ],
    },
    "model_not_allowlisted": {
        "title": "Model allowlist denied",
        "default_severity": Severity.LOW.value,
        "steps": [
            "Confirm requested model and current tenant allowlist.",
            "If business-approved, update allowlist via policy change controls.",
        ],
    },
    "unsupported_non_text_content": {
        "title": "Non-text content rejected",
        "default_severity": Severity.INFO.value,
        "steps": [
            "Confirm allow_multimodal setting for tenant policy.",
            "If multimodal is required, route to a multimodal-inspecting gateway.",
        ],
    },
}


async def enrich_and_send_siem_event(*, r: Optional[redis.Redis], payload: Dict[str, Any]) -> None:
    if not _apex_siem_webhook_url:
        return

    if _utc_now_z_fn is None or _get_apex_env_fn is None:
        raise RuntimeError("siem_ir not configured")

    sev = classify_severity(payload)
    incident: Optional[Dict[str, Any]] = None
    if r is not None:
        try:
            incident = await _correlate_alert(r, payload=payload, severity=sev)
        except Exception:
            incident = None

    timelines = ir_timelines()
    event = {
        "type": "APEX_GOVERNANCE_ALERT",
        "ts": _utc_now_z_fn(),
        "env": _get_apex_env_fn().value,
        "region": _apex_region,
        "chain_id": _apex_chain_id,
        "severity": sev.value,
        "timelines": timelines.get(sev.value) or timelines.get(Severity.INFO.value),
        "incident": incident,
        "runbook": RUNBOOKS.get(str(payload.get("violation") or payload.get("action") or "")) or None,
        "payload": payload,
    }
    await _send_to_siem(event, r=r)


async def send_alert_if_needed(payload: Dict[str, Any], *, r: Optional[redis.Redis] = None) -> None:
    if not _alert_webhook_url and not _apex_siem_webhook_url:
        return

    tony_score = float(payload.get("risk_axes", {}).get("tony", 0.0))
    decision = payload.get("decision")
    should_send = bool(
        _apex_siem_send_all
        or decision in {"BLOCK", "DENY"}
        or (decision == "ADMIN_ACTION")
        or (tony_score >= _alert_min_tony_score)
    )
    if not should_send:
        return

    async def _post() -> None:
        try:
            async with httpx.AsyncClient(timeout=float(_apex_siem_timeout_seconds or 5.0)) as client:
                if _alert_webhook_url:
                    try:
                        try:
                            if _enforce_sovereign_egress_or_raise_fn is None:
                                raise RuntimeError("siem_ir not configured")
                            await _enforce_sovereign_egress_or_raise_fn(
                                r,
                                tenant_id=str(payload.get("tenant_id") or "").strip() or None,
                                session_id=str(payload.get("session_id") or "").strip() or None,
                                subject=str(payload.get("subject") or "").strip() or None,
                                roles=payload.get("roles") if isinstance(payload.get("roles"), list) else None,
                                purpose="ALERT_WEBHOOK",
                                url=_alert_webhook_url,
                            )
                        except HTTPException:
                            return
                        await client.post(_alert_webhook_url, json=payload)
                    except Exception:
                        pass
        except Exception:
            pass

    asyncio.create_task(_post())

    if _apex_siem_webhook_url:
        asyncio.create_task(enrich_and_send_siem_event(r=r, payload=payload))
