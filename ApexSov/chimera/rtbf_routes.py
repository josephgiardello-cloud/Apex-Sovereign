from __future__ import annotations

import hashlib
import json
import unicodedata
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional

import boto3
from fastapi import Depends, HTTPException
from pydantic import BaseModel


class RtbfS3ObjectRef(BaseModel):
    bucket: str
    key: str


class RtbfRequest(BaseModel):
    """Right-to-be-forgotten request."""

    request_id: Optional[str] = None
    subject: Optional[str] = None
    session_id: Optional[str] = None
    reason: Optional[str] = None
    delete_session_state: bool = True
    delete_dlp_semantic: bool = False
    delete_adversarial_corpus: bool = False
    dedup_content_refs: Optional[List[str]] = None
    s3_objects: Optional[List[RtbfS3ObjectRef]] = None


class RtbfProofResponse(BaseModel):
    request_id: str
    tenant_id: str
    requested_at: str
    requested_by: Optional[str] = None
    subject_hash: Optional[str] = None
    session_id: Optional[str] = None
    reason: Optional[str] = None
    redis: Dict[str, Any] = {}
    drift: Dict[str, Any] = {}
    dlp_semantic: Dict[str, Any] = {}
    dedup: Dict[str, Any] = {}
    s3: Dict[str, Any] = {}


def register_rtbf_routes(
    app: Any,
    *,
    authz_engine: Any,
    get_identity: Callable[..., Any],
    get_redis_client: Callable[[], Awaitable[Any]],
    get_rtbf_proof_payload: Callable[..., Awaitable[Dict[str, Any]]],
    create_unsigned_ledger_entry: Callable[..., Awaitable[Any]],
    record_metrics_for_audit: Callable[..., Awaitable[None]],
    ledger_backpressure_error_cls: Any,
    utc_now_z: Callable[[], str],
    policy_version: str,
    region: str,
    chain_id: str,
    drift_engine_factory: Callable[..., Any],
    drift_backend: Any,
    vector_backend_cls: Any,
    redis_bow_backend_cls: Any,
    dlp_store_factory: Callable[..., Any],
    dlp_items_key: Callable[[str], str],
    dlp_meta_key: Callable[[str], str],
    rtbf_s3_allow: bool,
    rtbf_s3_bucket: str,
    ledger_s3_bucket: str,
    ledger_checkpoint_bucket: str,
    rtbf_proof_cache_ttl_seconds: int,
) -> None:
    @app.post("/admin/rtbf")
    async def right_to_be_forgotten(
        req: RtbfRequest,
        identity=Depends(get_identity),
    ):
        authz_engine.require_admin(identity)
        if not req.subject and not req.session_id:
            raise HTTPException(status_code=400, detail="subject or session_id required")

        def _rtbf_sha256_hex(s: str) -> str:
            try:
                data = unicodedata.normalize("NFC", (s or "")).encode("utf-8")
            except Exception:
                data = (s or "").encode("utf-8")
            return hashlib.sha256(data).hexdigest()

        def _normalize_session_id(tenant_id: str, session_id: str) -> str:
            raw = (session_id or "").strip()
            if not raw:
                raise HTTPException(status_code=400, detail="session_id empty")
            if ":" in raw:
                if not raw.startswith(f"{tenant_id}:"):
                    raise HTTPException(status_code=400, detail="session_id must be tenant-scoped")
                return raw
            return f"{tenant_id}:{raw}"

        def _rtbf_proof_cache_key(tenant_id: str, request_id: str) -> str:
            return f"apex:rtbf:proof:{tenant_id}:{request_id}"

        def _rtbf_proof_ledger_entry_key(tenant_id: str, request_id: str) -> str:
            return f"apex:rtbf:proof_ledger_entry:{tenant_id}:{request_id}"

        def _rtbf_request_index_key(tenant_id: str) -> str:
            return f"apex:rtbf:requests:{tenant_id}:index"

        def _rtbf_request_hash_key(tenant_id: str) -> str:
            return f"apex:rtbf:requests:{tenant_id}:by_id"

        def _dedup_key_from_ref(tenant_id: str, ref: str) -> Optional[str]:
            rref = (ref or "").strip()
            if not rref:
                return None
            if rref.startswith("apex:content:"):
                if not rref.startswith(f"apex:content:{tenant_id}:"):
                    return None
                return rref
            if rref.startswith(f"{tenant_id}:"):
                return f"apex:content:{rref}"
            return None

        def _key_hash(key: str) -> str:
            return _rtbf_sha256_hex(f"redis\0{key}")

        def _s3_key_hash(bucket: str, key: str) -> str:
            return _rtbf_sha256_hex(f"s3\0{bucket}\0{key}")

        r = await get_redis_client()

        request_id = (req.request_id or "").strip() or uuid.uuid4().hex
        requested_at = utc_now_z()
        subject_hash = _rtbf_sha256_hex(req.subject) if req.subject else None
        namespaced_session: Optional[str] = None
        if req.session_id:
            namespaced_session = _normalize_session_id(identity.tenant_id, req.session_id)

        marker_payload_ledger = {
            "ts": requested_at,
            "tenant_id": identity.tenant_id,
            "request_id": request_id,
            "subject_hash": subject_hash,
            "session_id": namespaced_session,
            "policy_version": policy_version,
            "decision": "RTBF_MARKER",
            "reason": req.reason,
            "requested_by": identity.subject,
            "region": region,
            "ledger_chain_id": chain_id,
        }

        marker_payload_response = dict(marker_payload_ledger)
        marker_payload_response["subject"] = req.subject
        marker_payload_response["session_id"] = req.session_id
        marker_payload_response["session_id_ns"] = namespaced_session

        try:
            await create_unsigned_ledger_entry(r, marker_payload_ledger)
            await record_metrics_for_audit(r, marker_payload_ledger)
        except ledger_backpressure_error_cls:
            print("[apex-rtbf] Dropping RTBF marker entry due to backlog")
        except Exception:
            pass

        try:
            request_record = {
                "request_id": request_id,
                "requested_at": requested_at,
                "tenant_id": identity.tenant_id,
                "subject_hash": subject_hash,
                "session_id": namespaced_session,
                "reason": req.reason,
                "requested_by": identity.subject,
            }
            async with r.pipeline(transaction=True) as pipe:
                pipe.hset(_rtbf_request_hash_key(identity.tenant_id), request_id, json.dumps(request_record))
                pipe.lpush(_rtbf_request_index_key(identity.tenant_id), request_id)
                pipe.ltrim(_rtbf_request_index_key(identity.tenant_id), 0, 499)
                await pipe.execute()
        except Exception:
            pass

        redis_attempts: List[Dict[str, Any]] = []
        drift_result: Dict[str, Any] = {}
        dlp_result: Dict[str, Any] = {}
        dedup_result: Dict[str, Any] = {}
        s3_result: Dict[str, Any] = {}

        deleted_key_hashes: List[str] = []
        s3_deleted_hashes: List[str] = []

        if namespaced_session and req.delete_session_state:
            prompts_key = f"session:{namespaced_session}:prompts"
            try:
                existed_before = int(await r.exists(prompts_key))
                deleted = int(await r.delete(prompts_key))
                exists_after = int(await r.exists(prompts_key))
                redis_attempts.append(
                    {
                        "key": prompts_key,
                        "action": "delete",
                        "existed_before": existed_before,
                        "deleted": deleted,
                        "exists_after": exists_after,
                        "ok": bool(existed_before == 0 or exists_after == 0),
                    }
                )
                if deleted > 0:
                    deleted_key_hashes.append(_key_hash(prompts_key))
            except Exception as exc:
                redis_attempts.append({"key": prompts_key, "action": "delete", "ok": False, "error": str(exc)})

            try:
                engine = drift_engine_factory(r_client=r, drift_backend=drift_backend)
                if isinstance(engine.drift_backend, (vector_backend_cls, redis_bow_backend_cls)):
                    await engine.drift_backend.reset_anchor(namespaced_session)
                    drift_result = {
                        "backend": type(engine.drift_backend).__name__,
                        "action": "reset_anchor",
                        "session_id": namespaced_session,
                        "ok": True,
                    }
                else:
                    drift_result = {"backend": "unknown", "action": "reset_anchor", "ok": False, "error": "unsupported_backend"}
            except Exception as exc:
                drift_result = {"backend": "error", "action": "reset_anchor", "ok": False, "error": str(exc)}

        if req.delete_adversarial_corpus:
            corpus_key = f"apex:adversarial_corpus:{identity.tenant_id}"
            try:
                existed_before = int(await r.exists(corpus_key))
                deleted = int(await r.delete(corpus_key))
                exists_after = int(await r.exists(corpus_key))
                redis_attempts.append(
                    {
                        "key": corpus_key,
                        "action": "delete",
                        "existed_before": existed_before,
                        "deleted": deleted,
                        "exists_after": exists_after,
                        "ok": bool(existed_before == 0 or exists_after == 0),
                    }
                )
                if deleted > 0:
                    deleted_key_hashes.append(_key_hash(corpus_key))
            except Exception as exc:
                redis_attempts.append({"key": corpus_key, "action": "delete", "ok": False, "error": str(exc)})

        if req.delete_dlp_semantic:
            items_key = dlp_items_key(identity.tenant_id)
            meta_key = dlp_meta_key(identity.tenant_id)
            deleted_exemplar_text_keys: List[str] = []
            try:
                store = dlp_store_factory(r)
                loaded = await store.load(identity.tenant_id)
                items = loaded.get("items") or []

                for it in items:
                    tref = (it or {}).get("text_ref") or {}
                    if isinstance(tref, dict):
                        tenant_ref = tref.get("tenant_ref")
                        if isinstance(tenant_ref, str) and tenant_ref.startswith(f"{identity.tenant_id}:"):
                            deleted_exemplar_text_keys.append(f"apex:content:{tenant_ref}")

                deleted_counts = 0
                if deleted_exemplar_text_keys:
                    try:
                        deleted_counts += int(await r.delete(*deleted_exemplar_text_keys))
                        for k in deleted_exemplar_text_keys[:200]:
                            deleted_key_hashes.append(_key_hash(k))
                    except Exception:
                        pass

                deleted_counts += int(await r.delete(items_key, meta_key))
                deleted_key_hashes.append(_key_hash(items_key))
                deleted_key_hashes.append(_key_hash(meta_key))

                dlp_result = {
                    "deleted": True,
                    "deleted_keys_count": int(deleted_counts),
                    "exemplar_text_keys_targeted": int(len(deleted_exemplar_text_keys)),
                    "ok": True,
                }
            except Exception as exc:
                dlp_result = {"deleted": False, "ok": False, "error": str(exc)}

        dedup_targets: List[str] = []
        invalid_dedup_refs: List[str] = []
        for ref in req.dedup_content_refs or []:
            k = _dedup_key_from_ref(identity.tenant_id, ref)
            if not k:
                invalid_dedup_refs.append(ref)
                continue
            dedup_targets.append(k)
        if dedup_targets:
            try:
                deleted = int(await r.delete(*dedup_targets))
                for k in dedup_targets[:200]:
                    deleted_key_hashes.append(_key_hash(k))
                dedup_result = {
                    "targets": int(len(dedup_targets)),
                    "deleted": int(deleted),
                    "invalid_refs": invalid_dedup_refs,
                    "ok": True,
                }
            except Exception as exc:
                dedup_result = {
                    "targets": int(len(dedup_targets)),
                    "invalid_refs": invalid_dedup_refs,
                    "ok": False,
                    "error": str(exc),
                }
        elif invalid_dedup_refs:
            dedup_result = {"targets": 0, "invalid_refs": invalid_dedup_refs, "ok": False, "error": "invalid_dedup_refs"}

        if req.s3_objects:
            if not rtbf_s3_allow:
                raise HTTPException(status_code=400, detail="S3 deletion is disabled (set APEX_RTBF_S3_ALLOW=true)")
            if not rtbf_s3_bucket:
                raise HTTPException(status_code=400, detail="APEX_RTBF_S3_BUCKET must be set for S3 deletion")

            forbidden_buckets = {b for b in [ledger_s3_bucket, ledger_checkpoint_bucket] if b}
            if rtbf_s3_bucket in forbidden_buckets:
                raise HTTPException(status_code=400, detail="APEX_RTBF_S3_BUCKET cannot point at ledger buckets")

            s3 = boto3.client("s3")
            attempts: List[Dict[str, Any]] = []
            for obj in req.s3_objects:
                bucket = (obj.bucket or "").strip()
                key = (obj.key or "").strip()
                if bucket != rtbf_s3_bucket:
                    attempts.append({"bucket": bucket, "key": key, "ok": False, "error": "bucket_not_allowed"})
                    continue
                if bucket in forbidden_buckets:
                    attempts.append({"bucket": bucket, "key": key, "ok": False, "error": "bucket_forbidden"})
                    continue
                try:
                    s3.delete_object(Bucket=bucket, Key=key)
                    verified_missing = False
                    try:
                        s3.head_object(Bucket=bucket, Key=key)
                        verified_missing = False
                    except Exception:
                        verified_missing = True
                    attempts.append({"bucket": bucket, "key": key, "action": "delete", "verified_missing": verified_missing, "ok": True})
                    s3_deleted_hashes.append(_s3_key_hash(bucket, key))
                except Exception as exc:
                    attempts.append({"bucket": bucket, "key": key, "action": "delete", "ok": False, "error": str(exc)})

            s3_result = {"attempts": attempts, "ok": True}

        if subject_hash:
            try:
                await r.sadd(f"apex:rtbf:subject:{identity.tenant_id}", subject_hash)
            except Exception:
                pass
        if namespaced_session:
            try:
                if req.session_id:
                    await r.sadd(f"apex:rtbf:session:{identity.tenant_id}", req.session_id)
                await r.sadd(f"apex:rtbf:session_ns:{identity.tenant_id}", namespaced_session)
            except Exception:
                pass

        proof = RtbfProofResponse(
            request_id=request_id,
            tenant_id=identity.tenant_id,
            requested_at=requested_at,
            requested_by=identity.subject,
            subject_hash=subject_hash,
            session_id=namespaced_session,
            reason=req.reason,
            redis={"attempts": redis_attempts, "ok": True},
            drift=drift_result,
            dlp_semantic=dlp_result,
            dedup=dedup_result,
            s3=s3_result,
        )

        try:
            await r.set(_rtbf_proof_cache_key(identity.tenant_id, request_id), proof.json())
            if int(rtbf_proof_cache_ttl_seconds or 0) > 0:
                await r.expire(_rtbf_proof_cache_key(identity.tenant_id, request_id), int(rtbf_proof_cache_ttl_seconds))
        except Exception:
            pass

        proof_payload = {
            "ts": utc_now_z(),
            "tenant_id": identity.tenant_id,
            "request_id": request_id,
            "decision": "RTBF_PROOF",
            "subject_hash": subject_hash,
            "session_id": namespaced_session,
            "requested_at": requested_at,
            "requested_by": identity.subject,
            "region": region,
            "ledger_chain_id": chain_id,
            "proof": {
                "redis_deleted_key_hashes": deleted_key_hashes[:200],
                "redis_deleted_key_hashes_count": int(len(deleted_key_hashes)),
                "s3_deleted_object_hashes": s3_deleted_hashes[:200],
                "s3_deleted_object_hashes_count": int(len(s3_deleted_hashes)),
                "drift": {"ok": bool(drift_result.get("ok")), "backend": drift_result.get("backend")},
                "dlp_semantic": {"ok": bool(dlp_result.get("ok")), "deleted": bool(dlp_result.get("deleted"))},
            },
        }
        try:
            proof_index, proof_enriched = await create_unsigned_ledger_entry(r, proof_payload)
            try:
                entry_id = (proof_enriched or {}).get("entry_id")
                if entry_id:
                    await r.set(
                        _rtbf_proof_ledger_entry_key(identity.tenant_id, request_id),
                        json.dumps({"entry_id": entry_id, "index": int(proof_index)}),
                    )
            except Exception:
                pass
        except ledger_backpressure_error_cls:
            print("[apex-rtbf] Dropping RTBF proof entry due to backlog")
        except Exception:
            pass

        return {"status": "completed", "request_id": request_id, "marker": marker_payload_response, "proof": proof.dict()}

    @app.get("/admin/rtbf/{request_id}/proof")
    async def admin_get_rtbf_proof(
        request_id: str,
        identity=Depends(get_identity),
        zero_cache: bool = False,
    ):
        authz_engine.require_admin(identity)
        r = await get_redis_client()
        return await get_rtbf_proof_payload(
            r,
            tenant_id=identity.tenant_id,
            request_id=request_id,
            zero_cache=bool(zero_cache),
        )

    @app.get("/api/v1/audit/rtbf/{request_id}/proof")
    async def audit_get_rtbf_proof(
        request_id: str,
        identity=Depends(get_identity),
        zero_cache: bool = False,
    ):
        authz_engine.require_audit_read(identity)
        r = await get_redis_client()
        return await get_rtbf_proof_payload(
            r,
            tenant_id=identity.tenant_id,
            request_id=request_id,
            zero_cache=bool(zero_cache),
        )
