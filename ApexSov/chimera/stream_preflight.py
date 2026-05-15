"""Apex Sovereign - streaming route preflight helper."""

from typing import Any, Dict

from fastapi import HTTPException


async def run_stream_preflight(
    *,
    request_obj: Any,
    http_request: Any,
    identity: Any,
    tenant_id: str,
    session_id: str,
    r: Any,
    engine: Any,
    request_audit_context_fn: Any,
    seed_policy_for_group_fn: Any,
    validate_text_only_messages_fn: Any,
    external_model_map: Dict[str, str],
    policy_version: str,
    apex_region: str,
    apex_chain_id: str,
    utc_now_z_fn: Any,
    create_unsigned_ledger_entry_fn: Any,
    record_metrics_for_audit_fn: Any,
    ledger_backpressure_error_cls: Any,
    model_allowlist: Any,
    authz_engine: Any,
    authorization_decision_allow: Any,
    no_content_retention_enabled_fn: Any,
    policy_retention_seconds_fn: Any,
    vector_db_drift_backend_cls: Any,
    get_tool_scoping_fn: Any,
    filter_tools_for_policy_fn: Any,
    default_policy_tool_scoping: Dict[str, Any],
) -> Dict[str, Any]:
    audit_ctx: Dict[str, Any] = {}
    if http_request is not None:
        audit_ctx = request_audit_context_fn(http_request)

    model_params = {
        "max_tokens": request_obj.max_tokens,
        "temperature": request_obj.temperature,
        "top_p": request_obj.top_p,
    }
    model_params = {k: v for k, v in model_params.items() if v is not None}

    policy_record = await engine.policy_store.get_policy_or_seed(
        tenant_id,
        seed_policy=seed_policy_for_group_fn("default"),
    )
    policy = policy_record.policy

    allow_multimodal = bool(policy.get("allow_multimodal", False))
    is_text_only, reason = validate_text_only_messages_fn(request_obj.messages)
    if not is_text_only and not allow_multimodal:
        audit_payload = {
            "ts": utc_now_z_fn(),
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_version": policy_version,
            "decision": "DENY",
            "violation": "unsupported_non_text_content",
            "reason": reason,
            "model": external_model_map.get(request_obj.model, request_obj.model),
            "requested_model": request_obj.model,
            "model_params": model_params,
            "subject": identity.subject,
            "roles": identity.roles,
            **audit_ctx,
            "region": apex_region,
            "ledger_chain_id": apex_chain_id,
        }
        try:
            await create_unsigned_ledger_entry_fn(r, audit_payload)
            await record_metrics_for_audit_fn(r, audit_payload)
        except ledger_backpressure_error_cls:
            pass
        except Exception:
            pass
        raise HTTPException(status_code=415, detail="Unsupported content type: non-text messages are not supported")

    requested_internal_model = external_model_map.get(request_obj.model, request_obj.model)

    allowlist = model_allowlist.read_policy_allowlist(policy)
    if isinstance(allowlist, list) and len(allowlist) > 0 and requested_internal_model not in allowlist:
        audit_payload = {
            "ts": utc_now_z_fn(),
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_version": policy_version,
            "decision": "DENY",
            "violation": "model_not_allowlisted",
            "score": 1.0,
            "model": requested_internal_model,
            "requested_model": request_obj.model,
            "model_params": model_params,
            "subject": identity.subject,
            "roles": identity.roles,
            **audit_ctx,
            "region": apex_region,
            "ledger_chain_id": apex_chain_id,
        }
        try:
            await create_unsigned_ledger_entry_fn(r, audit_payload)
            await record_metrics_for_audit_fn(r, audit_payload)
        except ledger_backpressure_error_cls:
            print("[apex-stream] Dropping DENY ledger entry due to backlog")
        except Exception:
            pass
        raise HTTPException(status_code=403, detail="Access denied: model not allowlisted for tenant")

    authz_result = await authz_engine.check(identity, requested_model=requested_internal_model)
    if authz_result.decision != authorization_decision_allow:
        raise HTTPException(status_code=403, detail=f"Access denied: {authz_result.reason}")

    internal_model = authz_result.effective_model or requested_internal_model

    tool_scoping = get_tool_scoping_fn(policy, default_policy_tool_scoping)
    filtered_tools, tool_filter_result = filter_tools_for_policy_fn(
        request_obj.tools,
        tool_scoping=tool_scoping,
    )
    request_obj.tools = filtered_tools

    if int(tool_filter_result.get("provided") or 0) > 0 and int(tool_filter_result.get("kept") or 0) == 0:
        audit_payload = {
            "ts": utc_now_z_fn(),
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_version": policy_version,
            "decision": "DENY",
            "violation": "tool_scope_denied",
            "score": 1.0,
            "model": internal_model,
            "requested_model": request_obj.model,
            "model_params": model_params,
            "subject": identity.subject,
            "roles": identity.roles,
            "tool_filter": tool_filter_result,
            **audit_ctx,
            "region": apex_region,
            "ledger_chain_id": apex_chain_id,
        }
        try:
            await create_unsigned_ledger_entry_fn(r, audit_payload)
            await record_metrics_for_audit_fn(r, audit_payload)
        except ledger_backpressure_error_cls:
            pass
        except Exception:
            pass
        raise HTTPException(status_code=403, detail="Access denied: all requested tools are blocked by policy")

    latest_user = next(
        (m.get("content", "") for m in reversed(request_obj.messages) if m.get("role") == "user"),
        "",
    )
    if latest_user and not no_content_retention_enabled_fn(policy):
        prompts_key = f"session:{session_id}:prompts"
        await r.rpush(prompts_key, latest_user)
        prompts_ttl = policy_retention_seconds_fn(policy, "session_prompts_ttl_seconds")
        if prompts_ttl > 0:
            try:
                await r.expire(prompts_key, prompts_ttl)
            except Exception:
                pass
        if isinstance(engine.drift_backend, vector_db_drift_backend_cls):
            await engine.drift_backend.add_prompt_embedding(session_id, latest_user)

    return {
        "audit_ctx": audit_ctx,
        "model_params": model_params,
        "policy": policy,
        "internal_model": internal_model,
        "tool_filter": tool_filter_result,
    }
