"""Apex Sovereign - streaming runtime helper for /v1/stream."""

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Optional

import httpx
from fastapi import HTTPException


async def stream_llm_with_risk(
    *,
    request_obj: Any,
    tenant_id: str,
    session_id: str,
    identity: Any,
    r: Any,
    engine: Any,
    policy: Dict[str, Any],
    model_params: Dict[str, Any],
    internal_model: str,
    audit_ctx: Dict[str, Any],
    request_sem: Any,
    llm_circuit: Any,
    tracer: Any,
    openai_url: str,
    upstream_provider_pool: Any,
    internal_to_external_model: Dict[str, str],
    model_prices_usd_per_1k: Dict[str, Dict[str, float]],
    default_policy_baseline: Dict[str, Any],
    stream_window: int,
    apex_region: str,
    apex_chain_id: str,
    policy_version: str,
    enforce_sovereign_egress_or_raise_fn: Any,
    secret_provider: Any,
    build_upstream_llm_headers_or_raise_fn: Any,
    decode_required_json_object_fn: Any,
    evaluate_risk_fn: Any,
    explain_block_fn: Any,
    create_unsigned_ledger_entry_fn: Any,
    record_metrics_for_audit_fn: Any,
    send_alert_if_needed_fn: Any,
    utc_now_z_fn: Any,
    ledger_backpressure_error_cls: Any,
    redact_pii_fn: Any,
    select_provider_order_fn: Any,
    build_provider_headers_fn: Any,
    get_usage_quotas_fn: Any,
    estimate_messages_tokens_fn: Any,
    estimate_text_tokens_fn: Any,
    reserve_usage_or_raise_fn: Any,
    add_completion_usage_fn: Any,
    estimate_cost_usd_fn: Any,
    classify_failure_fn: Any,
) -> AsyncGenerator[bytes, None]:
    committed_prefix_raw = ""
    committed_prefix_streamed = ""
    overlap_tail = ""

    usage_finalized = False
    usage_reservation: Dict[str, Any] = {}

    async def finalize_usage(audit_payload: Dict[str, Any], generated_text: str) -> None:
        nonlocal usage_finalized
        if usage_finalized:
            return

        completion_tokens = int(estimate_text_tokens_fn(generated_text or "") or 0)
        completion_usage = await add_completion_usage_fn(
            r,
            keys=usage_reservation.get("keys") or {},
            completion_tokens=completion_tokens,
        )
        prompt_tokens = int(usage_reservation.get("prompt_tokens") or 0)
        total_tokens = prompt_tokens + completion_tokens
        cost_usd = float(
            estimate_cost_usd_fn(
                internal_model=internal_model,
                internal_to_external_model=internal_to_external_model,
                model_prices_usd_per_1k=model_prices_usd_per_1k,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
            or 0.0
        )

        audit_payload["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "requests_per_minute": int(usage_reservation.get("requests_per_minute") or 0),
            "tokens_per_minute": int(completion_usage.get("tokens_per_minute") or usage_reservation.get("tokens_per_minute") or 0),
            "tokens_per_day": int(completion_usage.get("tokens_per_day") or usage_reservation.get("tokens_per_day") or 0),
            "tokens_per_month": int(completion_usage.get("tokens_per_month") or usage_reservation.get("tokens_per_month") or 0),
            "estimated_cost_usd": round(cost_usd, 10),
        }
        usage_finalized = True

    async with request_sem:
        llm_circuit.before_call()
        try:
            quotas = get_usage_quotas_fn(policy, default_policy_baseline)
            prompt_tokens_estimate = int(estimate_messages_tokens_fn(request_obj.messages) or 0)
            usage_reservation = await reserve_usage_or_raise_fn(
                r,
                tenant_id=tenant_id,
                quotas=quotas,
                prompt_tokens_estimate=prompt_tokens_estimate,
                now=datetime.now(timezone.utc),
            )

            payload = {
                "model": internal_to_external_model.get(internal_model, internal_model),
                "messages": request_obj.messages,
                "max_tokens": request_obj.max_tokens,
                "temperature": request_obj.temperature,
                "top_p": request_obj.top_p,
                "stream": True,
                "tools": request_obj.tools,
                "tool_choice": request_obj.tool_choice,
            }
            payload = {k: v for k, v in payload.items() if v is not None}

            provider_pool = list(upstream_provider_pool or [])
            provider_order = select_provider_order_fn(
                provider_pool,
                tenant_id=tenant_id,
                session_id=session_id,
                model_name=internal_model,
            )
            if not provider_order:
                provider_order = [{"name": "default-openai", "url": openai_url, "auth": {"type": "bearer", "env": "OPENAI_API_KEY"}}]

            last_error: Optional[Exception] = None

            for provider in provider_order:
                provider_name = str(provider.get("name") or "upstream")
                provider_url = str(provider.get("url") or openai_url)
                provider_auth = provider.get("auth") if isinstance(provider.get("auth"), dict) else {}
                provider_auth_type = str(provider_auth.get("type") or "bearer").strip().lower()
                provider_model_map = provider.get("model_map") if isinstance(provider.get("model_map"), dict) else {}
                upstream_model = str(
                    provider_model_map.get(internal_model)
                    or provider_model_map.get(internal_to_external_model.get(internal_model, internal_model))
                    or internal_to_external_model.get(internal_model, internal_model)
                )

                try:
                    await enforce_sovereign_egress_or_raise_fn(
                        r,
                        tenant_id=tenant_id,
                        session_id=session_id,
                        subject=identity.subject,
                        roles=identity.roles,
                        purpose="UPSTREAM_LLM",
                        url=provider_url,
                    )

                    headers = build_provider_headers_fn(provider)
                    if provider_auth_type == "bearer" and "Authorization" not in headers and provider_url == openai_url:
                        openai_key = await secret_provider.get_openai_key()
                        headers = build_upstream_llm_headers_or_raise_fn(api_key=openai_key, endpoint_url=provider_url)

                    with tracer.start_as_current_span("apex.stream.llm_call") as llm_span:
                        llm_span.set_attribute("tenant.id", tenant_id)
                        llm_span.set_attribute("session.id", session_id)
                        llm_span.set_attribute("model.internal", internal_model)
                        llm_span.set_attribute("model.upstream", upstream_model)
                        llm_span.set_attribute("upstream.url", provider_url)
                        llm_span.set_attribute("upstream.provider", provider_name)

                        payload["model"] = upstream_model

                        async with httpx.AsyncClient(timeout=None) as client:
                            async with client.stream("POST", provider_url, headers=headers, json=payload) as resp:
                                llm_span.set_attribute("upstream.status_code", resp.status_code)
                                if resp.status_code in (429, 500, 502, 503, 504):
                                    llm_circuit.after_call_failure()
                                    last_error = HTTPException(status_code=resp.status_code, detail=await resp.aread())
                                    continue
                                if resp.status_code != 200:
                                    llm_circuit.after_call_failure()
                                    raise HTTPException(status_code=resp.status_code, detail=await resp.aread())

                                llm_circuit.after_call_success()

                                pii_patterns = policy.get("pii_patterns", [])
                                pii_mode = policy.get("pii_mode", "block")

                                async for line in resp.aiter_lines():
                                    if not line:
                                        continue
                                    if not line.startswith("data: "):
                                        continue
                                    try:
                                        chunk = decode_required_json_object_fn(line[len("data: ") :])
                                    except Exception:
                                        continue

                                    delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                                    if not delta:
                                        continue

                                    candidate_text = committed_prefix_raw + overlap_tail + delta

                                    with tracer.start_as_current_span("apex.stream.risk_eval") as risk_span:
                                        risk_span.set_attribute("text.len", len(candidate_text))
                                        risk_vec = await engine.compute_risk_for_prompt(
                                            tenant_id=tenant_id,
                                            session_id=session_id,
                                            prompt=candidate_text,
                                            policy=policy,
                                        )
                                        decision, violation, score = evaluate_risk_fn(risk_vec, policy)
                                        risk_span.set_attribute("risk.score", score)
                                        risk_span.set_attribute("risk.decision", decision)

                                    pii_thresh = policy.get("axis_thresholds", {}).get("pii", 0.2)
                                    if pii_mode == "block" and risk_vec.get("pii", 0.0) >= pii_thresh:
                                        reason_code = "axis_pii_threshold"
                                        explanation = explain_block_fn(reason_code, risk_vec)
                                        audit_payload = {
                                            "ts": utc_now_z_fn(),
                                            "tenant_id": tenant_id,
                                            "session_id": session_id,
                                            "policy_version": policy_version,
                                            "decision": "BLOCK",
                                            "violation": reason_code,
                                            "score": risk_vec.get("pii", 0.0),
                                            "model": internal_model,
                                            "model_params": model_params,
                                            "subject": identity.subject,
                                            "roles": identity.roles,
                                            **audit_ctx,
                                            "risk_axes": {
                                                "pii": risk_vec.get("pii", 0.0),
                                                "jailbreak": risk_vec.get("jailbreak", 0.0),
                                                "semantic_injection": risk_vec.get("semantic_injection", 0.0),
                                                "toxicity": risk_vec.get("toxicity", 0.0),
                                                "drift": risk_vec.get("drift", 0.0),
                                                "grooming": risk_vec.get("grooming", 0.0),
                                                "dlp": risk_vec.get("dlp", 0.0),
                                                "dlp_semantic": risk_vec.get("dlp_semantic", 0.0),
                                                "threat_intel": risk_vec.get("threat_intel", 0.0),
                                                "context": risk_vec.get("context", 0.0),
                                                "tony": risk_vec.get("tony", 0.0),
                                            },
                                            "upstream_provider": provider_name,
                                            "region": apex_region,
                                            "ledger_chain_id": apex_chain_id,
                                            "explanation": explanation.dict(),
                                        }
                                        await finalize_usage(audit_payload, candidate_text)
                                        try:
                                            await create_unsigned_ledger_entry_fn(r, audit_payload)
                                            await record_metrics_for_audit_fn(r, audit_payload)
                                        except ledger_backpressure_error_cls:
                                            pass
                                        except Exception:
                                            pass
                                        await send_alert_if_needed_fn(audit_payload, r=r)
                                        msg = f"\n[BLOCK] {explanation.human_message} Hint: {explanation.remediation_hint or ''}\n"
                                        yield msg.encode("utf-8")
                                        return

                                    if decision != "PASS":
                                        reason_code = violation or "tony_threshold"
                                        explanation = explain_block_fn(reason_code, risk_vec)
                                        audit_payload = {
                                            "ts": utc_now_z_fn(),
                                            "tenant_id": tenant_id,
                                            "session_id": session_id,
                                            "policy_version": policy_version,
                                            "decision": decision,
                                            "violation": reason_code,
                                            "score": score,
                                            "model": internal_model,
                                            "model_params": model_params,
                                            "subject": identity.subject,
                                            "roles": identity.roles,
                                            **audit_ctx,
                                            "risk_axes": {
                                                "pii": risk_vec.get("pii", 0.0),
                                                "jailbreak": risk_vec.get("jailbreak", 0.0),
                                                "semantic_injection": risk_vec.get("semantic_injection", 0.0),
                                                "toxicity": risk_vec.get("toxicity", 0.0),
                                                "drift": risk_vec.get("drift", 0.0),
                                                "grooming": risk_vec.get("grooming", 0.0),
                                                "dlp": risk_vec.get("dlp", 0.0),
                                                "dlp_semantic": risk_vec.get("dlp_semantic", 0.0),
                                                "threat_intel": risk_vec.get("threat_intel", 0.0),
                                                "context": risk_vec.get("context", 0.0),
                                                "tony": risk_vec.get("tony", 0.0),
                                            },
                                            "upstream_provider": provider_name,
                                            "region": apex_region,
                                            "ledger_chain_id": apex_chain_id,
                                            "explanation": explanation.dict(),
                                        }
                                        await finalize_usage(audit_payload, candidate_text)
                                        try:
                                            await create_unsigned_ledger_entry_fn(r, audit_payload)
                                            await record_metrics_for_audit_fn(r, audit_payload)
                                        except ledger_backpressure_error_cls:
                                            pass
                                        except Exception:
                                            pass
                                        await send_alert_if_needed_fn(audit_payload, r=r)
                                        msg = f"\n[BLOCK] {explanation.human_message} Hint: {explanation.remediation_hint or ''}\n"
                                        yield msg.encode("utf-8")
                                        return

                                    new_safe_prefix_len = max(0, len(candidate_text) - stream_window)
                                    safe_prefix_raw = candidate_text[:new_safe_prefix_len]
                                    new_overlap_tail = candidate_text[new_safe_prefix_len:]

                                    if pii_mode == "redact":
                                        redacted_prefix = redact_pii_fn(safe_prefix_raw, pii_patterns)
                                    else:
                                        redacted_prefix = safe_prefix_raw

                                    to_stream = redacted_prefix[len(committed_prefix_streamed) :]
                                    if to_stream:
                                        yield to_stream.encode("utf-8")

                                    committed_prefix_raw = safe_prefix_raw
                                    committed_prefix_streamed = redacted_prefix
                                    overlap_tail = new_overlap_tail

                                final_text = committed_prefix_raw + overlap_tail
                                try:
                                    v2 = await engine.compute_unified_risk(
                                        tenant_id=tenant_id,
                                        subject=identity.subject or "unknown",
                                        session_id=session_id,
                                        prompt=final_text,
                                    )
                                    decision = v2.get("decision", "PASS")
                                    score = float(v2.get("tony", 0.0))
                                    risk_vec = v2.get("risk_vec", {})

                                    audit_payload = {
                                        "ts": utc_now_z_fn(),
                                        "tenant_id": tenant_id,
                                        "session_id": session_id,
                                        "policy_version": policy_version,
                                        "decision": decision,
                                        "violation": None,
                                        "score": score,
                                        "model": internal_model,
                                        "model_params": model_params,
                                        "subject": identity.subject,
                                        "roles": identity.roles,
                                        **audit_ctx,
                                        "risk_axes": {
                                            "pii": risk_vec.get("pii", 0.0),
                                            "jailbreak": risk_vec.get("jailbreak", 0.0),
                                            "semantic_injection": risk_vec.get("semantic_injection", 0.0),
                                            "toxicity": risk_vec.get("toxicity", 0.0),
                                            "drift": risk_vec.get("drift", 0.0),
                                            "grooming": risk_vec.get("grooming", 0.0),
                                            "dlp": risk_vec.get("dlp", 0.0),
                                            "dlp_semantic": risk_vec.get("dlp_semantic", 0.0),
                                            "threat_intel": risk_vec.get("threat_intel", 0.0),
                                            "context": risk_vec.get("context", 0.0),
                                            "tony": risk_vec.get("tony", 0.0),
                                        },
                                        "upstream_provider": provider_name,
                                        "region": apex_region,
                                        "ledger_chain_id": apex_chain_id,
                                    }
                                    await finalize_usage(audit_payload, final_text)
                                    try:
                                        await create_unsigned_ledger_entry_fn(r, audit_payload)
                                        await record_metrics_for_audit_fn(r, audit_payload)
                                    except ledger_backpressure_error_cls:
                                        pass
                                    except Exception:
                                        pass
                                    await send_alert_if_needed_fn(audit_payload, r=r)
                                except Exception:
                                    pass

                                if final_text:
                                    if pii_mode == "redact":
                                        final_stream_text = redact_pii_fn(final_text, pii_patterns)
                                    else:
                                        final_stream_text = final_text
                                    tail_to_stream = final_stream_text[len(committed_prefix_streamed) :]
                                    if tail_to_stream:
                                        yield tail_to_stream.encode("utf-8")

                                return
                except asyncio.CancelledError:
                    raise
                except httpx.RequestError as exc:
                    llm_circuit.after_call_failure()
                    last_error = exc
                    continue
                except HTTPException as exc:
                    if int(exc.status_code) in (429, 500, 502, 503, 504):
                        last_error = exc
                        continue
                    raise

            llm_circuit.after_call_failure()
            if isinstance(last_error, HTTPException):
                raise last_error
            if last_error is not None:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "message": f"All upstream providers failed: {last_error}",
                        "failure": classify_failure_fn(last_error),
                    },
                )
            unknown_error = RuntimeError("All upstream providers failed")
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "All upstream providers failed",
                    "failure": classify_failure_fn(unknown_error),
                },
            )
        except asyncio.CancelledError:
            raise
        finally:
            committed_prefix_raw = ""
            committed_prefix_streamed = ""
            overlap_tail = ""
