from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

from starlette.requests import Request

from chimera.adapters import AdapterRegistry, AdapterSpec
from chimera.build_gates import GateResult, evaluate_gate_set
from chimera.contracts import ContractVersion, check_contract_compat
from chimera.decision_authority import resolve_final_decision
from chimera.domain import BuildGate, DecisionAuthority, DecisionKind, DecisionRecord
from chimera.replay import build_turn_context_hash
from chimera.telemetry_policy import FieldClass, redact_telemetry_payload


class ChimeraCoreTests(unittest.TestCase):
    def test_decision_precedence_policy_first(self) -> None:
        records = [
            DecisionRecord(authority=DecisionAuthority.PROVIDER, decision=DecisionKind.ALLOW, reason="provider_ok"),
            DecisionRecord(authority=DecisionAuthority.POLICY, decision=DecisionKind.BLOCK, reason="policy_block"),
        ]
        final = resolve_final_decision(records)
        self.assertIsNotNone(final)
        self.assertEqual(final.authority, DecisionAuthority.POLICY)
        self.assertEqual(final.decision, DecisionKind.BLOCK)

    def test_contract_compat(self) -> None:
        ok, reason = check_contract_compat(ContractVersion(1, 2), ContractVersion(1, 3))
        self.assertTrue(ok)
        self.assertEqual(reason, "compatible")

        ok, _ = check_contract_compat(ContractVersion(1, 2), ContractVersion(2, 0))
        self.assertFalse(ok)

    def test_context_hash_deterministic(self) -> None:
        h1 = build_turn_context_hash(
            policy_hash="p",
            tool_manifest_hash="t",
            model_config_hash="m",
            request_shape_hash="r",
        )
        h2 = build_turn_context_hash(
            policy_hash="p",
            tool_manifest_hash="t",
            model_config_hash="m",
            request_shape_hash="r",
        )
        self.assertEqual(h1, h2)

    def test_telemetry_redaction(self) -> None:
        payload = {"a": 1, "b": "secret", "c": "drop"}
        out = redact_telemetry_payload(
            payload,
            {
                "a": FieldClass.REQUIRED,
                "b": FieldClass.RESTRICTED,
                "c": FieldClass.FORBIDDEN,
            },
        )
        self.assertEqual(out["a"], 1)
        self.assertEqual(out["b"], "[REDACTED]")
        self.assertNotIn("c", out)

    def test_adapter_registry_compat(self) -> None:
        reg = AdapterRegistry()
        reg.register(
            AdapterSpec(
                name="ollama-chat",
                required_contract=ContractVersion(1, 0),
                provided_contract=ContractVersion(1, 2),
                source_repo="ollama/ollama",
            )
        )
        self.assertIn("ollama-chat", reg.as_dict())

    def test_gate_eval(self) -> None:
        summary = evaluate_gate_set(
            [
                GateResult(gate=BuildGate.TIER0, passed=True, details="ok"),
                GateResult(gate=BuildGate.TIER1, passed=False, details="migration_failure"),
            ]
        )
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["failure_count"], 1)


class StreamIdempotencyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_request_id_coalesces_via_streaming_proxy(self) -> None:
        import BaseT8 as gateway

        original_get_redis_client = gateway.get_redis_client
        original_enforce_failsafe = gateway._enforce_failsafe_or_raise
        original_engine_cls = gateway.ApexSovereignEngine
        original_preflight = gateway.chimera_stream_preflight.run_stream_preflight
        original_stream_runtime = gateway.chimera_streaming_runtime.stream_llm_with_risk
        original_boundary = gateway.IDEMPOTENCY_BOUNDARY
        original_tracer = gateway.tracer

        stream_call_count = 0

        class _FakeEngine:
            def __init__(self, *args, **kwargs):
                pass

        async def _fake_preflight(**kwargs):
            return {
                "audit_ctx": {},
                "model_params": {},
                "policy": {},
                "internal_model": "gpt-4o-mini",
                "tool_filter": {},
            }

        async def _fake_stream_runtime(**kwargs):
            nonlocal stream_call_count
            stream_call_count += 1
            for part in (b"hello ", b"world"):
                await asyncio.sleep(0.01)
                yield part

        async def _fake_get_redis_client():
            return object()

        async def _fake_enforce_failsafe(_):
            return None

        async def _invoke_streaming_proxy(identity, req_obj, http_request):
            resp = await gateway.streaming_proxy(
                http_request=http_request,
                request=req_obj,
                x_tenant_id=identity.tenant_id,
                x_session_id="session-1",
                identity=identity,
            )
            chunks: list[bytes] = []
            async for chunk in resp.body_iterator:
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    chunks.append(str(chunk or "").encode("utf-8"))
            return b"".join(chunks).decode("utf-8", errors="ignore")

        class _TracerSpan:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def set_attribute(self, key, value):
                return None

        class _Tracer:
            def start_as_current_span(self, name):
                return _TracerSpan()

        try:
            gateway.get_redis_client = _fake_get_redis_client
            gateway._enforce_failsafe_or_raise = _fake_enforce_failsafe
            gateway.ApexSovereignEngine = _FakeEngine
            gateway.chimera_stream_preflight.run_stream_preflight = _fake_preflight
            gateway.chimera_streaming_runtime.stream_llm_with_risk = _fake_stream_runtime
            gateway.IDEMPOTENCY_BOUNDARY = gateway.IdempotencyBoundary()
            gateway.tracer = _Tracer()

            identity = SimpleNamespace(tenant_id="tenant-a", subject="user-1", roles=["admin"])
            req_obj = gateway.UniversalRequest(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hello"}],
                stream=True,
            )

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/stream",
                "headers": [
                    (b"x-request-id", b"req-123"),
                    (b"x-device-id", b"dev-1"),
                ],
                "client": ("127.0.0.1", 12345),
            }
            http_request = Request(scope)

            task1 = asyncio.create_task(_invoke_streaming_proxy(identity, req_obj, http_request))
            await asyncio.sleep(0.002)
            task2 = asyncio.create_task(_invoke_streaming_proxy(identity, req_obj, http_request))

            out1, out2 = await asyncio.gather(task1, task2)
            self.assertEqual(out1, "hello world")
            self.assertEqual(out2, "hello world")
            self.assertEqual(stream_call_count, 1)
        finally:
            gateway.get_redis_client = original_get_redis_client
            gateway._enforce_failsafe_or_raise = original_enforce_failsafe
            gateway.ApexSovereignEngine = original_engine_cls
            gateway.chimera_stream_preflight.run_stream_preflight = original_preflight
            gateway.chimera_streaming_runtime.stream_llm_with_risk = original_stream_runtime
            gateway.IDEMPOTENCY_BOUNDARY = original_boundary
            gateway.tracer = original_tracer

    async def test_authz_deny_includes_failure_envelope(self) -> None:
        """Verify that authz-deny responses include a properly structured failure envelope."""
        import BaseT8 as gateway
        from fastapi import HTTPException

        original_stream_preflight = gateway.chimera_stream_preflight.run_stream_preflight
        original_tracer = gateway.tracer
        original_get_redis_client = gateway.get_redis_client
        original_enforce_failsafe = gateway._enforce_failsafe_or_raise

        class _AuthzDenyPreflight:
            async def __call__(self, **kwargs):
                # Simulate authorization denial
                from chimera.failure_taxonomy import classify_failure
                failure = classify_failure(PermissionError("authorization_denied:insufficient_role"))
                detail = {
                    "message": "Access denied: insufficient_role",
                    "failure": failure,
                }
                raise HTTPException(status_code=403, detail=detail)

        class _Tracer:
            def start_as_current_span(self, name):
                class _TracerSpan:
                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, tb):
                        return False

                    def set_attribute(self, key, value):
                        return None
                return _TracerSpan()

        async def _fake_get_redis_client():
            return object()

        async def _fake_enforce_failsafe(_):
            return None

        try:
            gateway.chimera_stream_preflight.run_stream_preflight = _AuthzDenyPreflight()
            gateway.tracer = _Tracer()
            gateway.get_redis_client = _fake_get_redis_client
            gateway._enforce_failsafe_or_raise = _fake_enforce_failsafe

            identity = SimpleNamespace(
                tenant_id="tenant-a",
                subject="user-1",
                roles=["basic"],  # restricted role
            )
            req_obj = gateway.UniversalRequest(
                model="gpt-4o",  # high-tier model
                messages=[{"role": "user", "content": "hello"}],
                stream=True,
            )

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/stream",
                "headers": [
                    (b"x-request-id", b"req-auth-test"),
                    (b"x-device-id", b"dev-1"),
                ],
                "client": ("127.0.0.1", 12345),
            }
            http_request = Request(scope)

            # Invoke streaming proxy and expect HTTPException with 403
            with self.assertRaises(HTTPException) as exc_ctx:
                await gateway.streaming_proxy(
                    http_request=http_request,
                    request=req_obj,
                    x_tenant_id=identity.tenant_id,
                    x_session_id="session-1",
                    identity=identity,
                )

            exc = exc_ctx.exception
            self.assertEqual(exc.status_code, 403)

            # Verify detail structure includes failure envelope
            detail = exc.detail
            self.assertIsInstance(detail, dict)
            self.assertIn("failure", detail)

            failure_envelope = detail["failure"]
            self.assertIsInstance(failure_envelope, dict)

            # Check required failure envelope fields
            self.assertIn("failure_type", failure_envelope)
            self.assertIn("failure_class", failure_envelope)
            self.assertIn("failure_source", failure_envelope)
            self.assertIn("retryable", failure_envelope)
            self.assertIn("failure_action", failure_envelope)
            self.assertIn("exception_type", failure_envelope)

            # Verify field values match expected NON_RETRYABLE policy
            self.assertEqual(failure_envelope["failure_type"], "non_retryable")
            self.assertEqual(failure_envelope["failure_class"], "contract_violation")
            self.assertEqual(failure_envelope["failure_source"], "input")
            self.assertFalse(failure_envelope["retryable"])
            self.assertEqual(failure_envelope["failure_action"], "fail_fast")
            self.assertEqual(failure_envelope["exception_type"], "PermissionError")

        finally:
            gateway.chimera_stream_preflight.run_stream_preflight = original_stream_preflight
            gateway.tracer = original_tracer
            gateway.get_redis_client = original_get_redis_client
            gateway._enforce_failsafe_or_raise = original_enforce_failsafe


if __name__ == "__main__":
    unittest.main()
