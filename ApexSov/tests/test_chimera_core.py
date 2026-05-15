from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
