# Chimera Integration Map

## Apex Components to Keep as Core

1. Policy and tenant governance surface from `BaseT8.py`.
2. Egress and no-internet controls.
3. Ledger and audit persistence semantics.
4. Operational endpoints and background health loops.

## Dadbot-Derived Patterns to Integrate

1. Strict runtime contracts and capability boundaries.
2. Deterministic trace and replay artifacts.
3. Risk-tiered evaluation gates.
4. Explicit error taxonomy and wrapped-cause behavior.

## External Forks and Usage Policy

1. Ollama: local model runtime, default inference backend.
2. LangGraph: optional orchestration backend for complex multi-agent workflows.
3. Open WebUI: optional UX shell, never a control-plane dependency.
4. AutoGen: reference patterns only, avoid deep runtime dependency.

## Upgrade-Safe Rule

External dependencies are only accessed through adapters registered under Chimera contracts.

## Current State

1. Offline runtime scripts exist and compile.
2. Chimera contract package exists and has executable verification.
3. Full monolith extraction is still pending and must follow contract-first slicing.
