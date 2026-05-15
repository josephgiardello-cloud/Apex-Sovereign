# Chimera Build Specification

This file is the finalized build contract for evolving Apex into the target Chimera architecture.

## 1. Architecture Graph

1. Control plane: policy, tenancy, authorization.
2. Execution plane: orchestrator, model routing, tool invocation.
3. Data plane: session memory, ledger, artifacts.
4. Safety plane: risk, DLP, drift, egress enforcement.
5. Operations plane: telemetry, diagnostics, rollout controls.

## 2. Decision Authority Precedence

1. Policy
2. Safety
3. Orchestrator
4. Provider

Any conflict resolves by highest-precedence authority.

## 3. Modular Contracts

Mandatory contracts are defined in `chimera/contracts.py`.

1. ChatProvider
2. EmbeddingProvider
3. ToolExecutor
4. TraceSink
5. LedgerSink

All adapters must satisfy major-version compatibility.

## 4. Adapter Control

Adapter registration is mediated through `chimera/adapters.py`.

Required metadata:

1. adapter name
2. required contract version
3. provided contract version
4. source repository

## 5. Replay Determinism

Turn context hash must include:

1. policy hash
2. tool manifest hash
3. model configuration hash
4. request shape hash

Implemented in `chimera/replay.py`.

## 6. Telemetry Minimization

Field classification:

1. required
2. optional
3. restricted
4. forbidden

Emission policy enforcement is implemented in `chimera/telemetry_policy.py`.

## 7. Migration Protocol

Use forward-compatible migration registry in `chimera/migration_protocol.py`.

Minimum requirements:

1. unique migration id
2. from and to version
3. forward-only marker
4. deterministic handler execution

## 8. Build Gates

Build gate tiers:

1. Tier 0: policy, authz, egress, ledger integrity
2. Tier 1: orchestration, tools, migrations
3. Tier 2: performance and UX

Gate evaluation model in `chimera/build_gates.py`.

## 9. Verification Command

Run:

```powershell
py -3 verify_chimera.py
```

A non-zero exit code means Chimera core contracts are not satisfied.
