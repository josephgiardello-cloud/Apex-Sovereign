# DadBot In-Place Upgrade Guide

This runbook upgrades your current Apex Sovereign deployment for Dad-Bot integration without creating a new repo.

## Objective

Keep Apex Sovereign as the control plane and route all Dad-Bot LLM calls through `POST /v1/stream`.

## Prerequisites

- Apex repo available (this repository)
- Dad-Bot repository available separately
- Redis running locally
- Ollama running locally (or an alternative provider)

## Step 1: Start Apex in DadBot mode

1. Copy the env template:
   - Copy `.env.dadbot.example` to `.env` (or export equivalent values in shell)
2. Ensure Ollama is up:
   - `ollama serve`
3. Start Apex:
   - `uvicorn ApexSov.BaseT8:app --host 0.0.0.0 --port 8000`
4. Verify health:
   - `GET /healthz`
   - `GET /readyz`

## Step 2: Use DadBot policy template

The `dadbot` policy template is available in Apex policy templates.

Recommended tenant bootstrap:

1. Create a tenant policy record with template group `dadbot`
2. Confirm tool allowlist includes only approved family tools
3. Verify policy enforcement by issuing a test call with disallowed tool payload

## Step 3: Point Dad-Bot at Apex

In Dad-Bot runtime environment, use:

- `DADBOT_LLM_PROVIDER=sovereign`
- `DADBOT_SOVEREIGN_BASE_URL=http://localhost:8000`
- `DADBOT_SOVEREIGN_TENANT_ID=family-default`

Dad-Bot request headers should include:

- `x-tenant-id`
- `x-session-id`
- `x-device-id`
- `x-request-id` (recommended for idempotency)

## Step 4: Validate end-to-end

Run one Dad-Bot turn and check:

1. Apex accepted the request via `/v1/stream`
2. A ledger entry was written (`/api/v1/audit/ledger/*`)
3. Failure envelopes classify denials consistently
4. Idempotency endpoint reflects request replay state (`/api/v1/runtime/idempotency`)

## Step 5: Production hardening

Before production:

- Enable OIDC and audience checks
- Enable egress allowlist
- Enable compliance/failsafe flags
- Configure webhook destinations (SIEM/alerts)
- Switch KMS mode from software signer to managed key

## Notes

- You do not need to merge Dad-Bot source into this repository.
- Keep Dad-Bot and Apex independently versioned while integrating over the API boundary.
- This reduces merge complexity while preserving governance guarantees.

## Gaps and Remaining Issues (Technical Deep Dive)

These items are current engineering risks, not blockers for local integration.

### 1) Testing Depth

- `verify_chimera.py` currently executes `unittest tests.test_chimera_core`.
- The visible committed suite is minimal and does not yet represent full integration coverage.
- Required next step: add integration tests for stream path, Redis availability edge cases, ledger write/read/verify paths, and policy enforcement under mixed traffic.

### 2) Risk Model Maturity

- Current heuristic scoring and controls are a practical baseline, not state-of-the-art.
- Advanced ML-based risk scoring is not in-core and depends on optional sidecars.
- Semantic drift detection quality depends on exemplar coverage and must be populated with production-like examples before strong guarantees are claimed.

### 3) Performance and Scale

- Per-chunk risk checks, async signing, and Redis interactions can add measurable latency at high request volume.
- Backpressure behavior is intentionally defensive, but if untuned it can reduce availability during bursts.
- Redis is a central dependency and is a single point of failure unless HA topology (sentinel/cluster/managed failover) is configured.

### 4) Error Handling and Resilience

- Failure taxonomy and retryability classification are strong design elements.
- Confidence still depends on chaos testing with partial failure injection, especially around ledger write, signing, and sync paths.
- Required next step: execute fault campaigns for Redis outages, signer timeouts, partial ledger persistence, and downstream provider flaps.

### 5) Security Surface

- As a full proxy with outbound paths (LLM providers, webhooks, embeddings), egress policy and input sanitization are critical controls.
- Current controls appear solid by design review, but external audit and penetration testing are still required before high-trust deployment.

### 6) Dad-Bot Integration Scope Reality

- Dad-Bot integration guidance in this document is planning guidance for API-boundary integration.
- Apex Sovereign remains independently deployable and can proxy directly to local Ollama.
- Deep in-process merge with an existing Dad-Bot codebase is a larger refactor requiring call-path consolidation and contract alignment, and should be planned as a separate project phase.

## Recommended Validation Sequence

1. Expand integration tests beyond `tests.test_chimera_core` to cover runtime and failure paths.
2. Run load tests with backpressure tuning and percentile latency targets.
3. Run chaos tests focused on ledger partial-failure behavior and replay consistency.
4. Perform security audit of egress allowlist, webhook handling, and sanitizer coverage.
5. Treat Dad-Bot deep merge as a scoped migration plan, not an in-place toggle.
