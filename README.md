# Apex Sovereign

**Unified AI Governance Gateway** — Streaming LLM proxy with enterprise-grade audit, risk, compliance, and incident-response infrastructure in a single deployable service.

---

## What This Is

Apex Sovereign is a FastAPI-based reverse proxy that sits between your users and any OpenAI-compatible LLM endpoint. Every request is authenticated, risk-evaluated, governed by tenant policy, cryptographically ledgered, and auditable end-to-end — before a single token of output reaches the client.

It is not a chatbot. It is not an SDK wrapper. It is the **security and compliance plane** for LLM traffic in regulated or enterprise environments.

## Recommended Offline Stack

For the current local-first Apex setup, the recommended baseline is:

- Ollama as the offline inference runtime
- `qwen2.5:7b` as the local model core
- `apex-qwen` as the stable Apex-facing Ollama alias
- Apex Sovereign as the governance/control plane in front of `/v1/chat/completions`

From [ApexSov](ApexSov), the quickest local setup path is:

```powershell
.\setup_ollama_qwen.ps1
py -3 run_offline.py --host 127.0.0.1 --port 8000
```

---

## Architecture at a Glance

```
Client
  │  OIDC Bearer token  +  x-tenant-id  +  x-session-id
  ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI  /v1/stream                                        │
│                                                             │
│  1. OIDC/JWKS Auth   → TenantIdentity                      │
│  2. Failsafe gate    → halt if audit integrity at risk      │
│  3. Preflight        → policy, model allowlist, RBAC,       │
│                         tool scoping, input sanitization    │
│  4. Quota check      → RPM / TPM / daily / monthly limits   │
│  5. Upstream select  → provider pool rotation + failover    │
│  6. Streaming proxy  → incremental risk eval per chunk      │
│  7. BLOCK / PASS     → redact PII or terminate stream       │
│  8. Ledger write     → append-only audit entry (Redis)      │
│  9. KMS signing      → async ECDSA via worker queue         │
│ 10. SIEM / Alert     → best-effort webhook dispatch         │
└─────────────────────────────────────────────────────────────┘
          │  signed audit entries
          ▼
       Redis  ──► (optional) S3 JSONL offload
       Qdrant  (optional vector drift backend)
       AWS KMS / Soft ECDSA signer
```

---

## Key Capabilities

### Identity & Authorization
| Capability | Detail |
|---|---|
| OIDC/JWKS authentication | Bearer token validation with cached JWKS rotation |
| Multi-tenant binding | Token claim + header consistency enforced |
| RBAC | Per-model tier access control via `AuthorizationEngine` |
| Tenant isolation | All state keys namespaced by `tenant_id` |

### Risk Engine (TONY Score)
| Axis | Method |
|---|---|
| PII detection | Regex patterns, configurable per-tenant |
| Jailbreak / prompt injection | Regex + threat-intel indicator matching |
| Toxicity | Classifier (fast regex or neural HTTP sidecar) |
| Semantic DLP | Embedding cosine similarity against exemplar corpus |
| Drift / grooming | Redis bag-of-words baseline OR Qdrant vector backend |
| Threat intel | Push-ingested rules with severity weighting |
| Context | Composite multi-axis scoring |
| **TONY** | Weighted unified score → PASS / BLOCK decision |

Risk is evaluated **incrementally per streaming chunk**, not after the full response.

### Policy Engine
- Per-tenant versioned policies stored in Redis
- Policy templates: `DEFAULT`, `finance`, `healthcare`, `government`, `dadbot`
- PII mode: `block` (default) or `redact`
- Tool scoping: allowlist/denylist per-policy for function-calling
- Compliance mode: enforced TTLs, retention caps, audit hash salting
- Two-person approval for policy mutations (finance-grade governance)
- Data minimization: hash PII before ledger write when enabled

### Audit Ledger
- **Append-only chain** in Redis (`apex:audit_ledger`) with chained SHA-256 hashes
- Every PASS, BLOCK, DENY, and governance event produces a ledger entry
- Merkle checkpoints every N entries with optional KMS signature
- Async signing queue with backpressure — if queue fills, service denies new requests to protect audit integrity
- Optional S3 JSONL offload for cold archival
- Integrity verification: `GET /api/v1/audit/ledger/verify`

### KMS / Signing
| Mode | Config |
|---|---|
| AWS KMS ECDSA | `APEX_KMS_KEY_ID` + `APEX_KMS_REGION` |
| Software ECDSA | Auto-fallback in dev/stage (ephemeral key) |
| FIPS mode | `APEX_FIPS_MODE=true` enforces key compliance |
| Dual-control | `APEX_KMS_DUAL_CONTROL=true` — runtime key must match approved env-config |

### Multi-Upstream Provider Pool
- Pool defined via `APEX_UPSTREAM_PROVIDERS_JSON`
- Deterministic per-tenant/session provider rotation
- Automatic failover on 429 / 5xx with circuit breaker (half-open)
- Per-provider auth injection (bearer, header, API key env lookup)
- Egress enforcement before each upstream call

### Quota & Cost Accounting
- Per-tenant quota buckets: RPM, TPM, tokens/day, tokens/month
- Prompt token pre-reservation before any upstream call
- Completion token attribution on stream completion
- Per-model USD cost estimation logged in every audit entry

### Egress Control (SSRF/Exfil Defense)
- Regex allowlist for all outbound URLs (`APEX_EGRESS_ALLOWLIST_REGEX`)
- IP literal blocking (`APEX_EGRESS_BLOCK_IP_LITERALS=true`)
- No-internet posture (`APEX_NO_INTERNET=true`)
- Applied before: upstream LLM calls, SIEM webhooks, alert webhooks

### RTBF (Right to Be Forgotten)
- Per-session data erasure with cryptographic proof
- Proof cache in Redis with configurable TTL
- Optional S3 proof archival

### SIEM & Alerting
- Alert webhook (`APEX_ALERT_WEBHOOK_URL`) with TONY score threshold gating
- SIEM webhook (`APEX_SIEM_WEBHOOK_URL`) with optional send-all mode
- Alert correlation: coalesce repeated alerts per tenant/session/reason (configurable window)
- Incident correlation: severity classification, IR timelines, operator runbooks
- Egress-checked before every webhook dispatch

---

## Project Layout

```
ApexSov/
├── BaseT8.py                    # Unified entry point — FastAPI app, all wiring
├── config.py                    # Env-driven configuration contract
├── verify_chimera.py            # 6-test offline verification suite
├── verify_proof.py              # Ledger proof verifier CLI
├── bootstrap_offline.py         # Local bootstrap without cloud deps
├── preflight_offline.py         # Pre-startup env validation
├── run_offline.py               # Offline mode launcher
├── requirements.txt
├── Dockerfile
├── OPERATIONS.md                # Backup/restore, DR, key rotation procedures
├── CHIMERA_BUILD_SPEC.md        # Module extraction spec
├── CHIMERA_INTEGRATION_MAP.md   # Cross-module dependency map
│
└── chimera/                     # Modular runtime components
    ├── adapters.py              # Generic I/O adapter contracts
    ├── admin_misc_routes.py     # Admin API routes (misc)
    ├── admin_security_routes.py # Admin API routes (security)
    ├── apex_engine.py           # ApexSovereignEngine — risk computation hub
    ├── auth_identity.py         # OIDC/JWKS, TenantIdentity, AuthorizationEngine
    ├── build_gates.py           # CI/build gate helpers
    ├── content_store.py         # SHA-256 dedup content store (Redis)
    ├── contracts.py             # Shared data contracts
    ├── control_plane_payloads.py
    ├── control_plane_reads.py
    ├── control_plane_runtime.py # Control-plane route registration
    ├── dashboard_routes.py      # CISO dashboard routes
    ├── dashboard_views.py
    ├── decision_authority.py    # Decision delegation contracts
    ├── dlp_semantic_store.py    # Semantic DLP: exemplar embeddings
    ├── domain.py                # Core domain types
    ├── drift_runtime.py         # Drift backends: Redis BoW + Qdrant vector
    ├── env_config_changes.py
    ├── env_config_governance.py # Env config dual-control governance
    ├── env_config_routes.py
    ├── env_config_views.py
    ├── governance_events.py     # Governance event payload builders
    ├── governance_runtime.py    # Governance ledger event dispatch
    ├── idempotency_runtime.py   # Request-id based in-flight dedupe and replay cache
    ├── import_compat.py         # Package-relative import compatibility shim
    ├── input_sanitizer.py       # Input sanitizer (control chars + regex scrub)
    ├── kms_signer.py            # KMS ECDSA signer (lazy boto3)
    ├── ledger_audit_routes.py   # Ledger inspection API
    ├── ledger_primitives.py     # Raw ledger read/write/checkpoint
    ├── ledger_s3_sync.py        # S3 JSONL offload
    ├── ledger_verify_helpers.py # Chain verification helpers
    ├── ledger_verify_routes.py  # Chain verify API routes
    ├── ledger_write.py          # Unsigned entry creation, backpressure
    ├── message_validation.py    # Message schema validation
    ├── metrics_runtime.py       # Rolling 24h metrics (Redis)
    ├── migration_protocol.py    # Data migration helpers
    ├── model_allowlist.py       # Per-tenant model allowlist enforcement
    ├── pagination.py            # Cursor-based pagination helpers
    ├── policy_governance.py     # Policy mutation governance
    ├── policy_records.py        # Policy record builders
    ├── policy_routes.py         # Policy CRUD API
    ├── policy_templates.py      # Template catalog (default/finance/healthcare/gov)
    ├── policy_tool_scoping.py   # Tool allowlist/denylist enforcement
    ├── policy_views.py          # Policy read views
    ├── redis_json_views.py      # Redis JSON encode/decode helpers
    ├── redis_runtime.py         # Redis connection hardening
    ├── replay.py                # Audit replay for forensics
    ├── retention_policy.py      # Compliance TTL enforcement
    ├── failure_taxonomy.py      # Unified retryability/action classification
    ├── risk_components.py       # FastRiskClassifier, NeuralSafetyClassifier
    ├── risk_decisions.py        # TONY evaluation, block explanations
    ├── rtbf_proof_views.py      # RTBF proof read views
    ├── rtbf_routes.py           # RTBF API routes
    ├── runtime_health.py        # Fail-safe health checks, self-test loop
    ├── runtime_status_routes.py # /healthz, /readyz, /governance_status
    ├── secret_provider.py       # Secret retrieval (env-backed)
    ├── siem_ir.py               # SIEM webhooks, incident correlation, runbooks
    ├── signing_audit.py         # KMS access audit log
    ├── signing_runtime.py       # Async signing worker loop
    ├── startup_runtime.py       # Startup wiring: drift backend, background tasks
    ├── stream_preflight.py      # Request validation before streaming
    ├── streaming_runtime.py     # /v1/stream: provider failover + risk eval loop
    ├── telemetry_policy.py      # OTel telemetry policy
    ├── tenant_policy_store.py   # PolicyStore, TenantStore (Redis-backed)
    ├── threat_intel_store.py    # Threat intel push ingestion + scoring
    ├── upstream_auth.py         # Upstream LLM auth header builder
    ├── upstream_runtime.py      # Provider pool parsing, rotation, header injection
    └── usage_runtime.py         # Quota enforcement + cost accounting
```

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/stream` | Main streaming LLM proxy |
| `GET` | `/healthz` | Liveness check |
| `GET` | `/readyz` | Readiness: Redis, signer, backlog |
| `GET` | `/governance_status` | Signer health + ledger backlog state |
| `GET/POST` | `/api/v1/policy/*` | Tenant policy CRUD |
| `GET/POST` | `/api/v1/audit/ledger/*` | Ledger inspection and verification |
| `POST` | `/api/v1/rtbf/*` | Right-to-be-forgotten erasure + proof |
| `GET` | `/api/v1/env-config/*` | Env-config governance (dual-control) |
| `POST` | `/api/v1/threat-intel/*` | Threat intel rule ingestion |
| `GET` | `/api/v1/dashboard/*` | CISO dashboard |
| `GET` | `/api/v1/runtime/status` | Runtime status detail |
| `GET` | `/api/v1/runtime/idempotency` | Tenant-scoped idempotency cache/in-flight status with age metadata (`max_keys`, optional `session_id`) (admin) |

---

## Environment Variables (Core)

| Variable | Default | Purpose |
|---|---|---|
| `APEX_ENV` | *(required)* | `dev` / `stage` / `prod` |
| `APEX_REDIS_URL` | *(required)* | Redis connection string (TLS+auth in prod) |
| `APEX_OIDC_ISSUER` | `""` | OIDC issuer URL for token validation |
| `APEX_OIDC_AUDIENCE` | `""` | Expected token audience |
| `OPENAI_API_KEY` | *(env)* | OpenAI API key for default upstream |
| `APEX_OPENAI_URL` | `https://api.openai.com/v1/chat/completions` | LLM endpoint |
| `APEX_UPSTREAM_PROVIDERS_JSON` | `""` | JSON array of provider pool entries |
| `APEX_KMS_KEY_ID` | `""` | AWS KMS key ARN for ECDSA signing |
| `APEX_KMS_REGION` | `""` | AWS region for KMS |
| `APEX_FIPS_MODE` | `false` | Enforce FIPS-compliant key operations |
| `APEX_KMS_DUAL_CONTROL` | `false` | Runtime key must match approved env-config |
| `APEX_FAILSAFE_GOV` | `false` | Halt traffic if audit integrity at risk |
| `APEX_COMPLIANCE_MODE` | `false` | Enforce retention TTLs and data minimization |
| `APEX_DRIFT_BACKEND` | `redis` | `redis` (BoW) or `qdrant` (vector) |
| `QDRANT_URL` | `http://localhost:6333` | Qdrant endpoint for vector drift |
| `APEX_EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model for vector drift |
| `APEX_DLP_SEMANTIC_ENABLED` | `false` | Enable semantic DLP exemplar matching |
| `APEX_NEURAL_SAFETY_MODE` | `stub` | `stub` or `http` (sidecar classifier) |
| `APEX_NEURAL_SAFETY_URL` | `http://localhost:8081/analyze` | Neural safety sidecar endpoint |
| `APEX_ALERT_WEBHOOK_URL` | `""` | Alert webhook for high-risk events |
| `APEX_SIEM_WEBHOOK_URL` | `""` | SIEM outbound webhook |
| `APEX_NO_INTERNET` | `false` | Block all non-allowlisted egress |
| `APEX_EGRESS_ALLOWLIST_REGEX` | `""` | Regex allowlist for outbound URLs |
| `APEX_TWO_PERSON_POLICY` | `false` | Require two-person approval for policy changes |
| `APEX_LEDGER_S3_BUCKET` | `""` | S3 bucket for JSONL ledger offload |
| `APEX_MODEL_PRICES_USD_PER_1K_TOKENS_JSON` | `""` | Per-model pricing for cost attribution |

---

## Quick Start (Offline / Dev)

```bash
# 1. Install dependencies
pip install -r ApexSov/requirements.txt

# 2. Verify chimera modules
python ApexSov/verify_chimera.py

# 3. Bootstrap offline env
python ApexSov/bootstrap_offline.py

# 4. Start (offline mode)
APEX_ENV=dev APEX_REDIS_URL=redis://localhost:6379 \
  uvicorn ApexSov.BaseT8:app --host 0.0.0.0 --port 8000

# 5. Or run with Docker
docker build -t apex-sovereign -f ApexSov/Dockerfile ApexSov/
docker run -e APEX_ENV=dev -e APEX_REDIS_URL=redis://host.docker.internal:6379 \
  -p 8000:8000 apex-sovereign
```

### DadBot-Style Local UI

Run a lightweight DadBot-style Streamlit interface that talks to Sovereign `/v1/stream`:

```bash
# Start Apex Sovereign first (port 8000)
python ApexSov/run_offline.py

# In another shell, launch UI
streamlit run ApexSov/dadbot_sovereign_ui.py
```

Open `http://localhost:8501`.

Notes:
- This is an interface layer only; Apex remains the governance/runtime plane.
- For protected deployments, paste a valid bearer token in the UI sidebar.

---

## Quick Start (Production)

```bash
export APEX_ENV=prod
export APEX_REDIS_URL="rediss://:password@redis-host:6380"
export APEX_OIDC_ISSUER="https://your-idp.example.com"
export APEX_OIDC_AUDIENCE="apex-sovereign"
export OPENAI_API_KEY="sk-..."
export APEX_KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/..."
export APEX_KMS_REGION="us-east-1"
export APEX_FAILSAFE_GOV=true
export APEX_COMPLIANCE_MODE=true

uvicorn ApexSov.BaseT8:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Unauthenticated access | OIDC/JWKS required on all routes |
| Tenant data leakage | All Redis keys namespaced by `tenant_id` |
| Prompt injection / jailbreak | Regex + threat-intel + neural safety classifier |
| PII exfiltration via LLM output | Streaming risk eval on every chunk; PII block or redact |
| Grooming attacks (long-horizon manipulation) | Session drift detection (BoW or vector) |
| Tool misuse / function-calling abuse | Per-policy tool scoping allowlist |
| Audit tampering | Append-only chained hash ledger + async KMS ECDSA signing |
| SSRF / egress exfiltration | Sovereign egress allowlist + IP literal blocking |
| Ledger overflow / DoS | Backpressure: new requests denied when signing queue is full |
| Government-grade failure scenarios | Fail-safe mode: halt traffic if ledger capacity threshold breached |
| Credential exposure | Secret provider with env-backed lazy loading; no eager key import |

---

## Verification

```bash
# Run offline 6-test chimera verification
python ApexSov/verify_chimera.py

# Verify a ledger proof file
python ApexSov/verify_proof.py --proof path/to/proof.json

# Check chain integrity via API
curl http://localhost:8000/api/v1/audit/ledger/verify
```

---

## DadBot Sovereign Integration Blueprint

This repository can be evolved into DadBot Sovereign (also called Apex Dad Sovereign) by combining:
- Dad-Bot as the personality, memory, voice, and proactive UX layer
- Apex Sovereign as the governance, audit, risk, identity, and runtime plane

Core principle:
- All LLM traffic is forced through `/v1/stream`
- Dad-Bot features remain user-facing
- Apex enforces policy, risk, and cryptographic audit on every turn

### In-Place Upgrade Mode (Recommended)

You do **not** need a brand-new repository.

Use this existing Apex repository as the governance/control plane and connect Dad-Bot as a separate client/runtime that points to this Apex `/v1/stream` endpoint.

Minimal wiring model:
- Keep Apex in this repo and run it as-is.
- Keep Dad-Bot in its own repo/worktree.
- Set Dad-Bot provider to `sovereign` and point it at this Apex base URL.
- Apply the `dadbot` tenant policy template in Apex.
- Route all Dad-Bot LLM traffic through Apex.

See `ApexSov/DADBOT_INPLACE_UPGRADE.md` and `ApexSov/.env.dadbot.example` for concrete setup.

### Target Architecture

```text
User (Streamlit / PWA / Voice)
  |
  v
DadBot Sovereign Frontend (Streamlit + optional React/HTMX overlays)
  |
  v
All LLM calls -> Apex Sovereign /v1/stream (local Ollama or cloud)
  |
  +-- OIDC or simple auth -> TenantIdentity (single-user or family multi-tenant)
  +-- Policy Engine (custom DADBOT template)
  +-- Risk Engine (TONY score on every streamed chunk)
  +-- Semantic memory + drift detection
  +-- Append-only ledger + KMS or software signing
```

### Dad-Bot Components To Port or Adapt

| Component | Dad-Bot Location | Sovereign Adaptation | Priority |
|---|---|---|---|
| Core conversation logic | `dadbot/core/dadbot.py`, `dadbot/runtime_core/` | Refactor to call Apex `/v1/stream` instead of direct Ollama | ★★★★★ |
| Long-term memory | `dadbot/memory/` | Keep semantic/vector memory, route embeddings to Apex drift backend (`redis` or `qdrant`) | ★★★★★ |
| Relationship and personality | `dadbot/relationship.py`, `dadbot/profile.py`, `dadbot/mood.py`, `dadbot/tone.py` | Keep mostly intact, align with emotional safety policy controls | ★★★★ |
| Streamlit UI | `dad_streamlit.py`, `dadbot/ui/` | Replace direct model calls with Apex proxy client, show governance/risk indicators | ★★★★★ |
| Voice system | WebRTC + Piper + Whisper | Keep voice I/O, send transcribed text through Apex, stream response to TTS | ★★★★ |
| Proactive background jobs | `dadbot/background.py`, `dadbot/notifications.py` | Keep scheduler, force all LLM generation through Apex | ★★★★ |
| Tools and calendar | `dadbot/tools/`, service modules | Convert to Apex function-call schema with policy scoping | ★★★ |
| PII scrubber | `dadbot/pii_scrubber.py` | Deprecate or merge into Apex DLP pipeline | ★★★ |
| Audit and logging | `audit.py`, `dadbot_system/` | Replace with Apex ledger pipeline | ★★★★★ |
| Config and profile | `dadbot/config.py`, `dad_profile.template.json` | Merge into tenant policy and env-config governance | ★★★ |
| CLI and API entrypoints | `Dad.py`, `api_entrypoint.py` | Wrap or replace with Apex client adapters | ★★★ |

Keep mostly as-is:
- Avatar generation
- First-run wizard
- Heritage import
- Prompt/template content

### Phased Integration Plan

1. Phase 1 (Foundation, 1-2 weeks)
- Keep this Apex repo as the control plane (no repo split required)
- Connect Dad-Bot runtime to Apex `/v1/stream` via a thin client adapter
- Add `DADBOT` policy template: warm, family-safe, emotionally aware, low hallucination tolerance
- Extend allowlist/provider pool for local Ollama via `APEX_UPSTREAM_PROVIDERS_JSON`
- Keep software signer fallback for personal deployments
- Add thin Python Apex client SDK for Dad-Bot

2. Phase 2 (LLM Path Migration, 2-3 weeks)
- Replace direct `ollama.chat()` and `AsyncOllama` usage with Apex proxy calls
- Implement streaming chunk adapter into Dad-Bot turn pipeline
- Route memory embedding paths into Apex drift/vector backend

3. Phase 3 (Feature Porting)
- Voice: Whisper transcription -> Apex stream -> TTS playback
- Proactive background generation through Apex only
- Tool and calendar actions defined as policy-scoped Apex tools
- Story mode mapped to policy toggles and approval gates

4. Phase 4 (Governance and Product Polish)
- Add Streamlit governance tab (ledger state, TONY trends, risk events)
- Enable RTBF by conversation/session with verifiable proof
- Add family multi-tenancy support
- Align health/status UX with Apex runtime status views
- Ensure every Dad-Bot turn is signed and auditable

5. Phase 5 (Deployment and UX)
- Unified compose stack: Apex API + Redis + Qdrant + Ollama + Streamlit
- Keep PWA/mobile client pointed at governed backend
- Optional runtime mode switch: fully local or governed cloud hybrid

### Recommended In-Place Structure

```text
Apex-Sovereign/
├── ApexSov/                      # Apex Sovereign runtime and governance plane
│   ├── .env.dadbot.example       # DadBot-targeted local env template
│   └── DADBOT_INPLACE_UPGRADE.md # In-place DadBot integration runbook
├── README.md
└── (external) Dad-Bot repository
  └── points to this Apex instance via /v1/stream
```

### Challenges and Mitigations

| Challenge | Mitigation |
|---|---|
| Additional latency from governance checks | Use local Ollama, Redis tuning, lighter personal policies where acceptable |
| Merge complexity across two mature codebases | Start with MVP: Apex proxy in front of existing Dad-Bot |
| Local non-cloud signing requirements | Keep software ECDSA signer mode for local deployments |
| Memory consistency under new runtime path | Ensure memory writes are ledgered and replay-verifiable |

---

## Module Extraction Status (Chimera)

The codebase follows a modular extraction pattern. Each chimera module owns a single concern and is wired into `BaseT8.py` via `import_compat`. New modules can be added without touching the rest of the system.

| Phase | Modules | Status |
|---|---|---|
| Core infrastructure | `redis_runtime`, `ledger_primitives`, `ledger_write`, `content_store` | ✅ Complete |
| Identity & auth | `auth_identity`, `upstream_auth` | ✅ Complete |
| Policy plane | `policy_templates`, `policy_records`, `tenant_policy_store`, `policy_governance`, `policy_tool_scoping` | ✅ Complete |
| Risk engine | `risk_components`, `risk_decisions`, `apex_engine`, `drift_runtime` | ✅ Complete |
| Signing & ledger | `kms_signer`, `signing_runtime`, `signing_audit`, `ledger_s3_sync` | ✅ Complete |
| Alerting & IR | `siem_ir`, `metrics_runtime`, `governance_runtime` | ✅ Complete |
| Routing | `stream_preflight`, `streaming_runtime`, `control_plane_runtime`, `runtime_status_routes` | ✅ Complete |
| Provider management | `upstream_runtime`, `usage_runtime`, `secret_provider` | ✅ Complete |
| Threat intelligence | `threat_intel_store`, `dlp_semantic_store` | ✅ Complete |
| Operational | `startup_runtime`, `runtime_health`, `retention_policy` | ✅ Complete |
| Compliance | `rtbf_routes`, `env_config_governance`, `migration_protocol` | ✅ Complete |
| Runtime hardening | `idempotency_runtime`, `input_sanitizer`, `failure_taxonomy` | ✅ Complete |

---

## License

Proprietary. All rights reserved.
