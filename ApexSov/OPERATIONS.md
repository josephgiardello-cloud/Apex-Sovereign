# ApexSov Operations (Backup/Restore + DR)

This document covers:
- Backup/restore procedures (Redis + optional S3 offload)
- Redis snapshot strategy
- S3 recovery strategy
- Signer key rotation plan (AWS KMS / HSM)

Scope note: the append-only audit ledger is stored in Redis under `apex:audit_ledger`. Retention policies in this service apply only to **non-ledger** Redis state (e.g., session prompts, content store); the ledger itself is intended to be immutable and never deleted.

For local-only deployments, see `OFFLINE_QUICKSTART.md` and run `py -3 verify_chimera.py` before startup.

---

## 1) Backup / Restore Procedures

### 1.1 What must be backed up

**Tier 0 (critical for audit continuity)**
- Redis dataset containing:
  - `apex:audit_ledger` (append-only ledger list)
  - `apex:audit_checkpoints` (checkpoint list)
  - `apex:signing_queue` (unsigned signing backlog)
  - `apex:signed_ledger_buffer` (S3 flush buffer)

**Tier 1 (control plane / governance)**
- Policies and tenant metadata:
  - `apex:policy:*:current`, `apex:policy:*:history`
  - `apex:tenant:*:meta`
  - Proposal workflows:
    - `apex:policy:*:proposals*`
    - `apex:envcfg:*`

**Tier 2 (volatile / policy-retained state)**
- Session prompts and content stores (TTL-governed):
  - `session:{tenant}:{session}:prompts`
  - `apex:content:{tenant}:{kind}:{sha256}`
  - `apex:adversarial_corpus:{tenant}`
  - Threat intel and semantic DLP stores (tenant-scoped)

### 1.2 Recommended backup modes

Choose one (or both) depending on RPO/RTO and compliance.

**Option A (recommended): Managed Redis backups**
- Use the Redis provider’s snapshot + replication features.
- Ensure backups cover the full dataset, including lists/hashes.

**Option B: Self-hosted Redis persistence (RDB/AOF) + offsite copies**
- Enable Redis persistence:
  - RDB snapshots for point-in-time recovery
  - AOF for lower RPO (recommended for append-only ledgers)
- Copy `dump.rdb` and/or `appendonly.aof*` to immutable storage.

**Option C: Evidence export as an additional audit artifact (API)**
- Use the JSONL evidence export endpoint:
  - `GET /api/v1/audit/ledger/export?start_index=0&end_index=-1`
- Treat this as an **audit artifact** and secondary recovery source.

### 1.3 Restore procedure (Redis-first)

1) Provision a new Redis instance/cluster.
2) Restore persistence artifacts (provider snapshot, `dump.rdb`, and/or AOF).
3) Start the gateway with correct required env vars:
   - `APEX_ENV` in `{dev,stage,prod}`
   - `APEX_REDIS_URL` (TLS + auth required in PROD)
   - OIDC issuer/audience for authenticated routes
4) Validate integrity:
   - Redis-backed chain verify:
     - `python BaseT8.py --mode redis`
   - Optional: hit `GET /api/v1/audit/ledger/verify`
5) Validate signer health and backlog:
   - `GET /readyz`
   - `GET /governance_status`

If restore includes a large `apex:signing_queue`, consider letting the signing worker drain it (expected), or temporarily scaling signing workers.

---

## 2) Redis Snapshot Strategy

### 2.1 Goals
- Preserve the append-only audit ledger with minimal RPO.
- Keep restore deterministic and verifiable.
- Avoid partial snapshots that split ledger/checkpoints inconsistently.

### 2.2 Recommended configuration

**For ledger-heavy deployments:**
- Prefer **AOF** enabled (append-only file) for durability.
- Keep periodic **RDB** snapshots for fast full restores.

**Why:** the ledger is an append-only list; AOF provides strong durability for recent writes. RDB provides a compact base image.

### 2.3 Snapshot cadence (baseline)

Adjust for traffic and RPO requirements:
- RDB snapshots: every 15–60 minutes
- AOF: `everysec` (typical), or stricter if required and performance allows
- Offsite copy retention: at least 7–30 days (or per compliance)

### 2.4 Consistency notes

- The ledger’s integrity is hash-chained, so corruption/partial writes should be detectable via `--mode redis` verification.
- The service applies backpressure when unsigned signing backlog is too large; this is intentional to preserve audit integrity.

---

## 3) S3 Recovery Strategy

This service supports best-effort S3 offload of signed ledger entries (JSONL) and checkpoints.

### 3.1 What is stored in S3

If configured:
- **Signed ledger JSONL** (append batches):
  - Bucket: `APEX_LEDGER_S3_BUCKET`
  - Prefix: `APEX_LEDGER_S3_PREFIX` (default `ledger`)
  - Key pattern: `{prefix}/{region}/{YYYY-MM-DD}/audit.jsonl`

- **Checkpoints** (optional):
  - Bucket: `APEX_LEDGER_CHECKPOINT_BUCKET`
  - Key pattern: `checkpoints/{chain_id}/{ts}.json`

### 3.2 Recovery scenarios

**Scenario A: Redis lost, S3 intact (re-hydrate Redis)**
- Goal: repopulate Redis `apex:audit_ledger` from S3 JSONL.
- Approach:
  1) Restore newest S3 objects for the required date range.
  2) Rebuild Redis list by iterating JSONL lines and `RPUSH` into `apex:audit_ledger` in order.
  3) Run `python BaseT8.py --mode redis` to validate.

Operational note: If you rehydrate from S3, you may want to also restore `apex:audit_checkpoints` (optional), or let new checkpoints accrue after recovery.

**Scenario B: S3 lost, Redis intact**
- Primary integrity source remains Redis.
- Restore S3 buckets from their backup/replication (recommended: versioning + cross-region replication).

### 3.3 Verification of S3 offload integrity

- Verify end-to-end ledger chain from S3:
  - `python BaseT8.py --mode s3 --bucket <bucket> --prefix <prefix> --region <region>`

This recomputes the hash chain across the S3 JSONL stream.

### 3.4 S3 bucket hardening recommendations
- Enable bucket versioning.
- Enable Object Lock / WORM mode if required.
- Use SSE-KMS encryption.
- Restrict IAM so the gateway can write but not delete objects.

---

## 4) Signer Key Rotation Plan (AWS KMS / HSM)

### 4.1 Goals
- Rotate ECDSA signing keys without breaking verification of historical entries.
- Ensure auditors can verify old anchors and new anchors.

### 4.2 Current behavior (important)
- Each ledger entry stores `kid` and `alg`.
- The verifier endpoint returns `public_key_b64` (SPKI DER) for the anchor.
- Rotation requires the system to return the correct public key for the anchor’s `kid`.

### 4.3 Rotation procedure (recommended)

1) **Create a new KMS asymmetric ECDSA key** (same algorithm and usage).
2) **Deploy configuration change**:
   - Update `APEX_KMS_KEY_ID` to the new key id/arn.
   - Redeploy the gateway + signing worker(s).
3) **Keep the old key enabled** for a defined overlap window.
   - This allows verification of anchors signed with the old `kid`.
4) **Verify rotation**
   - Generate a new checkpoint/anchor window (or wait for checkpoint interval).
   - Call `GET /api/v1/verify/{entry_id}?verify_signature=true` for:
     - a pre-rotation anchor
     - a post-rotation anchor
   - Confirm `signature_verified=true` for both.
5) **Decommission old key**
   - After auditors confirm historical verification is complete and retention rules permit, disable scheduling or restrict the old key.

### 4.4 Operational controls
- Store `kid` as the full KMS key ARN (preferred) to avoid ambiguity.
- Ensure the runtime role has `kms:GetPublicKey` permission for both old and new keys during overlap.

### 4.5 Failure modes and mitigations

- **If old key is disabled too early:**
  - Historical anchor verification can fail because public key retrieval fails.
  - Mitigation: re-enable `kms:GetPublicKey` access or re-enable the old key.

- **If the new key uses a different algorithm:**
  - Verification will fail and may break audit workflows.
  - Mitigation: restrict key policy to enforce approved algorithms.

### 4.6 KMS key policy recommendations (signing)

Goal: ensure only the signing worker runtime identity can use `kms:Sign`, while a separate admin/security role manages the key.

Minimal permissions the **signing worker role** needs:
- `kms:Sign`
- `kms:GetPublicKey` (required for auditor verification workflows)
- `kms:DescribeKey`

Example key policy (sketch; tailor to your org):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableKeyAdmins",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<KMS_ADMIN_ROLE>"},
      "Action": [
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:DisableKey",
        "kms:EnableKey",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:TagResource",
        "kms:UntagResource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowGatewaySigningRole",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<APEX_SIGNING_ROLE>"},
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": "*"
    }
  ]
}
```

Hardening suggestions:
- Prefer a dedicated signing role/service account (Kubernetes IRSA) with *only* the above permissions.
- Keep key administration under a different role than runtime usage.
- If you use aliases for rotation, ensure `APEX_KMS_KEY_ID` is set to a stable key ARN/ID you intend to use.

### 4.7 Access logs for signing operations

Recommended sources of truth:
- **AWS CloudTrail** for KMS API calls (`Sign`, `GetPublicKey`, `DescribeKey`).
- Optional: forward CloudTrail to CloudWatch Logs / SIEM for alerting and retention.

In-service (best-effort, non-ledger) signing telemetry:
- The signing worker emits a bounded Redis stream `apex:signing:audit` (configurable) with success/failure, `kid`, and ledger index.
- Env knobs:
  - `APEX_SIGN_AUDIT_ENABLED` (default: `true`)
  - `APEX_SIGN_AUDIT_STREAM_KEY` (default: `apex:signing:audit`)
  - `APEX_SIGN_AUDIT_TTL_SECONDS` (default: 14 days)

HTTP summary endpoints (no direct Redis access required):

- **Admin** (any tenant / optional filter):
  - `GET /admin/signing/audit/summary?limit=50&tenant_id=<optional>`
  - Requires an admin/security role.

- **Auditor** (caller tenant only):
  - `GET /api/v1/audit/signing/audit/summary?limit=50`
  - Requires an audit role; results are automatically filtered to the caller’s tenant.

Notes:
- These are **best-effort telemetry** and should be treated as operational signals.
- The authoritative audit trail for KMS usage remains **CloudTrail**.

### 4.8 Dual-control for key usage (app-level guardrail)

This service supports **dual-control over key selection** (defense-in-depth) by requiring that the runtime `APEX_KMS_KEY_ID` matches a previously **approved** desired env-config proposal.

How it works:
- Enable: `APEX_KMS_DUAL_CONTROL=true`
- In PROD/FIPS modes, signing and readiness checks will fail-closed unless:
  1) an env-config proposal was approved (two-person rule), and
  2) the approved desired `APEX_KMS_KEY_ID` hash matches the runtime key id.

Operational flow:
1) Propose desired change via `POST /admin/env_config/proposals` including `APEX_KMS_KEY_ID`.
2) Approve via `POST /admin/env_config/proposals/{proposal_id}/approve` (must be a different actor).
3) Redeploy the gateway/signing workers with `APEX_KMS_KEY_ID` set to that approved value.

Important limitation:
- AWS KMS does not provide per-request human approval/quorum for `kms:Sign`; this feature enforces dual-control over which key the service is allowed to use.

---

## 5) DR Checklist (Quick)

- Redis restore complete (snapshot/AOF replay)
- `python BaseT8.py --mode redis` passes
- `GET /readyz` and `GET /governance_status` OK
- If using S3 offload: `python BaseT8.py --mode s3 ...` passes
- If recently rotated keys: verify both pre/post rotation anchors with `verify_signature=true`

---

## 6) Ingress / Egress Restrictions

### 6.1 Ingress (what can reach the gateway)

Recommended controls:
- Expose **only** the FastAPI service port (typically 443 via an ingress/load balancer).
- Restrict inbound sources to:
  - your approved ingress tier (ALB/NLB/ingress controller), and/or
  - a small allowlist of corporate CIDRs / service meshes.
- Treat these endpoints as the minimum externally reachable surface:
  - `GET /healthz` (liveness)
  - `GET /readyz` (readiness; may be used only internally)
- All other endpoints should be reachable only from trusted networks and already require OIDC auth + tenant binding.

Operational note: if you must expose auditor endpoints externally, restrict them by network policy **and** role (`auditor`/`security-auditor`/`compliance-auditor`).

### 6.2 Egress (what the gateway can call)

The gateway performs outbound calls for:
- OIDC JWKS fetch: `APEX_OIDC_ISSUER + /.well-known/jwks.json`
- Upstream LLM: `APEX_OPENAI_URL`
- Optional: AWS APIs (KMS for signing, S3 for offload/checkpoints)

Recommended controls:
- Default-deny egress at the VPC/subnet level.
- Allow egress only to:
  - your IdP/JWKS endpoint (internal/private if running no-internet)
  - your upstream LLM endpoint (private/internal if running no-internet)
  - AWS VPC endpoints for required services (KMS, S3) or approved NAT path
- Block all other destinations.

#### 6.2.1 Application-level sovereign egress policy (SSRF + exfil defense)

In addition to network-layer controls, ApexSov enforces a **defense-in-depth outbound URL policy** on its own HTTP call sites (LLM upstream + webhooks).

What this gives you:
- **SSRF/IMDS protection:** blocks outbound URLs whose hostname is a literal IP (IPv4/IPv6). This prevents trivial calls like `http://169.254.169.254/...`.
- **Exfiltration defense:** if you set an allowlist regex, outbound calls to non-allowlisted hosts are blocked.
- **Auditability:** blocked outbound attempts are best-effort written as `SOVEREIGN_EGRESS_BLOCK` entries into the Merkle-anchored ledger (when Redis is available and backpressure allows).

Environment variables:
- `APEX_EGRESS_BLOCK_IP_LITERALS` (default: `true`)
  - When `true`, blocks IP-literal hostnames.
- `APEX_EGRESS_ALLOWLIST_REGEX` (default: empty)
  - Empty means: no hostname allowlist is enforced (only IP-literal blocking applies).
  - If set, it is a comma-separated list of regex patterns matched against the **parsed hostname** (not the full URL).
  - Example pattern set aligned with a “sovereign/private” posture:
    - `(^|.*\\.)svc\\.cluster\\.local$,(^|.*\\.)amazonaws\\.com$,(^|.*\\.)corp\\.internal$,(^|.*\\.)openai\\.azure\\.com$`
- `APEX_EGRESS_AUDIT_BLOCKS` (default: `true`)
  - When `true`, emit `SOVEREIGN_EGRESS_BLOCK` into the ledger on each block (best-effort).

Operational notes:
- This is not a sandbox against arbitrary code execution; it constrains the gateway’s own outbound calls.
- For regulated environments, treat this as an additional guardrail and still enforce default-deny egress at the VPC + Kubernetes NetworkPolicy layers.

Validation helper (no outbound call is performed):
- `GET /admin/egress/validate?url=https://example.svc.cluster.local/path`
  - Returns `allowed` + `reason` + parsed hostname details.

---

## 7) VPC-Only Deployment Pattern

### 7.1 Goal

Run ApexSov fully private:
- No public IPs on tasks/nodes
- Ingress via private load balancer or internal ingress
- Egress constrained to VPC endpoints (preferred) or explicit proxies

### 7.2 Typical reference architecture

- **Private subnets**: run the ApexSov service + Redis.
- **Ingress**:
  - internal ALB/NLB (or service mesh gateway) -> ApexSov
- **Redis**:
  - private subnet, security-group restricted to ApexSov only
- **AWS APIs**:
  - VPC endpoints for `com.amazonaws.<region>.kms`
  - gateway endpoint for S3 or interface endpoint + PrivateLink pattern

---

## 8) No-Internet Mode

### 8.1 Definition

"No-internet" means:
- No route from the workload subnets to the public internet (no IGW/NAT), OR
- Egress is strictly limited to approved private endpoints and private AWS endpoints.

### 8.2 Requirements for ApexSov to function

To run without internet, you must ensure all required dependencies are reachable privately:
- `APEX_OIDC_ISSUER` must point to an internally reachable IdP/JWKS service.
- `APEX_OPENAI_URL` must point to an internally reachable LLM endpoint (e.g., a private model gateway) rather than a public SaaS URL.
- AWS dependencies must be reachable via VPC endpoints (KMS, optional S3).

Operational note: the code fetches JWKS over HTTP(S). If your IdP is not reachable privately, auth will fail.

### 8.3 Recommended enforcement

Infrastructure (preferred):
- Implement no-internet by network design (private subnets without NAT).

Application guardrail (optional):
- Set `APEX_NO_INTERNET=true` and fail startup if configured URLs look public.

---

## 9) TLS Enforcement

### 9.1 Ingress TLS

Terminate TLS at your ingress tier (recommended) or at the app.
- Require HTTPS-only listeners.
- Enforce modern cipher suites per your org standard.

### 9.2 Redis TLS

In PROD, ApexSov enforces:
- `APEX_REDIS_URL` must use `rediss://`
- Redis URL must include authentication (or be ACL-secured)

### 9.3 Upstream TLS

Configure upstream endpoints as `https://...` and restrict egress:
- OIDC issuer / JWKS endpoint
- `APEX_OPENAI_URL` (or your private LLM gateway URL)

### 9.4 AWS TLS

AWS SDK calls (KMS/S3) are HTTPS. Prefer VPC endpoints so traffic stays on AWS private networking.

---

## 10) AWS EKS (FIPS-Compliant) Pattern

This section is a practical checklist for running ApexSov on AWS EKS in a VPC-only posture.

### 10.1 Cluster posture (VPC-only)

- Prefer a **private EKS cluster** (private endpoint access enabled, public endpoint disabled or tightly CIDR-restricted).
- Run workloads in **private subnets** (no public IPs).
- Prefer **no NAT gateway** for true no-internet posture; rely on VPC endpoints.

### 10.2 Required outbound dependencies (plan these first)

ApexSov needs network access to:
- **Redis** (ElastiCache/MemoryDB/self-managed) inside the VPC
- **OIDC issuer / JWKS** (`APEX_OIDC_ISSUER`) reachable privately (internal IdP, PrivateLink, or in-cluster)
- **Upstream LLM** (`APEX_OPENAI_URL`) reachable privately (your private model gateway)
- **AWS APIs** as needed:
  - KMS for signing (PROD/FIPS)
  - optional S3 for ledger offload/checkpoints

If you enable `APEX_NO_INTERNET=true`, the service will fail-fast if any of:
- `APEX_OIDC_ISSUER`
- `APEX_OPENAI_URL`
- `APEX_ALERT_WEBHOOK_URL`
- `APEX_SIEM_WEBHOOK_URL`
appear to be public/internet endpoints.

### 10.3 VPC endpoints (typical)

For a VPC-only EKS deployment you typically need:
- Interface endpoints:
  - KMS (for signing)
  - STS (common for IRSA flows)
  - CloudWatch Logs (if using aws-for-fluent-bit or similar)
  - ECR API + ECR DKR (for pulling images)
- S3 gateway endpoint (or interface endpoint pattern) if you use S3 offload/checkpoints

Exact endpoints vary by region and logging/image strategy.

### 10.4 Ingress (internal ALB + TLS)

- Use the AWS Load Balancer Controller with an **internal** ALB.
- Terminate TLS at the ALB using ACM and enforce modern TLS policy.
- Restrict ALB security group inbound to approved CIDRs (corp networks, VPN, trusted peering).
- Restrict pod/service security groups to only accept traffic from the ALB.

### 10.5 Egress restrictions (Kubernetes + VPC)

Use defense-in-depth:
- **VPC/Security groups**: default-deny egress where possible; allow only Redis, IdP/JWKS, model gateway, and AWS endpoints.
- **Kubernetes NetworkPolicies**: restrict namespace egress so the ApexSov pods can only talk to:
  - kube-dns
  - Redis service
  - internal IdP/JWKS service
  - internal model gateway service
  - (optional) in-VPC SIEM collector

### 10.6 Redis TLS enforcement (PROD)

In production, ApexSov enforces Redis TLS:
- `APEX_REDIS_URL` must be `rediss://...`
- Redis must be authenticated (URL contains auth or is ACL-secured)

For ElastiCache/MemoryDB:
- enable in-transit encryption
- use AUTH/ACL per org policy

### 10.7 FIPS considerations (deployment)

FIPS compliance is a system property (OS + crypto modules + configuration). Operationally:
- Run nodes on a FIPS-capable OS image and enable FIPS mode per your platform standard.
- Ensure your container base image and OpenSSL/crypto stack aligns with your compliance requirements.
- Keep `APEX_FIPS_MODE=true` when you intend to require KMS signing and surface FIPS posture in `/fips_status`.

Note: application-level flags can’t guarantee FIPS compliance by themselves; validate using your platform’s compliance evidence.

---

## 11) Security Baseline (CIS + Patching + Supply Chain)

This section defines the *operational* controls expected around ApexSov.
It avoids quoting CIS benchmark text; treat it as an implementation checklist.

### 11.1 CIS benchmark alignment (baseline)

Target benchmarks (choose what matches your deployment):
- **OS**: CIS for your host OS (Ubuntu/RHEL/Amazon Linux) at Level 1 minimum.
- **Kubernetes** (if used): CIS Kubernetes Benchmark.
- **Container runtime** (if used): CIS Docker / CIS Container Runtime Benchmark.

Minimum alignment controls (practical checklist):
- **Least privilege**
  - Run the service as non-root where possible; drop Linux capabilities not required.
  - Restrict file system writes (read-only rootfs where possible).
  - Use a dedicated runtime identity (IRSA/workload identity) with minimum AWS permissions.
- **Network hardening**
  - Default-deny egress at the network layer (VPC + NetworkPolicy).
  - Restrict inbound sources (LB/ingress only) and keep `/readyz` internal.
- **Logging and time**
  - Ensure host time sync (NTP/chrony). Ledger timestamps are UTC and used in evidence exports.
  - Centralize logs and retain per compliance (gateway logs, CloudTrail, IdP audit logs).
- **Secure configuration management**
  - Store secrets in a secret manager (not plain env vars) where possible.
  - Treat policy/env-config change workflows as controlled change management.
- **Cryptographic posture**
  - In PROD, require TLS for Redis (`rediss://`) and authenticated access.
  - Prefer AWS KMS for signing; keep CloudTrail enabled.

### 11.2 OS patching policy

Scope: host OS images (VMs/nodes), base container images, and critical runtime packages.

Patch SLAs (recommended):
- **Critical (RCE/priv-esc in kernel, OpenSSL, glibc, container runtime)**: deploy fix within 7 days (sooner if exploited).
- **High**: deploy fix within 14 days.
- **Medium/Low**: deploy fix within 30–60 days.

Operational rules:
- Use immutable infrastructure: patch by rolling new images/nodes, not in-place where possible.
- Reboots are expected for kernel/runtime updates; schedule rolling reboots.
- Maintain an emergency patch path for actively exploited CVEs.
- Record evidence: change ticket + rollout window + post-change verification (`/readyz`, `/api/v1/audit/ledger/verify`).

### 11.3 Dependency vulnerability scanning

The repo includes a minimal dependency manifest at `requirements.txt` for scanning/CI.

CI workflow:
- GitHub Actions runs `pip-audit` on pushes/PRs via `.github/workflows/dependency-vulnerability-scan.yml`.

Local run:
- `python -m pip install -r requirements.txt`
- `python -m pip install pip-audit`
- `pip-audit -r requirements.txt`

Notes:
- Treat findings as release blockers when they affect internet-facing components, crypto, auth, HTTP clients, or Redis clients.
- Pin/lock dependencies in your production build pipeline if you require fully reproducible builds.

### 11.4 Container image signing

If you ship ApexSov as a container, sign images after push and verify at deploy time.

Recommended approach:
- **Cosign keyless** signing using CI OIDC identity (Sigstore).
- Enforce signature verification in your deploy pipeline (policy-as-code) before running workloads.

CI workflow:
- `.github/workflows/container-image-sign.yml` builds, pushes to **AWS ECR**, and signs the pushed digest.

Required GitHub repo configuration (for ECR push):
- `vars.AWS_ACCOUNT_ID` (12-digit AWS account id)
- `vars.AWS_REGION` (e.g., `us-east-1`)
- `vars.ECR_REPOSITORY` (e.g., `apexsov`)
- Recommended (OIDC): `secrets.AWS_ROLE_TO_ASSUME` (IAM role ARN; must allow ECR push for that repository)
- Fallback (not recommended): `secrets.AWS_ACCESS_KEY_ID` + `secrets.AWS_SECRET_ACCESS_KEY`

Verify (example):
- `cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>@<digest>`

ECR image reference format:
- `<aws_account_id>.dkr.ecr.<region>.amazonaws.com/<repository>@sha256:<digest>`

Notes:
- Signing must be done by digest (`<image>@sha256:...`), not by a mutable tag.
- Pair image signing with SBOM generation and provenance if your program requires it.


