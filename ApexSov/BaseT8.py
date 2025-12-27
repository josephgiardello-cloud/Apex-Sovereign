"""
Apex Sovereign Gateway – Unified Governance Proxy, Ledger, and Risk Engine

High-level architecture (single deployable, modular responsibilities):

- Proxy layer (FastAPI):
  - /v1/stream: tenant-aware LLM streaming proxy with inline risk evaluation
  - /admin/* and /api/v1/*: governance, policy, and CISO dashboard endpoints
  - /healthz, /readyz, /governance_status: operational health and governance status

- Governance model:
  - Subjects: OIDC-authenticated identities (TenantIdentity.subject, roles, scopes)
  - Tenants: Logical organizations (TenantMetadata.tenant_id)
  - Objects: LLM interactions (prompt/response text, sessions, policies)
  - Policies: Per-tenant, versioned risk configuration (PolicyStore)
  - Decisions: PASS/BLOCK + special RTBF markers; PII mode (block/redact)

- Security & risk engine:
  - Regex-based PII detection with tenant policy templates (DEFAULT/finance/healthcare/government)
  - Drift & grooming detection:
    - Redis BoW (baseline) or
    - Qdrant + OpenAI embeddings (vector drift backend)
  - Unified TONY score and axis thresholds for BLOCK/PASS decisions

- Ledger & integrity:
  - Append-only audit ledger in Redis ("apex:audit_ledger") with chained hashes
  - Asynchronous AWS KMS / HSM ECDSA signing via signing worker
  - Optional S3 JSONL offload with incremental checkpoints
  - Backpressure on unsigned queue to preserve audit integrity

- Identity & authorization:
  - OIDC/JWKS validation with cached JWKS (JwksCache)
  - Tenant binding via token claim and header consistency checks
  - Simple RBAC for high-risk models and admin APIs

This file is intentionally unified but organized into clearly separated sections
to make the architecture, data contracts, and governance model understandable
in a single pass.
"""

import asyncio
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional, List, Tuple, AsyncGenerator, Any, Protocol, Literal
from urllib.parse import urlparse
import ipaddress

import math
import re
import unicodedata
import ssl
from collections import Counter
import random

import numpy as np
import redis.asyncio as redis
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from jose import jwt
from jose.exceptions import JWTError
import requests
from pydantic import BaseModel
import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    VectorParams,
    Distance,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)

# =========================================================
# 0. GLOBAL CONFIG & CATALOG (DEPLOYMENT & MODEL MAP)
# =========================================================

POLICY_VERSION = os.getenv("APEX_POLICY_VERSION", "apex_v19.1.0")

# KMS / HSM config
HSM_KEY_ID = os.getenv("APEX_HSM_KEY_ID", "")
KMS_KEY_ID = os.getenv("APEX_KMS_KEY_ID", HSM_KEY_ID)
KMS_REGION = os.getenv("APEX_KMS_REGION", "")
APEX_FIPS_MODE = os.getenv("APEX_FIPS_MODE", "false").lower() == "true"

# Key usage governance
# - Dual-control is enforced by requiring the runtime KMS key id to match the
#   currently-approved desired env-config (stored redacted in Redis).
APEX_KMS_DUAL_CONTROL = os.getenv("APEX_KMS_DUAL_CONTROL", "false").lower() == "true"

# Signing access logs (best-effort, non-ledger; do NOT write these into the ledger to avoid recursion)
APEX_SIGN_AUDIT_ENABLED = os.getenv("APEX_SIGN_AUDIT_ENABLED", "true").lower() == "true"
APEX_SIGN_AUDIT_STREAM_KEY = os.getenv("APEX_SIGN_AUDIT_STREAM_KEY", "apex:signing:audit")
APEX_SIGN_AUDIT_TTL_SECONDS = int(os.getenv("APEX_SIGN_AUDIT_TTL_SECONDS", str(14 * 24 * 3600)))

# Government-grade fail-safe posture (FedRAMP/NIST-style): halt traffic if audit integrity is at risk.
APEX_FAILSAFE_GOV = os.getenv("APEX_FAILSAFE_GOV", "false").lower() == "true"
APEX_LEDGER_CAPACITY_FAIL_PCT = float(os.getenv("APEX_LEDGER_CAPACITY_FAIL_PCT", "0.80"))
APEX_SELF_TEST_INTERVAL_SECONDS = int(os.getenv("APEX_SELF_TEST_INTERVAL_SECONDS", str(24 * 3600)))

APEX_REDIS_URL_ENV = "APEX_REDIS_URL"
APEX_REGION = os.getenv("APEX_REGION", KMS_REGION or "us-east-1")
APEX_CHAIN_ID = os.getenv("APEX_CHAIN_ID", "main-net-01")

# Compliance lifecycle controls (retention governance)
APEX_COMPLIANCE_MODE = os.getenv("APEX_COMPLIANCE_MODE", "false").lower() == "true"
# When compliance mode is enabled, require TTLs for governed non-ledger stores.
APEX_COMPLIANCE_REQUIRE_TTLS = os.getenv("APEX_COMPLIANCE_REQUIRE_TTLS", "true").lower() == "true"
# Optional caps (seconds). If unset/0, no cap is applied.
APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS", "0"))
APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS", "0"))
APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS", "0"))

# RTBF (Right-to-be-forgotten) operational controls
# Proofs are anchored in the append-only ledger; this cache is convenience-only.
APEX_RTBF_PROOF_CACHE_TTL_SECONDS = int(os.getenv("APEX_RTBF_PROOF_CACHE_TTL_SECONDS", str(30 * 24 * 3600)))

# Optional: allow RTBF deletion of non-ledger S3 objects. This is fail-closed by default.
APEX_RTBF_S3_ALLOW = os.getenv("APEX_RTBF_S3_ALLOW", "false").lower() == "true"
APEX_RTBF_S3_BUCKET = os.getenv("APEX_RTBF_S3_BUCKET", "")

# Audit minimization
# Optional salt to reduce cross-system linkability of hashed fields in hash-only audit mode.
APEX_AUDIT_HASH_SALT = os.getenv("APEX_AUDIT_HASH_SALT", "")

# OIDC / IdP config
OIDC_ISSUER = os.getenv("APEX_OIDC_ISSUER", "")
OIDC_AUDIENCE = os.getenv("APEX_OIDC_AUDIENCE", "")
OIDC_TENANT_CLAIM = os.getenv("APEX_OIDC_TENANT_CLAIM", "tid")
JWKS_CACHE_TTL_SECONDS = int(os.getenv("APEX_JWKS_CACHE_TTL_SECONDS", "300"))

# Ledger checkpointing
LEDGER_CHAIN_ID = os.getenv("APEX_LEDGER_CHAIN_ID", "apex-audit-ledger")
LEDGER_CHECKPOINT_INTERVAL = int(os.getenv("APEX_LEDGER_CHECKPOINT_INTERVAL", "100"))
LEDGER_CHECKPOINT_BUCKET = os.getenv("APEX_LEDGER_CHECKPOINT_BUCKET", "")
LEDGER_S3_BUCKET = os.getenv("APEX_LEDGER_S3_BUCKET", "")
LEDGER_S3_PREFIX = os.getenv("APEX_LEDGER_S3_PREFIX", "ledger")

# Async signing queue
SIGNING_QUEUE_KEY = os.getenv("APEX_SIGNING_QUEUE_KEY", "apex:signing_queue")
MAX_UNSIGNED_QUEUE = int(os.getenv("APEX_MAX_UNSIGNED_QUEUE", "1000"))
UNSIGNED_WARN_FRACTION = float(os.getenv("APEX_UNSIGNED_WARN_FRACTION", "0.7"))

# Upstream LLM
OPENAI_URL = os.getenv("APEX_OPENAI_URL", "https://api.openai.com/v1/chat/completions")
REQUEST_SEM = asyncio.Semaphore(int(os.getenv("APEX_MAX_CONCURRENT", "64")))

# Drift backend selection
APEX_DRIFT_BACKEND = os.getenv("APEX_DRIFT_BACKEND", "redis").lower()

# Qdrant config
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_API_KEY = os.getenv("QDRANT_API_KEY", "")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "apex_drift")

# Embeddings config
APEX_EMBEDDING_MODEL = os.getenv("APEX_EMBEDDING_MODEL", "text-embedding-3-small")

# Semantic DLP (Option B): embed & compare against per-tenant exemplars.
APEX_DLP_SEMANTIC_ENABLED = os.getenv("APEX_DLP_SEMANTIC_ENABLED", "false").lower() == "true"
APEX_DLP_SEMANTIC_MAX_EXEMPLARS = int(os.getenv("APEX_DLP_SEMANTIC_MAX_EXEMPLARS", "200"))

# Global policy anchor text for drift (vector backend)
GLOBAL_POLICY_TEXT = os.getenv(
    "APEX_GLOBAL_POLICY_TEXT",
    "This is a standard, safe, professional corporate assistant that follows compliance and does not discuss prohibited topics.",
)

# Alerting
ALERT_WEBHOOK_URL = os.getenv("APEX_ALERT_WEBHOOK_URL", "")
ALERT_MIN_TONY_SCORE = float(os.getenv("APEX_ALERT_MIN_TONY_SCORE", "0.8"))

# SIEM integration (optional): best-effort outbound webhook with redacted payload.
APEX_SIEM_WEBHOOK_URL = os.getenv("APEX_SIEM_WEBHOOK_URL", "")
APEX_SIEM_WEBHOOK_HEADERS_JSON = os.getenv("APEX_SIEM_WEBHOOK_HEADERS_JSON", "")
APEX_SIEM_TIMEOUT_SECONDS = float(os.getenv("APEX_SIEM_TIMEOUT_SECONDS", "5.0"))
APEX_SIEM_SEND_ALL = os.getenv("APEX_SIEM_SEND_ALL", "false").lower() == "true"

# Alert correlation window: coalesce repeated alerts for the same tenant/session/reason.
APEX_ALERT_CORRELATION_WINDOW_SECONDS = int(os.getenv("APEX_ALERT_CORRELATION_WINDOW_SECONDS", "900"))

# Optional no-internet posture (defense-in-depth). Prefer enforcing this at the network layer.
APEX_NO_INTERNET = os.getenv("APEX_NO_INTERNET", "false").lower() == "true"

# Sovereign egress policy (defense-in-depth against SSRF/exfil via misconfig or future features).
# This is NOT a sandbox against arbitrary code execution; it enforces outbound URL checks
# on the gateway's own egress code paths.
APEX_EGRESS_ALLOWLIST_REGEX = os.getenv("APEX_EGRESS_ALLOWLIST_REGEX", "").strip()
APEX_EGRESS_BLOCK_IP_LITERALS = os.getenv("APEX_EGRESS_BLOCK_IP_LITERALS", "true").lower() == "true"
APEX_EGRESS_AUDIT_BLOCKS = os.getenv("APEX_EGRESS_AUDIT_BLOCKS", "true").lower() == "true"


def _is_sensitive_env_key(name: str) -> bool:
    n = (name or "").upper()
    # Conservative heuristic: treat any key-like or secret-like env var as sensitive.
    return any(tok in n for tok in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE", "CREDENTIAL", "AUTH"))


def _redact_env_value(name: str, value: str) -> Dict[str, Any]:
    """Return a redacted representation of an env var value.

    We avoid returning raw secrets. Instead we include a stable hash so operators
    can detect changes over time without revealing the underlying value.
    """
    v = value if isinstance(value, str) else str(value)
    return {
        "redacted": True,
        "sha256": hashlib.sha256(v.encode("utf-8")).hexdigest(),
        "len": len(v),
    }


def _collect_env_config_snapshot() -> Dict[str, Any]:
    """Collect a redacted snapshot of relevant runtime environment configuration.

    Notes:
    - This does NOT attempt to mutate environment variables.
    - It is intended for change management: versioning + audit visibility.
    """
    # Prefer APEX_* knobs plus a few known integration toggles.
    allow_prefixes = ("APEX_", "OIDC_", "QDRANT_", "OPENAI_")
    deny_exact = {
        # Avoid emitting full URLs that may contain embedded credentials.
        "APEX_REDIS_URL",
        # Common secret env vars (still hashed/redacted by heuristic; deny list adds defense-in-depth).
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    }

    raw: Dict[str, str] = {}
    for k, v in os.environ.items():
        if k in deny_exact:
            continue
        if not any(k.startswith(p) for p in allow_prefixes):
            continue
        raw[k] = v

    # Add explicitly-validated core vars (redacted where appropriate).
    raw.setdefault("APEX_ENV", os.getenv("APEX_ENV", ""))
    # Capture presence/shape of Redis URL without leaking value.
    redis_url = os.getenv("APEX_REDIS_URL", "")
    raw["APEX_REDIS_URL_PRESENT"] = "true" if bool(redis_url) else "false"
    raw["APEX_REDIS_URL_SCHEME"] = redis_url.split("://", 1)[0] if "://" in redis_url else ""

    redacted_vars: Dict[str, Any] = {}
    for k in sorted(raw.keys()):
        v = raw[k]
        if _is_sensitive_env_key(k):
            redacted_vars[k] = _redact_env_value(k, v)
        else:
            # Still avoid dumping long values into the snapshot.
            sv = v if isinstance(v, str) else str(v)
            if len(sv) > 512:
                redacted_vars[k] = {
                    "redacted": True,
                    "sha256": hashlib.sha256(sv.encode("utf-8")).hexdigest(),
                    "len": len(sv),
                }
            else:
                redacted_vars[k] = {"redacted": False, "value": sv}

    snapshot = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "env": get_apex_env().value,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
        "vars": redacted_vars,
    }

    # Compute a stable version hash over a canonical representation.
    version_material = json.dumps(snapshot["vars"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    snapshot["config_version"] = hashlib.sha256(version_material).hexdigest()
    snapshot["hash_alg"] = "sha256"
    return snapshot


ENV_CONFIG_SNAPSHOT: Dict[str, Any] = {}
try:
    # Best-effort: avoid breaking import-time sanity checks.
    ENV_CONFIG_SNAPSHOT = _collect_env_config_snapshot()
except Exception:
    ENV_CONFIG_SNAPSHOT = {}


class ApexEnv(str, Enum):
    DEV = "dev"
    STAGE = "stage"
    PROD = "prod"


def get_apex_env() -> ApexEnv:
    raw = os.getenv("APEX_ENV", "").lower().strip()
    if raw not in {e.value for e in ApexEnv}:
        raise RuntimeError(f"Invalid APEX_ENV={raw!r}, must be one of {[e.value for e in ApexEnv]}")
    return ApexEnv(raw)


def is_prod() -> bool:
    return get_apex_env() == ApexEnv.PROD


def validate_env_sanity() -> None:
    """
    Basic safety guardrail: ensure APEX_ENV and cluster role are consistent.
    Prevents accidentally running non-prod configuration in a prod cluster.
    """
    env = get_apex_env()
    cluster_role = os.getenv("APEX_CLUSTER_ROLE", "unknown").lower()
    if "prod" in cluster_role and env != ApexEnv.PROD:
        raise RuntimeError(f"Forbidden configuration: cluster_role={cluster_role} with APEX_ENV={env.value}")


def _is_likely_public_hostname(url: str) -> bool:
    """Heuristic guardrail for no-internet mode.

    This is intentionally conservative and is not a substitute for real network egress controls.
    """
    u = (url or "").strip().lower()
    if not u:
        return False
    # Explicitly treat common public SaaS endpoints as "internet".
    if "api.openai.com" in u:
        return True
    # If an operator points at localhost or a private hostname, treat as non-public.
    if "://localhost" in u or "://127.0.0.1" in u or "://[::1]" in u:
        return False
    # If it looks like a raw RFC1918 address, treat as private.
    # (Lightweight: avoid importing ipaddress; keep it simple.)
    if "://10." in u or "://192.168." in u:
        return False
    if "://172." in u:
        # 172.16.0.0/12
        try:
            rest = u.split("://", 1)[1]
            host = rest.split("/", 1)[0].split(":", 1)[0]
            if host.startswith("172."):
                octets = host.split(".")
                if len(octets) >= 2:
                    b = int(octets[1])
                    if 16 <= b <= 31:
                        return False
        except Exception:
            pass
    # Default: assume public.
    return True


def validate_no_internet_posture() -> None:
    """Fail-fast if APEX_NO_INTERNET is enabled but config implies public egress."""
    if not APEX_NO_INTERNET:
        return
    # JWKS and upstream LLM are the two explicit outbound URLs.
    if _is_likely_public_hostname(OIDC_ISSUER):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_OIDC_ISSUER appears to be a public endpoint")
    if _is_likely_public_hostname(OPENAI_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_OPENAI_URL appears to be a public endpoint")

    # Optional outbound webhooks (alerts/SIEM) can accidentally violate no-internet posture.
    if _is_likely_public_hostname(ALERT_WEBHOOK_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_ALERT_WEBHOOK_URL appears to be a public endpoint")
    if _is_likely_public_hostname(APEX_SIEM_WEBHOOK_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_SIEM_WEBHOOK_URL appears to be a public endpoint")


_EGRESS_ALLOWLIST_CACHE: Optional[List[re.Pattern]] = None


def _compile_egress_allowlist_patterns() -> List[re.Pattern]:
    """Compile regex allowlist patterns for outbound URLs.

    Env: APEX_EGRESS_ALLOWLIST_REGEX
    - Empty => allow all (except explicit IP-literal blocks if enabled)
        - Otherwise: comma-separated list of regex patterns matched against the URL hostname
            (e.g., '(^|.*\\.)svc\\.cluster\\.local$')
    """
    global _EGRESS_ALLOWLIST_CACHE
    if _EGRESS_ALLOWLIST_CACHE is not None:
        return _EGRESS_ALLOWLIST_CACHE

    raw = (APEX_EGRESS_ALLOWLIST_REGEX or "").strip()
    if not raw:
        _EGRESS_ALLOWLIST_CACHE = []
        return _EGRESS_ALLOWLIST_CACHE

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    compiled: List[re.Pattern] = []
    for p in parts:
        try:
            compiled.append(re.compile(p))
        except re.error:
            # Fail closed: invalid pattern disables startup.
            raise RuntimeError("Invalid regex in APEX_EGRESS_ALLOWLIST_REGEX")

    _EGRESS_ALLOWLIST_CACHE = compiled
    return compiled


def _is_ip_literal_hostname(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def _egress_check_url(url: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Return (allowed, reason, details) for an outbound URL."""
    u = (url or "").strip()
    if not u:
        return False, "empty_url", {}

    try:
        parsed = urlparse(u)
    except Exception:
        return False, "invalid_url", {}

    scheme = (parsed.scheme or "").lower()
    hostname = parsed.hostname
    port = parsed.port

    details = {
        "scheme": scheme,
        "host": hostname,
        "port": port,
        "path_len": len(parsed.path or ""),
    }

    if scheme not in {"https", "http"}:
        return False, "unsupported_scheme", details

    if not hostname:
        return False, "missing_hostname", details

    if APEX_EGRESS_BLOCK_IP_LITERALS and _is_ip_literal_hostname(hostname):
        # Blocks IMDS style SSRF (e.g., http://169.254.169.254/...).
        return False, "ip_literal_blocked", details

    patterns = _compile_egress_allowlist_patterns()
    if patterns:
        host = str(hostname or "")
        if not any(p.search(host) for p in patterns):
            return False, "allowlist_mismatch", details

    return True, "allowed", details


def validate_egress_config_or_raise() -> None:
    """Validate configured outbound endpoints against sovereign egress policy."""
    # Compile patterns early (invalid patterns => fail fast).
    _compile_egress_allowlist_patterns()

    # Validate only configured outbound URLs.
    urls: List[Tuple[str, str]] = []
    if OIDC_ISSUER:
        urls.append(("oidc_issuer", OIDC_ISSUER))
        urls.append(("oidc_jwks", OIDC_ISSUER.rstrip("/") + "/.well-known/jwks.json"))
    if OPENAI_URL:
        urls.append(("upstream_llm", OPENAI_URL))
    if ALERT_WEBHOOK_URL:
        urls.append(("alert_webhook", ALERT_WEBHOOK_URL))
    if APEX_SIEM_WEBHOOK_URL:
        urls.append(("siem_webhook", APEX_SIEM_WEBHOOK_URL))

    for purpose, u in urls:
        ok, reason, _ = _egress_check_url(u)
        if not ok:
            raise RuntimeError(f"Egress blocked by policy for {purpose}: {reason}")


async def _audit_egress_block(
    r: Optional[redis.Redis],
    *,
    tenant_id: Optional[str],
    session_id: Optional[str],
    subject: Optional[str],
    roles: Optional[List[str]],
    purpose: str,
    url: str,
    reason: str,
    details: Dict[str, Any],
) -> None:
    if not APEX_EGRESS_AUDIT_BLOCKS:
        return
    if r is None:
        return

    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id or "unknown",
        "session_id": session_id,
        "decision": "SOVEREIGN_EGRESS_BLOCK",
        "action": str(purpose or "EGRESS"),
        "reason": reason,
        "blocked_url_sha256": hashlib.sha256((url or "").encode("utf-8")).hexdigest(),
        "blocked_url": {
            "scheme": details.get("scheme"),
            "host": details.get("host"),
            "port": details.get("port"),
            "path_len": details.get("path_len"),
        },
        "subject": subject,
        "roles": roles or [],
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }

    # Best-effort: record into the Merkle-anchored ledger.
    try:
        await create_unsigned_ledger_entry(r, payload)
    except LedgerBackpressureError:
        pass
    except Exception:
        pass


async def enforce_sovereign_egress_or_raise(
    r: Optional[redis.Redis],
    *,
    tenant_id: Optional[str],
    session_id: Optional[str],
    subject: Optional[str],
    roles: Optional[List[str]],
    purpose: str,
    url: str,
) -> None:
    ok, reason, details = _egress_check_url(url)
    if ok:
        return
    await _audit_egress_block(
        r,
        tenant_id=tenant_id,
        session_id=session_id,
        subject=subject,
        roles=roles,
        purpose=purpose,
        url=url,
        reason=reason,
        details=details,
    )
    raise HTTPException(status_code=503, detail=f"Sovereign egress blocked: {reason}")


validate_env_sanity()
validate_no_internet_posture()
validate_egress_config_or_raise()

# Internal model catalog and map to upstream identifiers.
MODEL_CATALOG = {
    "safe-small": {"id": "llama-guard-safe-small", "tier": "SAFE"},
    "default-mid": {"id": "gpt-4o", "tier": "DEFAULT"},
    "cheap-mini": {"id": "gpt-4o-mini", "tier": "CHEAP"},
    "reasoning-pro": {"id": "gpt-4o-2024-08-06", "tier": "DEFAULT"},
}

EXTERNAL_MODEL_MAP = {
    "gpt-4o": "default-mid",
    "gpt-4o-mini": "cheap-mini",
    "o1-preview": "reasoning-pro",
}

INTERNAL_TO_EXTERNAL_MODEL = {
    "default-mid": "gpt-4o",
    "cheap-mini": "gpt-4o-mini",
    "safe-small": "llama-guard-safe-small",
    "reasoning-pro": "o1-preview",
}

# =========================================================
# 1. TELEMETRY & SECRETS (CROSS-CUTTING)
# =========================================================

try:
    from opentelemetry import trace

    tracer = trace.get_tracer("sovereign.apex")

    def tracing_available() -> bool:
        return True

except Exception:
    class _NoOpTracer:
        def start_as_current_span(self, name: str):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    tracer = _NoOpTracer()

    def tracing_available() -> bool:
        return False


class SecretProvider:
    """
    Simple secret abstraction for upstream providers.
    In a more complete deployment this could be backed by a KMS/secret manager.
    """

    async def get_openai_key(self) -> str:
        return os.getenv("OPENAI_API_KEY", "")

    async def get_anthropic_key(self) -> str:
        return os.getenv("ANTHROPIC_API_KEY", "")


secret_provider = SecretProvider()

# =========================================================
# 2. REDIS HARDENING, WORKER COORDINATION, LEDGER STORAGE
# =========================================================

_GLOBAL_REDIS_CLIENT: Optional[redis.Redis] = None


def build_redis_url() -> str:
    base = os.getenv(APEX_REDIS_URL_ENV, "")
    if not base:
        raise RuntimeError(f"{APEX_REDIS_URL_ENV} must be set")

    env = get_apex_env()
    if env == ApexEnv.PROD:
        if not base.startswith("rediss://"):
            raise RuntimeError("Redis in PROD must use TLS (rediss://)")
        if "@" not in base:
            raise RuntimeError("Redis in PROD must include authentication in URL or be ACL-secured")
    return base


async def get_redis_client() -> redis.Redis:
    """
    Global async Redis client with basic production sanity checks.
    """
    global _GLOBAL_REDIS_CLIENT
    if _GLOBAL_REDIS_CLIENT is not None:
        return _GLOBAL_REDIS_CLIENT

    url = build_redis_url()
    use_ssl = url.startswith("rediss://")
    _GLOBAL_REDIS_CLIENT = redis.from_url(url, decode_responses=True, ssl=use_ssl)
    return _GLOBAL_REDIS_CLIENT


MAX_WORKER_ID = 1023
WORKER_LEASE_TTL = 60
WORKER_ID_RETRIES = 16


async def get_worker_id(r: redis.Redis) -> int:
    """
    Snowflake-style worker ID lease using Redis with retry and backoff.
    Ensures multiple workers can coordinate without collisions.
    """
    for attempt in range(WORKER_ID_RETRIES):
        val = await r.incr("snowflake:next_worker_id")
        candidate = int(val) & MAX_WORKER_ID
        lease_key = f"snowflake:lease:{candidate}"
        ok = await r.set(lease_key, "1", ex=WORKER_LEASE_TTL, nx=True)
        if ok:
            return candidate
        await asyncio.sleep(0.05 * (attempt + 1))
    raise RuntimeError("Unable to allocate worker_id: all IDs appear leased (possible DoS or misconfig)")


async def write_raw_ledger_entry(r: redis.Redis, entry: Dict[str, Any]) -> int:
    encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    length = await r.rpush("apex:audit_ledger", encoded)
    return length


async def read_raw_ledger_entry(r: redis.Redis, index: int) -> Optional[Dict[str, Any]]:
    raw = await r.lindex("apex:audit_ledger", index)
    if not raw:
        return None
    return json.loads(raw)


async def update_raw_ledger_entry(r: redis.Redis, index: int, entry: Dict[str, Any]) -> None:
    encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    await r.lset("apex:audit_ledger", index, encoded)


async def enqueue_for_signing(r: redis.Redis, index: int) -> None:
    await r.rpush(SIGNING_QUEUE_KEY, str(index))


async def write_checkpoint(r: redis.Redis, checkpoint: Dict[str, Any]) -> None:
    """
    Write a checkpoint into Redis and optionally S3 for independent verification.
    """
    encoded = json.dumps(checkpoint, separators=(",", ":"), sort_keys=True)
    await r.rpush("apex:audit_checkpoints", encoded)

    bucket = LEDGER_CHECKPOINT_BUCKET
    if bucket:
        def _put():
            s3 = boto3.client("s3")
            key = f"checkpoints/{checkpoint['chain_id']}/{checkpoint['ts']}.json"
            s3.put_object(Bucket=bucket, Key=key, Body=encoded.encode("utf-8"))

        await asyncio.to_thread(_put)

# =========================================================
# 2b. POLICY STORE, TEMPLATES & TENANT METADATA
# =========================================================

# Domain-specific PII augmentations per industry template
FINANCE_SPECIFIC_PATTERNS = [
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
    r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
]

HEALTHCARE_SPECIFIC_PATTERNS = [
    r"\bMRN[:\s]*[A-Za-z0-9\-]{4,20}\b",
    r"\b(patient|member)\s*id[:\s]*[A-Za-z0-9\-]{4,20}\b",
]

GOVERNMENT_SPECIFIC_PATTERNS = [
    r"\bpassport\s*no[:\s]*[A-Za-z0-9]{6,15}\b",
    r"\bnational\s*id[:\s]*[A-Za-z0-9\-]{4,20}\b",
]

DEFAULT_POLICY_BASELINE = {
    "unified_thresh": 0.65,
    "axis_thresholds": {
        "pii": 0.2,
        "jailbreak": 0.3,
        "grooming": 0.3,
        # Optional high-risk/DLP axis. Default is disabled (0.0).
        "dlp": 0.0,
        # Optional semantic DLP axis (embedding similarity to exemplars). Default disabled.
        "dlp_semantic": 0.0,
    },
    "risk_weights": {
        "pii": 1.0,
        "jailbreak": 1.2,
        "grooming": 0.8,
        "toxicity": 0.5,
        "drift": 0.3,
        "dlp": 0.9,
        "dlp_semantic": 1.0,
    },
    "pii_patterns": [
        # email
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}\b",
        # SSN
        r"\b\d{3}-\d{2}-\d{4}\b",
        # phone
        r"\b(?:\+1[\s\-_.]*)?(?:\(?\d{3}\)?|\d{3})[\s\-_.]?\d{3}[\s\-_.]?\d{4}\b",
        # generic card-like
        r"\b(?:\d[\s\-_.]?){13,19}\b",
        # address-ish
        r"\b\d{1,5}\s+\w+\s+(street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr)\b",
    ],
    "pii_mode": "block",  # or "redact"
    # Multimodal guardrail: this gateway only supports text inspection.
    # If false, any non-text message content will be rejected.
    "allow_multimodal": False,

    # Retention applies only to non-ledger state in Redis.
    # Ledger is append-only and is never deleted by retention.
    "retention": {
        "session_prompts_ttl_seconds": 180 * 24 * 3600,
        "adversarial_corpus_ttl_seconds": 365 * 24 * 3600,
        "content_store_ttl_seconds": 365 * 24 * 3600,
    },

    # Data minimization controls (tenant-configurable).
    # - no_content_retention: disables storing raw prompts and any deduped content derived from prompts.
    # - audit_mode: controls how identifiers/context are recorded to the append-only audit ledger.
    #   Supported: full | hash_only | redacted_only
    "data_minimization": {
        "no_content_retention": False,
        "audit_mode": "full",
        "include_subject": True,
        "include_session_id": True,
        "include_request_context": True,
    },
}

POLICY_TEMPLATE_MAP: Dict[str, Dict[str, Any]] = {
    "default": DEFAULT_POLICY_BASELINE,
    "finance": {
        "unified_thresh": 0.75,
        "axis_thresholds": {
            "pii": 0.1,
            "jailbreak": 0.2,
            "grooming": 0.3,
            # Finance: enable a stricter high-risk/DLP threshold.
            "dlp": 0.25,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + FINANCE_SPECIFIC_PATTERNS,
        # Finance: per-tenant model allowlist and retention defaults.
        # Note: ledger is append-only; these TTLs apply only to non-ledger stores.
        "model_allowlist": ["safe-small", "default-mid", "reasoning-pro"],
        "retention": {
            # Typical finance evidence retention is 5–7y for immutable audit logs.
            # Prompt/session stores are usually much shorter to reduce sensitive-data exposure.
            "session_prompts_ttl_seconds": 180 * 24 * 3600,
            "adversarial_corpus_ttl_seconds": 365 * 24 * 3600,
            "content_store_ttl_seconds": 365 * 24 * 3600,
        },
        "data_minimization": DEFAULT_POLICY_BASELINE.get("data_minimization") or {},
        "evidence_retention_years": 7,
    },
    "healthcare": {
        "unified_thresh": 0.7,
        "axis_thresholds": {
            "pii": 0.15,
            "jailbreak": 0.25,
            "grooming": 0.3,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + HEALTHCARE_SPECIFIC_PATTERNS,
        "retention": DEFAULT_POLICY_BASELINE.get("retention") or {},
        "data_minimization": DEFAULT_POLICY_BASELINE.get("data_minimization") or {},
    },
    "government": {
        "unified_thresh": 0.8,
        "axis_thresholds": {
            "pii": 0.1,
            "jailbreak": 0.2,
            "grooming": 0.25,
        },
        "risk_weights": DEFAULT_POLICY_BASELINE["risk_weights"],
        "pii_mode": "block",
        "pii_patterns": DEFAULT_POLICY_BASELINE["pii_patterns"] + GOVERNMENT_SPECIFIC_PATTERNS,
        "retention": DEFAULT_POLICY_BASELINE.get("retention") or {},
        "data_minimization": DEFAULT_POLICY_BASELINE.get("data_minimization") or {},
    },
}


def _coerce_positive_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            iv = int(v)
        else:
            iv = int(str(v).strip())
        if iv <= 0:
            return None
        return iv
    except Exception:
        return None


def _effective_retention_seconds(policy: Dict[str, Any], key: str) -> int:
    """Return an enforceable TTL (seconds) for a governed non-ledger store.

    - Falls back to DEFAULT_POLICY_BASELINE['retention'] if missing/invalid.
    - If APEX_COMPLIANCE_MODE and APEX_COMPLIANCE_REQUIRE_TTLS, ensures TTL > 0.
    - Optionally applies compliance max caps when configured.
    """
    baseline = (DEFAULT_POLICY_BASELINE.get("retention") or {})
    retention = policy.get("retention") if isinstance(policy, dict) else None
    if not isinstance(retention, dict):
        retention = {}

    ttl = _coerce_positive_int(retention.get(key))
    if ttl is None:
        ttl = _coerce_positive_int(baseline.get(key)) or 0

    if APEX_COMPLIANCE_MODE and APEX_COMPLIANCE_REQUIRE_TTLS:
        # If still unset/invalid, treat it as non-compliant but enforce a baseline TTL.
        if ttl <= 0:
            ttl = _coerce_positive_int(baseline.get(key)) or 0

    # Apply optional caps.
    cap = 0
    if key == "session_prompts_ttl_seconds":
        cap = int(APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS or 0)
    elif key == "adversarial_corpus_ttl_seconds":
        cap = int(APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS or 0)
    elif key == "content_store_ttl_seconds":
        cap = int(APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS or 0)
    if cap > 0 and ttl > cap:
        ttl = cap

    return int(ttl or 0)


def _validate_retention_policy_or_raise(policy: Dict[str, Any]) -> None:
    """Compliance-mode validator for policy retention fields."""
    if not APEX_COMPLIANCE_MODE:
        return
    if not APEX_COMPLIANCE_REQUIRE_TTLS:
        return

    retention = policy.get("retention")
    if not isinstance(retention, dict):
        raise HTTPException(status_code=400, detail="Compliance mode: policy.retention must be provided")

    required = [
        "session_prompts_ttl_seconds",
        "adversarial_corpus_ttl_seconds",
        "content_store_ttl_seconds",
    ]
    missing: List[str] = []
    for k in required:
        if _coerce_positive_int(retention.get(k)) is None:
            missing.append(k)
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Compliance mode: retention TTLs must be > 0 for: {', '.join(missing)}",
        )


class PolicyRecord(BaseModel):
    """
    Versioned tenant policy record, with provenance and free-form comment.
    """
    version: str
    policy: Dict[str, Any]
    created_at: str
    created_by: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None
    # Optional governance metadata for two-person change control.
    change_request_id: Optional[str] = None
    proposal_id: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None


class PolicyStore:
    """
    Per-tenant policy store on Redis:
    - current policy key
    - append-only history list
    """

    def __init__(self, r: redis.Redis):
        self.r = r

    def _current_key(self, tenant_id: str) -> str:
        return f"apex:policy:{tenant_id}:current"

    def _history_key(self, tenant_id: str) -> str:
        return f"apex:policy:{tenant_id}:history"

    async def get_policy_record(self, tenant_id: str) -> PolicyRecord:
        raw = await self.r.get(self._current_key(tenant_id))
        if not raw:
            raise HTTPException(status_code=404, detail="Policy not found for tenant")
        data = json.loads(raw)
        return PolicyRecord(**data)

    async def get_policy_or_seed(self, tenant_id: str, seed_policy: Dict[str, Any]) -> PolicyRecord:
        """
        Fetch current policy or seed from template if tenant has no explicit policy yet.
        """
        raw = await self.r.get(self._current_key(tenant_id))
        if raw:
            data = json.loads(raw)
            return PolicyRecord(**data)
        record = PolicyRecord(
            version=POLICY_VERSION,
            policy=seed_policy,
            created_at=datetime.utcnow().isoformat() + "Z",
            created_by="system",
            comment="seed_from_template",
        )
        await self.set_policy(tenant_id, record, is_new=True)
        return record

    async def set_policy(self, tenant_id: str, record: PolicyRecord, is_new: bool = False) -> None:
        """
        Set current policy and optionally push prior policy to history.
        """
        key = self._current_key(tenant_id)
        hist_key = self._history_key(tenant_id)

        async with self.r.pipeline(transaction=True) as pipe:
            if not is_new:
                current_raw = await self.r.get(key)
                if current_raw:
                    await pipe.rpush(hist_key, current_raw)
            await pipe.set(key, record.json())
            await pipe.execute()

    async def list_versions(self, tenant_id: str) -> List[PolicyRecord]:
        history = await self.r.lrange(self._history_key(tenant_id), 0, -1)
        out: List[PolicyRecord] = []
        for h in history:
            try:
                out.append(PolicyRecord(**json.loads(h)))
            except Exception:
                continue
        try:
            current = await self.get_policy_record(tenant_id)
            out.append(current)
        except Exception:
            pass
        return out

    async def rollback_to_version(self, tenant_id: str, version: str, actor: str) -> PolicyRecord:
        history = await self.r.lrange(self._history_key(tenant_id), 0, -1)
        for h in reversed(history):
            data = json.loads(h)
            if data.get("version") == version:
                record = PolicyRecord(**data)
                record.comment = f"rollback_by_{actor}"
                await self.set_policy(tenant_id, record, is_new=False)
                return record
        raise HTTPException(status_code=404, detail="Policy version not found for tenant")


def _policy_retention_seconds(policy: Dict[str, Any], key: str) -> int:
    """Read retention TTL (seconds) from a policy's free-form `retention` object.

    Convention (all optional):
      policy["retention"]["session_prompts_ttl_seconds"]
      policy["retention"]["adversarial_corpus_ttl_seconds"]
      policy["retention"]["content_store_ttl_seconds"]

    Returns 0 if no TTL is configured/enforceable.
    """
    try:
        return int(_effective_retention_seconds(policy, key) or 0)
    except Exception:
        return 0


class TenantMetadata(BaseModel):
    """
    Governance subject grouping:
    - tenant_id binds all policies, RTBF markers, and metrics
    """
    tenant_id: str
    organization_name: str
    tier: str
    industry: str
    contact_email: str
    active: bool = True
    created_at: str
    policy_group: str = "default"


class TenantStore:
    """
    Tenant metadata store and policy seeding.
    """

    def __init__(self, r: redis.Redis):
        self.r = r
        self.policy_store = PolicyStore(r)

    def _meta_key(self, tenant_id: str) -> str:
        return f"apex:tenant:{tenant_id}:meta"

    async def onboard_tenant(self, metadata: TenantMetadata) -> None:
        await self.r.set(self._meta_key(metadata.tenant_id), metadata.json())
        template = POLICY_TEMPLATE_MAP.get(metadata.policy_group, DEFAULT_POLICY_BASELINE)
        seed_policy = json.loads(json.dumps(template))
        record = PolicyRecord(
            version=POLICY_VERSION,
            policy=seed_policy,
            created_at=datetime.utcnow().isoformat() + "Z",
            created_by=metadata.tenant_id,
            comment=f"seed_from_policy_group:{metadata.policy_group}",
        )
        await self.policy_store.set_policy(metadata.tenant_id, record, is_new=True)

    async def upsert_metadata(self, metadata: TenantMetadata) -> None:
        await self.r.set(self._meta_key(metadata.tenant_id), metadata.json())

    async def get_metadata(self, tenant_id: str) -> TenantMetadata:
        raw = await self.r.get(self._meta_key(tenant_id))
        if not raw:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return TenantMetadata(**json.loads(raw))

    async def list_all(self) -> List[TenantMetadata]:
        keys = await self.r.keys("apex:tenant:*:meta")
        out: List[TenantMetadata] = []
        for k in keys:
            raw = await self.r.get(k)
            if raw:
                try:
                    out.append(TenantMetadata(**json.loads(raw)))
                except Exception:
                    continue
        return out

# =========================================================
# 3. KMS SIGNING (ASYNCHRONOUS) & LEDGER STRUCTURE
# =========================================================

APEX_ENABLE_MERKLE_CHECKPOINTS = os.getenv("APEX_ENABLE_MERKLE_CHECKPOINTS", "true").lower() == "true"
APEX_SIGN_CHECKPOINTS = os.getenv("APEX_SIGN_CHECKPOINTS", "false").lower() == "true"
APEX_ENABLE_ANCHOR_ENTRIES = os.getenv("APEX_ENABLE_ANCHOR_ENTRIES", "true").lower() == "true"
APEX_CONTENT_DEDUP = os.getenv("APEX_CONTENT_DEDUP", "true").lower() == "true"
APEX_CONTENT_TTL_SECONDS = int(os.getenv("APEX_CONTENT_TTL_SECONDS", "0"))
APEX_VERIFY_SCAN_LIMIT = int(os.getenv("APEX_VERIFY_SCAN_LIMIT", "20000"))
APEX_ANCHOR_SEARCH_LIMIT = int(os.getenv("APEX_ANCHOR_SEARCH_LIMIT", "5000"))

# Finance-grade governance: require two-person approval for policy mutations.
APEX_TWO_PERSON_POLICY = os.getenv("APEX_TWO_PERSON_POLICY", "false").lower() == "true"

_PUBLIC_KEY_CACHE_B64: Optional[str] = None
_PUBLIC_KEY_CACHE_BY_KID: Dict[str, str] = {}

_KMS_DUAL_CONTROL_CACHE: Dict[str, Any] = {"expires_at": 0.0, "ok": True, "reason": None}


async def _enforce_kms_dual_control_or_raise(r: Optional[redis.Redis]) -> None:
    """Enforce dual-control for which KMS key id the signer may use.

    This is an application-level governance guardrail (defense-in-depth).

    Mechanism:
    - When enabled, require that the currently running `APEX_KMS_KEY_ID` matches
      the *approved* desired env-config stored in Redis.
    - The desired config stores values redacted; for sensitive keys we compare
      the sha256 of the runtime value against the stored sha256.

    Notes:
    - This does not provide per-signature human approval (AWS KMS does not offer
      per-request quorum approvals). It provides dual-control over key *selection*
      and therefore key usage by the service.
    """

    if not APEX_KMS_DUAL_CONTROL:
        return
    if r is None:
        raise RuntimeError("dual_control_requires_redis")

    try:
        env = get_apex_env()
    except Exception:
        env = None

    # Only enforce in high-assurance modes.
    if not (APEX_FIPS_MODE or env == ApexEnv.PROD):
        return

    now = time.time()
    cached = dict(_KMS_DUAL_CONTROL_CACHE)
    if float(cached.get("expires_at") or 0.0) > now:
        if not bool(cached.get("ok", True)):
            raise RuntimeError(str(cached.get("reason") or "dual_control_failed"))
        return

    if not KMS_KEY_ID:
        raise RuntimeError("dual_control_missing_runtime_kms_key_id")

    desired_raw = await r.get(_envcfg_desired_current_key())
    if not desired_raw:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_desired_config"})
        raise RuntimeError("dual_control_missing_desired_config")

    try:
        desired = json.loads(desired_raw)
    except Exception:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_invalid_desired_config"})
        raise RuntimeError("dual_control_invalid_desired_config")

    if not isinstance(desired, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_invalid_desired_config"})
        raise RuntimeError("dual_control_invalid_desired_config")

    # Ensure the record is an approved desired config.
    if not (desired.get("approved_by") and desired.get("approved_at")):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_desired_config_not_approved"})
        raise RuntimeError("dual_control_desired_config_not_approved")

    changes = desired.get("changes")
    if not isinstance(changes, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_changes"})
        raise RuntimeError("dual_control_missing_changes")

    kms_change = changes.get("APEX_KMS_KEY_ID")
    if not isinstance(kms_change, dict):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_missing_approved_kms_key"})
        raise RuntimeError("dual_control_missing_approved_kms_key")
    if kms_change.get("unset") is True:
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_kms_key_unset"})
        raise RuntimeError("dual_control_kms_key_unset")

    desired_sha = kms_change.get("sha256")
    if not (isinstance(desired_sha, str) and desired_sha):
        # If not redacted, fall back to direct compare.
        desired_val = kms_change.get("value")
        if isinstance(desired_val, str) and desired_val:
            desired_sha = hashlib.sha256(desired_val.encode("utf-8")).hexdigest()

    runtime_sha = hashlib.sha256(str(KMS_KEY_ID).encode("utf-8")).hexdigest()
    if not (isinstance(desired_sha, str) and desired_sha == runtime_sha):
        _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 10.0, "ok": False, "reason": "dual_control_kms_key_mismatch"})
        raise RuntimeError("dual_control_kms_key_mismatch")

    _KMS_DUAL_CONTROL_CACHE.update({"expires_at": now + 30.0, "ok": True, "reason": None})


async def _emit_signing_access_log(
    r: Optional[redis.Redis],
    *,
    tenant_id: Optional[str],
    status: str,
    ledger_index: int,
    entry_id: Optional[str],
    kid: Optional[str],
    alg: Optional[str],
    signing_status: Optional[str],
    error: Optional[str] = None,
) -> None:
    """Best-effort signing access log.

    This is intentionally NOT written to the audit ledger to avoid recursion.
    Use AWS CloudTrail as the authoritative KMS access log.
    """
    if not APEX_SIGN_AUDIT_ENABLED:
        return
    if r is None:
        return

    try:
        fields: Dict[str, str] = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "env": get_apex_env().value,
            "region": str(APEX_REGION or ""),
            "chain_id": str(APEX_CHAIN_ID or ""),
            "tenant_id": str((tenant_id or "").strip() or ""),
            "status": str(status or "unknown"),
            "ledger_index": str(int(ledger_index)),
            "entry_id": str(entry_id or ""),
            "kid": str(kid or ""),
            "alg": str(alg or ""),
            "signing_status": str(signing_status or ""),
        }
        if error:
            fields["error"] = str(error)[:256]

        # Stream of signing events (bounded, best-effort). Operators can sink this to SIEM.
        await r.xadd(APEX_SIGN_AUDIT_STREAM_KEY, fields, maxlen=10000, approximate=True)
        if int(APEX_SIGN_AUDIT_TTL_SECONDS or 0) > 0:
            # Expire the whole stream key best-effort; TTL governs stream retention.
            await r.expire(APEX_SIGN_AUDIT_STREAM_KEY, int(APEX_SIGN_AUDIT_TTL_SECONDS))

        # Minimal counters for dashboards.
        if str(status).lower() == "success":
            await r.incr("apex:signing:ops:success", 1)
        else:
            await r.incr("apex:signing:ops:failure", 1)
            if error:
                await r.set("apex:signing:ops:last_error", str(error)[:256])
                await r.set("apex:signing:ops:last_error_at", datetime.utcnow().isoformat() + "Z")
            # Keep counters reasonably fresh.
        await r.expire("apex:signing:ops:success", int(APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:failure", int(APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:last_error", int(APEX_SIGN_AUDIT_TTL_SECONDS))
        await r.expire("apex:signing:ops:last_error_at", int(APEX_SIGN_AUDIT_TTL_SECONDS))
    except Exception:
        return


async def _read_signing_audit_stream(
    r: redis.Redis,
    *,
    limit: int,
    tenant_id_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Read recent signing audit events from Redis stream.

    Notes:
    - Uses XREVRANGE to fetch most recent events.
    - Optional in-memory filtering by tenant_id.
    """
    lim = max(1, min(int(limit), 500))
    tenant_filter = (tenant_id_filter or "").strip() or None

    # Fetch a little more when filtering to increase odds of returning `lim` events.
    fetch = lim
    if tenant_filter:
        fetch = min(2000, lim * 10)

    events: List[Dict[str, Any]] = []
    try:
        raw = await r.xrevrange(APEX_SIGN_AUDIT_STREAM_KEY, max="+", min="-", count=fetch)
    except Exception:
        raw = []

    for stream_id, fields in raw or []:
        try:
            f = dict(fields or {})
            f["stream_id"] = stream_id
            if tenant_filter:
                t = str(f.get("tenant_id") or "").strip() or None
                if t != tenant_filter:
                    continue
            events.append(f)
            if len(events) >= lim:
                break
        except Exception:
            continue
    return events


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root_hex(leaves_hex: List[str]) -> Optional[str]:
    """Compute a SHA-256 Merkle root from hex-encoded leaf hashes.

    - If the number of leaves is odd at any level, the last leaf is duplicated.
    - Returns hex root, or None if leaves_hex is empty.
    """
    if not leaves_hex:
        return None

    level = [bytes.fromhex(h) for h in leaves_hex]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1]
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


def compute_merkle_inclusion_proof_hex(leaves_hex: List[str], leaf_index: int) -> List[Dict[str, str]]:
    """Return an inclusion proof for a leaf within a SHA-256 Merkle tree.

    Proof format: list of {"sibling": <hex>, "sibling_position": "left"|"right"}
    where sibling_position denotes where the sibling sits relative to the running hash.
    """
    if leaf_index < 0 or leaf_index >= len(leaves_hex):
        raise ValueError("leaf_index out of range")

    level = [bytes.fromhex(h) for h in leaves_hex]
    idx = int(leaf_index)
    proof: List[Dict[str, str]] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        sibling_idx = idx ^ 1
        sibling_position = "right" if (idx % 2 == 0) else "left"
        proof.append({"sibling": level[sibling_idx].hex(), "sibling_position": sibling_position})

        next_level: List[bytes] = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
        idx = idx // 2

    return proof


def _public_key_spki_der_b64_from_private_key_pem(private_key_pem: bytes) -> str:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    pub = key.public_key()
    spki_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(spki_der).decode("ascii")


def _kms_public_key_spki_der_b64(key_id: str, region: Optional[str]) -> str:
    session_kwargs: Dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    client = boto3.client("kms", **session_kwargs)
    resp = client.get_public_key(KeyId=key_id)
    der = resp.get("PublicKey")
    if not der:
        raise RuntimeError("KMS GetPublicKey returned empty PublicKey")
    return base64.b64encode(der).decode("ascii")


def get_signer_public_key_b64(key_id: Optional[str] = None) -> Optional[str]:
    """Best-effort signer public key export for third-party verification.

    Returns base64-encoded DER SubjectPublicKeyInfo.

    Rotation-aware behavior:
    - If `key_id` is provided and looks like a KMS key id/arn, this fetches that
      key's public key (PROD/FIPS).
    - Otherwise it falls back to the currently configured signer (KMS or dev PEM).
    """
    global _PUBLIC_KEY_CACHE_B64

    try:
        env = get_apex_env()
    except Exception:
        return None

    try:
        if APEX_FIPS_MODE or env == ApexEnv.PROD:
            kid = (key_id or "").strip() or KMS_KEY_ID
            if not kid:
                return None
            cached = _PUBLIC_KEY_CACHE_BY_KID.get(kid)
            if cached:
                return cached
            pub = _kms_public_key_spki_der_b64(kid, KMS_REGION or None)
            _PUBLIC_KEY_CACHE_BY_KID[kid] = pub
            # Keep the legacy single-value cache as a best-effort shortcut.
            _PUBLIC_KEY_CACHE_B64 = pub
            return pub

        dev_key_pem = os.getenv("APEX_DEV_LEDGER_PRIVATE_KEY_PEM", "").encode("utf-8")
        if not dev_key_pem.strip():
            return None
        cached = _PUBLIC_KEY_CACHE_BY_KID.get("dev")
        if cached:
            return cached
        pub = _public_key_spki_der_b64_from_private_key_pem(dev_key_pem)
        _PUBLIC_KEY_CACHE_BY_KID["dev"] = pub
        _PUBLIC_KEY_CACHE_B64 = pub
        return pub
    except Exception:
        return None


async def _store_deduped_content(
    r: redis.Redis,
    *,
    tenant_id: Optional[str] = None,
    kind: str,
    content: str,
    ttl_seconds: int = 0,
) -> Dict[str, Any]:
    """Store large content once and refer to it by hash.

    This is meant to reduce Redis/S3 bloat for repeated large strings while
    keeping deterministic references.
    """
    normalized = unicodedata.normalize("NFC", content)
    digest = _sha256_hex(f"{kind}\0{normalized}".encode("utf-8"))
    if tenant_id:
        key = f"apex:content:{tenant_id}:{kind}:{digest}"
    else:
        key = f"apex:content:{kind}:{digest}"
    # Best-effort dedup; value is only written if absent.
    try:
        was_set = await r.set(key, normalized, nx=True)
        effective_ttl = int(ttl_seconds or 0) or int(APEX_CONTENT_TTL_SECONDS or 0)
        if effective_ttl > 0:
            # Strictly enforce TTL even if the key pre-exists (avoid accidental forever retention).
            try:
                current_ttl = await r.ttl(key)
            except Exception:
                current_ttl = None

            # Redis TTL semantics: -2 missing, -1 no-expiry.
            should_shorten = (
                isinstance(current_ttl, int)
                and current_ttl >= 0
                and int(current_ttl) > int(effective_ttl)
            )
            should_set = (
                (was_set is True)
                or (current_ttl == -1)
                or should_shorten
            )
            if should_set:
                await r.expire(key, int(effective_ttl))
    except Exception:
        # If content store fails, callers can fall back to inline storage.
        pass

    out: Dict[str, Any] = {"ref": f"{kind}:{digest}", "sha256": digest, "len": len(normalized)}
    if tenant_id:
        out["tenant_id"] = tenant_id
        out["tenant_ref"] = f"{tenant_id}:{kind}:{digest}"
    return out


# =========================================================
# 3a. THREAT INTELLIGENCE (PUSH INGESTION, MINIMAL)
# =========================================================

_THREAT_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}


def _threat_intel_rules_key(tenant_id: str, feed_version: str) -> str:
    return f"apex:threat_intel:{tenant_id}:rules:{feed_version}"


def _threat_intel_versions_key(tenant_id: str) -> str:
    return f"apex:threat_intel:{tenant_id}:versions"


def _threat_intel_meta_key(tenant_id: str) -> str:
    return f"apex:threat_intel:{tenant_id}:meta"


def _severity_weight(severity: str) -> float:
    s = (severity or "").lower().strip()
    if s == "low":
        return 0.30
    if s == "medium":
        return 0.60
    if s == "high":
        return 0.90
    if s == "critical":
        return 1.00
    return 0.60


class ThreatIntelRule(BaseModel):
    """A lightweight match rule.

    `indicator` is a substring match against normalized text.
    `indicator_hash` is a strict-mode option: store only a hash of the indicator
    tokens (no plaintext). Matching is performed by hashing token windows.
    """

    rule_id: Optional[str] = None
    indicator: Optional[str] = None
    indicator_hash: Optional[str] = None
    indicator_token_count: Optional[int] = None
    indicator_hash_alg: Optional[str] = None
    tactic: str = "prompt_injection"
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    source: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


class ThreatIntelIngestRequest(BaseModel):
    feed_version: Optional[str] = None
    mode: Literal["replace", "append"] = "replace"
    activate: bool = True
    comment: Optional[str] = None
    # If true, server stores only indicator hashes (no plaintext indicator strings).
    hash_indicators: bool = False
    rules: List[ThreatIntelRule]


class ThreatIntelActivateRequest(BaseModel):
    feed_version: str


# =========================================================
# 3b. SEMANTIC DLP (OPTION B: EXEMPLAR SIMILARITY)
# =========================================================

_DLP_EMBEDDER_CACHE: Dict[str, Any] = {"key": None, "embedder": None}


def _dlp_semantic_items_key(tenant_id: str) -> str:
    return f"apex:dlp_semantic:{tenant_id}:items"


def _dlp_semantic_meta_key(tenant_id: str) -> str:
    return f"apex:dlp_semantic:{tenant_id}:meta"


class DlpSemanticExemplar(BaseModel):
    exemplar_id: Optional[str] = None
    text: str
    label: Optional[str] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    created_at: Optional[str] = None


class DlpSemanticIngestRequest(BaseModel):
    mode: Literal["replace", "append"] = "replace"
    comment: Optional[str] = None
    exemplars: List[DlpSemanticExemplar]


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    if a.shape != b.shape:
        return 0.0
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


async def _get_dlp_embedder() -> Optional["OpenAIEmbeddingProvider"]:
    try:
        key = await secret_provider.get_openai_key()
    except Exception:
        key = ""
    if not key:
        return None

    cached_key = _DLP_EMBEDDER_CACHE.get("key")
    if cached_key == key and _DLP_EMBEDDER_CACHE.get("embedder") is not None:
        return _DLP_EMBEDDER_CACHE["embedder"]

    embedder = OpenAIEmbeddingProvider(api_key=key, model=APEX_EMBEDDING_MODEL)
    _DLP_EMBEDDER_CACHE["key"] = key
    _DLP_EMBEDDER_CACHE["embedder"] = embedder
    return embedder


class DlpSemanticStore:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def load(self, tenant_id: str) -> Dict[str, Any]:
        meta_raw = await self.r.get(_dlp_semantic_meta_key(tenant_id))
        items_raw = await self.r.get(_dlp_semantic_items_key(tenant_id))
        meta: Dict[str, Any] = {}
        items: List[Dict[str, Any]] = []
        try:
            if meta_raw:
                meta = json.loads(meta_raw)
        except Exception:
            meta = {}
        try:
            if items_raw:
                items = json.loads(items_raw)
        except Exception:
            items = []
        return {"meta": meta, "items": items if isinstance(items, list) else []}

    async def ingest(
        self,
        tenant_id: str,
        req: DlpSemanticIngestRequest,
        *,
        content_ttl_seconds: int = 0,
    ) -> Dict[str, Any]:
        if not req.exemplars:
            raise HTTPException(status_code=400, detail="exemplars must be non-empty")

        existing_items: List[Dict[str, Any]] = []
        if req.mode == "append":
            loaded = await self.load(tenant_id)
            existing_items = list(loaded.get("items") or [])

        embedder = await _get_dlp_embedder()
        if embedder is None:
            raise HTTPException(status_code=400, detail="Semantic DLP requires OPENAI_API_KEY")

        compiled: List[Dict[str, Any]] = existing_items
        for ex in req.exemplars:
            txt = (ex.text or "").strip()
            if not txt:
                continue
            if len(txt) > 4000:
                raise HTTPException(status_code=400, detail="exemplar text too long (max 4000 chars)")

            ex_id = ex.exemplar_id or f"dlp_{uuid.uuid4().hex}"
            norm = unicodedata.normalize("NFC", txt)
            vec = await embedder.embed(norm)
            compiled.append(
                {
                    "exemplar_id": ex_id,
                    "label": ex.label,
                    "severity": ex.severity,
                    "confidence": float(ex.confidence),
                    "created_at": ex.created_at or datetime.utcnow().isoformat() + "Z",
                    # Store a dedup ref for the text; embed vector stored inline for fast scoring.
                    "text_ref": await _store_deduped_content(
                        self.r,
                        tenant_id=tenant_id,
                        kind="dlp_exemplar",
                        content=norm,
                        ttl_seconds=int(content_ttl_seconds or 0),
                    ),
                    "embedding": vec.tolist(),
                }
            )

        # Hard cap stored exemplars.
        if len(compiled) > int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS):
            compiled = compiled[: int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS)]

        meta = {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "mode": req.mode,
            "count": len(compiled),
            "comment": req.comment,
        }

        await self.r.set(_dlp_semantic_items_key(tenant_id), json.dumps(compiled, separators=(",", ":")))
        await self.r.set(_dlp_semantic_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))
        return meta


async def score_semantic_dlp(
    r: redis.Redis,
    *,
    tenant_id: str,
    text: str,
    max_hits: int = 5,
) -> Dict[str, Any]:
    if not APEX_DLP_SEMANTIC_ENABLED:
        return {"score": 0.0, "hits": []}
    embedder = await _get_dlp_embedder()
    if embedder is None:
        return {"score": 0.0, "hits": []}

    store = DlpSemanticStore(r)
    loaded = await store.load(tenant_id)
    items: List[Dict[str, Any]] = list(loaded.get("items") or [])
    if not items:
        return {"score": 0.0, "hits": []}

    # Embed current window
    norm = unicodedata.normalize("NFC", text or "")
    vec = await embedder.embed(norm)
    v = np.array(vec, dtype=float)

    best = 0.0
    hits: List[Dict[str, Any]] = []
    for it in items[: int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS)]:
        try:
            ev = np.array(it.get("embedding") or [], dtype=float)
            sim = _cosine_similarity(v, ev)
            sev = str(it.get("severity") or "medium")
            conf = float(it.get("confidence") or 0.0)
            score = clamp01(max(0.0, sim) * conf * _severity_weight(sev))
            if score > best:
                best = score
            if score > 0.0:
                hits.append(
                    {
                        "exemplar_id": it.get("exemplar_id"),
                        "label": it.get("label"),
                        "severity": sev,
                        "confidence": conf,
                        "similarity": sim,
                        "score": score,
                    }
                )
        except Exception:
            continue

    hits = sorted(hits, key=lambda h: float(h.get("score") or 0.0), reverse=True)[:max_hits]
    return {"score": float(best), "hits": hits, "count": len(items)}


def _gen_feed_version() -> str:
    return f"ti_{int(time.time())}_{uuid.uuid4().hex[:12]}"


def _tokenize_indicator_for_hash(indicator: str) -> List[str]:
    norm = normalize_for_security(indicator)
    if not norm:
        return []
    # Token-based hashing is more stable than raw-string hashing across whitespace.
    return [t for t in norm.split() if t]


def _hash_indicator_tokens(tokens: List[str]) -> str:
    joined = " ".join(tokens)
    return _sha256_hex(joined.encode("utf-8"))


def _extract_ngrams(s: str, *, n: int = 3, max_ngrams: int = 2000) -> List[str]:
    if not s:
        return []
    if len(s) < n:
        return []
    out: List[str] = []
    seen = set()
    # Keep it deterministic: left-to-right, de-dup.
    for i in range(0, len(s) - n + 1):
        g = s[i : i + n]
        if g in seen:
            continue
        seen.add(g)
        out.append(g)
        if len(out) >= max_ngrams:
            break
    return out


def _build_ngram_index(rules: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    index: Dict[str, List[int]] = {}
    for i, rule in enumerate(rules):
        try:
            ind = str(rule.get("indicator_norm") or "")
            for g in _extract_ngrams(ind, n=3, max_ngrams=256):
                index.setdefault(g, []).append(i)
        except Exception:
            continue
    return index


def _build_hashed_indicator_index(rules: List[Dict[str, Any]]) -> Dict[int, Dict[str, List[int]]]:
    """Index hashed indicators by token-count -> hash -> rule positions."""
    out: Dict[int, Dict[str, List[int]]] = {}
    for i, rule in enumerate(rules):
        try:
            h = rule.get("indicator_hash")
            tc = rule.get("indicator_token_count")
            if not (isinstance(h, str) and h):
                continue
            if not isinstance(tc, int) or tc <= 0 or tc > 256:
                continue
            out.setdefault(int(tc), {}).setdefault(h, []).append(i)
        except Exception:
            continue
    return out


class ThreatIntelStore:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def load_rules(self, tenant_id: str, *, force_reload: bool = False) -> Dict[str, Any]:
        now = time.time()
        cached = _THREAT_INTEL_CACHE.get(tenant_id)
        if cached and not force_reload:
            age = now - float(cached.get("loaded_at", 0.0) or 0.0)
            if age < 30.0:
                return cached

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta: Dict[str, Any] = {}
        try:
            if meta_raw:
                meta = json.loads(meta_raw)
        except Exception:
            meta = {}

        active_version = meta.get("active_feed_version")
        rules: List[Dict[str, Any]] = []
        if isinstance(active_version, str) and active_version:
            rules_raw = await self.r.get(_threat_intel_rules_key(tenant_id, active_version))
            try:
                if rules_raw:
                    rules = json.loads(rules_raw)
            except Exception:
                rules = []

        cached = {
            "loaded_at": now,
            "rules": rules if isinstance(rules, list) else [],
            "feed_version": active_version,
            "previous_feed_version": meta.get("previous_feed_version"),
            "updated_at": meta.get("updated_at"),
        }
        cached["ngram_index"] = _build_ngram_index(cached["rules"])
        cached["hashed_index"] = _build_hashed_indicator_index(cached["rules"])
        _THREAT_INTEL_CACHE[tenant_id] = cached
        return cached

    async def activate(self, tenant_id: str, feed_version: str) -> Dict[str, Any]:
        if not feed_version:
            raise HTTPException(status_code=400, detail="feed_version is required")

        # Must exist.
        exists = await self.r.exists(_threat_intel_rules_key(tenant_id, feed_version))
        if not exists:
            raise HTTPException(status_code=404, detail="unknown feed_version")

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta: Dict[str, Any] = {}
        try:
            if meta_raw:
                meta = json.loads(meta_raw)
        except Exception:
            meta = {}

        prev = meta.get("active_feed_version")
        meta["previous_feed_version"] = prev
        meta["active_feed_version"] = feed_version
        meta["updated_at"] = datetime.utcnow().isoformat() + "Z"

        await self.r.set(_threat_intel_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))

        # Track versions (most recent first).
        try:
            await self.r.lrem(_threat_intel_versions_key(tenant_id), 0, feed_version)
            await self.r.lpush(_threat_intel_versions_key(tenant_id), feed_version)
        except Exception:
            pass

        await self.load_rules(tenant_id, force_reload=True)
        return {
            "active_feed_version": feed_version,
            "previous_feed_version": prev,
            "updated_at": meta.get("updated_at"),
        }

    async def rollback(self, tenant_id: str) -> Dict[str, Any]:
        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta: Dict[str, Any] = {}
        try:
            if meta_raw:
                meta = json.loads(meta_raw)
        except Exception:
            meta = {}

        target = meta.get("previous_feed_version")
        if not (isinstance(target, str) and target):
            # fall back to second most recent in versions list
            try:
                candidate = await self.r.lindex(_threat_intel_versions_key(tenant_id), 1)
                if candidate:
                    target = candidate
            except Exception:
                target = None

        if not (isinstance(target, str) and target):
            raise HTTPException(status_code=409, detail="no previous feed version available")

        return await self.activate(tenant_id, target)

    async def ingest(self, tenant_id: str, req: ThreatIntelIngestRequest) -> Dict[str, Any]:
        if not req.rules:
            raise HTTPException(status_code=400, detail="rules must be non-empty")

        new_version = (req.feed_version or "").strip() or _gen_feed_version()
        if len(new_version) > 128:
            raise HTTPException(status_code=400, detail="feed_version too long")

        compiled: List[Dict[str, Any]] = []
        if req.mode == "append":
            existing = await self.load_rules(tenant_id, force_reload=True)
            compiled = list(existing.get("rules") or [])

        for r0 in req.rules:
            rid = r0.rule_id or f"ti_{uuid.uuid4().hex}"

            indicator = (r0.indicator or "").strip()
            indicator_hash = (r0.indicator_hash or "").strip()
            indicator_token_count = r0.indicator_token_count

            if req.hash_indicators:
                # Strict mode: persist only hashes (no plaintext indicators).
                if indicator:
                    if len(indicator) > 400:
                        raise HTTPException(status_code=400, detail="indicator too long (max 400)")
                    tokens = _tokenize_indicator_for_hash(indicator)
                    if not tokens:
                        continue
                    indicator_token_count = len(tokens)
                    indicator_hash = _hash_indicator_tokens(tokens)
                if not indicator_hash:
                    continue
                if not isinstance(indicator_token_count, int) or indicator_token_count <= 0:
                    raise HTTPException(status_code=400, detail="indicator_token_count required for hashed indicators")

                compiled.append(
                    {
                        "rule_id": rid,
                        "indicator_hash": indicator_hash,
                        "indicator_token_count": int(indicator_token_count),
                        "indicator_hash_alg": (r0.indicator_hash_alg or "sha256"),
                        "tactic": r0.tactic,
                        "severity": r0.severity,
                        "confidence": float(r0.confidence),
                        "source": r0.source,
                        "created_at": r0.created_at or datetime.utcnow().isoformat() + "Z",
                        "expires_at": r0.expires_at,
                    }
                )
            else:
                # Default mode: plaintext substring match (backwards compatible).
                if not indicator:
                    # Allow hashed indicators to be supplied explicitly even in non-hashed ingest.
                    if indicator_hash:
                        if not isinstance(indicator_token_count, int) or indicator_token_count <= 0:
                            raise HTTPException(
                                status_code=400,
                                detail="indicator_token_count required when providing indicator_hash",
                            )
                        compiled.append(
                            {
                                "rule_id": rid,
                                "indicator_hash": indicator_hash,
                                "indicator_token_count": int(indicator_token_count),
                                "indicator_hash_alg": (r0.indicator_hash_alg or "sha256"),
                                "tactic": r0.tactic,
                                "severity": r0.severity,
                                "confidence": float(r0.confidence),
                                "source": r0.source,
                                "created_at": r0.created_at or datetime.utcnow().isoformat() + "Z",
                                "expires_at": r0.expires_at,
                            }
                        )
                    continue
                if len(indicator) > 400:
                    raise HTTPException(status_code=400, detail="indicator too long (max 400)")

                indicator_norm = normalize_for_security(indicator)
                if not indicator_norm:
                    continue

                compiled.append(
                    {
                        "rule_id": rid,
                        "indicator": indicator,
                        "indicator_norm": indicator_norm,
                        "tactic": r0.tactic,
                        "severity": r0.severity,
                        "confidence": float(r0.confidence),
                        "source": r0.source,
                        "created_at": r0.created_at or datetime.utcnow().isoformat() + "Z",
                        "expires_at": r0.expires_at,
                    }
                )

        if len(compiled) > 500000:
            raise HTTPException(status_code=400, detail="too many rules (max 500000)")

        await self.r.set(
            _threat_intel_rules_key(tenant_id, new_version),
            json.dumps(compiled, separators=(",", ":")),
        )

        # Maintain versions list.
        try:
            await self.r.lrem(_threat_intel_versions_key(tenant_id), 0, new_version)
            await self.r.lpush(_threat_intel_versions_key(tenant_id), new_version)
        except Exception:
            pass

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta: Dict[str, Any] = {}
        try:
            if meta_raw:
                meta = json.loads(meta_raw)
        except Exception:
            meta = {}

        meta.update(
            {
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "mode": req.mode,
                "rule_count": len(compiled),
                "staged_feed_version": new_version,
            }
        )

        # Optionally activate immediately.
        if req.activate:
            meta["previous_feed_version"] = meta.get("active_feed_version")
            meta["active_feed_version"] = new_version
            meta["staged_feed_version"] = None

        await self.r.set(_threat_intel_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))
        await self.load_rules(tenant_id, force_reload=True)

        return {
            "active_feed_version": meta.get("active_feed_version"),
            "previous_feed_version": meta.get("previous_feed_version"),
            "staged_feed_version": new_version if not req.activate else None,
            "updated_at": meta.get("updated_at"),
            "mode": req.mode,
            "rule_count": len(compiled),
        }

    async def match(
        self,
        tenant_id: str,
        text_norm: str,
        *,
        max_checked: int = 500,
        max_hits: int = 10,
    ) -> Dict[str, Any]:
        cached = await self.load_rules(tenant_id)
        rules = list(cached.get("rules") or [])
        if not rules or not text_norm:
            return {"score": 0.0, "hits": [], "feed_version": cached.get("feed_version")}

        hits: List[Dict[str, Any]] = []
        max_score = 0.0
        checked = 0
        now_iso = datetime.utcnow().isoformat() + "Z"

        # First: hashed indicators (strict mode). These can be matched without plaintext.
        try:
            hashed_index: Dict[int, Dict[str, List[int]]] = cached.get("hashed_index") or {}
        except Exception:
            hashed_index = {}

        if hashed_index:
            tokens = [t for t in (text_norm or "").split() if t]
            seen_rule_ids: set = set()
            # Guardrail against CPU blowups on very long prompts.
            max_windows_per_token_count = 20000

            for token_count, hash_to_positions in hashed_index.items():
                if checked >= max_checked:
                    break
                if not isinstance(token_count, int) or token_count <= 0:
                    continue
                if token_count > len(tokens):
                    continue

                windows_checked = 0
                for i in range(0, len(tokens) - token_count + 1):
                    if checked >= max_checked:
                        break
                    windows_checked += 1
                    if windows_checked > max_windows_per_token_count:
                        break
                    window = " ".join(tokens[i : i + token_count])
                    wh = _sha256_hex(window.encode("utf-8"))
                    positions = hash_to_positions.get(wh)
                    if not positions:
                        continue

                    for pos in positions:
                        if checked >= max_checked:
                            break
                        try:
                            rule = rules[pos]
                            exp = rule.get("expires_at")
                            if isinstance(exp, str) and exp and exp < now_iso:
                                continue
                            rid = rule.get("rule_id")
                            if rid and rid in seen_rule_ids:
                                continue

                            sev = str(rule.get("severity") or "medium")
                            conf = float(rule.get("confidence") or 0.0)
                            score = clamp01(conf * _severity_weight(sev))
                            max_score = max(max_score, score)
                            hits.append(
                                {
                                    "rule_id": rid,
                                    "tactic": rule.get("tactic"),
                                    "severity": sev,
                                    "confidence": conf,
                                    "score": score,
                                    "source": rule.get("source"),
                                    "match_mode": "hashed",
                                }
                            )
                            if rid:
                                seen_rule_ids.add(rid)
                            checked += 1

                            if len(hits) >= max_hits and max_score >= 0.99:
                                break
                        except Exception:
                            continue

        # If we already have enough strong hits, we can short-circuit.
        if len(hits) >= max_hits and max_score >= 0.99:
            return {
                "score": float(max_score),
                "hits": hits[:max_hits],
                "feed_version": cached.get("feed_version"),
                "checked": checked,
            }

        # If the ruleset is large, use an n-gram index to shortlist candidates.
        candidate_indices: List[int]
        if len(rules) <= max_checked:
            candidate_indices = list(range(len(rules)))
        else:
            idx: Dict[str, List[int]] = cached.get("ngram_index") or {}
            counts: Dict[int, int] = {}
            for g in _extract_ngrams(text_norm, n=3, max_ngrams=1500):
                positions = idx.get(g)
                if not positions:
                    continue
                for pos in positions:
                    counts[pos] = counts.get(pos, 0) + 1
            # rank by n-gram overlap
            ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
            candidate_indices = [pos for pos, _ in ranked[:max_checked]]

        for pos in candidate_indices:
            if checked >= max_checked:
                break
            checked += 1
            try:
                rule = rules[pos]
                exp = rule.get("expires_at")
                if isinstance(exp, str) and exp and exp < now_iso:
                    continue
                ind = rule.get("indicator_norm") or ""
                if ind and ind in text_norm:
                    sev = str(rule.get("severity") or "medium")
                    conf = float(rule.get("confidence") or 0.0)
                    score = clamp01(conf * _severity_weight(sev))
                    max_score = max(max_score, score)
                    hits.append(
                        {
                            "rule_id": rule.get("rule_id"),
                            "tactic": rule.get("tactic"),
                            "severity": sev,
                            "confidence": conf,
                            "score": score,
                            "source": rule.get("source"),
                            "match_mode": "plaintext",
                        }
                    )
                    if len(hits) >= max_hits and max_score >= 0.99:
                        break
            except Exception:
                continue

        return {
            "score": float(max_score),
            "hits": hits,
            "feed_version": cached.get("feed_version"),
            "checked": checked,
        }

class Signer(Protocol):
    def sign(self, message: bytes) -> bytes:
        ...


class KmsEcdsaSigner:
    """
    AWS KMS-backed ECDSA signer.
    Produces signatures over SHA-256 digests of canonical ledger records.
    """

    def __init__(self, key_id: str, region: Optional[str] = None):
        if not key_id:
            raise RuntimeError("KMS key id must be set (APEX_KMS_KEY_ID or APEX_HSM_KEY_ID)")
        self.key_id = key_id
        session_kwargs: Dict[str, Any] = {}
        if region:
            session_kwargs["region_name"] = region
        self._client = boto3.client("kms", **session_kwargs)

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        try:
            resp = self._client.sign(
                KeyId=self.key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )
        except (BotoCoreError, ClientError) as e:
            raise RuntimeError(f"KMS signing failed: {e}")
        signature = resp.get("Signature")
        if not signature:
            raise RuntimeError("KMS returned no Signature")
        return signature


class SoftEcdsaSigner:
    """
    Dev-only ECDSA signer using a local private key (non-FIPS).
    """

    def __init__(self, private_key_pem: bytes):
        self._pem_buf = bytearray(private_key_pem)
        self._key = serialization.load_pem_private_key(bytes(self._pem_buf), password=None)

    def zeroize(self) -> None:
        """Best-effort overwrite of in-memory private key material.

        Note: Python cannot strictly guarantee zeroization of all copies (GC, allocator).
        This provides an operator-triggered "clear state" signal and reduces exposure.
        """
        try:
            for i in range(len(self._pem_buf)):
                self._pem_buf[i] = 0
        except Exception:
            pass
        self._key = None

    def sign(self, message: bytes) -> bytes:
        if self._key is None:
            raise RuntimeError("Soft signer key material has been zeroized")
        digest = hashlib.sha256(message).digest()
        return self._key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def load_signer_for_worker() -> Signer:
    """
    Load an appropriate signer for the current environment:
    - PROD or FIPS: KMS/HSM is mandatory
    - Non-prod: soft key via APEX_DEV_LEDGER_PRIVATE_KEY_PEM
    """
    env = get_apex_env()

    if APEX_FIPS_MODE:
        if not KMS_KEY_ID:
            raise RuntimeError("APEX_FIPS_MODE enabled but no KMS/HSM key configured (APEX_KMS_KEY_ID/APEX_HSM_KEY_ID)")
        return KmsEcdsaSigner(key_id=KMS_KEY_ID, region=KMS_REGION or None)

    if env == ApexEnv.PROD:
        if not KMS_KEY_ID:
            raise RuntimeError("APEX_KMS_KEY_ID (or APEX_HSM_KEY_ID) must be set in PROD")
        return KmsEcdsaSigner(key_id=KMS_KEY_ID, region=KMS_REGION or None)

    dev_key_pem = os.getenv("APEX_DEV_LEDGER_PRIVATE_KEY_PEM", "").encode("utf-8")
    if not dev_key_pem.strip():
        raise RuntimeError("APEX_DEV_LEDGER_PRIVATE_KEY_PEM must be set in non-prod for ledger signing")
    return SoftEcdsaSigner(private_key_pem=dev_key_pem)


def compute_entry_hash(payload: Dict[str, Any], prev_hash: Optional[str]) -> str:
    """
    Compute chained hash for ledger entry, binding payload + previous hash.
    """
    base_record = {
        "payload": payload,
        "prev_hash": prev_hash,
    }
    record_bytes = json.dumps(base_record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(record_bytes).hexdigest()


class LedgerBackpressureError(RuntimeError):
    """
    Raised when unsigned ledger queue exceeds configured safety threshold.
    """


_AUDIT_MINIMIZATION_CACHE: Dict[str, Dict[str, Any]] = {}


def _get_data_minimization(policy: Dict[str, Any]) -> Dict[str, Any]:
    base = DEFAULT_POLICY_BASELINE.get("data_minimization") or {}
    dm = policy.get("data_minimization") if isinstance(policy, dict) else None
    if not isinstance(dm, dict):
        dm = {}
    out = dict(base)
    out.update(dm)
    return out


def _no_content_retention_enabled(policy: Dict[str, Any]) -> bool:
    dm = _get_data_minimization(policy)
    return bool(dm.get("no_content_retention", False))


def _audit_hash_value(*, tenant_id: str, value: Any) -> str:
    s = str(value) if value is not None else ""
    material = f"{APEX_AUDIT_HASH_SALT}\0{tenant_id}\0{s}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _apply_audit_minimization_to_payload(*, tenant_id: str, payload: Dict[str, Any], dm: Dict[str, Any]) -> Dict[str, Any]:
    """Return a minimized copy of payload based on tenant data minimization policy."""
    mode = str(dm.get("audit_mode", "full") or "full").strip().lower()
    include_subject = bool(dm.get("include_subject", True))
    include_session_id = bool(dm.get("include_session_id", True))
    include_request_context = bool(dm.get("include_request_context", True))

    out = dict(payload)

    # Drop fields based on inclusion flags.
    if not include_subject:
        out.pop("subject", None)
    if not include_session_id:
        out.pop("session_id", None)
    if not include_request_context:
        for k in ("ip", "user_agent", "device_id"):
            out.pop(k, None)

    # Transform fields by audit mode.
    if mode == "full":
        return out

    hash_keys = ("subject", "session_id", "ip", "user_agent", "device_id")
    redact_keys = ("subject", "session_id", "ip", "user_agent", "device_id", "reason", "comment")

    if mode == "hash_only":
        for k in hash_keys:
            if k in out and out.get(k) is not None:
                out[k] = _audit_hash_value(tenant_id=tenant_id, value=out.get(k))
        out["audit_mode"] = "hash_only"
        return out

    if mode == "redacted_only":
        for k in redact_keys:
            if k in out and out.get(k) is not None:
                out[k] = "[REDACTED]"
        out["audit_mode"] = "redacted_only"
        return out

    # Unknown mode -> safest fallback.
    for k in hash_keys:
        if k in out and out.get(k) is not None:
            out[k] = _audit_hash_value(tenant_id=tenant_id, value=out.get(k))
    out["audit_mode"] = "hash_only"
    return out


async def _get_cached_tenant_minimization(r: redis.Redis, tenant_id: str) -> Dict[str, Any]:
    now = time.time()
    cached = _AUDIT_MINIMIZATION_CACHE.get(tenant_id)
    if isinstance(cached, dict) and float(cached.get("expires_at", 0)) > now:
        return cached.get("data_minimization") or (DEFAULT_POLICY_BASELINE.get("data_minimization") or {})

    dm = DEFAULT_POLICY_BASELINE.get("data_minimization") or {}
    try:
        store = PolicyStore(r)
        try:
            record = await store.get_policy_record(tenant_id)
        except HTTPException:
            record = None
        if record is not None:
            dm = _get_data_minimization(record.policy or {})
    except Exception:
        dm = DEFAULT_POLICY_BASELINE.get("data_minimization") or {}

    _AUDIT_MINIMIZATION_CACHE[tenant_id] = {
        "expires_at": now + 60.0,
        "data_minimization": dm,
    }
    return dm


async def get_unsigned_backlog_status(r: redis.Redis) -> Tuple[int, bool, bool]:
    queue_len = await r.llen(SIGNING_QUEUE_KEY) or 0
    warn_threshold = int(UNSIGNED_WARN_FRACTION * MAX_UNSIGNED_QUEUE)
    is_critical = queue_len >= MAX_UNSIGNED_QUEUE
    is_warning = queue_len >= warn_threshold and not is_critical
    return queue_len, is_warning, is_critical


async def create_unsigned_ledger_entry(
    r: redis.Redis,
    payload: Dict[str, Any],
    max_retries: int = 8,
    allow_checkpoint: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    """
    Atomically append a new ledger entry with backpressure and jittered retries:
    - Reject if unsigned queue too large (to preserve integrity).
    - WATCH tail, recompute prev_hash inside transaction, RPUSH.
    - Use randomized backoff to avoid thundering herd.

    Enriched schema:
    - entry_id: UUID per logical event
    - region: deployment region (APEX_REGION or KMS_REGION)
    - ledger_chain_id: logical chain identifier
    - ts: canonical event timestamp (UTC ISO8601)
    """
    queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
    if is_warning:
        print(f"[apex-ledger] WARNING: unsigned backlog high ({queue_len}/{MAX_UNSIGNED_QUEUE})")
    if is_critical:
        print(f"[apex-ledger] CRITICAL: unsigned backlog >= limit ({queue_len}/{MAX_UNSIGNED_QUEUE})")
        raise LedgerBackpressureError(
            f"Unsigned ledger queue too large ({queue_len} >= {MAX_UNSIGNED_QUEUE}); "
            f"refusing new entries to preserve audit integrity."
        )

    region = APEX_REGION
    chain_id = APEX_CHAIN_ID or LEDGER_CHAIN_ID

    # Apply tenant-configurable audit minimization before committing to the immutable ledger.
    tenant_id = payload.get("tenant_id") if isinstance(payload, dict) else None
    minimized_payload = dict(payload)
    if isinstance(tenant_id, str) and tenant_id.strip():
        try:
            dm = await _get_cached_tenant_minimization(r, tenant_id.strip())
            minimized_payload = _apply_audit_minimization_to_payload(
                tenant_id=tenant_id.strip(),
                payload=minimized_payload,
                dm=dm,
            )
        except Exception:
            minimized_payload = dict(payload)

    for attempt in range(max_retries):
        async with r.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch("apex:audit_ledger")
                last = await pipe.lindex("apex:audit_ledger", -1)
                if last:
                    last_entry = json.loads(last)
                    prev_hash = last_entry.get("entry_hash")
                else:
                    prev_hash = None

                enriched_payload = dict(minimized_payload)
                enriched_payload.setdefault("entry_id", str(uuid.uuid4()))
                enriched_payload.setdefault("region", region)
                enriched_payload.setdefault("ledger_chain_id", chain_id)
                enriched_payload.setdefault("ts", datetime.utcnow().isoformat() + "Z")

                entry_hash = compute_entry_hash(enriched_payload, prev_hash)

                entry = {
                    "payload": enriched_payload,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                    "kms_signature": None,
                    "kms_signed_at": None,
                    "signing_status": "pending_kms",
                    "signing_attempts": 0,
                    "alg": "ECDSA_SHA256",
                    "kid": KMS_KEY_ID or "dev-ledger-key",
                    "flushed_to_s3": False,
                }

                encoded = json.dumps(entry, separators=(",", ":"), sort_keys=True)

                pipe.multi()
                pipe.rpush("apex:audit_ledger", encoded)
                result = await pipe.execute()
                new_len = int(result[0])
                index = new_len - 1

                # Best-effort index for auditor workflows (fast lookup by entry_id).
                try:
                    entry_id = enriched_payload.get("entry_id")
                    if entry_id:
                        await r.set(f"apex:ledger:index:{entry_id}", str(index), nx=True)
                except Exception:
                    pass

                if allow_checkpoint and LEDGER_CHECKPOINT_INTERVAL > 0 and new_len % LEDGER_CHECKPOINT_INTERVAL == 0:
                    merkle_root: Optional[str] = None
                    merkle_start_index: Optional[int] = None
                    merkle_end_index: Optional[int] = None
                    merkle_leaf_count: Optional[int] = None

                    if APEX_ENABLE_MERKLE_CHECKPOINTS:
                        try:
                            # Compute a Merkle root over the most recent checkpoint window.
                            merkle_end_index = index
                            merkle_start_index = max(0, merkle_end_index - LEDGER_CHECKPOINT_INTERVAL + 1)
                            raw_entries = await r.lrange("apex:audit_ledger", merkle_start_index, merkle_end_index)
                            leaves: List[str] = []
                            for raw in raw_entries:
                                try:
                                    leaves.append(json.loads(raw).get("entry_hash", ""))
                                except Exception:
                                    leaves.append("")
                            leaves = [h for h in leaves if isinstance(h, str) and len(h) == 64]
                            merkle_leaf_count = len(leaves)
                            merkle_root = compute_merkle_root_hex(leaves)
                        except Exception:
                            merkle_root = None

                    checkpoint_payload = {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "chain_id": chain_id,
                        "last_index": index,
                        "last_entry_hash": entry_hash,
                        "entry_count": new_len,
                        "policy_version": POLICY_VERSION,
                        "env": get_apex_env().value,
                        "region": region,
                        "merkle_alg": "sha256",
                        "merkle_start_index": merkle_start_index,
                        "merkle_end_index": merkle_end_index,
                        "merkle_leaf_count": merkle_leaf_count,
                        "merkle_root": merkle_root,
                    }

                    if APEX_SIGN_CHECKPOINTS and merkle_root:
                        # Optional checkpoint signing for anchoring. Best-effort.
                        try:
                            signer = load_signer_for_worker()
                            sig = signer.sign(merkle_root.encode("utf-8"))
                            checkpoint_payload["checkpoint_signature_b64"] = base64.b64encode(sig).decode("ascii")
                            checkpoint_payload["checkpoint_sig_alg"] = "ECDSA_SHA256"
                            checkpoint_payload["checkpoint_sig_kid"] = KMS_KEY_ID or "dev-ledger-key"
                        except Exception:
                            pass
                    await write_checkpoint(r, checkpoint_payload)

                    # Create an anchored, KMS-signed ledger entry that carries the Merkle root.
                    # This supports auditor verification of large batches via a single signed anchor.
                    if APEX_ENABLE_ANCHOR_ENTRIES and merkle_root and merkle_start_index is not None and merkle_end_index is not None:
                        anchor_payload = {
                            "decision": "MERKLE_ANCHOR",
                            "chain_id": chain_id,
                            "merkle_alg": "sha256",
                            "merkle_root": merkle_root,
                            "anchored_start_index": merkle_start_index,
                            "anchored_end_index": merkle_end_index,
                            "anchored_leaf_count": merkle_leaf_count,
                            "anchored_last_entry_hash": entry_hash,
                            "checkpoint_interval": LEDGER_CHECKPOINT_INTERVAL,
                        }
                        try:
                            await create_unsigned_ledger_entry(
                                r,
                                anchor_payload,
                                max_retries=max_retries,
                                allow_checkpoint=False,
                            )
                        except LedgerBackpressureError:
                            # Best-effort: do not fail request traffic due to anchor backlog.
                            print("[apex-ledger] Dropping MERKLE_ANCHOR due to backlog")
                        except Exception:
                            pass

                await enqueue_for_signing(r, index)
                return index, entry
            except redis.WatchError:
                base = 0.01 * (attempt + 1)
                jitter = random.uniform(0.5, 1.5)
                await asyncio.sleep(base * jitter)
                continue

    raise RuntimeError("Failed to append ledger entry after retries (concurrent modifications too frequent)")


async def upload_to_s3(key: str, content: str) -> None:
    """
    Best-effort upload helper for JSONL batches.
    Currently: naive read-append-overwrite pattern.
    """
    bucket = LEDGER_S3_BUCKET
    if not bucket:
        return

    def _put():
        s3 = boto3.client("s3")
        try:
            try:
                existing = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            except s3.exceptions.NoSuchKey:
                existing = b""
            new_body = existing + content.encode("utf-8")
            s3.put_object(Bucket=bucket, Key=key, Body=new_body)
        except Exception as e:
            print(f"[apex-s3-ledger] upload_to_s3 error: {e}")

    await asyncio.to_thread(_put)


async def s3_ledger_sync_loop(stop_event: asyncio.Event) -> None:
    """
    Independent worker that pulls SIGNED entries from Redis
    and appends them to a regional S3 JSONL file.
    Redis key: apex:signed_ledger_buffer
    """
    r = await get_redis_client()
    buffer: List[Dict[str, Any]] = []
    MAX_BATCH = 100
    last_flush = time.time()

    while not stop_event.is_set():
        try:
            raw = await r.lpop("apex:signed_ledger_buffer")
            now = time.time()
            if raw:
                try:
                    buffer.append(json.loads(raw))
                except Exception:
                    pass

            time_since_last_flush = now - last_flush
            should_flush = (
                len(buffer) >= MAX_BATCH
                or (buffer and time_since_last_flush >= 60)
            )

            if should_flush:
                region = APEX_REGION
                date_str = datetime.utcnow().strftime("%Y-%m-%d")
                prefix = LEDGER_S3_PREFIX.rstrip("/") or "ledger"
                s3_key = f"{prefix}/{region}/{date_str}/audit.jsonl"

                jsonl_content = "\n".join(
                    json.dumps(e, separators=(",", ":"), sort_keys=True) for e in buffer
                ) + "\n"

                await upload_to_s3(s3_key, jsonl_content)

                buffer = []
                last_flush = now

            if not raw:
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[apex-s3-ledger] sync loop error: {e}")
            await asyncio.sleep(2.0)


# =========================================================
# 4a. GOVERNMENT-GRADE HEALTH (FAIL-SAFE) & SELF-TEST
# =========================================================

SIGNER_HEALTH: Dict[str, Any] = {
    "ok": True,
    "last_ok_at": None,
    "last_error": None,
    "last_error_at": None,
}

SELF_TEST: Dict[str, Any] = {
    "ok": True,
    "started_at": datetime.utcnow().isoformat() + "Z",
    "base_file_sha256": None,
    "last_run_at": None,
    "last_error": None,
}


def _sha256_file_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


async def _periodic_self_test_loop() -> None:
    base_path = os.path.abspath(__file__)
    if SELF_TEST.get("base_file_sha256") is None:
        try:
            SELF_TEST["base_file_sha256"] = _sha256_file_hex(base_path)
        except Exception as e:
            SELF_TEST["ok"] = False
            SELF_TEST["last_error"] = f"initial_self_test_failed:{e}"

    while True:
        try:
            SELF_TEST["last_run_at"] = datetime.utcnow().isoformat() + "Z"
            expected = SELF_TEST.get("base_file_sha256")
            if expected:
                current = _sha256_file_hex(base_path)
                if current != expected:
                    SELF_TEST["ok"] = False
                    SELF_TEST["last_error"] = "base_file_hash_changed"
        except Exception as e:
            SELF_TEST["ok"] = False
            SELF_TEST["last_error"] = f"self_test_error:{e}"

        await asyncio.sleep(max(60, int(APEX_SELF_TEST_INTERVAL_SECONDS)))


async def _retention_enforcer_loop() -> None:
    """Best-effort lifecycle enforcement for known non-ledger Redis keys.

    Purpose:
    - Apply TTLs automatically for governed stores when keys were created without TTL.
    - Never deletes the append-only audit ledger.

    Notes:
    - This is intentionally conservative and scoped to a few key patterns.
    - Uses SCAN with small COUNT to avoid heavy load.
    """
    await asyncio.sleep(5.0)
    while True:
        try:
            r = await get_redis_client()
            store = PolicyStore(r)

            # 1) Session prompts: session:{tenant}:{session}:prompts
            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="session:*:prompts", count=200)
                for k in keys or []:
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        parts = str(k).split(":")
                        tenant_id = parts[1] if len(parts) >= 3 else None
                        if not tenant_id:
                            continue
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
                        )
                        policy = current.policy or {}
                        prompts_ttl = _policy_retention_seconds(policy, "session_prompts_ttl_seconds")
                        if prompts_ttl > 0:
                            await r.expire(k, prompts_ttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

            # 2) Per-tenant adversarial corpus: apex:adversarial_corpus:{tenant}
            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="apex:adversarial_corpus:*", count=200)
                for k in keys or []:
                    if str(k) == "apex:adversarial_corpus":
                        continue
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        tenant_id = str(k).split(":", 2)[2]
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
                        )
                        policy = current.policy or {}
                        adv_ttl = _policy_retention_seconds(policy, "adversarial_corpus_ttl_seconds")
                        if adv_ttl > 0:
                            await r.expire(k, adv_ttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

            # 3) Tenant-scoped content store: apex:content:{tenant}:*
            cursor = 0
            while True:
                cursor, keys = await r.scan(cursor=cursor, match="apex:content:*:*:*", count=200)
                for k in keys or []:
                    try:
                        ttl = int(await r.ttl(k) or -1)
                    except Exception:
                        ttl = -1
                    if ttl != -1:
                        continue
                    try:
                        tenant_id = str(k).split(":", 3)[2]
                        current = await store.get_policy_or_seed(
                            tenant_id,
                            seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
                        )
                        policy = current.policy or {}
                        cttl = _policy_retention_seconds(policy, "content_store_ttl_seconds")
                        if cttl > 0:
                            await r.expire(k, cttl)
                    except Exception:
                        continue
                if int(cursor) == 0:
                    break

        except Exception:
            pass

        await asyncio.sleep(300)


async def _get_redis_memory_pressure(r: redis.Redis) -> Dict[str, Any]:
    try:
        info = await r.info(section="memory")
        used = int(info.get("used_memory", 0) or 0)
        maxmem = int(info.get("maxmemory", 0) or 0)
        if maxmem <= 0:
            return {"supported": False, "used_memory": used, "maxmemory": maxmem, "pressure": None}
        pressure = float(used) / float(maxmem)
        return {"supported": True, "used_memory": used, "maxmemory": maxmem, "pressure": pressure}
    except Exception:
        return {"supported": False, "used_memory": None, "maxmemory": None, "pressure": None}


async def _enforce_failsafe_or_raise(r: redis.Redis) -> None:
    if not APEX_FAILSAFE_GOV:
        return

    if not bool(SELF_TEST.get("ok", True)):
        raise HTTPException(status_code=503, detail="Fail-safe: self-test failed")

    if not bool(SIGNER_HEALTH.get("ok", True)):
        raise HTTPException(status_code=503, detail="Fail-safe: signer unhealthy")

    mem = await _get_redis_memory_pressure(r)
    pressure = mem.get("pressure")
    if mem.get("supported") and isinstance(pressure, float) and pressure >= float(APEX_LEDGER_CAPACITY_FAIL_PCT):
        raise HTTPException(status_code=503, detail=f"Fail-safe: Redis memory pressure high ({pressure:.2%})")


async def signing_worker_loop(stop_event: asyncio.Event) -> None:
    """
    Asynchronous signing worker:
    - Consumes indices from SIGNING_QUEUE_KEY
    - Verifies hash consistency
    - Produces KMS/soft signatures
    - Pushes signed entries into S3 flush buffer
    """
    try:
        signer = load_signer_for_worker()
        SIGNER_HEALTH["ok"] = True
        SIGNER_HEALTH["last_ok_at"] = datetime.utcnow().isoformat() + "Z"
        SIGNER_HEALTH["last_error"] = None
    except Exception as e:
        signer = None
        SIGNER_HEALTH["ok"] = False
        SIGNER_HEALTH["last_error"] = f"signer_load_failed:{e}"
        SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
    r = await get_redis_client()

    MAX_SIGNING_ATTEMPTS = 5
    RETRY_DELAY_SECONDS = 2.0

    while not stop_event.is_set():
        try:
            if signer is None:
                try:
                    signer = load_signer_for_worker()
                    SIGNER_HEALTH["ok"] = True
                    SIGNER_HEALTH["last_ok_at"] = datetime.utcnow().isoformat() + "Z"
                    SIGNER_HEALTH["last_error"] = None
                except Exception as e:
                    SIGNER_HEALTH["ok"] = False
                    SIGNER_HEALTH["last_error"] = f"signer_load_failed:{e}"
                    SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
                    await asyncio.sleep(2.0)
                    continue

            item = await r.blpop(SIGNING_QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, index_str = item
            index = int(index_str)

            entry = await read_raw_ledger_entry(r, index)
            if not entry:
                continue

            if entry.get("signing_status") == "kms_signed":
                continue

            attempts = int(entry.get("signing_attempts", 0))
            if attempts >= MAX_SIGNING_ATTEMPTS:
                entry["signing_status"] = "kms_failed"
                entry["kms_signed_at"] = entry.get("kms_signed_at") or datetime.utcnow().isoformat() + "Z"
                await update_raw_ledger_entry(r, index, entry)
                continue

            payload = entry.get("payload", {})
            prev_hash = entry.get("prev_hash")
            entry_hash = compute_entry_hash(payload, prev_hash)

            if entry_hash != entry.get("entry_hash"):
                entry["signing_status"] = "hash_mismatch"
                entry["kms_signed_at"] = datetime.utcnow().isoformat() + "Z"
                await update_raw_ledger_entry(r, index, entry)
                continue

            # Dual-control guardrail: ensure the signer is using an approved KMS key.
            # Fail closed in PROD/FIPS when enabled.
            try:
                await _enforce_kms_dual_control_or_raise(r)
            except Exception as e:
                SIGNER_HEALTH["ok"] = False
                SIGNER_HEALTH["last_error"] = f"dual_control_failed:{e}"
                SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
                try:
                    await _emit_signing_access_log(
                        r,
                        tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                        status="failure",
                        ledger_index=index,
                        entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                        kid=(entry.get("kid") if isinstance(entry, dict) else None),
                        alg=(entry.get("alg") if isinstance(entry, dict) else None),
                        signing_status=str(entry.get("signing_status") or "pending_kms"),
                        error=f"dual_control:{str(e)}",
                    )
                except Exception:
                    pass
                # Requeue and back off to avoid hot-looping.
                try:
                    await enqueue_for_signing(r, index)
                except Exception:
                    pass
                await asyncio.sleep(2.0)
                continue

            message_bytes = json.dumps(
                {
                    "payload": payload,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

            def _sign():
                return signer.sign(message_bytes)

            try:
                signature = await asyncio.to_thread(_sign)
            except Exception as e:
                SIGNER_HEALTH["ok"] = False
                SIGNER_HEALTH["last_error"] = "sign_failed"
                SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
                try:
                    await _emit_signing_access_log(
                        r,
                        tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                        status="failure",
                        ledger_index=index,
                        entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                        kid=(entry.get("kid") if isinstance(entry, dict) else None),
                        alg=(entry.get("alg") if isinstance(entry, dict) else None),
                        signing_status=str(entry.get("signing_status") or "pending_kms"),
                        error=f"sign_failed:{str(e)}",
                    )
                except Exception:
                    pass
                attempts += 1
                entry["signing_attempts"] = attempts
                if attempts >= MAX_SIGNING_ATTEMPTS:
                    entry["signing_status"] = "kms_failed"
                    entry["kms_signed_at"] = datetime.utcnow().isoformat() + "Z"
                    await update_raw_ledger_entry(r, index, entry)
                else:
                    await update_raw_ledger_entry(r, index, entry)
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                    await enqueue_for_signing(r, index)
                continue

            entry["kms_signature"] = base64.b64encode(signature).decode("ascii")
            entry["kms_signed_at"] = datetime.utcnow().isoformat() + "Z"
            entry["signing_status"] = "kms_signed"
            entry["signing_attempts"] = attempts

            # Key-rotation correctness: record the actual signer key id used.
            try:
                signer_kid = getattr(signer, "key_id", None)
                if isinstance(signer_kid, str) and signer_kid.strip():
                    entry["kid"] = signer_kid.strip()
            except Exception:
                pass
            await update_raw_ledger_entry(r, index, entry)

            try:
                await _emit_signing_access_log(
                    r,
                    tenant_id=(payload.get("tenant_id") if isinstance(payload, dict) else None),
                    status="success",
                    ledger_index=index,
                    entry_id=(payload.get("entry_id") if isinstance(payload, dict) else None),
                    kid=(entry.get("kid") if isinstance(entry, dict) else None),
                    alg=(entry.get("alg") if isinstance(entry, dict) else None),
                    signing_status=str(entry.get("signing_status") or "kms_signed"),
                    error=None,
                )
            except Exception:
                pass

            SIGNER_HEALTH["ok"] = True
            SIGNER_HEALTH["last_ok_at"] = datetime.utcnow().isoformat() + "Z"
            SIGNER_HEALTH["last_error"] = None

            # enqueue into S3 flush buffer
            try:
                await r.rpush(
                    "apex:signed_ledger_buffer",
                    json.dumps(entry, separators=(",", ":"), sort_keys=True),
                )
            except Exception:
                pass

        except Exception as e:
            SIGNER_HEALTH["ok"] = False
            SIGNER_HEALTH["last_error"] = f"signing_loop_error:{e}"
            SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
            await asyncio.sleep(1.0)

# =========================================================
# 4. CIRCUIT BREAKERS (HALF-OPEN) FOR LLM & EMBEDDINGS
# =========================================================

class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class HalfOpenCircuitBreaker:
    """
    Simple per-process half-open circuit breaker.
    Protects against cascading failures to upstream LLM / embedding APIs.
    """

    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 30, half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_attempts = 0

    def before_call(self) -> None:
        now = time.time()
        if self.state == CircuitState.OPEN:
            if self._opened_at is None or now - self._opened_at > self.reset_timeout:
                self.state = CircuitState.HALF_OPEN
                self._half_open_attempts = 0
            else:
                raise HTTPException(status_code=503, detail="Upstream circuit open")

        if self.state == CircuitState.HALF_OPEN:
            self._half_open_attempts += 1
            if self._half_open_attempts > self.half_open_max_calls:
                self.state = CircuitState.OPEN
                self._opened_at = now
                raise HTTPException(status_code=503, detail="Upstream circuit re-opened")

    def after_call_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._half_open_attempts = 0
        self.state = CircuitState.CLOSED

    def after_call_failure(self) -> None:
        self._failures += 1
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self._opened_at = time.time()
            return
        if self._failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self._opened_at = time.time()


LLM_CIRCUIT = HalfOpenCircuitBreaker(failure_threshold=5, reset_timeout=30, half_open_max_calls=3)
EMBEDDER_CIRCUIT = HalfOpenCircuitBreaker(failure_threshold=3, reset_timeout=15, half_open_max_calls=2)

# =========================================================
# 5. CORE SECURITY ENGINE (TONY + PII + DRIFT BACKEND)
# =========================================================

def clamp01(x: float) -> float:
    return max(0.0, min(float(x), 1.0))


def normalize_for_security(text: str) -> str:
    """
    Normalize text to reduce evasion surface:
    - NFKC normalization
    - remove non-printable
    - lowercasing
    - at/dot obfuscation normalization
    - collapse punctuation/spaces between token characters
    - opportunistic base64 decode to enrich context
    """
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if ch.isprintable())
    t = t.lower()

    t = t.replace("[at]", "@").replace("(at)", "@")
    t = t.replace(" at ", "@")
    t = t.replace("[dot]", ".").replace("(dot)", ".")
    t = t.replace(" dot ", ".")

    t = re.sub(r"(\w)[\s\-\._]+(?=\w)", r"\1", t)
    t = re.sub(r"\s+", " ", t)

    if re.fullmatch(r"[A-Za-z0-9+/=\s]{20,}", t):
        try:
            decoded = base64.b64decode(t, validate=True).decode("utf-8", errors="ignore")
            if decoded.strip():
                t = t + " " + decoded.lower()
        except Exception:
            pass
    return t


def redact_pii(text: str, patterns: List[str]) -> str:
    """
    Regex-based PII redaction. This is intentionally conservative and can over-redact.
    """
    redacted = text
    for pat in patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


class DriftBackend(Protocol):
    """
    Drift backends provide per-session anchor vectors and (optionally) history text.
    """

    async def get_anchor(self, session_id: str) -> np.ndarray:
        ...

    async def get_history_prompts(self, session_id: str) -> List[str]:
        ...


class EmbeddingProvider(Protocol):
    async def embed(self, text: str) -> np.ndarray:
        ...


class OpenAIEmbeddingProvider:
    """
    Minimal OpenAI embedding client for drift backend.
    """

    def __init__(self, api_key: str, model: str = APEX_EMBEDDING_MODEL):
        self.api_key = api_key
        self.model = model
        self._client = httpx.AsyncClient(
            base_url="https://api.openai.com/v1",
            timeout=15.0,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        self._dim: Optional[int] = None

    async def _ensure_dim(self) -> int:
        if self._dim is not None:
            return self._dim
        payload = {"input": "apex-dim-probe", "model": self.model}
        resp = await self._client.post("/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
        vec = data["data"][0]["embedding"]
        self._dim = len(vec)
        return self._dim

    async def embed(self, text: str) -> np.ndarray:
        if not text.strip():
            dim = await self._ensure_dim()
            return np.zeros(dim, dtype=float)
        payload = {"input": text, "model": self.model}
        resp = await self._client.post("/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
        vec = data["data"][0]["embedding"]
        return np.array(vec, dtype=float)


class VectorIndex(Protocol):
    async def upsert(
        self,
        items: List[Dict[str, Any]],
    ) -> None:
        ...

    async def query(
        self,
        session_id: str,
        top_k: int,
    ) -> List[np.ndarray]:
        ...

    async def delete_session(self, session_id: str) -> None:
        ...


class QdrantIndex:
    """
    Qdrant-backed vector index for drift history.
    """

    def __init__(
        self,
        client: AsyncQdrantClient,
        collection: str,
        vector_dim: int,
        distance: Distance = Distance.COSINE,
    ):
        self.client = client
        self.collection = collection
        self.vector_dim = vector_dim
        self.distance = distance

    async def ensure_collection(self) -> None:
        collections = await self.client.get_collections()
        names = [c.name for c in collections.collections]
        if self.collection not in names:
            await self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(
                    size=self.vector_dim,
                    distance=self.distance,
                ),
            )

    async def upsert(self, items: List[Dict[str, Any]]) -> None:
        points = []
        for it in items:
            points.append(
                PointStruct(
                    id=it["id"],
                    vector=it["vector"],
                    payload=it.get("metadata", {}),
                )
            )

        await self.client.upsert(
            collection_name=self.collection,
            points=points,
        )

    async def query(self, session_id: str, top_k: int) -> List[np.ndarray]:
        flt = Filter(
            must=[
                FieldCondition(
                    key="session_id",
                    match=MatchValue(value=session_id),
                )
            ]
        )
        limit = top_k
        offset = None
        vectors: List[np.ndarray] = []
        while True:
            res, next_offset = await self.client.scroll(
                collection_name=self.collection,
                scroll_filter=flt,
                limit=min(limit, 100),
                with_vectors=True,
                with_payload=False,
                offset=offset,
            )
            for p in res:
                if p.vector is not None:
                    vectors.append(np.array(p.vector, dtype=float))
                    if len(vectors) >= top_k:
                        return vectors
            if not next_offset:
                break
            offset = next_offset
        return vectors

    async def delete_session(self, session_id: str) -> None:
        flt = Filter(
            must=[
                FieldCondition(
                    key="session_id",
                    match=MatchValue(value=session_id),
                )
            ]
        )
        await self.client.delete(
            collection_name=self.collection,
            wait=True,
            filter=flt,
        )


class RedisBowDriftBackend:
    """
    Baseline, Redis-backed, Bag-of-Words drift backend.
    """

    def __init__(self, r_client: redis.Redis, history_limit: int = 20):
        self.r = r_client
        self.history_limit = history_limit

    async def get_history_prompts(self, session_id: str) -> List[str]:
        return await self.r.lrange(f"session:{session_id}:prompts", -self.history_limit, -1)

    async def get_anchor(self, session_id: str) -> np.ndarray:
        prior_prompts = await self.get_history_prompts(session_id)
        if not prior_prompts:
            return np.zeros(1)

        all_text = " ".join(prior_prompts)
        words = all_text.split()
        if not words:
            return np.zeros(1)

        word_counts = Counter(words)
        vocab = sorted(set(words))
        vec = np.array([word_counts.get(w, 0) for w in vocab], dtype=float)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else np.zeros_like(vec)

    async def reset_anchor(self, session_id: str) -> None:
        await self.r.delete(f"session:{session_id}:prompts")


class VectorDbDriftBackend:
    """
    Vector DB-backed drift with:
    - per-session anchor (mean of recent embeddings)
    - global anchor around a canonical safe-policy text
    """

    def __init__(
        self,
        index: QdrantIndex,
        embedder: EmbeddingProvider,
        history_limit: int = 50,
        global_policy_text: str = GLOBAL_POLICY_TEXT,
    ):
        self.index = index
        self.embedder = embedder
        self.history_limit = history_limit
        self.global_policy_text = global_policy_text
        self._global_anchor_vec: Optional[np.ndarray] = None

    async def ensure_global_anchor(self) -> np.ndarray:
        if self._global_anchor_vec is not None:
            return self._global_anchor_vec
        vec = await self.embedder.embed(self.global_policy_text)
        norm = np.linalg.norm(vec)
        self._global_anchor_vec = vec / norm if norm > 0 else vec
        return self._global_anchor_vec

    async def get_history_prompts(self, session_id: str) -> List[str]:
        # Qdrant backend focuses on vector state; text history not used directly here.
        return []

    async def get_anchor(self, session_id: str) -> np.ndarray:
        vectors = await self.index.query(session_id=session_id, top_k=self.history_limit)
        if not vectors:
            return np.zeros(0, dtype=float)
        mat = np.stack(vectors, axis=0)
        mean_vec = mat.mean(axis=0)
        norm = np.linalg.norm(mean_vec)
        return mean_vec / norm if norm > 0 else np.zeros_like(mean_vec)

    async def add_prompt_embedding(self, session_id: str, prompt: str) -> None:
        vec = await self.embedder.embed(prompt)
        item = {
            "id": f"{session_id}:{int(time.time() * 1000)}",
            "vector": vec.tolist(),
            "metadata": {
                "session_id": session_id,
                "ts": datetime.utcnow().isoformat() + "Z",
            },
        }
        await self.index.upsert([item])

    async def reset_anchor(self, session_id: str) -> None:
        await self.index.delete_session(session_id)


DRIFT_BACKEND: Optional[DriftBackend] = None

# =========================================================
# 5b. ALERTING & XAI EXPLANATIONS
# =========================================================

class BlockExplanation(BaseModel):
    """
    Human-readable governance explanation for BLOCK decisions.
    """
    reason_code: str
    human_message: str
    remediation_hint: Optional[str] = None


def explain_block(reason_code: str, risk_vec: Dict[str, Any]) -> BlockExplanation:
    if reason_code == "axis_pii_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="Your message appears to contain sensitive personal information.",
            remediation_hint="Remove or obfuscate items like credit card numbers, SSNs, phone numbers, or addresses.",
        )
    if reason_code == "axis_jailbreak_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="Your request seems to be trying to bypass safety or system instructions.",
            remediation_hint="Rephrase the request without asking to ignore or override safety rules.",
        )
    if reason_code == "axis_grooming_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="The content looks like inappropriate or manipulative interaction.",
            remediation_hint="Avoid asking for secretive, suggestive, or age-related personal engagement.",
        )
    if reason_code == "axis_toxicity_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="The content appears toxic or abusive.",
            remediation_hint="Remove slurs, threats, or hateful language and try again.",
        )
    if reason_code == "axis_dlp_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This request appears to involve high-risk financial or sensitive operational content.",
            remediation_hint="Remove account/transfer/trading instructions or sensitive transaction details and try again.",
        )
    if reason_code == "tony_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This response crosses your organization's configured safety threshold.",
            remediation_hint="Simplify the request, remove risky details, or contact your administrator if this seems wrong.",
        )
    if reason_code == "flagged_risks":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This interaction triggered one or more critical safety flags.",
            remediation_hint="Avoid requests involving sensitive personal data, policy evasion, or abusive content.",
        )
    return BlockExplanation(
        reason_code=reason_code,
        human_message="This content has been blocked by the safety policy.",
        remediation_hint="Try removing sensitive details or potentially risky language.",
    )


def evaluate_risk(risk_vec: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[str, Optional[str], float]:
    """Evaluate a computed risk vector against a tenant policy.

    Returns (decision, violation_code, score).

    Notes:
    - Axis thresholds are checked first (PII/Jailbreak/Grooming/Toxicity).
    - If no axis crosses its threshold, unified TONY is compared to unified_thresh.
    """

    axis_thresholds = policy.get("axis_thresholds") or {}

    pii_score = float(risk_vec.get("pii", 0.0) or 0.0)
    jb_score = float(max(risk_vec.get("jailbreak", 0.0) or 0.0, risk_vec.get("semantic_injection", 0.0) or 0.0))
    grooming_score = float(risk_vec.get("grooming", 0.0) or 0.0)
    toxicity_score = float(max(risk_vec.get("toxicity", 0.0) or 0.0, risk_vec.get("semantic_toxicity", 0.0) or 0.0))
    dlp_score = float(risk_vec.get("dlp", 0.0) or 0.0)

    pii_thresh = float(axis_thresholds.get("pii", DEFAULT_POLICY_BASELINE["axis_thresholds"]["pii"]))
    jb_thresh = float(axis_thresholds.get("jailbreak", DEFAULT_POLICY_BASELINE["axis_thresholds"]["jailbreak"]))
    grooming_thresh = float(axis_thresholds.get("grooming", DEFAULT_POLICY_BASELINE["axis_thresholds"]["grooming"]))
    tox_thresh = float(axis_thresholds.get("toxicity", 0.0))
    dlp_thresh = float(axis_thresholds.get("dlp", 0.0))

    if pii_thresh > 0.0 and pii_score >= pii_thresh:
        return "BLOCK", "axis_pii_threshold", pii_score
    if jb_thresh > 0.0 and jb_score >= jb_thresh:
        return "BLOCK", "axis_jailbreak_threshold", jb_score
    if grooming_thresh > 0.0 and grooming_score >= grooming_thresh:
        return "BLOCK", "axis_grooming_threshold", grooming_score
    if tox_thresh > 0.0 and toxicity_score >= tox_thresh:
        return "BLOCK", "axis_toxicity_threshold", toxicity_score
    if dlp_thresh > 0.0 and dlp_score >= dlp_thresh:
        return "BLOCK", "axis_dlp_threshold", dlp_score

    unified_thresh = float(policy.get("unified_thresh", DEFAULT_POLICY_BASELINE["unified_thresh"]))
    tony_score = float(risk_vec.get("tony", 0.0) or 0.0)

    if tony_score >= unified_thresh:
        return "BLOCK", "tony_threshold", tony_score
    return "PASS", None, tony_score


async def send_alert_if_needed(payload: Dict[str, Any], *, r: Optional[redis.Redis] = None) -> None:
    """
    Optional webhook alert for high TONY score or BLOCK decisions.
    """
    # Backwards compatible behavior: when no alerting is configured at all, do nothing.
    if not ALERT_WEBHOOK_URL and not APEX_SIEM_WEBHOOK_URL:
        return

    tony_score = float(payload.get("risk_axes", {}).get("tony", 0.0))
    decision = payload.get("decision")
    should_send = bool(
        APEX_SIEM_SEND_ALL
        or decision in {"BLOCK", "DENY"}
        or (decision == "ADMIN_ACTION")
        or (tony_score >= ALERT_MIN_TONY_SCORE)
    )
    if not should_send:
        return

    async def _post():
        try:
            async with httpx.AsyncClient(timeout=float(APEX_SIEM_TIMEOUT_SECONDS or 5.0)) as client:
                # 1) Legacy/general alert webhook (if configured)
                if ALERT_WEBHOOK_URL:
                    try:
                        # Best-effort sovereign egress enforcement: do not break traffic.
                        try:
                            await enforce_sovereign_egress_or_raise(
                                r,
                                tenant_id=str(payload.get("tenant_id") or "").strip() or None,
                                session_id=str(payload.get("session_id") or "").strip() or None,
                                subject=str(payload.get("subject") or "").strip() or None,
                                roles=payload.get("roles") if isinstance(payload.get("roles"), list) else None,
                                purpose="ALERT_WEBHOOK",
                                url=ALERT_WEBHOOK_URL,
                            )
                        except HTTPException:
                            return
                        await client.post(ALERT_WEBHOOK_URL, json=payload)
                    except Exception:
                        pass
        except Exception:
            pass

    asyncio.create_task(_post())

    # 2) SIEM forwarding (best-effort, includes incident correlation when Redis is available)
    if APEX_SIEM_WEBHOOK_URL:
        asyncio.create_task(enrich_and_send_siem_event(r=r, payload=payload))


# =========================================================
# 5c. SIEM INTEGRATION, SEVERITY, INCIDENT CORRELATION, RUNBOOKS
# =========================================================

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _classify_severity(payload: Dict[str, Any]) -> Severity:
    """Best-effort severity classification for SIEM/IR.

    This is intentionally deterministic and lightweight.
    """
    decision = str(payload.get("decision") or "").upper()
    violation = str(payload.get("violation") or "").lower()

    try:
        tony = float((payload.get("risk_axes") or {}).get("tony") or payload.get("score") or 0.0)
    except Exception:
        tony = 0.0

    if decision in {"BLOCK"}:
        if violation in {"axis_pii_threshold", "axis_dlp_threshold"}:
            return Severity.HIGH
        if violation in {"axis_jailbreak_threshold"}:
            return Severity.MEDIUM
        if tony >= 0.95:
            return Severity.HIGH
        return Severity.MEDIUM

    if decision in {"DENY"}:
        return Severity.MEDIUM

    if decision in {"INCIDENT_OPENED", "INCIDENT_ESCALATED"}:
        return Severity.HIGH

    if tony >= max(ALERT_MIN_TONY_SCORE, 0.90):
        return Severity.MEDIUM
    return Severity.INFO


IR_TIMELINES_DEFAULT: Dict[str, Dict[str, Any]] = {
    Severity.INFO.value: {"ack_minutes": 240, "contain_minutes": 1440, "update_minutes": 1440},
    Severity.LOW.value: {"ack_minutes": 120, "contain_minutes": 720, "update_minutes": 720},
    Severity.MEDIUM.value: {"ack_minutes": 60, "contain_minutes": 240, "update_minutes": 240},
    Severity.HIGH.value: {"ack_minutes": 15, "contain_minutes": 60, "update_minutes": 60},
    Severity.CRITICAL.value: {"ack_minutes": 5, "contain_minutes": 30, "update_minutes": 30},
}


def _ir_timelines() -> Dict[str, Any]:
    """Return incident response timelines.

    Supports optional override via APEX_IR_TIMELINES_JSON.
    """
    raw = os.getenv("APEX_IR_TIMELINES_JSON", "")
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                # Shallow-merge; preserve defaults if keys missing.
                merged = json.loads(json.dumps(IR_TIMELINES_DEFAULT))
                for k, v in obj.items():
                    if isinstance(k, str) and isinstance(v, dict):
                        merged[k] = v
                return merged
        except Exception:
            pass
    return IR_TIMELINES_DEFAULT


def _incident_active_key(*, tenant_id: str, correlation_key: str) -> str:
    digest = _sha256_hex(f"{tenant_id}\0{correlation_key}".encode("utf-8"))
    return f"apex:incidents:active:{tenant_id}:{digest}"


def _incident_record_key(incident_id: str) -> str:
    return f"apex:incidents:record:{incident_id}"


async def _correlate_alert(
    r: redis.Redis,
    *,
    payload: Dict[str, Any],
    severity: Severity,
) -> Dict[str, Any]:
    """Correlate alerts into incidents using Redis.

    Rule (minimal): same tenant + session_id + violation/action within a window => same incident_id.
    """
    tenant_id = str(payload.get("tenant_id") or "").strip() or "unknown"
    session_id = str(payload.get("session_id") or "").strip()
    decision = str(payload.get("decision") or "").strip()
    violation = str(payload.get("violation") or payload.get("action") or "").strip() or "unknown"

    correlation_key = f"{decision}:{violation}:{session_id}" if session_id else f"{decision}:{violation}"
    active_key = _incident_active_key(tenant_id=tenant_id, correlation_key=correlation_key)

    incident_id = None
    opened = False
    now_iso = datetime.utcnow().isoformat() + "Z"
    ttl = max(60, int(APEX_ALERT_CORRELATION_WINDOW_SECONDS or 900))

    try:
        existing = await r.get(active_key)
        if existing:
            incident_id = str(existing)
    except Exception:
        incident_id = None

    if not incident_id:
        incident_id = f"inc_{uuid.uuid4().hex}"
        try:
            ok = await r.set(active_key, incident_id, ex=ttl, nx=True)
            if ok:
                opened = True
            else:
                # Raced; read winner.
                try:
                    winner = await r.get(active_key)
                    if winner:
                        incident_id = str(winner)
                        opened = False
                except Exception:
                    pass
        except Exception:
            pass

    record = {
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "decision": decision,
        "violation": violation,
        "correlation_key": correlation_key,
        "severity": severity.value,
        "opened": bool(opened),
        "first_seen_at": now_iso,
        "last_seen_at": now_iso,
        "count": 1,
    }

    # Best-effort: update incident record.
    try:
        rk = _incident_record_key(incident_id)
        existing_raw = await r.get(rk)
        if existing_raw:
            try:
                existing_obj = json.loads(existing_raw)
            except Exception:
                existing_obj = {}
            record["first_seen_at"] = existing_obj.get("first_seen_at") or record["first_seen_at"]
            record["count"] = int(existing_obj.get("count") or 0) + 1
            opened = False
            record["opened"] = False
        await r.set(rk, json.dumps(record, separators=(",", ":"), sort_keys=True), ex=30 * 24 * 3600)
    except Exception:
        pass

    return record


def _siem_headers() -> Dict[str, str]:
    if not APEX_SIEM_WEBHOOK_HEADERS_JSON:
        return {}
    try:
        obj = json.loads(APEX_SIEM_WEBHOOK_HEADERS_JSON)
        if isinstance(obj, dict):
            out: Dict[str, str] = {}
            for k, v in obj.items():
                if isinstance(k, str) and isinstance(v, str):
                    out[k] = v
            return out
    except Exception:
        pass
    return {}


async def _send_to_siem(event: Dict[str, Any], *, r: Optional[redis.Redis] = None) -> None:
    if not APEX_SIEM_WEBHOOK_URL:
        return
    try:
        # Best-effort sovereign egress enforcement: do not break traffic.
        try:
            await enforce_sovereign_egress_or_raise(
                r,
                tenant_id=str((event.get("payload") or {}).get("tenant_id") or "").strip() or None,
                session_id=str((event.get("payload") or {}).get("session_id") or "").strip() or None,
                subject=str((event.get("payload") or {}).get("subject") or "").strip() or None,
                roles=(event.get("payload") or {}).get("roles") if isinstance((event.get("payload") or {}).get("roles"), list) else None,
                purpose="SIEM_WEBHOOK",
                url=APEX_SIEM_WEBHOOK_URL,
            )
        except HTTPException:
            return
        headers = {"Content-Type": "application/json", **_siem_headers()}
        async with httpx.AsyncClient(timeout=float(APEX_SIEM_TIMEOUT_SECONDS or 5.0)) as client:
            await client.post(APEX_SIEM_WEBHOOK_URL, headers=headers, json=event)
    except Exception:
        # Best-effort: SIEM forwarding should not break request traffic.
        return


RUNBOOKS: Dict[str, Dict[str, Any]] = {
    "axis_pii_threshold": {
        "title": "PII detected and blocked",
        "default_severity": Severity.HIGH.value,
        "steps": [
            "Confirm tenant/session scope and whether the content was user-supplied.",
            "Verify PII mode (block/redact) and thresholds in the tenant policy.",
            "If policy permits, advise user to remove PII and retry.",
            "If repeated, consider tightening allowlists and enabling additional DLP controls.",
        ],
    },
    "axis_jailbreak_threshold": {
        "title": "Prompt injection / jailbreak attempt",
        "default_severity": Severity.MEDIUM.value,
        "steps": [
            "Review threat intel feed version/hits for this tenant.",
            "Check whether the request attempted to override system/developer messages.",
            "Consider adding/activating threat intel indicators for the pattern.",
        ],
    },
    "axis_dlp_threshold": {
        "title": "High-risk/DLP intent blocked",
        "default_severity": Severity.HIGH.value,
        "steps": [
            "Confirm whether the request involved funds movement, credentials, or trade surveillance triggers.",
            "Ensure finance policy template thresholds/weights match governance expectations.",
            "Escalate to compliance if this appears to be a real user attempt.",
        ],
    },
    "tony_threshold": {
        "title": "Unified risk threshold exceeded",
        "default_severity": Severity.MEDIUM.value,
        "steps": [
            "Inspect which axes contributed most to TONY and whether thresholds are too strict.",
            "Check recent policy changes and two-person approvals.",
        ],
    },
    "model_not_allowlisted": {
        "title": "Model allowlist denied",
        "default_severity": Severity.LOW.value,
        "steps": [
            "Confirm requested model and current tenant allowlist.",
            "If business-approved, update allowlist via policy change controls.",
        ],
    },
    "unsupported_non_text_content": {
        "title": "Non-text content rejected",
        "default_severity": Severity.INFO.value,
        "steps": [
            "Confirm allow_multimodal setting for tenant policy.",
            "If multimodal is required, route to a multimodal-inspecting gateway.",
        ],
    },
}


async def enrich_and_send_siem_event(*, r: Optional[redis.Redis], payload: Dict[str, Any]) -> None:
    """Attach severity + correlation info and forward to SIEM (best-effort)."""
    if not APEX_SIEM_WEBHOOK_URL:
        return

    sev = _classify_severity(payload)
    incident: Optional[Dict[str, Any]] = None
    if r is not None:
        try:
            incident = await _correlate_alert(r, payload=payload, severity=sev)
        except Exception:
            incident = None

    event = {
        "type": "APEX_GOVERNANCE_ALERT",
        "ts": datetime.utcnow().isoformat() + "Z",
        "env": get_apex_env().value,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
        "severity": sev.value,
        "timelines": _ir_timelines().get(sev.value) or _ir_timelines().get(Severity.INFO.value),
        "incident": incident,
        "runbook": RUNBOOKS.get(str(payload.get("violation") or payload.get("action") or "")) or None,
        "payload": payload,
    }
    await _send_to_siem(event, r=r)

# =========================================================
# 5b. NEURAL SAFETY LAYER (SEMANTIC UPGRADE)
# =========================================================

class NeuralSafetyClassifier:
    """
    Industry Benchmark Upgrade: Replaces Regex with Semantic Analysis.
    Acts as a 'Tier 2' semantic validator for intent detection.
    """
    def __init__(self):
        self.enabled = True

    async def analyze_intent(self, text: str) -> Dict[str, float]:
        """
        Detects 'hidden' intent that escapes regex (e.g. metaphors, roleplay).
        In production, this calls a local SLM (LlamaGuard or Cross-Encoder).
        """
        # Placeholder for neural inference results
        return {
            "semantic_injection": 0.0, 
            "semantic_toxicity": 0.0
        }


class HighRiskContentClassifier:
    """Heuristic high-risk/DLP-style classifier beyond regex.

    This is intentionally lightweight (no external model dependency). It flags
    finance-adjacent risky intents like trade surveillance triggers and funds
    movement instructions.
    """

    def __init__(self):
        self.enabled = True

        self._trade_surveillance_terms = (
            "material nonpublic",
            "mnpi",
            "insider",
            "front run",
            "front-run",
            "pump and dump",
            "pump-and-dump",
            "spoofing",
            "layering",
            "wash trade",
            "wash-trade",
        )

        self._funds_movement_terms = (
            "wire transfer",
            "send a wire",
            "ach",
            "routing number",
            "swift",
            "iban",
            "beneficiary",
            "account number",
            "bank account",
            "bank details",
        )

        self._credential_terms = (
            "password",
            "one-time code",
            "otp",
            "2fa",
            "mfa",
            "security code",
        )

    def analyze(self, text: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"dlp": 0.0, "dlp_flags": []}

        t = normalize_for_security(text or "")
        flags: List[str] = []
        score = 0.0

        if any(term in t for term in self._trade_surveillance_terms):
            flags.append("trade_surveillance")
            score += 0.65

        if any(term in t for term in self._funds_movement_terms):
            flags.append("funds_movement")
            score += 0.45

        if any(term in t for term in self._credential_terms):
            flags.append("credentials")
            score += 0.25

        # Amplify if the user is explicitly asking for action/instructions.
        if any(term in t for term in ("how do i", "how to", "steps", "instructions", "do this", "execute")):
            score *= 1.15

        return {
            "dlp": clamp01(score),
            "dlp_flags": flags,
        }

# =========================================================
# 5c. APEX ENGINE – RISK COMPUTATION & GOVERNANCE DECISION
# =========================================================

# -- Minimal runtime stubs for missing components (safe defaults) --
# These are intentionally lightweight placeholders so the module can be
# imported and basic flows exercised without the full production implementations.
MERKLE_BATCH_SIZE = int(os.getenv("APEX_MERKLE_BATCH_SIZE", "1000000"))


class UserRiskProfile:
    def __init__(self, tenant_id: str, subject: str):
        self.tenant_id = tenant_id
        self.subject = subject
        self.total_interactions = 0
        self.block_events = 0
        self.near_misses = 0


class UserRiskStore:
    def __init__(self, r_client: redis.Redis):
        self.r = r_client

    async def get(self, tenant_id: str, subject: str) -> UserRiskProfile:
        # Return a simple, mutable profile object. Real impl should hydrate from Redis.
        return UserRiskProfile(tenant_id, subject)

    async def update(self, profile: UserRiskProfile) -> None:
        # No-op stub: production would persist profile changes.
        return


class FastRiskClassifier:
    def predict(self, text: str) -> float:
        # Very conservative fast-path: treat short inputs as low risk.
        if not text or len(text.strip()) < 20:
            return 0.0
        # Default neutral score; production should implement heuristic model.
        return 0.0


class MerkleBatch:
    def __init__(self, size_limit: int = MERKLE_BATCH_SIZE):
        self.size_limit = size_limit
        self._items: List[str] = []

    def add(self, entry_hash: str) -> None:
        self._items.append(entry_hash)

    def is_full(self) -> bool:
        return len(self._items) >= self.size_limit

    def clear(self) -> None:
        self._items = []


class ApexSovereignEngine:
    """
    Core security engine facade:
    - Tiered Risk Logic (Fast-path vs Deep Neural)
    - Bayesian User Priors
    - Merkle-batch Ledger Anchoring
    """

    def __init__(self, r_client: redis.Redis, drift_backend: Optional[DriftBackend] = None):
        self.r = r_client
        self.policy_store = PolicyStore(r_client)
        self.user_store = UserRiskStore(r_client)

        # --- v2 Upgrades: Neural & Tiered Logic ---
        self.fast_clf = FastRiskClassifier()
        self.neural_safety = NeuralSafetyClassifier()
        self.high_risk = HighRiskContentClassifier()
        
        # --- Drift Backend Initialization ---
        if drift_backend is not None:
            self.drift_backend: DriftBackend = drift_backend
        else:
            self.drift_backend = RedisBowDriftBackend(r_client)

        # Merkle batch accumulator for ledger anchoring
        self.merkle_batch = MerkleBatch(size_limit=MERKLE_BATCH_SIZE)

    async def _seal_merkle_batch(self) -> None:
        """
        Lightweight placeholder for sealing a merkle batch. Production should
        compute a merkle root, write an anchored ledger entry, and clear the
        accumulator. This stub clears the batch to avoid blocking flows.
        """
        try:
            # In production, compute merkle root and create ledger entry here.
            self.merkle_batch.clear()
        except Exception:
            # Non-fatal stub behavior
            pass

    async def compute_unified_risk(
        self,
        tenant_id: str,
        subject: str,
        session_id: str,
        prompt: str,
    ) -> Dict[str, Any]:
        """
        Unified risk engine entry point:
        - Tier 1: Fast-path heuristic check
        - Tier 2: Neural semantic analysis + Bayesian priors
        """
        
        # -----------------------------
        # TIER 1: FAST-PATH CLASSIFIER
        # -----------------------------
        coarse_risk = self.fast_clf.predict(prompt)
        if coarse_risk < 0.1:
            return {
                "decision": "PASS",
                "tony": coarse_risk,
                "tier": 1,
                "risk_vec": {},
            }

        # -----------------------------
        # TIER 2: FULL RISK ENGINE
        # -----------------------------
        # Load context & semantic analysis
        profile = await self.user_store.get(tenant_id, subject or "unknown")
        semantic_risks = await self.neural_safety.analyze_intent(prompt)
        
        # Original Axis Computation (Regex/PII/Drift)
        risk_vec = await self.compute_risk_for_prompt(tenant_id, session_id, prompt)
        
        # Merge Neural results into the vector
        risk_vec.update(semantic_risks)

        # Apply Bayesian Weighting
        policy = await self.get_tenant_policy(tenant_id)
        weights = self._adjust_axis_weights(policy.get("risk_weights", {}), profile)

        # Unified TONY Aggregation with Semantic Priority (Max-Pooling)
        # We take the MAX of regex hits and neural intent for robustness
        jb_score = max(risk_vec.get("jailbreak", 0.0), risk_vec.get("semantic_injection", 0.0))
        tox_score = max(risk_vec.get("toxicity", 0.0), risk_vec.get("semantic_toxicity", 0.0))

        severity_agg = (
            risk_vec["pii"] * weights.get("pii", 1.0) +
            jb_score * weights.get("jailbreak", 1.2) +
            risk_vec["grooming"] * weights.get("grooming", 0.8) +
            tox_score * weights.get("toxicity", 0.5) +
            risk_vec["drift"] * weights.get("drift", 0.3) +
            float(risk_vec.get("dlp", 0.0) or 0.0) * weights.get("dlp", 0.9) +
            float(risk_vec.get("dlp_semantic", 0.0) or 0.0) * weights.get("dlp_semantic", 1.0)
        )
        
        # TONY multipliers & context factoring
        tony_score = self._apply_tony_multipliers(severity_agg, risk_vec.get("context", 0.0))
        risk_vec["tony"] = float(tony_score)

        unified_thresh = policy.get("unified_thresh", 0.65)
        decision = "PASS" if tony_score < unified_thresh else "BLOCK"

        # Update Governance Metadata (Priors, Ledger, Corpus)
        await self._finalize_governance_metadata(
            profile, decision, tony_score, tenant_id, subject, session_id, prompt, risk_vec
        )

        return {
            "decision": decision,
            "tony": float(tony_score),
            "tier": 2,
            "risk_vec": risk_vec,
        }

    async def get_tenant_policy(self, tenant_id: str) -> Dict[str, Any]:
        """Compatibility helper for policy reads.

        The engine uses `PolicyStore` as the source of truth.
        """
        record = await self.policy_store.get_policy_or_seed(
            tenant_id,
            seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
        )
        return record.policy

    async def compute_risk_for_prompt(
        self,
        tenant_id: str,
        session_id: str,
        prompt: str,
        policy: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute risk axes for a single prompt window.

        This is the primary mid-stream evaluator. It is intentionally lightweight
        and does not require external ML dependencies.
        """

        policy = policy or await self.get_tenant_policy(tenant_id)
        text = prompt or ""
        norm = normalize_for_security(text)

        intel_score = 0.0
        intel_hits: List[Dict[str, Any]] = []
        intel_feed_version: Optional[str] = None
        try:
            ti = ThreatIntelStore(self.r)
            intel_res = await ti.match(tenant_id, norm)
            intel_score = float(intel_res.get("score") or 0.0)
            intel_hits = list(intel_res.get("hits") or [])
            intel_feed_version = intel_res.get("feed_version")
        except Exception:
            intel_score = 0.0

        dlp_sem_score = 0.0
        dlp_sem_hits: List[Dict[str, Any]] = []
        try:
            sem = await score_semantic_dlp(self.r, tenant_id=tenant_id, text=text)
            dlp_sem_score = float(sem.get("score") or 0.0)
            dlp_sem_hits = list(sem.get("hits") or [])
        except Exception:
            dlp_sem_score = 0.0

        # --- PII (regex patterns are policy-driven) ---
        pii_patterns = policy.get("pii_patterns") or DEFAULT_POLICY_BASELINE.get("pii_patterns") or []
        pii_hits = 0
        for pat in pii_patterns:
            try:
                if re.search(pat, norm, flags=re.IGNORECASE):
                    pii_hits += 1
            except re.error:
                continue
        # One hit should typically exceed default thresholds (0.1–0.2).
        pii_score = clamp01(pii_hits * 0.35)

        # --- Jailbreak (heuristic) ---
        jailbreak_terms = (
            "ignore previous",
            "disregard previous",
            "system prompt",
            "developer message",
            "jailbreak",
            "dan",
            "bypass safety",
            "override policy",
        )
        jb_hits = sum(1 for term in jailbreak_terms if term in norm)
        jailbreak_score = clamp01(jb_hits * 0.25)

        # Threat intel can contribute to semantic injection/jailbreak detection.
        semantic_injection_score = clamp01(intel_score)
        jailbreak_score = max(jailbreak_score, semantic_injection_score)

        # --- Grooming (heuristic) ---
        grooming_terms = (
            "how old are you",
            "your age",
            "are you alone",
            "keep this secret",
            "don't tell",
            "meet up",
        )
        grooming_hits = sum(1 for term in grooming_terms if term in norm)
        grooming_score = clamp01(grooming_hits * 0.25)

        # --- Toxicity (heuristic, minimal) ---
        toxicity_terms = (
            "kill yourself",
            "i hate you",
            "idiot",
            "stupid",
        )
        tox_hits = sum(1 for term in toxicity_terms if term in norm)
        toxicity_score = clamp01(tox_hits * 0.35)

        # --- DLP / high-risk intent beyond regex ---
        dlp_meta = self.high_risk.analyze(text)
        dlp_score = float(dlp_meta.get("dlp", 0.0) or 0.0)

        # --- Drift (history-aware; vector backend returns empty history) ---
        drift_score = 0.0
        try:
            history_prompts = await self.drift_backend.get_history_prompts(session_id)
        except Exception:
            history_prompts = []

        if history_prompts:
            try:
                # Simple token-set Jaccard drift: drift = 1 - similarity
                hist_text = " ".join([p for p in history_prompts if isinstance(p, str)])
                hist_norm = normalize_for_security(hist_text)
                hist_tokens = set(hist_norm.split())
                cur_tokens = set(norm.split())
                if hist_tokens and cur_tokens:
                    sim = len(hist_tokens & cur_tokens) / float(len(hist_tokens | cur_tokens))
                    drift_score = clamp01(1.0 - sim)
            except Exception:
                drift_score = 0.0

        # --- Context proxy ---
        context_score = clamp01(len(text) / 2000.0)

        # --- Unified TONY (fast aggregation for mid-stream decisions) ---
        weights = policy.get("risk_weights") or DEFAULT_POLICY_BASELINE.get("risk_weights") or {}
        severity_agg = (
            pii_score * float(weights.get("pii", 1.0))
            + jailbreak_score * float(weights.get("jailbreak", 1.2))
            + grooming_score * float(weights.get("grooming", 0.8))
            + toxicity_score * float(weights.get("toxicity", 0.5))
            + drift_score * float(weights.get("drift", 0.3))
            + dlp_score * float(weights.get("dlp", 0.9))
            + dlp_sem_score * float(weights.get("dlp_semantic", 1.0))
        )
        tony_score = float(self._apply_tony_multipliers(severity_agg, context_score))

        return {
            "pii": float(pii_score),
            "jailbreak": float(jailbreak_score),
            "semantic_injection": float(semantic_injection_score),
            "grooming": float(grooming_score),
            "toxicity": float(toxicity_score),
            "drift": float(drift_score),
            "context": float(context_score),
            "dlp": float(dlp_score),
            "dlp_flags": dlp_meta.get("dlp_flags", []),
            "dlp_semantic": float(dlp_sem_score),
            "dlp_semantic_hits": [h.get("exemplar_id") for h in dlp_sem_hits[:5] if isinstance(h, dict)],
            "threat_intel": float(intel_score),
            "threat_intel_feed_version": intel_feed_version,
            "threat_intel_hits": [h.get("rule_id") for h in intel_hits[:5] if isinstance(h, dict)],
            "tony": float(tony_score),
        }

    def _apply_tony_multipliers(self, severity_agg: float, context: float) -> float:
        """Helper for deterministic TONY scoring math."""
        context_mult = 1.0 + 0.2 * context
        drcf = 1 + 0.5 * 0.8 + 0.3 * 0.7 + 0.2 * 0.9
        persistence_log = 1 + math.log(1 + 2.0)
        # Multiplier stack: drcf * persistence * IRI * attribution * fsf * paf
        return (severity_agg * context_mult * drcf * persistence_log * 0.72 * 0.7695 * 0.765 * 1.1)

    async def _finalize_governance_metadata(self, profile, decision, score, t_id, sub, sess, text, risk_vec):
        """Update Bayesian priors and Merkle ledger."""
        # 1. Update Profile
        profile.total_interactions += 1
        if decision == "BLOCK":
            profile.block_events += 1
        elif score > 0.7:
            profile.near_misses += 1
        await self.user_store.update(profile)

        # 2. Merkle-batching
        entry_hash = hashlib.sha256(f"{t_id}:{sub}:{sess}:{text}".encode()).hexdigest()
        self.merkle_batch.add(entry_hash)
        if self.merkle_batch.is_full():
            await self._seal_merkle_batch()

        # 3. Adversarial Corpus Hook
        if decision != "PASS" or score > 0.7:
            policy: Dict[str, Any] = {}
            try:
                policy = await self.get_tenant_policy(t_id)
            except Exception:
                policy = {}

            no_content = _no_content_retention_enabled(policy)

            content_ttl = _policy_retention_seconds(policy, "content_store_ttl_seconds")
            adversarial_ttl = _policy_retention_seconds(policy, "adversarial_corpus_ttl_seconds")

            item: Dict[str, Any] = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "tony": score,
                "risk_vec": risk_vec,
            }
            if not no_content:
                if APEX_CONTENT_DEDUP and isinstance(text, str) and len(text) > 0:
                    ref = await _store_deduped_content(
                        self.r,
                        tenant_id=t_id,
                        kind="adversarial_text",
                        content=text,
                        ttl_seconds=content_ttl,
                    )
                    item["text_ref"] = ref
                else:
                    item["text"] = text

            # Write a per-tenant corpus list (enforceable lifecycle) and keep a legacy global list.
            per_tenant_key = f"apex:adversarial_corpus:{t_id}"
            await self.r.lpush(per_tenant_key, json.dumps(item))
            await self.r.lpush("apex:adversarial_corpus", json.dumps(item))

            if adversarial_ttl > 0:
                try:
                    await self.r.expire(per_tenant_key, adversarial_ttl)
                except Exception:
                    pass
                try:
                    await self.r.expire("apex:adversarial_corpus", adversarial_ttl)
                except Exception:
                    pass

    def _adjust_axis_weights(self, base_weights: Dict[str, float], profile: UserRiskProfile) -> Dict[str, float]:
        """Bayesian weight adjustment based on user trust."""
        if profile.total_interactions < 20:
            return base_weights

        trust_factor = max(0.5, 1.0 - (profile.block_events / max(1, profile.total_interactions)))
        adjusted = {}
        for axis, w in base_weights.items():
            # Hard safety axes remain strict regardless of trust
            if axis in ("pii", "grooming", "jailbreak"):
                adjusted[axis] = w
            else:
                adjusted[axis] = w * trust_factor
        return adjusted

# =========================================================
# 6. OIDC / JWKS + AUTHORIZATION ENGINE (RBAC)
# =========================================================

class JwksCache:
    """
    Cached JWKS fetcher for IdP validation.
    """

    def __init__(self, issuer: str, ttl_seconds: int):
        self.issuer = issuer.rstrip("/") if issuer else ""
        self.ttl_seconds = ttl_seconds
        self._jwks: Optional[Dict[str, Any]] = None
        self._loaded_at: Optional[float] = None

    def _is_fresh(self) -> bool:
        if self._jwks is None or self._loaded_at is None:
            return False
        return (time.time() - self._loaded_at) < self.ttl_seconds

    def _get_jwks_sync(self) -> Dict[str, Any]:
        if self._is_fresh():
            return self._jwks
        if not self.issuer:
            raise RuntimeError("APEX_OIDC_ISSUER must be set for IdP validation")
        jwks_url = self.issuer + "/.well-known/jwks.json"
        resp = requests.get(jwks_url, timeout=5)
        resp.raise_for_status()
        self._jwks = resp.json()
        self._loaded_at = time.time()
        return self._jwks

    async def get_jwks(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._get_jwks_sync)

    async def get_signing_key_async(self, token: str) -> Dict[str, Any]:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        jwks = await self.get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        raise JWTError("Signing key not found for kid in JWKS")


jwks_cache = JwksCache(issuer=OIDC_ISSUER, ttl_seconds=JWKS_CACHE_TTL_SECONDS)


class TenantIdentity(BaseModel):
    """
    Authenticated subject + tenant binding:
    - tenant_id: governance scope
    - subject: user or client id
    - roles/scopes: RBAC and access control decisions
    """
    tenant_id: str
    subject: str
    roles: List[str] = []
    scopes: List[str] = []
    raw_token: Optional[str] = None


class IdpVerifier:
    """
    OIDC token verifier with tenant header consistency checks.
    """

    async def verify(self, auth_header: str, header_tenant_id: str) -> TenantIdentity:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        token = auth_header[len("Bearer "):].strip()
        if not OIDC_ISSUER or not OIDC_AUDIENCE:
            raise HTTPException(status_code=500, detail="OIDC not configured")

        try:
            key = await jwks_cache.get_signing_key_async(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=[key.get("alg", "RS256")],
                audience=OIDC_AUDIENCE,
                issuer=OIDC_ISSUER,
            )
        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

        subject = claims.get("sub")
        tenant_from_token = claims.get(OIDC_TENANT_CLAIM)
        roles = claims.get("roles", [])
        scopes = claims.get("scp", claims.get("scope", "").split())

        if not tenant_from_token:
            raise HTTPException(status_code=403, detail="Tenant claim missing in token")

        if header_tenant_id and header_tenant_id != tenant_from_token:
            raise HTTPException(status_code=403, detail="Tenant header does not match token tenant")

        return TenantIdentity(
            tenant_id=tenant_from_token,
            subject=subject,
            roles=roles if isinstance(roles, list) else [roles],
            scopes=scopes,
            raw_token=token,
        )


idp_verifier = IdpVerifier()


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationResult(BaseModel):
    decision: AuthorizationDecision
    reason: Optional[str] = None
    effective_model: Optional[str] = None


class AuthorizationEngine:
    """
    Minimal RBAC engine:
    - Controls access to high-risk models
    - Enforces admin role for governance APIs
    """

    async def check(
        self,
        identity: TenantIdentity,
        requested_model: str,
    ) -> AuthorizationResult:
        high_risk_models = {"reasoning-pro"}
        roles_lower = {r.lower() for r in identity.roles}

        if requested_model in high_risk_models:
            if not ({"admin", "power-user"} & roles_lower):
                return AuthorizationResult(
                    decision=AuthorizationDecision.DENY,
                    reason="insufficient_role_for_high_risk_model",
                )

        effective_model = requested_model
        return AuthorizationResult(
            decision=AuthorizationDecision.ALLOW,
            reason=None,
            effective_model=effective_model,
        )

    def require_admin(self, identity: TenantIdentity) -> None:
        roles_lower = {r.lower() for r in identity.roles}
        if not ({"admin", "security-admin", "ciso"} & roles_lower):
            raise HTTPException(status_code=403, detail="Admin or security role required for this operation")

    def require_audit_read(self, identity: TenantIdentity) -> None:
        """Read-only governance/audit permission (no mutation)."""
        roles_lower = {r.lower() for r in identity.roles}
        allowed = {"admin", "security-admin", "ciso", "auditor", "security-auditor", "compliance-auditor"}
        if not (allowed & roles_lower):
            raise HTTPException(status_code=403, detail="Audit role required for this operation")


authz_engine = AuthorizationEngine()


def _envcfg_proposals_hash_key() -> str:
    return f"apex:envcfg:proposals:{get_apex_env().value}"


def _envcfg_proposals_index_key() -> str:
    return f"apex:envcfg:proposals:{get_apex_env().value}:index"


def _envcfg_desired_current_key() -> str:
    return f"apex:envcfg:desired:{get_apex_env().value}:current"


def _envcfg_desired_history_key() -> str:
    return f"apex:envcfg:desired:{get_apex_env().value}:history"


def _redact_env_change_value(name: str, value: Optional[str]) -> Dict[str, Any]:
    if value is None:
        return {"unset": True}
    v = value if isinstance(value, str) else str(value)
    if _is_sensitive_env_key(name) or len(v) > 512:
        return _redact_env_value(name, v)
    return {"redacted": False, "value": v}


def _sanitize_env_changes(changes: Dict[str, Optional[str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (changes or {}).items():
        if not isinstance(k, str) or not k.strip():
            continue
        key = k.strip().upper()
        # Restrict to known prefixes to avoid accidental storage of arbitrary data.
        if not (
            key.startswith("APEX_")
            or key.startswith("OIDC_")
            or key.startswith("QDRANT_")
            or key.startswith("OPENAI_")
        ):
            continue
        out[key] = _redact_env_change_value(key, v)
    return out


def _env_changes_version(changes_redacted: Dict[str, Any]) -> str:
    material = json.dumps(changes_redacted, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(material).hexdigest()

# =========================================================
# 7. REQUEST MODELS & FASTAPI APP (PROXY LAYER)
# =========================================================

class UniversalRequest(BaseModel):
    """
    Normalized chat completion request for the proxy.
    """
    model: str
    messages: List[Dict[str, Any]]
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    stream: bool = True


def _request_audit_context(http_request: Request) -> Dict[str, Any]:
    try:
        xff = http_request.headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            ip = http_request.client.host if http_request.client else None
    except Exception:
        ip = None

    return {
        "request_ip": ip,
        "user_agent": http_request.headers.get("user-agent"),
        "request_id": http_request.headers.get("x-request-id"),
        "device_id": http_request.headers.get("x-device-id"),
    }


def _validate_text_only_messages(messages: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Accepts either:
    - OpenAI-style `content: "..."`
    - OpenAI multimodal schema `content: [{"type":"text","text":"..."}, ...]` BUT text-only

    Rejects any other content shapes (images/audio/binary/tool payloads).
    """
    for i, m in enumerate(messages or []):
        content = m.get("content")
        if content is None:
            continue
        if isinstance(content, str):
            continue
        if isinstance(content, list):
            for j, part in enumerate(content):
                if not isinstance(part, dict):
                    return False, f"messages[{i}].content[{j}] non-dict part"
                ptype = str(part.get("type") or "")
                if ptype != "text":
                    return False, f"messages[{i}].content[{j}] type={ptype!r}"
                if not isinstance(part.get("text"), str):
                    return False, f"messages[{i}].content[{j}].text not str"
            continue
        # dict/bytes/other -> unsupported
        return False, f"messages[{i}].content type={type(content).__name__}"
    return True, None


class PolicyUpdateRequest(BaseModel):
    policy: Dict[str, Any]
    version: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None


class PolicyProposalRequest(BaseModel):
    """Create a pending policy change proposal (two-person rule workflow)."""

    policy: Dict[str, Any]
    change_request_id: Optional[str] = None
    requested_version: Optional[str] = None
    comment: Optional[str] = None
    justification: Optional[str] = None
    change_ticket: Optional[str] = None


class PolicyProposalApprovalRequest(BaseModel):
    """Approve and apply a pending proposal."""

    version: Optional[str] = None
    approval_comment: Optional[str] = None


class PolicyProposalRejectRequest(BaseModel):
    """Reject a pending proposal."""

    rejection_comment: Optional[str] = None


class EnvConfigProposalRequest(BaseModel):
    """Propose a desired change to runtime environment variables.

    Notes:
    - This does NOT mutate the running process environment.
    - Applying approved changes typically requires a redeploy.
    - Values are redacted in audit/reads.
    """

    # Optional operator-supplied idempotency/change ticket.
    change_request_id: Optional[str] = None
    change_ticket: Optional[str] = None
    justification: str
    comment: Optional[str] = None
    # Proposed changes: env var name -> desired value (string) or null to unset.
    changes: Dict[str, Optional[str]]


class EnvConfigProposalApprovalRequest(BaseModel):
    approval_comment: Optional[str] = None


class EnvConfigProposalRejectRequest(BaseModel):
    rejection_comment: Optional[str] = None


class ModelAllowlistUpdateRequest(BaseModel):
    """Admin request to update `policy.model_allowlist`.

    Accepts internal model names (keys of `MODEL_CATALOG`) or upstream/external
    names that are present in `EXTERNAL_MODEL_MAP`.
    """

    models: List[str]
    version: Optional[str] = None
    comment: Optional[str] = None


class RtbfS3ObjectRef(BaseModel):
    bucket: str
    key: str


class RtbfRequest(BaseModel):
    """Right-to-be-forgotten request.

    Backward compatible with the original marker-only API (subject/session_id/reason).
    Additional fields enable a structured deletion proof.
    """

    # Caller-supplied idempotency key; if absent, server generates one.
    request_id: Optional[str] = None

    subject: Optional[str] = None
    session_id: Optional[str] = None
    reason: Optional[str] = None

    # Optional explicit deletion directives.
    # If `session_id` is provided, prompt history + drift state are deleted best-effort by default.
    delete_session_state: bool = True

    # Clear semantic DLP exemplar store (includes deleting stored embeddings and referenced exemplar text content).
    delete_dlp_semantic: bool = False

    # Delete tenant-scoped adversarial corpus list.
    delete_adversarial_corpus: bool = False

    # Delete tenant-scoped dedup content objects.
    # Accepts either full Redis keys like "apex:content:{tenant}:{kind}:{sha256}" or tenant_refs like "{tenant}:{kind}:{sha256}".
    dedup_content_refs: Optional[List[str]] = None

    # Optional deletion of non-ledger S3 objects (requires APEX_RTBF_S3_ALLOW=true and APEX_RTBF_S3_BUCKET set).
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


app = FastAPI()


async def get_identity(
    authorization: str = Header(alias="Authorization"),
    x_tenant_id: str = Header(default=""),
) -> TenantIdentity:
    return await idp_verifier.verify(authorization, x_tenant_id)


@app.get("/api/v1/ir/timelines")
async def ir_timelines(identity: TenantIdentity = Depends(get_identity)):
    """Read-only incident response timelines (used by SIEM + runbooks)."""
    authz_engine.require_audit_read(identity)
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "timelines": _ir_timelines(),
    }


@app.get("/api/v1/ir/runbooks")
async def ir_runbooks(identity: TenantIdentity = Depends(get_identity)):
    """Read-only list of available runbooks."""
    authz_engine.require_audit_read(identity)
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "runbooks": sorted(RUNBOOKS.keys()),
    }


@app.get("/api/v1/ir/runbooks/{reason_code}")
async def ir_runbook(reason_code: str, identity: TenantIdentity = Depends(get_identity)):
    """Read-only runbook for a specific reason code (violation/action)."""
    authz_engine.require_audit_read(identity)
    code = (reason_code or "").strip()
    rb = RUNBOOKS.get(code)
    if not rb:
        raise HTTPException(status_code=404, detail="Runbook not found")
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "reason_code": code,
        "runbook": rb,
        "timelines": _ir_timelines(),
    }


@app.get("/api/v1/ir/incidents/{incident_id}")
async def ir_get_incident(incident_id: str, identity: TenantIdentity = Depends(get_identity)):
    """Read-only incident record lookup.

    Note: Incident records are best-effort and primarily intended for SIEM correlation.
    """
    authz_engine.require_audit_read(identity)
    inc_id = (incident_id or "").strip()
    if not inc_id:
        raise HTTPException(status_code=400, detail="incident_id is required")

    r = await get_redis_client()
    raw = await r.get(_incident_record_key(inc_id))
    if not raw:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        obj = json.loads(raw)
    except Exception:
        obj = {"raw": raw}

    # Enforce tenant scoping for auditors.
    if str(obj.get("tenant_id") or "").strip() != identity.tenant_id:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "incident": obj,
    }


@app.on_event("startup")
async def on_startup():
    """
    Startup hook:
    - Enforce tracing in PROD
    - Initialize Redis
    - Configure drift backend (Redis Bow or Qdrant + embeddings)
    """
    env = get_apex_env()
    if env == ApexEnv.PROD and not tracing_available():
        raise RuntimeError("Tracing is required in PROD but OpenTelemetry is not available/configured")

    asyncio.create_task(_periodic_self_test_loop())
    asyncio.create_task(_retention_enforcer_loop())

    r = await get_redis_client()

    global DRIFT_BACKEND

    if APEX_DRIFT_BACKEND == "vector":
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if not openai_key:
            raise RuntimeError("OPENAI_API_KEY must be set for vector drift backend")

        embedder = OpenAIEmbeddingProvider(api_key=openai_key, model=APEX_EMBEDDING_MODEL)
        qdrant = AsyncQdrantClient(
            url=QDRANT_URL,
            api_key=QDRANT_API_KEY or None,
        )

        dim = await embedder._ensure_dim()
        drift_index = QdrantIndex(
            client=qdrant,
            collection=QDRANT_COLLECTION,
            vector_dim=dim,
        )
        await drift_index.ensure_collection()

        DRIFT_BACKEND = VectorDbDriftBackend(index=drift_index, embedder=embedder)
        await DRIFT_BACKEND.ensure_global_anchor()
    else:
        DRIFT_BACKEND = RedisBowDriftBackend(r)


@app.get("/healthz")
async def healthz():
    """
    Basic liveness endpoint – does not imply readiness for traffic.
    """
    return {
        "status": "ok",
        "env": get_apex_env().value,
        "pid": os.getpid(),
        "fips_mode": APEX_FIPS_MODE,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
    }


@app.get("/fips_status")
async def fips_status():
    """
    FIPS posture endpoint (self-reported).

    Note: This reports runtime/library signals and configuration flags; it does not
    by itself prove the deployment is running a FIPS-validated cryptographic module.
    """
    return {
        "apex_fips_mode": bool(APEX_FIPS_MODE),
        "python_version": sys.version,
        "openssl_version": getattr(ssl, "OPENSSL_VERSION", None),
        "ssl_has_sni": getattr(ssl, "HAS_SNI", None),
        "signer_health": SIGNER_HEALTH,
        "self_test": SELF_TEST,
    }


@app.get("/readyz")
async def readyz():
    """
    Readiness endpoint:
    - Verifies Redis connectivity
    - Optionally verifies KMS signing ability in PROD
    - Checks ledger backlog is within tolerances
    """
    env = get_apex_env()

    if env == ApexEnv.PROD and not tracing_available():
        raise HTTPException(status_code=503, detail="Tracing not configured")

    try:
        r = await get_redis_client()
        pong = await r.ping()
        if pong is not True:
            raise RuntimeError("Redis did not respond with PONG")

        await _enforce_failsafe_or_raise(r)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis not ready: {str(e)}")

    if env == ApexEnv.PROD and os.getenv("APEX_KMS_HEALTH_CHECK", "true").lower() == "true":
        try:
            # Dual-control guardrail: ensure runtime KMS key matches approved desired config.
            try:
                await _enforce_kms_dual_control_or_raise(r)
            except Exception as e:
                SIGNER_HEALTH["ok"] = False
                SIGNER_HEALTH["last_error"] = f"dual_control_failed:{e}"
                SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
                raise HTTPException(status_code=503, detail=f"KMS dual-control failed: {str(e)}")

            signer = load_signer_for_worker()

            def _sign():
                return signer.sign(b"apex-kms-health-check")

            await asyncio.to_thread(_sign)

            SIGNER_HEALTH["ok"] = True
            SIGNER_HEALTH["last_ok_at"] = datetime.utcnow().isoformat() + "Z"
            SIGNER_HEALTH["last_error"] = None
        except Exception as e:
            SIGNER_HEALTH["ok"] = False
            SIGNER_HEALTH["last_error"] = f"kms_health_check_failed:{e}"
            SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"
            raise HTTPException(status_code=503, detail=f"KMS not ready: {str(e)}")

    try:
        r = await get_redis_client()
        queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
        if is_critical:
            raise HTTPException(
                status_code=503,
                detail=f"Ledger backlog too large ({queue_len} >= {MAX_UNSIGNED_QUEUE})",
            )
        if is_warning:
            print(f"[apex-readyz] WARNING: unsigned backlog high ({queue_len}/{MAX_UNSIGNED_QUEUE})")
    except HTTPException:
        raise
    except Exception:
        # Metrics-only failure should not prevent readiness.
        pass

    return {
        "status": "ready",
        "env": env.value,
    }


@app.get("/governance_status")
async def governance_status():
    """
    Governance-level health: highlights ledger backlog and environment.
    """
    r = await get_redis_client()
    queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)

    status = "OK"
    http_status = 200
    if is_critical:
        status = "CRITICAL"
        http_status = 503
    elif is_warning:
        status = "WARNING"

    body = {
        "status": status,
        "unsigned_backlog_len": queue_len,
        "max_unsigned_queue": MAX_UNSIGNED_QUEUE,
        "warning_threshold": int(UNSIGNED_WARN_FRACTION * MAX_UNSIGNED_QUEUE),
        "env": get_apex_env().value,
        "fips_mode": APEX_FIPS_MODE,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
    }

    if http_status != 200:
        raise HTTPException(status_code=http_status, detail=body)
    return body


STREAM_WINDOW = 128

# =========================================================
# 7b. METRICS HELPERS (ROLLING 24H)
# =========================================================

def _metrics_hour_key(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H")


def _metrics_total_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:total"


def _metrics_blocked_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:blocked"


def _metrics_highrisk_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:highrisk"


def _metrics_axis_hash_key(hour_key: str) -> str:
    return f"apex:metrics:interactions:{hour_key}:axis_counts"


async def record_metrics_for_audit(r: redis.Redis, payload: Dict[str, Any]) -> None:
    """
    Aggregate simple metrics for the CISO dashboard:
    - total / blocked / high-risk interactions
    - per-axis counts
    """
    ts_str = payload.get("ts")
    if not ts_str:
        return
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", ""))
    except Exception:
        return

    hour_key = _metrics_hour_key(ts)

    total_key = _metrics_total_key(hour_key)
    blocked_key = _metrics_blocked_key(hour_key)
    highrisk_key = _metrics_highrisk_key(hour_key)
    axis_hash = _metrics_axis_hash_key(hour_key)

    decision = payload.get("decision")
    risk_axes = payload.get("risk_axes", {})
    tony_score = float(risk_axes.get("tony", 0.0))

    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(total_key, 1)
        if decision == "BLOCK":
            pipe.incr(blocked_key, 1)
        if tony_score >= ALERT_MIN_TONY_SCORE:
            pipe.incr(highrisk_key, 1)

        for axis, val in risk_axes.items():
            if axis in ("tony", "context"):
                continue
            try:
                v = float(val)
            except Exception:
                continue
            if v > 0.0:
                pipe.hincrby(axis_hash, axis, 1)

        expire_seconds = 7 * 24 * 3600
        pipe.expire(total_key, expire_seconds)
        pipe.expire(blocked_key, expire_seconds)
        pipe.expire(highrisk_key, expire_seconds)
        pipe.expire(axis_hash, expire_seconds)

        await pipe.execute()

# =========================================================
# 7c. STREAMING PROXY – DEMO OF FULL PIPELINE
# =========================================================

@app.post("/v1/stream")
async def streaming_proxy(
    http_request: Request,
    request: UniversalRequest,
    x_tenant_id: str = Header(default=""),
    x_session_id: str = Header(default="anon-session"),
    identity: TenantIdentity = Depends(get_identity),
):
    """
    Main streaming proxy:
    - Authn via OIDC, tenant binding via header + claim
    - Authz via AuthorizationEngine (RBAC / model-tier)
    - Drift anchor update (Redis or Qdrant)
    - Streaming LLM proxy with incremental risk evaluation
    - Inline PII block/redact
    - Ledger audit + KMS signing via worker
    """
    tenant_id = identity.tenant_id
    session_id = f"{tenant_id}:{x_session_id}"
    r = await get_redis_client()
    await _enforce_failsafe_or_raise(r)
    engine = ApexSovereignEngine(r_client=r, drift_backend=DRIFT_BACKEND)

    audit_ctx: Dict[str, Any] = {}
    if http_request is not None:
        audit_ctx = _request_audit_context(http_request)

    model_params = {"max_tokens": request.max_tokens, "temperature": request.temperature, "top_p": request.top_p}
    model_params = {k: v for k, v in model_params.items() if v is not None}

    policy_record = await engine.policy_store.get_policy_or_seed(
        tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = policy_record.policy

    # Multimodal deep inspection is not implemented; fail closed unless the request is text-only.
    allow_multimodal = bool(policy.get("allow_multimodal", False))
    is_text_only, reason = _validate_text_only_messages(request.messages)
    if not is_text_only and not allow_multimodal:
        audit_payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_version": POLICY_VERSION,
            "decision": "DENY",
            "violation": "unsupported_non_text_content",
            "reason": reason,
            "model": EXTERNAL_MODEL_MAP.get(request.model, request.model),
            "requested_model": request.model,
            "model_params": model_params,
            "subject": identity.subject,
            "roles": identity.roles,
            **audit_ctx,
            "region": APEX_REGION,
            "ledger_chain_id": APEX_CHAIN_ID,
        }
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
            await record_metrics_for_audit(r, audit_payload)
        except LedgerBackpressureError:
            pass
        except Exception:
            pass
        raise HTTPException(status_code=415, detail="Unsupported content type: non-text messages are not supported")

    # Resolve requested model to internal name for allowlisting/tiering.
    requested_internal_model = EXTERNAL_MODEL_MAP.get(request.model, request.model)

    # Per-tenant model allowlist (finance-grade control).
    allowlist = policy.get("model_allowlist")
    if isinstance(allowlist, list) and len(allowlist) > 0 and requested_internal_model not in allowlist:
        audit_payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_version": POLICY_VERSION,
            "decision": "DENY",
            "violation": "model_not_allowlisted",
            "score": 1.0,
            "model": requested_internal_model,
            "requested_model": request.model,
            "model_params": model_params,
            "subject": identity.subject,
            "roles": identity.roles,
            **audit_ctx,
            "region": APEX_REGION,
            "ledger_chain_id": APEX_CHAIN_ID,
        }
        try:
            await create_unsigned_ledger_entry(r, audit_payload)
            await record_metrics_for_audit(r, audit_payload)
        except LedgerBackpressureError:
            print("[apex-stream] Dropping DENY ledger entry due to backlog")
        except Exception:
            pass
        raise HTTPException(status_code=403, detail="Access denied: model not allowlisted for tenant")

    authz_result = await authz_engine.check(identity, requested_model=requested_internal_model)
    if authz_result.decision != AuthorizationDecision.ALLOW:
        raise HTTPException(status_code=403, detail=f"Access denied: {authz_result.reason}")

    internal_model = authz_result.effective_model or requested_internal_model

    latest_user = next(
        (m.get("content", "") for m in reversed(request.messages) if m.get("role") == "user"),
        "",
    )
    if latest_user and not _no_content_retention_enabled(policy):
        prompts_key = f"session:{session_id}:prompts"
        await r.rpush(prompts_key, latest_user)
        prompts_ttl = _policy_retention_seconds(policy, "session_prompts_ttl_seconds")
        if prompts_ttl > 0:
            try:
                await r.expire(prompts_key, prompts_ttl)
            except Exception:
                pass
        if isinstance(engine.drift_backend, VectorDbDriftBackend):
            await engine.drift_backend.add_prompt_embedding(session_id, latest_user)

    async def stream_generator() -> AsyncGenerator[bytes, None]:
        committed_prefix_raw = ""
        committed_prefix_streamed = ""
        overlap_tail = ""
        client: Optional[httpx.AsyncClient] = None

        async with REQUEST_SEM:
            LLM_CIRCUIT.before_call()
            try:
                # Sovereign egress enforcement for the upstream LLM call.
                await enforce_sovereign_egress_or_raise(
                    r,
                    tenant_id=tenant_id,
                    session_id=session_id,
                    subject=identity.subject,
                    roles=identity.roles,
                    purpose="UPSTREAM_LLM",
                    url=OPENAI_URL,
                )
                openai_key = await secret_provider.get_openai_key()
                headers = {
                    "Authorization": f"Bearer {openai_key}",
                    "Content-Type": "application/json",
                }

                payload = {
                    "model": INTERNAL_TO_EXTERNAL_MODEL.get(internal_model, internal_model),
                    "messages": request.messages,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                    "top_p": request.top_p,
                    "stream": True,
                }
                payload = {k: v for k, v in payload.items() if v is not None}

                with tracer.start_as_current_span("apex.stream.llm_call") as llm_span:
                    llm_span.set_attribute("tenant.id", tenant_id)
                    llm_span.set_attribute("session.id", session_id)
                    llm_span.set_attribute("model.internal", internal_model)
                    llm_span.set_attribute("upstream.url", OPENAI_URL)

                    client = httpx.AsyncClient(timeout=None)
                    try:
                        async with client.stream("POST", OPENAI_URL, headers=headers, json=payload) as resp:
                            llm_span.set_attribute("upstream.status_code", resp.status_code)
                            if resp.status_code != 200:
                                LLM_CIRCUIT.after_call_failure()
                                raise HTTPException(status_code=resp.status_code, detail=await resp.aread())

                            LLM_CIRCUIT.after_call_success()

                            pii_patterns = policy.get("pii_patterns", [])
                            pii_mode = policy.get("pii_mode", "block")

                            async for line in resp.aiter_lines():
                                if not line:
                                    continue
                                if line.startswith("data: "):
                                    try:
                                        chunk = json.loads(line[len("data: "):])
                                    except Exception:
                                        continue
                                    delta = (
                                        chunk.get("choices", [{}])[0]
                                        .get("delta", {})
                                        .get("content", "")
                                    )
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
                                        decision, violation, score = evaluate_risk(risk_vec, policy)
                                        risk_span.set_attribute("risk.score", score)
                                        risk_span.set_attribute("risk.decision", decision)
                                        for axis, val in risk_vec.items():
                                            if isinstance(val, (int, float)):
                                                risk_span.set_attribute(f"risk.axis.{axis}", float(val))

                                    pii_thresh = policy.get("axis_thresholds", {}).get("pii", 0.2)
                                    if pii_mode == "block" and risk_vec.get("pii", 0.0) >= pii_thresh:
                                        reason_code = "axis_pii_threshold"
                                        explanation = explain_block(reason_code, risk_vec)
                                        audit_payload = {
                                            "ts": datetime.utcnow().isoformat() + "Z",
                                            "tenant_id": tenant_id,
                                            "session_id": session_id,
                                            "policy_version": POLICY_VERSION,
                                            "decision": "BLOCK",
                                            "violation": reason_code,
                                            "score": risk_vec.get("pii", 0.0),
                                            "model": internal_model,
                                            "model_params": model_params,
                                            "threat_intel_feed_version": risk_vec.get("threat_intel_feed_version"),
                                            "threat_intel_hits": risk_vec.get("threat_intel_hits"),
                                            "dlp_semantic_hits": risk_vec.get("dlp_semantic_hits"),
                                            "accumulated_text_len": len(candidate_text),
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
                                            "explanation": explanation.dict(),
                                            "region": APEX_REGION,
                                            "ledger_chain_id": APEX_CHAIN_ID,
                                        }
                                        try:
                                            await create_unsigned_ledger_entry(r, audit_payload)
                                            await record_metrics_for_audit(r, audit_payload)
                                        except LedgerBackpressureError:
                                            print("[apex-stream] Dropping BLOCK ledger entry due to backlog")
                                        except Exception:
                                            pass
                                        await send_alert_if_needed(audit_payload, r=r)
                                        msg = (
                                            f"\n[BLOCK] {explanation.human_message} "
                                            f"Hint: {explanation.remediation_hint or ''}\n"
                                        )
                                        yield msg.encode("utf-8")
                                        return

                                    if decision != "PASS":
                                        reason_code = violation or "tony_threshold"
                                        explanation = explain_block(reason_code, risk_vec)
                                        audit_payload = {
                                            "ts": datetime.utcnow().isoformat() + "Z",
                                            "tenant_id": tenant_id,
                                            "session_id": session_id,
                                            "policy_version": POLICY_VERSION,
                                            "decision": decision,
                                            "violation": reason_code,
                                            "score": score,
                                            "model": internal_model,
                                            "model_params": model_params,
                                            "threat_intel_feed_version": risk_vec.get("threat_intel_feed_version"),
                                            "threat_intel_hits": risk_vec.get("threat_intel_hits"),
                                            "dlp_semantic_hits": risk_vec.get("dlp_semantic_hits"),
                                            "accumulated_text_len": len(candidate_text),
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
                                            "explanation": explanation.dict(),
                                            "region": APEX_REGION,
                                            "ledger_chain_id": APEX_CHAIN_ID,
                                        }
                                        try:
                                            await create_unsigned_ledger_entry(r, audit_payload)
                                            await record_metrics_for_audit(r, audit_payload)
                                        except LedgerBackpressureError:
                                            print("[apex-stream] Dropping BLOCK ledger entry due to backlog")
                                        except Exception:
                                            pass
                                        await send_alert_if_needed(audit_payload, r=r)
                                        msg = (
                                            f"\n[BLOCK] {explanation.human_message} "
                                            f"Hint: {explanation.remediation_hint or ''}\n"
                                        )
                                        yield msg.encode("utf-8")
                                        return

                                    new_safe_prefix_len = max(0, len(candidate_text) - STREAM_WINDOW)
                                    safe_prefix_raw = candidate_text[:new_safe_prefix_len]
                                    new_overlap_tail = candidate_text[new_safe_prefix_len:]

                                    if pii_mode == "redact":
                                        redacted_prefix = redact_pii(safe_prefix_raw, pii_patterns)
                                    else:
                                        redacted_prefix = safe_prefix_raw

                                    to_stream = redacted_prefix[len(committed_prefix_streamed):]

                                    if to_stream:
                                        yield to_stream.encode("utf-8")

                                    committed_prefix_raw = safe_prefix_raw
                                    committed_prefix_streamed = redacted_prefix
                                    overlap_tail = new_overlap_tail

                            final_text = committed_prefix_raw + overlap_tail

                            # Evaluate unified risk for the final assembled text and emit audit
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
                                violation = None

                                audit_payload = {
                                    "ts": datetime.utcnow().isoformat() + "Z",
                                    "tenant_id": tenant_id,
                                    "session_id": session_id,
                                    "policy_version": POLICY_VERSION,
                                    "decision": decision,
                                    "violation": violation,
                                    "score": score,
                                    "model": internal_model,
                                    "model_params": model_params,
                                    "threat_intel_feed_version": risk_vec.get("threat_intel_feed_version"),
                                    "threat_intel_hits": risk_vec.get("threat_intel_hits"),
                                    "dlp_semantic_hits": risk_vec.get("dlp_semantic_hits"),
                                    "accumulated_text_len": len(final_text),
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
                                    "region": APEX_REGION,
                                    "ledger_chain_id": APEX_CHAIN_ID,
                                }
                                try:
                                    await create_unsigned_ledger_entry(r, audit_payload)
                                    await record_metrics_for_audit(r, audit_payload)
                                except LedgerBackpressureError:
                                    print("[apex-stream] Dropping PASS ledger entry due to backlog")
                                except Exception:
                                    pass
                                await send_alert_if_needed(audit_payload, r=r)
                            except Exception:
                                # If risk evaluation fails for any reason, continue without blocking the stream.
                                pass
                    finally:
                        if client is not None:
                            await client.aclose()
            except asyncio.CancelledError:
                raise
            except httpx.RequestError:
                LLM_CIRCUIT.after_call_failure()
                raise
            finally:
                # Reset local accumulation state to avoid leaking between connections
                committed_prefix_raw = ""
                committed_prefix_streamed = ""
                overlap_tail = ""

    with tracer.start_as_current_span("apex.stream.request") as span:
        span.set_attribute("tenant.id", identity.tenant_id)
        span.set_attribute("session.id", x_session_id)
        span.set_attribute("model.internal", request.model)
        span.set_attribute("auth.subject", identity.subject)
        return StreamingResponse(stream_generator(), media_type="text/plain")

# =========================================================
# 7d. ADMIN / MANAGEMENT API – GOVERNANCE CONTROL PLANE
# =========================================================

@app.post("/admin/threat_intel/{tenant_id}/ingest")
async def admin_threat_intel_ingest(
    tenant_id: str,
    req: ThreatIntelIngestRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = ThreatIntelStore(r)
    meta = await store.ingest(tenant_id, req)

    audit_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id,
        "subject": identity.subject,
        "roles": identity.roles,
        "decision": "ADMIN_ACTION",
        "action": "THREAT_INTEL_INGEST",
        "active_feed_version": meta.get("active_feed_version"),
        "staged_feed_version": meta.get("staged_feed_version"),
        "mode": meta.get("mode"),
        "rule_count": meta.get("rule_count"),
        "activate": bool(req.activate),
        "comment": req.comment,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    try:
        await create_unsigned_ledger_entry(r, audit_payload)
    except LedgerBackpressureError:
        pass
    except Exception:
        pass

    return {"ok": True, "meta": meta}


@app.post("/admin/threat_intel/{tenant_id}/activate")
async def admin_threat_intel_activate(
    tenant_id: str,
    req: ThreatIntelActivateRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = ThreatIntelStore(r)
    meta = await store.activate(tenant_id, req.feed_version)

    audit_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id,
        "subject": identity.subject,
        "roles": identity.roles,
        "decision": "ADMIN_ACTION",
        "action": "THREAT_INTEL_ACTIVATE",
        "active_feed_version": meta.get("active_feed_version"),
        "previous_feed_version": meta.get("previous_feed_version"),
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    try:
        await create_unsigned_ledger_entry(r, audit_payload)
    except Exception:
        pass

    return {"ok": True, "meta": meta}


@app.post("/admin/threat_intel/{tenant_id}/rollback")
async def admin_threat_intel_rollback(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = ThreatIntelStore(r)
    meta = await store.rollback(tenant_id)

    audit_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id,
        "subject": identity.subject,
        "roles": identity.roles,
        "decision": "ADMIN_ACTION",
        "action": "THREAT_INTEL_ROLLBACK",
        "active_feed_version": meta.get("active_feed_version"),
        "previous_feed_version": meta.get("previous_feed_version"),
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    try:
        await create_unsigned_ledger_entry(r, audit_payload)
    except Exception:
        pass

    return {"ok": True, "meta": meta}


@app.get("/admin/signing/audit/summary")
async def admin_signing_audit_summary(
    limit: int = 50,
    tenant_id: Optional[str] = None,
    identity: TenantIdentity = Depends(get_identity),
):
    """Admin-only view into best-effort signing audit telemetry.

    This reads a Redis stream emitted by the signing worker and returns recent
    success/failure events plus a few counters.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    events = await _read_signing_audit_stream(r, limit=limit, tenant_id_filter=tenant_id)

    # Best-effort counters maintained by _emit_signing_access_log.
    counters: Dict[str, Any] = {}
    try:
        counters = {
            "success": int(await r.get("apex:signing:ops:success") or 0),
            "failure": int(await r.get("apex:signing:ops:failure") or 0),
            "last_error": await r.get("apex:signing:ops:last_error"),
            "last_error_at": await r.get("apex:signing:ops:last_error_at"),
        }
    except Exception:
        counters = {}

    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "env": get_apex_env().value,
        "sign_audit": {
            "enabled": bool(APEX_SIGN_AUDIT_ENABLED),
            "stream_key": APEX_SIGN_AUDIT_STREAM_KEY,
            "ttl_seconds": int(APEX_SIGN_AUDIT_TTL_SECONDS or 0),
        },
        "filter": {"tenant_id": tenant_id},
        "counters": counters,
        "recent_events": events,
    }


@app.get("/api/v1/audit/signing/audit/summary")
async def audit_signing_audit_summary(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Auditor read-only view into signing audit telemetry for the caller tenant.

    This endpoint filters events by `tenant_id` (added to the stream by the signing worker).
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()

    events = await _read_signing_audit_stream(r, limit=limit, tenant_id_filter=identity.tenant_id)

    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "env": get_apex_env().value,
        "tenant_id": identity.tenant_id,
        "sign_audit": {
            "enabled": bool(APEX_SIGN_AUDIT_ENABLED),
            "stream_key": APEX_SIGN_AUDIT_STREAM_KEY,
            "ttl_seconds": int(APEX_SIGN_AUDIT_TTL_SECONDS or 0),
        },
        "recent_events": events,
    }


@app.get("/admin/threat_intel/{tenant_id}/status")
async def admin_threat_intel_status(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = ThreatIntelStore(r)
    cached = await store.load_rules(tenant_id, force_reload=True)
    try:
        versions = await r.lrange(_threat_intel_versions_key(tenant_id), 0, 9)
    except Exception:
        versions = []
    return {
        "tenant_id": tenant_id,
        "active_feed_version": cached.get("feed_version"),
        "previous_feed_version": cached.get("previous_feed_version"),
        "updated_at": cached.get("updated_at"),
        "rule_count": len(cached.get("rules") or []),
        "recent_versions": versions,
    }


@app.post("/admin/dlp_semantic/{tenant_id}/ingest")
async def admin_dlp_semantic_ingest(
    tenant_id: str,
    req: DlpSemanticIngestRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    # In no-content-retention mode, disallow storing exemplar text/embeddings.
    content_ttl = 0
    try:
        policy_record = await PolicyStore(r).get_policy_or_seed(
            tenant_id,
            seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
        )
        pol = policy_record.policy or {}
        if _no_content_retention_enabled(pol):
            raise HTTPException(status_code=409, detail="Tenant policy forbids content retention (semantic DLP ingest disabled)")
        content_ttl = _policy_retention_seconds(pol, "content_store_ttl_seconds")
    except HTTPException:
        raise
    except Exception:
        pass

    store = DlpSemanticStore(r)
    meta = await store.ingest(tenant_id, req, content_ttl_seconds=content_ttl)

    audit_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id,
        "subject": identity.subject,
        "roles": identity.roles,
        "decision": "ADMIN_ACTION",
        "action": "DLP_SEMANTIC_INGEST",
        "mode": meta.get("mode"),
        "count": meta.get("count"),
        "comment": req.comment,
        "enabled": bool(APEX_DLP_SEMANTIC_ENABLED),
        "embedding_model": APEX_EMBEDDING_MODEL,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    try:
        await create_unsigned_ledger_entry(r, audit_payload)
    except LedgerBackpressureError:
        pass
    except Exception:
        pass

    return {"ok": True, "meta": meta}


@app.get("/admin/dlp_semantic/{tenant_id}/status")
async def admin_dlp_semantic_status(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = DlpSemanticStore(r)
    loaded = await store.load(tenant_id)
    meta = loaded.get("meta") or {}
    items = loaded.get("items") or []
    return {
        "tenant_id": tenant_id,
        "enabled": bool(APEX_DLP_SEMANTIC_ENABLED),
        "embedding_model": APEX_EMBEDDING_MODEL,
        "max_exemplars": int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS),
        "updated_at": meta.get("updated_at"),
        "count": meta.get("count", len(items)),
        "comment": meta.get("comment"),
    }

@app.post("/admin/failsafe/zeroize")
async def admin_failsafe_zeroize(identity: TenantIdentity = Depends(get_identity)):
    """Best-effort emergency action: zeroize in-process soft signer key material.

    Notes:
    - Only affects the current process memory.
    - KMS/HSM-backed signers cannot be zeroized from here.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    signer = load_signer_for_worker()
    did_zeroize = False
    if hasattr(signer, "zeroize"):
        try:
            signer.zeroize()  # type: ignore[attr-defined]
            did_zeroize = True
        except Exception:
            did_zeroize = False

    SIGNER_HEALTH["ok"] = False
    SIGNER_HEALTH["last_error"] = "zeroized_by_admin" if did_zeroize else "zeroize_attempt_failed"
    SIGNER_HEALTH["last_error_at"] = datetime.utcnow().isoformat() + "Z"

    audit_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": identity.tenant_id,
        "subject": identity.subject,
        "roles": identity.roles,
        "decision": "ADMIN_ACTION",
        "action": "SIGNER_ZEROIZE",
        "did_zeroize": did_zeroize,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    try:
        await create_unsigned_ledger_entry(r, audit_payload)
    except LedgerBackpressureError:
        pass
    except Exception:
        pass

    return {"ok": True, "did_zeroize": did_zeroize, "signer_health": SIGNER_HEALTH}

@app.get("/admin/tenants")
async def list_tenants(identity: TenantIdentity = Depends(get_identity)):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = TenantStore(r)
    return await store.list_all()


@app.post("/admin/tenants/{tenant_id}")
async def upsert_tenant(
    tenant_id: str,
    metadata: TenantMetadata,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    if tenant_id != metadata.tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id mismatch")
    r = await get_redis_client()
    store = TenantStore(r)
    existing_meta_raw = await r.get(store._meta_key(tenant_id))
    if existing_meta_raw:
        await store.upsert_metadata(metadata)
    else:
        await store.onboard_tenant(metadata)
    return metadata


@app.get("/admin/policies/{tenant_id}")
async def get_policy_for_tenant(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)
    record = await store.get_policy_record(tenant_id)
    return record


@app.post("/admin/policies/{tenant_id}")
async def update_policy_for_tenant(
    tenant_id: str,
    req: PolicyUpdateRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    if APEX_TWO_PERSON_POLICY:
        raise HTTPException(
            status_code=409,
            detail="Two-person policy control enabled; use /admin/policies/{tenant_id}/proposals and approve with a second admin.",
        )
    if not isinstance(req.justification, str) or not req.justification.strip():
        raise HTTPException(status_code=400, detail="Policy change requires justification")
    r = await get_redis_client()
    store = PolicyStore(r)
    _validate_retention_policy_or_raise(req.policy)
    new_version = req.version or f"{POLICY_VERSION}:{int(time.time())}"
    record = PolicyRecord(
        version=new_version,
        policy=req.policy,
        created_at=datetime.utcnow().isoformat() + "Z",
        created_by=identity.subject,
        comment=req.comment,
        justification=req.justification,
        change_ticket=req.change_ticket,
    )
    await store.set_policy(tenant_id, record, is_new=False)

    # Change-management ledger event (no full policy blob; versioned reference only).
    await _best_effort_governance_ledger_event(
        r,
        tenant_id=tenant_id,
        actor=identity.subject,
        event_type="POLICY_UPDATED",
        extra={
            "version": new_version,
            "change_ticket": req.change_ticket,
        },
    )
    return record


def _policy_proposals_hash_key(tenant_id: str) -> str:
    return f"apex:policy:{tenant_id}:proposals"


def _policy_proposals_index_key(tenant_id: str) -> str:
    return f"apex:policy:{tenant_id}:proposals:index"


async def _best_effort_governance_ledger_event(
    r: redis.Redis,
    tenant_id: str,
    actor: str,
    event_type: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": tenant_id,
        "decision": event_type,
        "subject": actor,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }
    if extra:
        payload.update(extra)
    try:
        await create_unsigned_ledger_entry(r, payload)
    except LedgerBackpressureError:
        print("[apex-admin] Dropping governance ledger entry due to backlog")
    except Exception:
        pass


@app.post("/admin/policies/{tenant_id}/proposals")
async def propose_policy_change(
    tenant_id: str,
    req: PolicyProposalRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """Create a pending policy proposal.

    When `APEX_TWO_PERSON_POLICY=true`, this is the supported path for policy changes.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    if not isinstance(req.justification, str) or not req.justification.strip():
        raise HTTPException(status_code=400, detail="Policy change requires justification")

    _validate_retention_policy_or_raise(req.policy)

    proposal_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + "Z"
    record = {
        "proposal_id": proposal_id,
        "tenant_id": tenant_id,
        "policy": req.policy,
        "change_request_id": req.change_request_id,
        "requested_version": req.requested_version,
        "comment": req.comment,
        "justification": req.justification,
        "change_ticket": req.change_ticket,
        "status": "PENDING",
        "created_by": identity.subject,
        "created_at": created_at,
        "approved_by": None,
        "approved_at": None,
        "approval_comment": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_comment": None,
    }

    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(record))
        pipe.lpush(_policy_proposals_index_key(tenant_id), proposal_id)
        # keep a bounded index
        pipe.ltrim(_policy_proposals_index_key(tenant_id), 0, 499)
        await pipe.execute()

    await _best_effort_governance_ledger_event(
        r,
        tenant_id=tenant_id,
        actor=identity.subject,
        event_type="POLICY_PROPOSED",
        extra={"proposal_id": proposal_id, "change_request_id": req.change_request_id, "change_ticket": req.change_ticket},
    )

    return record


@app.get("/admin/policies/{tenant_id}/proposals")
async def list_policy_proposals(
    tenant_id: str,
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    lim = max(1, min(int(limit), 200))
    ids = await r.lrange(_policy_proposals_index_key(tenant_id), 0, lim - 1)
    out: List[Dict[str, Any]] = []
    if not ids:
        return out

    raw_map = await r.hmget(_policy_proposals_hash_key(tenant_id), *ids)
    for raw in raw_map:
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            continue
    return out


@app.get("/admin/policies/{tenant_id}/proposals/{proposal_id}")
async def get_policy_proposal(
    tenant_id: str,
    proposal_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    raw = await r.hget(_policy_proposals_hash_key(tenant_id), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return json.loads(raw)


@app.post("/admin/policies/{tenant_id}/proposals/{proposal_id}/approve")
async def approve_policy_proposal(
    tenant_id: str,
    proposal_id: str,
    req: PolicyProposalApprovalRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """Approve and apply a proposal; approver must be different from proposer."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)

    raw = await r.hget(_policy_proposals_hash_key(tenant_id), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = json.loads(raw)
    if proposal.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail="Proposal is not pending")

    proposer = proposal.get("created_by")
    if proposer and identity.subject and proposer == identity.subject:
        raise HTTPException(status_code=403, detail="Two-person rule: proposer cannot approve their own proposal")

    approved_at = datetime.utcnow().isoformat() + "Z"
    proposal["status"] = "APPROVED"
    proposal["approved_by"] = identity.subject
    proposal["approved_at"] = approved_at
    proposal["approval_comment"] = req.approval_comment

    # Apply policy as a versioned record, carrying governance metadata.
    new_version = (
        req.version
        or proposal.get("requested_version")
        or f"{POLICY_VERSION}:{int(time.time())}:approved"
    )

    record = PolicyRecord(
        version=new_version,
        policy=proposal.get("policy") or {},
        created_at=proposal.get("created_at") or approved_at,
        created_by=proposer,
        comment=proposal.get("comment") or "approved_policy_change",
        justification=proposal.get("justification"),
        change_ticket=proposal.get("change_ticket"),
        change_request_id=proposal.get("change_request_id"),
        proposal_id=proposal_id,
        approved_by=identity.subject,
        approved_at=approved_at,
    )

    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(proposal))
        await pipe.execute()

    await store.set_policy(tenant_id, record, is_new=False)

    await _best_effort_governance_ledger_event(
        r,
        tenant_id=tenant_id,
        actor=identity.subject,
        event_type="POLICY_APPROVED",
        extra={"proposal_id": proposal_id, "change_request_id": proposal.get("change_request_id"), "version": new_version},
    )

    return {
        "proposal": proposal,
        "applied_policy_record": record,
    }


@app.post("/admin/policies/{tenant_id}/proposals/{proposal_id}/reject")
async def reject_policy_proposal(
    tenant_id: str,
    proposal_id: str,
    req: PolicyProposalRejectRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    raw = await r.hget(_policy_proposals_hash_key(tenant_id), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = json.loads(raw)
    if proposal.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail="Proposal is not pending")

    rejected_at = datetime.utcnow().isoformat() + "Z"
    proposal["status"] = "REJECTED"
    proposal["rejected_by"] = identity.subject
    proposal["rejected_at"] = rejected_at
    proposal["rejection_comment"] = req.rejection_comment

    await r.hset(_policy_proposals_hash_key(tenant_id), proposal_id, json.dumps(proposal))

    await _best_effort_governance_ledger_event(
        r,
        tenant_id=tenant_id,
        actor=identity.subject,
        event_type="POLICY_REJECTED",
        extra={"proposal_id": proposal_id, "change_request_id": proposal.get("change_request_id")},
    )

    return proposal


@app.post("/admin/policies/{tenant_id}/model_allowlist")
async def update_model_allowlist_for_tenant(
    tenant_id: str,
    req: ModelAllowlistUpdateRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """Update only the per-tenant model allowlist.

    This is a convenience wrapper for finance-style operations: it performs
    lightweight validation and writes a versioned policy record.
    """
    authz_engine.require_admin(identity)
    if APEX_TWO_PERSON_POLICY:
        raise HTTPException(
            status_code=409,
            detail="Two-person policy control enabled; update allowlist via a proposal and approval.",
        )
    r = await get_redis_client()
    store = PolicyStore(r)

    current = await store.get_policy_or_seed(
        tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = dict(current.policy or {})

    if not isinstance(req.models, list) or len(req.models) == 0:
        raise HTTPException(status_code=400, detail="models must be a non-empty list")

    normalized: List[str] = []
    seen: set = set()
    for m in req.models:
        if not isinstance(m, str) or not m.strip():
            continue
        raw = m.strip()
        internal = EXTERNAL_MODEL_MAP.get(raw, raw)
        if internal not in MODEL_CATALOG:
            raise HTTPException(status_code=400, detail=f"Unknown model: {raw}")
        if internal not in seen:
            normalized.append(internal)
            seen.add(internal)

    if len(normalized) == 0:
        raise HTTPException(status_code=400, detail="No valid models provided")

    policy["model_allowlist"] = normalized

    _validate_retention_policy_or_raise(policy)

    new_version = req.version or f"{POLICY_VERSION}:{int(time.time())}:allowlist"
    record = PolicyRecord(
        version=new_version,
        policy=policy,
        created_at=datetime.utcnow().isoformat() + "Z",
        created_by=identity.subject,
        comment=req.comment or "update_model_allowlist",
    )
    await store.set_policy(tenant_id, record, is_new=False)
    return record


@app.get("/admin/policies/{tenant_id}/model_allowlist")
async def get_model_allowlist_for_tenant(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """Fetch only the per-tenant model allowlist (admin-only)."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)

    current = await store.get_policy_or_seed(
        tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = current.policy or {}
    allowlist = policy.get("model_allowlist")
    if not isinstance(allowlist, list):
        allowlist = []

    return {
        "tenant_id": tenant_id,
        "policy_version": current.version,
        "model_allowlist": allowlist,
        "known_models": list(MODEL_CATALOG.keys()),
    }


@app.get("/api/v1/audit/model_allowlist")
async def audit_get_model_allowlist(identity: TenantIdentity = Depends(get_identity)):
    """Auditor read-only view of the caller tenant's model allowlist."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    store = PolicyStore(r)

    current = await store.get_policy_or_seed(
        identity.tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = current.policy or {}
    allowlist = policy.get("model_allowlist")
    if not isinstance(allowlist, list):
        allowlist = []

    return {
        "tenant_id": identity.tenant_id,
        "policy_version": current.version,
        "model_allowlist": allowlist,
        "known_models": list(MODEL_CATALOG.keys()),
    }


@app.get("/api/v1/audit/dlp_semantic/status")
async def audit_get_dlp_semantic_status(identity: TenantIdentity = Depends(get_identity)):
    """Auditor read-only view of semantic DLP status for the caller tenant."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    store = DlpSemanticStore(r)
    loaded = await store.load(identity.tenant_id)
    meta = loaded.get("meta") or {}
    items = loaded.get("items") or []
    return {
        "tenant_id": identity.tenant_id,
        "enabled": bool(APEX_DLP_SEMANTIC_ENABLED),
        "embedding_model": APEX_EMBEDDING_MODEL,
        "max_exemplars": int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS),
        "updated_at": meta.get("updated_at"),
        "count": meta.get("count", len(items)),
        "comment": meta.get("comment"),
    }


def _effective_retention_view(*, tenant_id: str, policy: Dict[str, Any], policy_version: Optional[str]) -> Dict[str, Any]:
    keys = [
        "session_prompts_ttl_seconds",
        "adversarial_corpus_ttl_seconds",
        "content_store_ttl_seconds",
    ]
    configured: Dict[str, Any] = {}
    try:
        configured = (policy.get("retention") or {}) if isinstance(policy, dict) else {}
    except Exception:
        configured = {}

    effective: Dict[str, int] = {k: int(_effective_retention_seconds(policy, k) or 0) for k in keys}

    return {
        "tenant_id": tenant_id,
        "policy_version": policy_version,
        "compliance": {
            "mode": bool(APEX_COMPLIANCE_MODE),
            "require_ttls": bool(APEX_COMPLIANCE_REQUIRE_TTLS),
            "max_ttls_seconds": {
                "session_prompts_ttl_seconds": int(APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS or 0),
                "adversarial_corpus_ttl_seconds": int(APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS or 0),
                "content_store_ttl_seconds": int(APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS or 0),
            },
        },
        "retention": {
            "configured": {
                k: configured.get(k) for k in keys
            },
            "effective_seconds": effective,
            "applies_to": [
                "session:{tenant}:{session}:prompts",
                "apex:adversarial_corpus:{tenant}",
                "apex:content:{tenant}:{kind}:{sha256}",
            ],
            "never_deleted": ["apex:audit_ledger"],
        },
    }


@app.get("/api/v1/audit/retention/effective")
async def audit_retention_effective(identity: TenantIdentity = Depends(get_identity)):
    """Auditor read-only view of governed retention (own tenant).

    Returns retention TTLs after applying baselines and compliance caps.
    Does not return the full policy blob.
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    store = PolicyStore(r)
    current = await store.get_policy_or_seed(
        identity.tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = current.policy or {}
    return _effective_retention_view(tenant_id=identity.tenant_id, policy=policy, policy_version=current.version)


@app.get("/admin/retention/{tenant_id}/effective")
async def admin_retention_effective(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """Admin/operator view of governed retention for any tenant."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)
    current = await store.get_policy_or_seed(
        tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = current.policy or {}
    return _effective_retention_view(tenant_id=tenant_id, policy=policy, policy_version=current.version)


@app.get("/admin/policies/{tenant_id}/versions")
async def list_policy_versions(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)
    versions = await store.list_versions(tenant_id)
    return versions


@app.get("/admin/env_config/current")
async def admin_env_config_current(identity: TenantIdentity = Depends(get_identity)):
    """Admin/operator view of the current runtime env snapshot and approved desired config."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    desired_raw = None
    try:
        desired_raw = await r.get(_envcfg_desired_current_key())
    except Exception:
        desired_raw = None

    desired: Optional[Dict[str, Any]] = None
    if desired_raw:
        try:
            desired = json.loads(desired_raw)
        except Exception:
            desired = {"raw": desired_raw}

    return {
        "env": get_apex_env().value,
        "runtime_snapshot": ENV_CONFIG_SNAPSHOT,
        "desired_config": desired,
    }


@app.get("/api/v1/audit/env_config/current")
async def audit_env_config_current(identity: TenantIdentity = Depends(get_identity)):
    """Auditor read-only view of env config (redacted) and desired config (redacted)."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    desired_raw = None
    try:
        desired_raw = await r.get(_envcfg_desired_current_key())
    except Exception:
        desired_raw = None

    desired: Optional[Dict[str, Any]] = None
    if desired_raw:
        try:
            desired = json.loads(desired_raw)
        except Exception:
            desired = {"raw": desired_raw}

    return {
        "env": get_apex_env().value,
        "runtime_snapshot": ENV_CONFIG_SNAPSHOT,
        "desired_config": desired,
    }


@app.get("/admin/env_config/history")
async def admin_env_config_history(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Admin/operator view of approved desired env config history (redacted).

    Notes:
    - Most recent approvals are returned first.
    - This does not include pending proposals; see /admin/env_config/proposals.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    lim = max(1, min(int(limit), 200))
    raw_items = await r.lrange(_envcfg_desired_history_key(), 0, lim - 1)
    out: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            out.append({"raw": raw})
    return {"env": get_apex_env().value, "items": out}


@app.get("/api/v1/audit/env_config/history")
async def audit_env_config_history(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Auditor read-only view of approved desired env config history (redacted)."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    lim = max(1, min(int(limit), 200))
    raw_items = await r.lrange(_envcfg_desired_history_key(), 0, lim - 1)
    out: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            out.append({"raw": raw})
    return {"env": get_apex_env().value, "items": out}


@app.get("/admin/env_config/overview")
async def admin_env_config_overview(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Admin/operator view of env config: snapshot + desired config + approved history (redacted)."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    desired_raw = None
    try:
        desired_raw = await r.get(_envcfg_desired_current_key())
    except Exception:
        desired_raw = None

    desired: Optional[Dict[str, Any]] = None
    if desired_raw:
        try:
            desired = json.loads(desired_raw)
        except Exception:
            desired = {"raw": desired_raw}

    lim = max(1, min(int(limit), 200))
    raw_items = await r.lrange(_envcfg_desired_history_key(), 0, lim - 1)
    history: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        if not raw:
            continue
        try:
            history.append(json.loads(raw))
        except Exception:
            history.append({"raw": raw})

    return {
        "env": get_apex_env().value,
        "runtime_snapshot": ENV_CONFIG_SNAPSHOT,
        "desired_config": desired,
        "approved_history": history,
    }


@app.get("/api/v1/audit/env_config/overview")
async def audit_env_config_overview(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Auditor read-only view of env config: snapshot + desired config + approved history (redacted)."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()

    desired_raw = None
    try:
        desired_raw = await r.get(_envcfg_desired_current_key())
    except Exception:
        desired_raw = None

    desired: Optional[Dict[str, Any]] = None
    if desired_raw:
        try:
            desired = json.loads(desired_raw)
        except Exception:
            desired = {"raw": desired_raw}

    lim = max(1, min(int(limit), 200))
    raw_items = await r.lrange(_envcfg_desired_history_key(), 0, lim - 1)
    history: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        if not raw:
            continue
        try:
            history.append(json.loads(raw))
        except Exception:
            history.append({"raw": raw})

    return {
        "env": get_apex_env().value,
        "runtime_snapshot": ENV_CONFIG_SNAPSHOT,
        "desired_config": desired,
        "approved_history": history,
    }


@app.post("/admin/env_config/proposals")
async def propose_env_config_change(
    req: EnvConfigProposalRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """Propose a desired env var change (two-person approval; does not mutate runtime env)."""
    authz_engine.require_admin(identity)
    if not isinstance(req.justification, str) or not req.justification.strip():
        raise HTTPException(status_code=400, detail="justification is required")

    changes_redacted = _sanitize_env_changes(req.changes or {})
    if not changes_redacted:
        raise HTTPException(status_code=400, detail="no valid env var changes provided")

    proposal_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + "Z"
    version = _env_changes_version(changes_redacted)

    record = {
        "proposal_id": proposal_id,
        "env": get_apex_env().value,
        "version": version,
        "changes": changes_redacted,
        "change_request_id": req.change_request_id,
        "change_ticket": req.change_ticket,
        "justification": req.justification,
        "comment": req.comment,
        "status": "PENDING",
        "created_by": identity.subject,
        "created_by_tenant": identity.tenant_id,
        "created_at": created_at,
        "approved_by": None,
        "approved_at": None,
        "approval_comment": None,
        "rejected_by": None,
        "rejected_at": None,
        "rejection_comment": None,
    }

    r = await get_redis_client()
    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(record, separators=(",", ":"), sort_keys=True))
        pipe.lpush(_envcfg_proposals_index_key(), proposal_id)
        pipe.ltrim(_envcfg_proposals_index_key(), 0, 499)
        await pipe.execute()

    # Ledger event (redacted values only)
    await _best_effort_governance_ledger_event(
        r,
        tenant_id=identity.tenant_id,
        actor=identity.subject,
        event_type="ENV_CONFIG_PROPOSED",
        extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": version, "change_request_id": req.change_request_id},
    )

    return record


@app.get("/admin/env_config/proposals")
async def list_env_config_proposals(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    lim = max(1, min(int(limit), 200))
    ids = await r.lrange(_envcfg_proposals_index_key(), 0, lim - 1)
    if not ids:
        return []
    raw_map = await r.hmget(_envcfg_proposals_hash_key(), *ids)
    out: List[Dict[str, Any]] = []
    for raw in raw_map:
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            continue
    return out


@app.get("/admin/env_config/proposals/{proposal_id}")
async def get_env_config_proposal(
    proposal_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    raw = await r.hget(_envcfg_proposals_hash_key(), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return json.loads(raw)


@app.post("/admin/env_config/proposals/{proposal_id}/approve")
async def approve_env_config_proposal(
    proposal_id: str,
    req: EnvConfigProposalApprovalRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """Approve an env config proposal; approver must be different from proposer."""
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    raw = await r.hget(_envcfg_proposals_hash_key(), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = json.loads(raw)
    if proposal.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail="Proposal is not pending")

    proposer = proposal.get("created_by")
    if proposer and identity.subject and proposer == identity.subject:
        raise HTTPException(status_code=403, detail="Two-person rule: proposer cannot approve their own proposal")

    approved_at = datetime.utcnow().isoformat() + "Z"
    proposal["status"] = "APPROVED"
    proposal["approved_by"] = identity.subject
    proposal["approved_at"] = approved_at
    proposal["approval_comment"] = req.approval_comment

    # Apply approved desired config as a versioned record.
    desired_record = {
        "env": get_apex_env().value,
        "version": proposal.get("version"),
        "changes": proposal.get("changes"),
        "approved_by": identity.subject,
        "approved_at": approved_at,
        "proposal_id": proposal_id,
        "change_request_id": proposal.get("change_request_id"),
        "change_ticket": proposal.get("change_ticket"),
        "justification": proposal.get("justification"),
    }

    async with r.pipeline(transaction=True) as pipe:
        pipe.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(proposal, separators=(",", ":"), sort_keys=True))
        pipe.set(_envcfg_desired_current_key(), json.dumps(desired_record, separators=(",", ":"), sort_keys=True))
        pipe.lpush(_envcfg_desired_history_key(), json.dumps(desired_record, separators=(",", ":"), sort_keys=True))
        pipe.ltrim(_envcfg_desired_history_key(), 0, 199)
        await pipe.execute()

    await _best_effort_governance_ledger_event(
        r,
        tenant_id=identity.tenant_id,
        actor=identity.subject,
        event_type="ENV_CONFIG_APPROVED",
        extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": proposal.get("version")},
    )

    return {"proposal": proposal, "desired_config": desired_record}


@app.post("/admin/env_config/proposals/{proposal_id}/reject")
async def reject_env_config_proposal(
    proposal_id: str,
    req: EnvConfigProposalRejectRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    raw = await r.hget(_envcfg_proposals_hash_key(), proposal_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Proposal not found")
    proposal = json.loads(raw)
    if proposal.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail="Proposal is not pending")

    rejected_at = datetime.utcnow().isoformat() + "Z"
    proposal["status"] = "REJECTED"
    proposal["rejected_by"] = identity.subject
    proposal["rejected_at"] = rejected_at
    proposal["rejection_comment"] = req.rejection_comment

    await r.hset(_envcfg_proposals_hash_key(), proposal_id, json.dumps(proposal, separators=(",", ":"), sort_keys=True))

    await _best_effort_governance_ledger_event(
        r,
        tenant_id=identity.tenant_id,
        actor=identity.subject,
        event_type="ENV_CONFIG_REJECTED",
        extra={"proposal_id": proposal_id, "env": get_apex_env().value, "version": proposal.get("version")},
    )

    return proposal


@app.get("/api/v1/audit/env_config/proposals")
async def audit_list_env_config_proposals(
    limit: int = 50,
    identity: TenantIdentity = Depends(get_identity),
):
    """Auditor read-only view of env config proposals (redacted)."""
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    lim = max(1, min(int(limit), 200))
    ids = await r.lrange(_envcfg_proposals_index_key(), 0, lim - 1)
    if not ids:
        return []
    raw_map = await r.hmget(_envcfg_proposals_hash_key(), *ids)
    out: List[Dict[str, Any]] = []
    for raw in raw_map:
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            continue
    return out


@app.post("/admin/policies/{tenant_id}/rollback/{version}")
async def rollback_policy(
    tenant_id: str,
    version: str,
    identity: TenantIdentity = Depends(get_identity),
):
    authz_engine.require_admin(identity)
    if APEX_TWO_PERSON_POLICY:
        raise HTTPException(
            status_code=409,
            detail="Two-person policy control enabled; perform rollback via a proposal and approval.",
        )
    r = await get_redis_client()
    store = PolicyStore(r)
    record = await store.rollback_to_version(tenant_id, version, actor=identity.subject)
    return record


@app.post("/admin/sessions/{session_id}/anchor/reset")
async def reset_session_anchor(
    session_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """
    Governance API for resetting drift anchor for a session.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    engine = ApexSovereignEngine(r_client=r, drift_backend=DRIFT_BACKEND)

    if isinstance(engine.drift_backend, VectorDbDriftBackend):
        await engine.drift_backend.reset_anchor(session_id)
    elif isinstance(engine.drift_backend, RedisBowDriftBackend):
        await engine.drift_backend.reset_anchor(session_id)
    else:
        raise HTTPException(status_code=400, detail="Unsupported drift backend for anchor reset")

    return {"status": "ok", "session_id": session_id, "action": "anchor_reset"}


@app.post("/admin/rtbf")
async def right_to_be_forgotten(
    req: RtbfRequest,
    identity: TenantIdentity = Depends(get_identity),
):
    """
    Right-to-be-forgotten marker:
    - Records RTBF intent into the ledger
    - Marks subject/session ids in Redis for downstream erasure processes
    """
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
            # must be tenant-scoped
            if not rref.startswith(f"apex:content:{tenant_id}:"):
                return None
            return rref
        # tenant_ref form: "{tenant}:{kind}:{sha256}"
        if rref.startswith(f"{tenant_id}:"):
            return f"apex:content:{rref}"
        return None

    def _key_hash(key: str) -> str:
        return _rtbf_sha256_hex(f"redis\0{key}")

    def _s3_key_hash(bucket: str, key: str) -> str:
        return _rtbf_sha256_hex(f"s3\0{bucket}\0{key}")

    r = await get_redis_client()

    request_id = (req.request_id or "").strip() or uuid.uuid4().hex
    requested_at = datetime.utcnow().isoformat() + "Z"
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
        "policy_version": POLICY_VERSION,
        "decision": "RTBF_MARKER",
        "reason": req.reason,
        "requested_by": identity.subject,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
    }

    marker_payload_response = dict(marker_payload_ledger)
    # Preserve the old echo behavior for operators while avoiding raw subject in the ledger.
    marker_payload_response["subject"] = req.subject
    # Preserve the old marker shape: session_id is the raw (non-namespaced) value.
    marker_payload_response["session_id"] = req.session_id
    marker_payload_response["session_id_ns"] = namespaced_session

    try:
        await create_unsigned_ledger_entry(r, marker_payload_ledger)
        await record_metrics_for_audit(r, marker_payload_ledger)
    except LedgerBackpressureError:
        print("[apex-rtbf] Dropping RTBF marker entry due to backlog")
    except Exception:
        pass

    # Record the RTBF request for operational tracking (hashes only).
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

    # Best-effort deletion + proof.
    redis_attempts: List[Dict[str, Any]] = []
    drift_result: Dict[str, Any] = {}
    dlp_result: Dict[str, Any] = {}
    dedup_result: Dict[str, Any] = {}
    s3_result: Dict[str, Any] = {}

    deleted_key_hashes: List[str] = []
    s3_deleted_hashes: List[str] = []

    # 1) Session prompts + drift embeddings
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
        except Exception as e:
            redis_attempts.append({"key": prompts_key, "action": "delete", "ok": False, "error": str(e)})

        # Drift backend embeddings/state
        try:
            engine = ApexSovereignEngine(r_client=r, drift_backend=DRIFT_BACKEND)
            if isinstance(engine.drift_backend, (VectorDbDriftBackend, RedisBowDriftBackend)):
                await engine.drift_backend.reset_anchor(namespaced_session)
                drift_result = {
                    "backend": type(engine.drift_backend).__name__,
                    "action": "reset_anchor",
                    "session_id": namespaced_session,
                    "ok": True,
                }
            else:
                drift_result = {"backend": "unknown", "action": "reset_anchor", "ok": False, "error": "unsupported_backend"}
        except Exception as e:
            drift_result = {"backend": "error", "action": "reset_anchor", "ok": False, "error": str(e)}

    # 2) Adversarial corpus (tenant-scoped)
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
        except Exception as e:
            redis_attempts.append({"key": corpus_key, "action": "delete", "ok": False, "error": str(e)})

    # 3) Semantic DLP store (embeddings + referenced exemplar text)
    if req.delete_dlp_semantic:
        items_key = _dlp_semantic_items_key(identity.tenant_id)
        meta_key = _dlp_semantic_meta_key(identity.tenant_id)
        deleted_exemplar_text_keys: List[str] = []
        try:
            store = DlpSemanticStore(r)
            loaded = await store.load(identity.tenant_id)
            items = loaded.get("items") or []

            # Delete deduped exemplar text objects referenced by the semantic store.
            for it in items if isinstance(items, list) else []:
                tref = (it or {}).get("text_ref") or {}
                if isinstance(tref, dict):
                    tenant_ref = tref.get("tenant_ref")
                    if isinstance(tenant_ref, str) and tenant_ref.startswith(f"{identity.tenant_id}:"):
                        k = f"apex:content:{tenant_ref}"
                        deleted_exemplar_text_keys.append(k)

            # Perform deletes
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
        except Exception as e:
            dlp_result = {"deleted": False, "ok": False, "error": str(e)}

    # 4) Explicit tenant-scoped dedup keys
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
        except Exception as e:
            dedup_result = {"targets": int(len(dedup_targets)), "invalid_refs": invalid_dedup_refs, "ok": False, "error": str(e)}
    elif invalid_dedup_refs:
        dedup_result = {"targets": 0, "invalid_refs": invalid_dedup_refs, "ok": False, "error": "invalid_dedup_refs"}

    # 5) Optional S3 deletions (non-ledger only)
    if req.s3_objects:
        if not APEX_RTBF_S3_ALLOW:
            raise HTTPException(status_code=400, detail="S3 deletion is disabled (set APEX_RTBF_S3_ALLOW=true)")
        if not APEX_RTBF_S3_BUCKET:
            raise HTTPException(status_code=400, detail="APEX_RTBF_S3_BUCKET must be set for S3 deletion")

        # Explicitly forbid deleting ledger/checkpoint buckets.
        forbidden_buckets = {b for b in [LEDGER_S3_BUCKET, LEDGER_CHECKPOINT_BUCKET] if b}
        if APEX_RTBF_S3_BUCKET in forbidden_buckets:
            raise HTTPException(status_code=400, detail="APEX_RTBF_S3_BUCKET cannot point at ledger buckets")

        s3 = boto3.client("s3")
        attempts: List[Dict[str, Any]] = []
        for obj in req.s3_objects:
            bucket = (obj.bucket or "").strip()
            key = (obj.key or "").strip()
            if bucket != APEX_RTBF_S3_BUCKET:
                attempts.append({"bucket": bucket, "key": key, "ok": False, "error": "bucket_not_allowed"})
                continue
            if bucket in forbidden_buckets:
                attempts.append({"bucket": bucket, "key": key, "ok": False, "error": "bucket_forbidden"})
                continue
            try:
                s3.delete_object(Bucket=bucket, Key=key)
                # Verify best-effort
                verified_missing = False
                try:
                    s3.head_object(Bucket=bucket, Key=key)
                    verified_missing = False
                except Exception:
                    verified_missing = True
                attempts.append({"bucket": bucket, "key": key, "action": "delete", "verified_missing": verified_missing, "ok": True})
                s3_deleted_hashes.append(_s3_key_hash(bucket, key))
            except Exception as e:
                attempts.append({"bucket": bucket, "key": key, "action": "delete", "ok": False, "error": str(e)})

        s3_result = {"attempts": attempts, "ok": True}

    # Store marker sets (hashes only)
    if subject_hash:
        try:
            await r.sadd(f"apex:rtbf:subject:{identity.tenant_id}", subject_hash)
        except Exception:
            pass
    if namespaced_session:
        try:
            # Store both raw and namespaced forms for compatibility with existing operator workflows.
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

    # Cache proof for operator/auditor retrieval; canonical proof remains in ledger.
    try:
        await r.set(_rtbf_proof_cache_key(identity.tenant_id, request_id), proof.json())
        if int(APEX_RTBF_PROOF_CACHE_TTL_SECONDS or 0) > 0:
            await r.expire(_rtbf_proof_cache_key(identity.tenant_id, request_id), int(APEX_RTBF_PROOF_CACHE_TTL_SECONDS))
    except Exception:
        pass

    # Anchor the proof in the append-only ledger (hashes + counts, not raw keys).
    proof_payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "tenant_id": identity.tenant_id,
        "request_id": request_id,
        "decision": "RTBF_PROOF",
        "subject_hash": subject_hash,
        "session_id": namespaced_session,
        "requested_at": requested_at,
        "requested_by": identity.subject,
        "region": APEX_REGION,
        "ledger_chain_id": APEX_CHAIN_ID,
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
        # Store a stable lookup for cache misses (request_id -> entry_id/index).
        try:
            entry_id = (proof_enriched or {}).get("entry_id")
            if entry_id:
                await r.set(
                    _rtbf_proof_ledger_entry_key(identity.tenant_id, request_id),
                    json.dumps({"entry_id": entry_id, "index": int(proof_index)}),
                )
        except Exception:
            pass
    except LedgerBackpressureError:
        print("[apex-rtbf] Dropping RTBF proof entry due to backlog")
    except Exception:
        pass

    return {"status": "completed", "request_id": request_id, "marker": marker_payload_response, "proof": proof.dict()}


async def _load_rtbf_proof_from_ledger(
    r: redis.Redis,
    *,
    tenant_id: str,
    request_id: str,
    max_scan: int = 5000,
    ignore_mapping: bool = False,
    write_back: bool = True,
) -> Optional[Dict[str, Any]]:
    """Best-effort RTBF proof retrieval from the canonical ledger.

    Strategy:
    1) Use request_id -> entry_id/index mapping if present.
    2) Fallback: bounded reverse scan of the ledger tail.
    """

    ledger_key = "apex:audit_ledger"
    mapping_key = f"apex:rtbf:proof_ledger_entry:{tenant_id}:{request_id}"

    if not ignore_mapping:
        try:
            raw_map = await r.get(mapping_key)
            if raw_map:
                try:
                    m = json.loads(raw_map)
                    idx = m.get("index")
                    entry_id = m.get("entry_id")
                    if idx is not None:
                        raw = await r.lindex(ledger_key, int(idx))
                        if raw:
                            e = json.loads(raw)
                            payload = (e.get("payload") or {}) if isinstance(e, dict) else {}
                            if payload.get("tenant_id") == tenant_id and payload.get("request_id") == request_id and payload.get("decision") == "RTBF_PROOF":
                                return {"source": "ledger_index", "index": int(idx), "entry_id": entry_id, "payload": payload}
                except Exception:
                    pass
        except Exception:
            pass

    try:
        length = int(await r.llen(ledger_key) or 0)
        if length <= 0:
            return None
        start = max(0, length - int(max_scan))
        for idx in range(length - 1, start - 1, -1):
            raw = await r.lindex(ledger_key, idx)
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except Exception:
                continue
            payload = (e.get("payload") or {}) if isinstance(e, dict) else {}
            if payload.get("decision") != "RTBF_PROOF":
                continue
            if payload.get("tenant_id") != tenant_id:
                continue
            if payload.get("request_id") != request_id:
                continue
            entry_id = payload.get("entry_id")
            # Cache mapping for next time.
            try:
                if write_back and entry_id:
                    await r.set(mapping_key, json.dumps({"entry_id": entry_id, "index": int(idx)}))
            except Exception:
                pass
            return {"source": "ledger_scan", "index": int(idx), "entry_id": entry_id, "payload": payload}
    except Exception:
        return None

    return None


@app.get("/admin/rtbf/{request_id}/proof")
async def admin_get_rtbf_proof(
    request_id: str,
    identity: TenantIdentity = Depends(get_identity),
    zero_cache: bool = False,
):
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    key = f"apex:rtbf:proof:{identity.tenant_id}:{request_id}"
    raw = None if zero_cache else await r.get(key)
    if not raw:
        from_ledger = await _load_rtbf_proof_from_ledger(
            r,
            tenant_id=identity.tenant_id,
            request_id=request_id,
            ignore_mapping=bool(zero_cache),
            write_back=not bool(zero_cache),
        )
        if not from_ledger:
            raise HTTPException(status_code=404, detail="RTBF proof not found; retrieve via ledger export")
        # Provide the canonical ledger proof payload and a stable entry_id to fetch inclusion proofs.
        return {
            "source": from_ledger.get("source"),
            "ledger_index": from_ledger.get("index"),
            "ledger_entry_id": from_ledger.get("entry_id"),
            "payload": from_ledger.get("payload"),
        }
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


@app.get("/api/v1/audit/rtbf/{request_id}/proof")
async def audit_get_rtbf_proof(
    request_id: str,
    identity: TenantIdentity = Depends(get_identity),
    zero_cache: bool = False,
):
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    key = f"apex:rtbf:proof:{identity.tenant_id}:{request_id}"
    raw = None if zero_cache else await r.get(key)
    if not raw:
        from_ledger = await _load_rtbf_proof_from_ledger(
            r,
            tenant_id=identity.tenant_id,
            request_id=request_id,
            ignore_mapping=bool(zero_cache),
            write_back=not bool(zero_cache),
        )
        if not from_ledger:
            raise HTTPException(status_code=404, detail="RTBF proof not found; retrieve via ledger export")
        return {
            "source": from_ledger.get("source"),
            "ledger_index": from_ledger.get("index"),
            "ledger_entry_id": from_ledger.get("entry_id"),
            "payload": from_ledger.get("payload"),
        }
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


@app.get("/admin/governance/summary")
async def governance_summary(identity: TenantIdentity = Depends(get_identity)):
    """
    High-level governance summary for operators.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    queue_len, is_warning, is_critical = await get_unsigned_backlog_status(r)
    return {
        "env": get_apex_env().value,
        "ledger_backlog_len": queue_len,
        "ledger_backlog_state": "CRITICAL" if is_critical else "WARNING" if is_warning else "OK",
        "fips_mode": APEX_FIPS_MODE,
        "policy_version": POLICY_VERSION,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
    }


@app.get("/admin/egress/validate")
async def admin_egress_validate(
    url: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """Admin-only helper to test sovereign egress policy decisions.

    This endpoint does NOT perform any outbound call.
    It only evaluates the configured egress policy against the provided URL.
    """
    authz_engine.require_admin(identity)
    ok, reason, details = _egress_check_url(url)
    patterns = _compile_egress_allowlist_patterns()
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "allowed": bool(ok),
        "reason": reason,
        "details": details,
        "policy": {
            "block_ip_literals": bool(APEX_EGRESS_BLOCK_IP_LITERALS),
            "allowlist_regex": APEX_EGRESS_ALLOWLIST_REGEX,
            "allowlist_patterns": int(len(patterns)),
            "audit_blocks": bool(APEX_EGRESS_AUDIT_BLOCKS),
        },
    }


@app.get("/api/v1/audit/egress/validate")
async def audit_egress_validate(
    url: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """Auditor read-only helper to test sovereign egress policy decisions.

    This endpoint does NOT perform any outbound call.
    It only evaluates the configured egress policy against the provided URL.
    """
    authz_engine.require_audit_read(identity)
    ok, reason, details = _egress_check_url(url)
    patterns = _compile_egress_allowlist_patterns()
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "allowed": bool(ok),
        "reason": reason,
        "details": details,
        "policy": {
            "block_ip_literals": bool(APEX_EGRESS_BLOCK_IP_LITERALS),
            "allowlist_regex": APEX_EGRESS_ALLOWLIST_REGEX,
            "allowlist_patterns": int(len(patterns)),
            "audit_blocks": bool(APEX_EGRESS_AUDIT_BLOCKS),
        },
    }


@app.get("/sdk/config")
async def sdk_config():
    """
    Simple configuration endpoint for SDKs or clients to auto-configure proxy access.
    """
    return {
        "stream_endpoint": "/v1/stream",
        "auth_scheme": "Bearer",
        "required_headers": ["Authorization", "x-tenant-id", "x-session-id"],
        "models": list(MODEL_CATALOG.keys()),
    }

# =========================================================
# 8. MINIMAL CISO DASHBOARD ENDPOINTS (READ-ONLY)
# =========================================================

async def _get_last_kms_signed_at(r: redis.Redis) -> Optional[str]:
    length = await r.llen("apex:audit_ledger")
    if length == 0:
        return None
    for idx in range(length - 1, max(length - 2000, -1), -1):
        raw = await r.lindex("apex:audit_ledger", idx)
        if not raw:
            continue
        entry = json.loads(raw)
        kms_signed_at = entry.get("kms_signed_at")
        signing_status = entry.get("signing_status")
        if kms_signed_at and signing_status == "kms_signed":
            return kms_signed_at
    return None


async def _get_24h_risk_stats(r: redis.Redis) -> Dict[str, Any]:
    now = datetime.utcnow()
    total = 0
    blocked = 0
    high_risk_alerts = 0
    axis_counts: Dict[str, int] = {}

    for i in range(24):
        dt = now - timedelta(hours=i)
        hour_key = _metrics_hour_key(dt)
        total_key = _metrics_total_key(hour_key)
        blocked_key = _metrics_blocked_key(hour_key)
        highrisk_key = _metrics_highrisk_key(hour_key)
        axis_hash_key = _metrics_axis_hash_key(hour_key)

        t = await r.get(total_key)
        b = await r.get(blocked_key)
        h = await r.get(highrisk_key)
        axis_map = await r.hgetall(axis_hash_key)

        total += int(t or 0)
        blocked += int(b or 0)
        high_risk_alerts += int(h or 0)

        for axis, count_str in axis_map.items():
            try:
                c = int(count_str)
            except Exception:
                continue
            axis_counts[axis] = axis_counts.get(axis, 0) + c

    top_risk_axis = None
    if axis_counts:
        top_risk_axis = max(axis_counts.items(), key=lambda kv: kv[1])[0]

    return {
        "total_interactions_24h": total,
        "blocked_interactions_24h": blocked,
        "top_risk_axis": top_risk_axis,
        "high_risk_alerts": high_risk_alerts,
    }


@app.get("/api/v1/dashboard/summary")
async def dashboard_summary(identity: TenantIdentity = Depends(get_identity)):
    """
    CISO dashboard summary:
    - Ledger integrity
    - Backpressure level
    - Recent risk stats
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()

    queue_len, _, _ = await get_unsigned_backlog_status(r)
    backpressure_level = float(queue_len) / float(MAX_UNSIGNED_QUEUE) if MAX_UNSIGNED_QUEUE else 0.0
    last_kms_signed_at = await _get_last_kms_signed_at(r)

    ledger_status = "unknown"
    length = await r.llen("apex:audit_ledger")
    if length == 0:
        ledger_status = "empty"
    else:
        start_idx = max(0, length - 100)
        prev_hash: Optional[str] = None
        ok = True
        for idx in range(start_idx, length):
            raw = await r.lindex("apex:audit_ledger", idx)
            if not raw:
                ok = False
                break
            entry = json.loads(raw)
            payload = entry.get("payload", {})
            expected_prev = entry.get("prev_hash")
            entry_hash = entry.get("entry_hash")
            recomputed = compute_entry_hash(payload, prev_hash)
            if expected_prev != prev_hash or entry_hash != recomputed:
                ok = False
                break
            prev_hash = entry_hash
        ledger_status = "healthy" if ok else "error"

    risk_overview = await _get_24h_risk_stats(r)

    return {
        "system_integrity": {
            "ledger_status": ledger_status,
            "last_kms_signed_at": last_kms_signed_at,
            "backpressure_level": backpressure_level,
            "fips_mode": APEX_FIPS_MODE,
        },
        "risk_overview": risk_overview,
    }


@app.get("/api/v1/audit/dashboard/summary")
async def audit_dashboard_summary(identity: TenantIdentity = Depends(get_identity)):
    """Auditor-facing compliance dashboard summary (read-only).

    Intended for finance-style operational wrappers:
    - ledger integrity/backpressure signal
    - recent risk stats
    - tenant control-plane visibility (model allowlist + retention knobs)
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()

    queue_len, _, _ = await get_unsigned_backlog_status(r)
    backpressure_level = float(queue_len) / float(MAX_UNSIGNED_QUEUE) if MAX_UNSIGNED_QUEUE else 0.0
    last_kms_signed_at = await _get_last_kms_signed_at(r)

    ok, count, last_checkpoint = await _verify_ledger_chain_for_api(r)
    risk_overview = await _get_24h_risk_stats(r)

    store = PolicyStore(r)
    current = await store.get_policy_or_seed(
        identity.tenant_id,
        seed_policy=POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE),
    )
    policy = current.policy or {}

    dlp_store = DlpSemanticStore(r)
    dlp_loaded = await dlp_store.load(identity.tenant_id)
    dlp_meta = dlp_loaded.get("meta") or {}
    dlp_items = dlp_loaded.get("items") or []

    return {
        "system_integrity": {
            "ledger_chain_verified": bool(ok),
            "ledger_entry_count": int(count),
            "last_checkpoint": last_checkpoint,
            "last_kms_signed_at": last_kms_signed_at,
            "backpressure_level": backpressure_level,
            "fips_mode": APEX_FIPS_MODE,
            "region": APEX_REGION,
            "chain_id": APEX_CHAIN_ID,
        },
        "risk_overview": risk_overview,
        "tenant_controls": {
            "tenant_id": identity.tenant_id,
            "model_allowlist": policy.get("model_allowlist") or [],
            "retention": policy.get("retention") or {},
            "retention_effective": _effective_retention_view(
                tenant_id=identity.tenant_id,
                policy=policy,
                policy_version=current.version,
            ),
            "retention_governed": _effective_retention_view(
                tenant_id=identity.tenant_id,
                policy=policy,
                policy_version=current.version,
            ),
            "dlp_semantic": {
                "enabled": bool(APEX_DLP_SEMANTIC_ENABLED),
                "embedding_model": APEX_EMBEDDING_MODEL,
                "max_exemplars": int(APEX_DLP_SEMANTIC_MAX_EXEMPLARS),
                "updated_at": dlp_meta.get("updated_at"),
                "count": dlp_meta.get("count", len(dlp_items)),
            },
        },
        "platform": {
            "models": list(MODEL_CATALOG.keys()),
        },
    }


@app.get("/api/v1/policy/{tenant_id}/current")
async def dashboard_policy_current(
    tenant_id: str,
    identity: TenantIdentity = Depends(get_identity),
):
    """
    CISO dashboard view of per-tenant policy and its history.
    """
    authz_engine.require_admin(identity)
    r = await get_redis_client()
    store = PolicyStore(r)

    try:
        current = await store.get_policy_record(tenant_id)
    except HTTPException as e:
        if e.status_code == 404:
            template = POLICY_TEMPLATE_MAP.get("default", DEFAULT_POLICY_BASELINE)
            current = await store.get_policy_or_seed(tenant_id, seed_policy=template)
        else:
            raise

    history_records = await store.list_versions(tenant_id)
    history = []
    for rec in history_records:
        if rec.version == current.version and rec.created_at == current.created_at:
            continue
        history.append(
            {
                "version": rec.version,
                "comment": rec.comment,
                "date": rec.created_at,
            }
        )

    return {
        "version": current.version,
        "created_at": current.created_at,
        "policy": current.policy,
        "history": history,
    }

# =========================================================
# 9. LEDGER VERIFY ENDPOINT + CLI (AUDIT TRAIL INTEGRITY)
# =========================================================

async def _verify_ledger_chain_for_api(r: redis.Redis) -> Tuple[bool, int, Optional[str]]:
    length = await r.llen("apex:audit_ledger")
    prev_hash: Optional[str] = None
    ok = True
    for idx in range(length):
        raw = await r.lindex("apex:audit_ledger", idx)
        if not raw:
            ok = False
            break
        entry = json.loads(raw)
        payload = entry.get("payload", {})
        expected_prev = entry.get("prev_hash")
        entry_hash = entry.get("entry_hash")

        recomputed = compute_entry_hash(payload, prev_hash)
        if expected_prev != prev_hash or entry_hash != recomputed:
            ok = False
            break
        prev_hash = entry_hash
    last_checkpoint_ts: Optional[str] = None
    cl = await r.llen("apex:audit_checkpoints")
    if cl and cl > 0:
        last_cp_raw = await r.lindex("apex:audit_checkpoints", cl - 1)
        if last_cp_raw:
            try:
                cp = json.loads(last_cp_raw)
                last_checkpoint_ts = cp.get("ts")
            except Exception:
                pass
    return ok, length, last_checkpoint_ts


@app.get("/api/v1/audit/ledger/verify")
async def audit_ledger_verify(identity: TenantIdentity = Depends(get_identity)):
    """
    API-based ledger integrity verification for auditors.
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    ok, count, last_checkpoint = await _verify_ledger_chain_for_api(r)
    return {
        "verification_status": "verified" if ok else "failed",
        "entry_count": count,
        "chain_integrity_score": 1.0 if ok else 0.0,
        "last_checkpoint": last_checkpoint,
        "region": APEX_REGION,
        "chain_id": APEX_CHAIN_ID,
    }


@app.get("/api/v1/audit/ledger/export")
async def audit_ledger_export(
    tenant_id: Optional[str] = None,
    start_index: int = 0,
    end_index: int = -1,
    identity: TenantIdentity = Depends(get_identity),
):
    """Evidence export for discovery.

    Returns JSONL:
      - First line is an EXPORT_META record
      - Following lines are raw ledger entry objects

    Notes:
    - This is read-only and intended for auditors/admins.
    - Tenant scoping is optional via `tenant_id` filtering.
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()
    length = int(await r.llen("apex:audit_ledger") or 0)

    s = max(0, int(start_index))
    e = int(end_index)
    if e < 0:
        e = length - 1
    e = min(e, length - 1)

    async def _gen() -> AsyncGenerator[bytes, None]:
        meta = {
            "type": "EXPORT_META",
            "ts": datetime.utcnow().isoformat() + "Z",
            "region": APEX_REGION,
            "chain_id": APEX_CHAIN_ID,
            "tenant_filter": tenant_id,
            "start_index": s,
            "end_index": e,
            "policy_version": POLICY_VERSION,
            "entry_count": 0 if length == 0 or s > e else (e - s + 1),
        }
        yield (json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

        if length == 0 or s > e:
            return

        for idx in range(s, e + 1):
            raw = await r.lindex("apex:audit_ledger", idx)
            if not raw:
                continue
            if tenant_id:
                try:
                    obj = json.loads(raw)
                    payload = obj.get("payload") or {}
                    if payload.get("tenant_id") != tenant_id:
                        continue
                    yield (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
                except Exception:
                    continue
            else:
                yield (raw + "\n").encode("utf-8")

    return StreamingResponse(_gen(), media_type="application/jsonl")


class MerkleAnchorInfo(BaseModel):
    anchor_index: int
    anchor_entry_id: Optional[str] = None
    anchored_start_index: int
    anchored_end_index: int
    merkle_alg: str
    merkle_root: str
    kms_signature_b64: Optional[str] = None
    signing_status: Optional[str] = None
    kms_signed_at: Optional[str] = None
    kid: Optional[str] = None
    alg: Optional[str] = None
    public_key_b64: Optional[str] = None
    public_key_format: Optional[str] = None
    signed_message_canonical: str
    signature_verified: Optional[bool] = None
    signature_verification_error: Optional[str] = None


class InclusionProofResponse(BaseModel):
    entry_index: int
    entry: Dict[str, Any]
    leaf_hash: str
    merkle_proof: List[Dict[str, str]]
    anchor: MerkleAnchorInfo


@app.get("/api/v1/verify/{entry_id}")
async def verify_entry_inclusion(
    entry_id: str,
    identity: TenantIdentity = Depends(get_identity),
    zero_cache: bool = False,
    entry_index: Optional[int] = None,
    verify_signature: bool = False,
):
    """Auditor workflow: return an inclusion proof for a ledger entry_id.

    Proof shows the entry_hash is included in a Merkle root that is itself carried
    by a KMS-signed MERKLE_ANCHOR ledger entry.
    """
    authz_engine.require_audit_read(identity)
    r = await get_redis_client()

    # 1) Locate ledger index
    index: Optional[int] = None
    length = int(await r.llen("apex:audit_ledger") or 0)

    if entry_index is not None:
        if int(entry_index) < 0 or int(entry_index) >= length:
            raise HTTPException(status_code=400, detail="entry_index out of range")
        candidate = await read_raw_ledger_entry(r, int(entry_index))
        if not candidate:
            raise HTTPException(status_code=404, detail="ledger entry missing")
        cand_payload = candidate.get("payload") or {}
        if cand_payload.get("entry_id") != entry_id:
            raise HTTPException(status_code=400, detail="entry_index does not match entry_id")
        index = int(entry_index)
    else:
        if not zero_cache:
            try:
                raw_idx = await r.get(f"apex:ledger:index:{entry_id}")
                if raw_idx is not None:
                    index = int(raw_idx)
            except Exception:
                index = None

        if index is None:
            # Fallback scan. In zero-cache mode, avoid unbounded scans by default.
            if zero_cache and length > max(1, int(APEX_VERIFY_SCAN_LIMIT)):
                raise HTTPException(
                    status_code=413,
                    detail="zero_cache scan too large; provide entry_index or increase APEX_VERIFY_SCAN_LIMIT",
                )

            start = 0 if zero_cache else max(0, length - max(1, int(APEX_VERIFY_SCAN_LIMIT)))
            for i in range(start, length):
                raw = await r.lindex("apex:audit_ledger", i)
                if not raw:
                    continue
                try:
                    e = json.loads(raw)
                    if (e.get("payload") or {}).get("entry_id") == entry_id:
                        index = i
                        break
                except Exception:
                    continue

    if index is None:
        raise HTTPException(status_code=404, detail="entry_id not found")

    entry = await read_raw_ledger_entry(r, index)
    if not entry:
        raise HTTPException(status_code=404, detail="ledger entry missing")

    payload = entry.get("payload", {})
    prev_hash = entry.get("prev_hash")
    leaf_hash = entry.get("entry_hash") or compute_entry_hash(payload, prev_hash)

    # 2) Find the corresponding MERKLE_ANCHOR entry
    anchor_entry: Optional[Dict[str, Any]] = None
    anchor_index: Optional[int] = None
    length = int(await r.llen("apex:audit_ledger") or 0)
    search_end = min(length, index + max(1, APEX_ANCHOR_SEARCH_LIMIT))
    for j in range(index, search_end):
        candidate = await read_raw_ledger_entry(r, j)
        if not candidate:
            continue
        cand_payload = candidate.get("payload") or {}
        if cand_payload.get("decision") != "MERKLE_ANCHOR":
            continue
        try:
            s = int(cand_payload.get("anchored_start_index"))
            e = int(cand_payload.get("anchored_end_index"))
        except Exception:
            continue
        if s <= index <= e:
            anchor_entry = candidate
            anchor_index = j
            break

    if not anchor_entry or anchor_index is None:
        raise HTTPException(status_code=404, detail="no MERKLE_ANCHOR found for this entry (not anchored yet)")

    a_payload = anchor_entry.get("payload") or {}
    merkle_root = a_payload.get("merkle_root")
    if not merkle_root:
        raise HTTPException(status_code=500, detail="anchor entry missing merkle_root")

    anchored_start = int(a_payload.get("anchored_start_index"))
    anchored_end = int(a_payload.get("anchored_end_index"))
    raw_entries = await r.lrange("apex:audit_ledger", anchored_start, anchored_end)
    if len(raw_entries) != (anchored_end - anchored_start + 1):
        raise HTTPException(status_code=500, detail="anchored leaf window incomplete")

    leaves: List[str] = []
    if zero_cache:
        # Recompute the hash-chain locally inside the anchored window and derive
        # Merkle leaves from recomputed entry_hash values (no dependence on stored leaf hashes).
        chain_prev: Optional[str] = None
        for k, raw in enumerate(raw_entries):
            try:
                e = json.loads(raw)
            except Exception:
                raise HTTPException(status_code=500, detail="invalid ledger entry JSON in anchored window")

            p = e.get("payload") or {}
            stored_prev = e.get("prev_hash")
            stored_hash = e.get("entry_hash")

            if k == 0:
                chain_prev = stored_prev
            else:
                if stored_prev != chain_prev:
                    raise HTTPException(status_code=500, detail="ledger chain mismatch inside anchored window")

            recomputed = compute_entry_hash(p, chain_prev)
            if stored_hash and stored_hash != recomputed:
                raise HTTPException(status_code=500, detail="ledger entry_hash mismatch inside anchored window")

            leaves.append(recomputed)
            chain_prev = recomputed

        computed_root = compute_merkle_root_hex(leaves)
        if computed_root and computed_root != merkle_root:
            raise HTTPException(status_code=500, detail="anchor merkle_root does not match recomputed root")
    else:
        for raw in raw_entries:
            try:
                leaves.append(json.loads(raw).get("entry_hash", ""))
            except Exception:
                leaves.append("")
        leaves = [h for h in leaves if isinstance(h, str) and len(h) == 64]

    pos = index - anchored_start
    if pos < 0 or pos >= len(leaves):
        raise HTTPException(status_code=500, detail="entry index not within anchored leaf set")

    proof = compute_merkle_inclusion_proof_hex(leaves, pos)

    if zero_cache:
        leaf_hash = leaves[pos]

    # Canonical signed message (matches signing_worker_loop)
    a_prev = anchor_entry.get("prev_hash")
    a_entry_hash = anchor_entry.get("entry_hash")
    canonical = json.dumps(
        {
            "payload": a_payload,
            "prev_hash": a_prev,
            "entry_hash": a_entry_hash,
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    signature_verified: Optional[bool] = None
    signature_verification_error: Optional[str] = None
    if verify_signature:
        try:
            sig_b64 = anchor_entry.get("kms_signature")
            if not (isinstance(sig_b64, str) and sig_b64):
                raise RuntimeError("anchor entry missing kms_signature")

            anchor_kid = anchor_entry.get("kid")
            pub_b64 = get_signer_public_key_b64(anchor_kid if isinstance(anchor_kid, str) else None)
            if not (isinstance(pub_b64, str) and pub_b64):
                raise RuntimeError("signer public key unavailable")

            # Verify the anchor entry_hash is consistent with the canonical payload.
            recomputed_anchor_hash = compute_entry_hash(a_payload, a_prev)
            if a_entry_hash and recomputed_anchor_hash != a_entry_hash:
                raise RuntimeError("anchor entry_hash mismatch")

            # Verify ECDSA signature over SHA-256 digest of canonical message.
            sig = base64.b64decode(sig_b64)
            pub_der = base64.b64decode(pub_b64)
            pub = serialization.load_der_public_key(pub_der)
            digest = hashlib.sha256(canonical.encode("utf-8")).digest()
            pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            signature_verified = True
        except Exception as e:
            signature_verified = False
            signature_verification_error = str(e)[:200]

    anchor_info = MerkleAnchorInfo(
        anchor_index=anchor_index,
        anchor_entry_id=(a_payload.get("entry_id") if isinstance(a_payload, dict) else None),
        anchored_start_index=anchored_start,
        anchored_end_index=anchored_end,
        merkle_alg=a_payload.get("merkle_alg", "sha256"),
        merkle_root=merkle_root,
        kms_signature_b64=anchor_entry.get("kms_signature"),
        signing_status=anchor_entry.get("signing_status"),
        kms_signed_at=anchor_entry.get("kms_signed_at"),
        kid=anchor_entry.get("kid"),
        alg=anchor_entry.get("alg"),
        public_key_b64=get_signer_public_key_b64(anchor_entry.get("kid") if isinstance(anchor_entry.get("kid"), str) else None),
        public_key_format="spki_der",
        signed_message_canonical=canonical,
        signature_verified=signature_verified,
        signature_verification_error=signature_verification_error,
    )

    return InclusionProofResponse(
        entry_index=index,
        entry=entry,
        leaf_hash=leaf_hash,
        merkle_proof=proof,
        anchor=anchor_info,
    )


def verify_ledger_chain_from_redis() -> None:
    """
    CLI helper to verify ledger integrity directly from Redis.
    """
    import asyncio as _asyncio

    async def _inner():
        r = await get_redis_client()
        length = await r.llen("apex:audit_ledger")
        print(f"[apex] Verifying ledger chain, length={length}, region={APEX_REGION}, chain_id={APEX_CHAIN_ID}")

        prev_hash: Optional[str] = None
        for idx in range(length):
            raw = await r.lindex("apex:audit_ledger", idx)
            if not raw:
                print(f"[apex] Missing entry at index={idx}")
                return
            entry = json.loads(raw)
            payload = entry.get("payload", {})
            expected_prev = entry.get("prev_hash")
            entry_hash = entry.get("entry_hash")

            recomputed = compute_entry_hash(payload, prev_hash)

            if expected_prev != prev_hash:
                print(
                    f"[apex] prev_hash mismatch at index={idx}, "
                    f"expected={prev_hash}, stored={expected_prev}"
                )
                return
            if entry_hash != recomputed:
                print(
                    f"[apex] entry_hash mismatch at index={idx}, "
                    f"stored={entry_hash}, recomputed={recomputed}"
                )
                return

            prev_hash = entry_hash

        print("[apex] Ledger chain OK")

    _asyncio.run(_inner())


def verify_ledger_from_s3(
    bucket: str,
    prefix: str = "ledger/",
    region: Optional[str] = None,
) -> None:
    """
    CLI helper to verify S3 offloaded ledger integrity end-to-end.
    """
    session_kwargs: Dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    _s3 = boto3.client("s3", **session_kwargs)

    paginator = _s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

    prev_hash: Optional[str] = None
    total_entries = 0

    for page in pages:
        for obj in page.get("Contents", []):
            key = obj["Key"]
            body = _s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            for line in body.splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                payload = entry.get("payload", {})
                expected_prev = entry.get("prev_hash")
                entry_hash = entry.get("entry_hash")
                recomputed = compute_entry_hash(payload, prev_hash)

                if expected_prev != prev_hash:
                    print(
                        f"[apex] S3 prev_hash mismatch at entry={total_entries}, "
                        f"key={key}, expected={prev_hash}, stored={expected_prev}"
                    )
                    return
                if entry_hash != recomputed:
                    print(
                        f"[apex] S3 entry_hash mismatch at entry={total_entries}, "
                        f"key={key}, stored={entry_hash}, recomputed={recomputed}"
                    )
                    return

                prev_hash = entry_hash
                total_entries += 1

    print(f"[apex] S3 ledger chain OK, entries={total_entries}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Apex Sovereign Ledger & Governance CLI")
    parser.add_argument(
        "--mode",
        choices=["redis", "s3"],
        default="redis",
        help="Verification mode: redis (default) or s3",
    )
    parser.add_argument("--bucket", help="S3 bucket name (for mode=s3)")
    parser.add_argument("--prefix", default=LEDGER_S3_PREFIX or "ledger/", help="S3 prefix for ledger (for mode=s3)")
    parser.add_argument("--region", default=None, help="AWS region for S3 client")

    args = parser.parse_args()

    if args.mode == "redis":
        verify_ledger_chain_from_redis()
    else:
        if not args.bucket:
            raise SystemExit("bucket is required for mode=s3")
        verify_ledger_from_s3(bucket=args.bucket, prefix=args.prefix, region=args.region)
