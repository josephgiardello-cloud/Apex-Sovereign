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
import copy
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Optional, List, Tuple, Any, Protocol, Literal, Callable, Pattern, cast
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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

try:
    from .chimera import import_compat as chimera_import_compat
except Exception:
    import chimera.import_compat as chimera_import_compat  # type: ignore[no-redef]

apex_config = chimera_import_compat.import_module_compat(__package__, ".config", "config")
chimera_retention_policy = chimera_import_compat.import_module_compat(__package__, ".chimera.retention_policy", "chimera.retention_policy")
chimera_upstream_auth = chimera_import_compat.import_module_compat(__package__, ".chimera.upstream_auth", "chimera.upstream_auth")
chimera_policy_templates = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_templates", "chimera.policy_templates")
chimera_policy_records = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_records", "chimera.policy_records")
chimera_policy_governance = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_governance", "chimera.policy_governance")
chimera_env_config_governance = chimera_import_compat.import_module_compat(__package__, ".chimera.env_config_governance", "chimera.env_config_governance")
chimera_env_config_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.env_config_routes", "chimera.env_config_routes")
chimera_policy_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_routes", "chimera.policy_routes")
chimera_rtbf_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.rtbf_routes", "chimera.rtbf_routes")
chimera_governance_events = chimera_import_compat.import_module_compat(__package__, ".chimera.governance_events", "chimera.governance_events")
chimera_model_allowlist = chimera_import_compat.import_module_compat(__package__, ".chimera.model_allowlist", "chimera.model_allowlist")
chimera_redis_json_views = chimera_import_compat.import_module_compat(__package__, ".chimera.redis_json_views", "chimera.redis_json_views")
chimera_redis_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.redis_runtime", "chimera.redis_runtime")
chimera_message_validation = chimera_import_compat.import_module_compat(__package__, ".chimera.message_validation", "chimera.message_validation")
chimera_pagination = chimera_import_compat.import_module_compat(__package__, ".chimera.pagination", "chimera.pagination")
chimera_control_plane_payloads = chimera_import_compat.import_module_compat(__package__, ".chimera.control_plane_payloads", "chimera.control_plane_payloads")
chimera_control_plane_reads = chimera_import_compat.import_module_compat(__package__, ".chimera.control_plane_reads", "chimera.control_plane_reads")
chimera_policy_views = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_views", "chimera.policy_views")
chimera_rtbf_proof_views = chimera_import_compat.import_module_compat(__package__, ".chimera.rtbf_proof_views", "chimera.rtbf_proof_views")
chimera_dashboard_views = chimera_import_compat.import_module_compat(__package__, ".chimera.dashboard_views", "chimera.dashboard_views")
chimera_dashboard_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.dashboard_routes", "chimera.dashboard_routes")
chimera_ledger_verify_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_verify_routes", "chimera.ledger_verify_routes")
chimera_ledger_audit_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_audit_routes", "chimera.ledger_audit_routes")
chimera_admin_security_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.admin_security_routes", "chimera.admin_security_routes")
chimera_runtime_status_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.runtime_status_routes", "chimera.runtime_status_routes")
chimera_admin_misc_routes = chimera_import_compat.import_module_compat(__package__, ".chimera.admin_misc_routes", "chimera.admin_misc_routes")
chimera_threat_intel_store = chimera_import_compat.import_module_compat(__package__, ".chimera.threat_intel_store", "chimera.threat_intel_store")
chimera_dlp_semantic_store = chimera_import_compat.import_module_compat(__package__, ".chimera.dlp_semantic_store", "chimera.dlp_semantic_store")
chimera_auth_identity = chimera_import_compat.import_module_compat(__package__, ".chimera.auth_identity", "chimera.auth_identity")
chimera_tenant_policy_store = chimera_import_compat.import_module_compat(__package__, ".chimera.tenant_policy_store", "chimera.tenant_policy_store")
chimera_drift_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.drift_runtime", "chimera.drift_runtime")
chimera_siem_ir = chimera_import_compat.import_module_compat(__package__, ".chimera.siem_ir", "chimera.siem_ir")
chimera_risk_components = chimera_import_compat.import_module_compat(__package__, ".chimera.risk_components", "chimera.risk_components")
chimera_runtime_health = chimera_import_compat.import_module_compat(__package__, ".chimera.runtime_health", "chimera.runtime_health")
chimera_metrics_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.metrics_runtime", "chimera.metrics_runtime")
chimera_ledger_verify_helpers = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_verify_helpers", "chimera.ledger_verify_helpers")
chimera_risk_decisions = chimera_import_compat.import_module_compat(__package__, ".chimera.risk_decisions", "chimera.risk_decisions")
chimera_apex_engine = chimera_import_compat.import_module_compat(__package__, ".chimera.apex_engine", "chimera.apex_engine")
chimera_signing_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.signing_runtime", "chimera.signing_runtime")
chimera_ledger_s3_sync = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_s3_sync", "chimera.ledger_s3_sync")
chimera_kms_signer = chimera_import_compat.import_module_compat(__package__, ".chimera.kms_signer", "chimera.kms_signer")
chimera_signing_audit = chimera_import_compat.import_module_compat(__package__, ".chimera.signing_audit", "chimera.signing_audit")
chimera_ledger_write = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_write", "chimera.ledger_write")
chimera_ledger_primitives = chimera_import_compat.import_module_compat(__package__, ".chimera.ledger_primitives", "chimera.ledger_primitives")
chimera_content_store = chimera_import_compat.import_module_compat(__package__, ".chimera.content_store", "chimera.content_store")
chimera_secret_provider = chimera_import_compat.import_module_compat(__package__, ".chimera.secret_provider", "chimera.secret_provider")
chimera_streaming_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.streaming_runtime", "chimera.streaming_runtime")
chimera_startup_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.startup_runtime", "chimera.startup_runtime")
chimera_governance_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.governance_runtime", "chimera.governance_runtime")
chimera_control_plane_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.control_plane_runtime", "chimera.control_plane_runtime")
chimera_stream_preflight = chimera_import_compat.import_module_compat(__package__, ".chimera.stream_preflight", "chimera.stream_preflight")
chimera_policy_tool_scoping = chimera_import_compat.import_module_compat(__package__, ".chimera.policy_tool_scoping", "chimera.policy_tool_scoping")
chimera_upstream_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.upstream_runtime", "chimera.upstream_runtime")
chimera_usage_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.usage_runtime", "chimera.usage_runtime")
chimera_idempotency_runtime = chimera_import_compat.import_module_compat(__package__, ".chimera.idempotency_runtime", "chimera.idempotency_runtime")
chimera_input_sanitizer = chimera_import_compat.import_module_compat(__package__, ".chimera.input_sanitizer", "chimera.input_sanitizer")
chimera_failure_taxonomy = chimera_import_compat.import_module_compat(__package__, ".chimera.failure_taxonomy", "chimera.failure_taxonomy")

ALERT_MIN_TONY_SCORE = apex_config.ALERT_MIN_TONY_SCORE
ALERT_WEBHOOK_URL = apex_config.ALERT_WEBHOOK_URL
APEX_AUDIT_HASH_SALT = apex_config.APEX_AUDIT_HASH_SALT
APEX_CHAIN_ID = apex_config.APEX_CHAIN_ID
APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS = apex_config.APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS
APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS = apex_config.APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS
APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS = apex_config.APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS
APEX_COMPLIANCE_MODE = apex_config.APEX_COMPLIANCE_MODE
APEX_COMPLIANCE_REQUIRE_TTLS = apex_config.APEX_COMPLIANCE_REQUIRE_TTLS
APEX_DLP_SEMANTIC_ENABLED = apex_config.APEX_DLP_SEMANTIC_ENABLED
APEX_DLP_SEMANTIC_MAX_EXEMPLARS = apex_config.APEX_DLP_SEMANTIC_MAX_EXEMPLARS
APEX_DRIFT_BACKEND = apex_config.APEX_DRIFT_BACKEND
APEX_EGRESS_ALLOWLIST_REGEX = apex_config.APEX_EGRESS_ALLOWLIST_REGEX
APEX_EGRESS_AUDIT_BLOCKS = apex_config.APEX_EGRESS_AUDIT_BLOCKS
APEX_EGRESS_BLOCK_IP_LITERALS = apex_config.APEX_EGRESS_BLOCK_IP_LITERALS
APEX_FAILSAFE_GOV = apex_config.APEX_FAILSAFE_GOV
APEX_FIPS_MODE = apex_config.APEX_FIPS_MODE
APEX_LEDGER_CAPACITY_FAIL_PCT = apex_config.APEX_LEDGER_CAPACITY_FAIL_PCT
APEX_NO_INTERNET = apex_config.APEX_NO_INTERNET
APEX_REDIS_URL_ENV = apex_config.APEX_REDIS_URL_ENV
APEX_REGION = apex_config.APEX_REGION
APEX_RTBF_PROOF_CACHE_TTL_SECONDS = apex_config.APEX_RTBF_PROOF_CACHE_TTL_SECONDS
APEX_RTBF_S3_ALLOW = apex_config.APEX_RTBF_S3_ALLOW
APEX_RTBF_S3_BUCKET = apex_config.APEX_RTBF_S3_BUCKET
APEX_SIEM_SEND_ALL = apex_config.APEX_SIEM_SEND_ALL
APEX_SIEM_TIMEOUT_SECONDS = apex_config.APEX_SIEM_TIMEOUT_SECONDS
APEX_SIEM_WEBHOOK_HEADERS_JSON = apex_config.APEX_SIEM_WEBHOOK_HEADERS_JSON
APEX_SIEM_WEBHOOK_URL = apex_config.APEX_SIEM_WEBHOOK_URL
APEX_SIGN_AUDIT_ENABLED = apex_config.APEX_SIGN_AUDIT_ENABLED
APEX_SIGN_AUDIT_STREAM_KEY = apex_config.APEX_SIGN_AUDIT_STREAM_KEY
APEX_SIGN_AUDIT_TTL_SECONDS = apex_config.APEX_SIGN_AUDIT_TTL_SECONDS
APEX_SELF_TEST_INTERVAL_SECONDS = apex_config.APEX_SELF_TEST_INTERVAL_SECONDS
APEX_KMS_DUAL_CONTROL = apex_config.APEX_KMS_DUAL_CONTROL
APEX_ALERT_CORRELATION_WINDOW_SECONDS = apex_config.APEX_ALERT_CORRELATION_WINDOW_SECONDS
APEX_EMBEDDING_MODEL = apex_config.APEX_EMBEDDING_MODEL
APEX_UPSTREAM_PROVIDERS_JSON = apex_config.APEX_UPSTREAM_PROVIDERS_JSON
APEX_NEURAL_SAFETY_MODE = apex_config.APEX_NEURAL_SAFETY_MODE
APEX_NEURAL_SAFETY_URL = apex_config.APEX_NEURAL_SAFETY_URL
APEX_NEURAL_SAFETY_TIMEOUT_SECONDS = apex_config.APEX_NEURAL_SAFETY_TIMEOUT_SECONDS
APEX_NEURAL_SAFETY_FAIL_OPEN = apex_config.APEX_NEURAL_SAFETY_FAIL_OPEN
APEX_NEURAL_SAFETY_MIN_CHARS = apex_config.APEX_NEURAL_SAFETY_MIN_CHARS
ENV_CONFIG_SNAPSHOT = apex_config.ENV_CONFIG_SNAPSHOT
EXTERNAL_MODEL_MAP = apex_config.EXTERNAL_MODEL_MAP
GLOBAL_POLICY_TEXT = apex_config.GLOBAL_POLICY_TEXT
HSM_KEY_ID = apex_config.HSM_KEY_ID
INTERNAL_TO_EXTERNAL_MODEL = apex_config.INTERNAL_TO_EXTERNAL_MODEL
JWKS_CACHE_TTL_SECONDS = apex_config.JWKS_CACHE_TTL_SECONDS
KMS_KEY_ID = apex_config.KMS_KEY_ID
KMS_REGION = apex_config.KMS_REGION
LEDGER_CHAIN_ID = apex_config.LEDGER_CHAIN_ID
LEDGER_CHECKPOINT_BUCKET = apex_config.LEDGER_CHECKPOINT_BUCKET
LEDGER_CHECKPOINT_INTERVAL = apex_config.LEDGER_CHECKPOINT_INTERVAL
LEDGER_S3_BUCKET = apex_config.LEDGER_S3_BUCKET
LEDGER_S3_PREFIX = apex_config.LEDGER_S3_PREFIX
MAX_UNSIGNED_QUEUE = apex_config.MAX_UNSIGNED_QUEUE
MODEL_CATALOG = apex_config.MODEL_CATALOG
MODEL_PRICES_USD_PER_1K = apex_config.MODEL_PRICES_USD_PER_1K
OIDC_AUDIENCE = apex_config.OIDC_AUDIENCE
OIDC_ISSUER = apex_config.OIDC_ISSUER
OIDC_TENANT_CLAIM = apex_config.OIDC_TENANT_CLAIM
OPENAI_URL = apex_config.OPENAI_URL
POLICY_VERSION = apex_config.POLICY_VERSION
QDRANT_API_KEY = apex_config.QDRANT_API_KEY
QDRANT_COLLECTION = apex_config.QDRANT_COLLECTION
QDRANT_URL = apex_config.QDRANT_URL
REQUEST_SEM = apex_config.REQUEST_SEM
SIGNING_QUEUE_KEY = apex_config.SIGNING_QUEUE_KEY
UNSIGNED_WARN_FRACTION = apex_config.UNSIGNED_WARN_FRACTION
ApexEnv = apex_config.ApexEnv


def compile_egress_allowlist_patterns() -> List[Pattern[str]]:
    patterns = cast(Any, apex_config.compile_egress_allowlist_patterns)()
    return [cast(Pattern[str], pattern) for pattern in cast(List[Any], patterns)]


egress_check_url: Any = apex_config.egress_check_url
get_apex_env: Any = apex_config.get_apex_env
is_ip_literal_hostname: Any = apex_config.is_ip_literal_hostname
is_likely_public_hostname: Any = apex_config.is_likely_public_hostname
is_prod: Any = apex_config.is_prod
redact_env_value: Any = apex_config.redact_env_value
collect_env_config_snapshot: Any = apex_config.collect_env_config_snapshot
is_sensitive_env_key: Any = apex_config.is_sensitive_env_key
validate_egress_config_or_raise = apex_config.validate_egress_config_or_raise
validate_env_sanity = apex_config.validate_env_sanity
validate_no_internet_posture = apex_config.validate_no_internet_posture


def build_upstream_llm_headers_or_raise(*, api_key: str, endpoint_url: str) -> Dict[str, str]:
    try:
        return chimera_upstream_auth.build_upstream_headers(
            api_key=api_key,
            endpoint_url=endpoint_url,
            is_public_hostname=apex_config.is_likely_public_hostname,
            public_key_required_message="OPENAI_API_KEY is required for public upstream LLM endpoints",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def require_vector_backend_api_key_or_raise(*, api_key: str, endpoint_url: str) -> None:
    chimera_upstream_auth.require_key_for_public_endpoint(
        api_key=api_key,
        endpoint_url=endpoint_url,
        is_public_hostname=apex_config.is_likely_public_hostname,
        failure_message="OPENAI_API_KEY must be set for vector drift backend unless the embeddings endpoint is local",
    )


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

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            pass

    tracer = _NoOpTracer()

    def tracing_available() -> bool:
        return False


SecretProvider = chimera_secret_provider.SecretProvider
secret_provider = chimera_secret_provider.build_secret_provider()

# =========================================================
# 2. REDIS HARDENING, WORKER COORDINATION, LEDGER STORAGE
# =========================================================
chimera_redis_runtime.configure_redis_runtime(
    redis_url_env=APEX_REDIS_URL_ENV,
    get_apex_env_fn=get_apex_env,
    apex_env_prod=ApexEnv.PROD,
)

build_redis_url = chimera_redis_runtime.build_redis_url
get_redis_client = chimera_redis_runtime.get_redis_client
get_worker_id = chimera_redis_runtime.get_worker_id


chimera_ledger_primitives.configure_ledger_primitives(
    signing_queue_key=SIGNING_QUEUE_KEY,
    ledger_checkpoint_bucket=LEDGER_CHECKPOINT_BUCKET,
    decode_required_json_object_fn=chimera_redis_json_views.decode_required_json_object,
)

write_raw_ledger_entry = chimera_ledger_primitives.write_raw_ledger_entry
read_raw_ledger_entry = chimera_ledger_primitives.read_raw_ledger_entry
update_raw_ledger_entry = chimera_ledger_primitives.update_raw_ledger_entry
enqueue_for_signing = chimera_ledger_primitives.enqueue_for_signing
write_checkpoint = chimera_ledger_primitives.write_checkpoint

# =========================================================
# 2b. POLICY STORE, TEMPLATES & TENANT METADATA
# =========================================================

# Policy baseline and template catalogs are hosted in chimera.policy_templates.
FINANCE_SPECIFIC_PATTERNS = chimera_policy_templates.FINANCE_SPECIFIC_PATTERNS
HEALTHCARE_SPECIFIC_PATTERNS = chimera_policy_templates.HEALTHCARE_SPECIFIC_PATTERNS
GOVERNMENT_SPECIFIC_PATTERNS = chimera_policy_templates.GOVERNMENT_SPECIFIC_PATTERNS
DEFAULT_POLICY_BASELINE = chimera_policy_templates.DEFAULT_POLICY_BASELINE
DEFAULT_POLICY_RETENTION = chimera_policy_templates.DEFAULT_POLICY_RETENTION
DEFAULT_POLICY_DATA_MINIMIZATION = chimera_policy_templates.DEFAULT_POLICY_DATA_MINIMIZATION
DEFAULT_POLICY_TOOL_SCOPING = chimera_policy_templates.DEFAULT_POLICY_TOOL_SCOPING
POLICY_TEMPLATE_MAP = chimera_policy_templates.POLICY_TEMPLATE_MAP


def _seed_policy_for_group(policy_group: str) -> Dict[str, Any]:
    return chimera_policy_templates.build_seed_policy_for_group(policy_group)


def _effective_retention_seconds(policy: Dict[str, Any], key: str) -> int:
    """Return an enforceable TTL (seconds) for a governed non-ledger store.

    - Falls back to DEFAULT_POLICY_BASELINE['retention'] if missing/invalid.
    - If APEX_COMPLIANCE_MODE and APEX_COMPLIANCE_REQUIRE_TTLS, ensures TTL > 0.
    - Optionally applies compliance max caps when configured.
    """
    return chimera_retention_policy.effective_retention_seconds(
        policy,
        key,
        baseline_retention=DEFAULT_POLICY_RETENTION,
        compliance_mode=bool(APEX_COMPLIANCE_MODE),
        compliance_require_ttls=bool(APEX_COMPLIANCE_REQUIRE_TTLS),
        max_session_prompts_ttl_seconds=int(APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS or 0),
        max_adversarial_corpus_ttl_seconds=int(APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS or 0),
        max_content_store_ttl_seconds=int(APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS or 0),
    )


def _validate_retention_policy_or_raise(policy: Dict[str, Any]) -> None:
    """Compliance-mode validator for policy retention fields."""
    missing = chimera_retention_policy.missing_required_retention_fields(
        policy,
        compliance_mode=bool(APEX_COMPLIANCE_MODE),
        compliance_require_ttls=bool(APEX_COMPLIANCE_REQUIRE_TTLS),
    )
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Compliance mode: retention TTLs must be > 0 for: {', '.join(missing)}",
        )


chimera_tenant_policy_store.configure_tenant_policy_store(
    policy_version=POLICY_VERSION,
    seed_policy_for_group_fn=_seed_policy_for_group,
    seed_from_template_fields_fn=chimera_policy_records.seed_from_template_fields,
    seed_from_policy_group_fields_fn=chimera_policy_records.seed_from_policy_group_fields,
    effective_retention_seconds_fn=_effective_retention_seconds,
)


PolicyRecord = chimera_tenant_policy_store.PolicyRecord
PolicyStore = chimera_tenant_policy_store.PolicyStore
_policy_retention_seconds = chimera_tenant_policy_store.policy_retention_seconds
TenantMetadata = chimera_tenant_policy_store.TenantMetadata
TenantStore = chimera_tenant_policy_store.TenantStore

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

chimera_kms_signer.configure_kms_signer(
    apex_fips_mode=APEX_FIPS_MODE,
    kms_key_id=KMS_KEY_ID,
    kms_region=KMS_REGION,
    get_apex_env_fn=get_apex_env,
    apex_env_prod=ApexEnv.PROD,
)

chimera_signing_audit.configure_signing_audit(
    apex_kms_dual_control=APEX_KMS_DUAL_CONTROL,
    apex_fips_mode=APEX_FIPS_MODE,
    kms_key_id=KMS_KEY_ID,
    get_apex_env_fn=get_apex_env,
    apex_env_prod=ApexEnv.PROD,
    apex_sign_audit_enabled=APEX_SIGN_AUDIT_ENABLED,
    apex_sign_audit_stream_key=APEX_SIGN_AUDIT_STREAM_KEY,
    apex_sign_audit_ttl_seconds=APEX_SIGN_AUDIT_TTL_SECONDS,
    apex_region=APEX_REGION,
    apex_chain_id=APEX_CHAIN_ID,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
    envcfg_desired_current_key_fn=chimera_env_config_governance.envcfg_desired_current_key,
    decode_required_json_object_fn=chimera_redis_json_views.decode_required_json_object,
    clamp_limit_fn=chimera_pagination.clamp_limit,
)

_enforce_kms_dual_control_or_raise = chimera_signing_audit.enforce_kms_dual_control_or_raise
_emit_signing_access_log = chimera_signing_audit.emit_signing_access_log
_read_signing_audit_stream = chimera_signing_audit.read_signing_audit_stream


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


compute_merkle_root_hex = chimera_kms_signer.compute_merkle_root_hex
compute_merkle_inclusion_proof_hex = chimera_kms_signer.compute_merkle_inclusion_proof_hex
get_signer_public_key_b64 = chimera_kms_signer.get_signer_public_key_b64


chimera_content_store.configure_content_store(
    apex_content_ttl_seconds=APEX_CONTENT_TTL_SECONDS,
    sha256_hex_fn=_sha256_hex,
)

_store_deduped_content = chimera_content_store.store_deduped_content


# =========================================================
# 3a. THREAT INTELLIGENCE (PUSH INGESTION, MINIMAL)
# =========================================================

_threat_intel_rules_key = chimera_threat_intel_store._threat_intel_rules_key
_threat_intel_versions_key = chimera_threat_intel_store._threat_intel_versions_key
_threat_intel_meta_key = chimera_threat_intel_store._threat_intel_meta_key
_severity_weight = chimera_threat_intel_store._severity_weight
ThreatIntelRule = chimera_threat_intel_store.ThreatIntelRule
ThreatIntelIngestRequest = chimera_threat_intel_store.ThreatIntelIngestRequest
ThreatIntelActivateRequest = chimera_threat_intel_store.ThreatIntelActivateRequest
ThreatIntelStore = chimera_threat_intel_store.ThreatIntelStore


# =========================================================
# 3b. SEMANTIC DLP (OPTION B: EXEMPLAR SIMILARITY)
# =========================================================

_dlp_semantic_items_key = chimera_dlp_semantic_store._dlp_semantic_items_key
_dlp_semantic_meta_key = chimera_dlp_semantic_store._dlp_semantic_meta_key
DlpSemanticExemplar = chimera_dlp_semantic_store.DlpSemanticExemplar
DlpSemanticIngestRequest = chimera_dlp_semantic_store.DlpSemanticIngestRequest
DlpSemanticStore = chimera_dlp_semantic_store.DlpSemanticStore
score_semantic_dlp = chimera_dlp_semantic_store.score_semantic_dlp


Signer = chimera_kms_signer.Signer
KmsEcdsaSigner = chimera_kms_signer.KmsEcdsaSigner
SoftEcdsaSigner = chimera_kms_signer.SoftEcdsaSigner
load_signer_for_worker = chimera_kms_signer.load_signer_for_worker
compute_entry_hash = chimera_kms_signer.compute_entry_hash


chimera_ledger_write.configure_ledger_write(
    apex_audit_hash_salt=APEX_AUDIT_HASH_SALT,
    apex_region=APEX_REGION,
    apex_chain_id=APEX_CHAIN_ID,
    ledger_chain_id=LEDGER_CHAIN_ID,
    kms_key_id=KMS_KEY_ID,
    policy_version=POLICY_VERSION,
    max_unsigned_queue=MAX_UNSIGNED_QUEUE,
    unsigned_warn_fraction=UNSIGNED_WARN_FRACTION,
    signing_queue_key=SIGNING_QUEUE_KEY,
    ledger_checkpoint_interval=LEDGER_CHECKPOINT_INTERVAL,
    apex_enable_merkle_checkpoints=APEX_ENABLE_MERKLE_CHECKPOINTS,
    apex_sign_checkpoints=APEX_SIGN_CHECKPOINTS,
    apex_enable_anchor_entries=APEX_ENABLE_ANCHOR_ENTRIES,
    default_policy_baseline=DEFAULT_POLICY_BASELINE,
    get_apex_env_fn=get_apex_env,
    policy_store_factory=PolicyStore,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
    compute_entry_hash_fn=compute_entry_hash,
    compute_merkle_root_hex_fn=compute_merkle_root_hex,
    load_signer_for_worker_fn=load_signer_for_worker,
    decode_required_json_object_fn=chimera_redis_json_views.decode_required_json_object,
    extract_entry_hash_leaves_fn=chimera_redis_json_views.extract_entry_hash_leaves,
    enqueue_for_signing_fn=enqueue_for_signing,
    write_checkpoint_fn=write_checkpoint,
)

LedgerBackpressureError = chimera_ledger_write.LedgerBackpressureError
_get_data_minimization = chimera_ledger_write.get_data_minimization
_no_content_retention_enabled = chimera_ledger_write.no_content_retention_enabled
_apply_audit_minimization_to_payload = chimera_ledger_write.apply_audit_minimization_to_payload
_get_cached_tenant_minimization = chimera_ledger_write.get_cached_tenant_minimization
get_unsigned_backlog_status = chimera_ledger_write.get_unsigned_backlog_status
create_unsigned_ledger_entry = chimera_ledger_write.create_unsigned_ledger_entry







chimera_ledger_s3_sync.configure_ledger_s3_sync(
    ledger_s3_bucket=LEDGER_S3_BUCKET,
    ledger_s3_prefix=LEDGER_S3_PREFIX,
    apex_region=APEX_REGION,
    get_redis_client_fn=get_redis_client,
    decode_single_json_skip_invalid_fn=chimera_redis_json_views.decode_single_json_skip_invalid,
)

upload_to_s3 = chimera_ledger_s3_sync.upload_to_s3
s3_ledger_sync_loop = chimera_ledger_s3_sync.s3_ledger_sync_loop


# =========================================================
# 4a. GOVERNMENT-GRADE HEALTH (FAIL-SAFE) & SELF-TEST
# =========================================================

chimera_runtime_health.configure_runtime_health(
    get_redis_client_fn=get_redis_client,
    policy_store_factory=PolicyStore,
    seed_policy_for_group_fn=_seed_policy_for_group,
    policy_retention_seconds_fn=_policy_retention_seconds,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
    apex_self_test_interval_seconds=APEX_SELF_TEST_INTERVAL_SECONDS,
    apex_failsafe_gov=APEX_FAILSAFE_GOV,
    apex_ledger_capacity_fail_pct=APEX_LEDGER_CAPACITY_FAIL_PCT,
)

SIGNER_HEALTH = chimera_runtime_health.SIGNER_HEALTH
SELF_TEST = chimera_runtime_health.SELF_TEST
_periodic_self_test_loop = chimera_runtime_health.periodic_self_test_loop
_retention_enforcer_loop = chimera_runtime_health.retention_enforcer_loop
_enforce_failsafe_or_raise = chimera_runtime_health.enforce_failsafe_or_raise

chimera_signing_runtime.configure_signing_runtime(
    load_signer_for_worker_fn=load_signer_for_worker,
    signer_health=SIGNER_HEALTH,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
    get_redis_client_fn=get_redis_client,
    signing_queue_key=SIGNING_QUEUE_KEY,
    read_raw_ledger_entry_fn=read_raw_ledger_entry,
    update_raw_ledger_entry_fn=update_raw_ledger_entry,
    compute_entry_hash_fn=compute_entry_hash,
    enforce_kms_dual_control_or_raise_fn=_enforce_kms_dual_control_or_raise,
    emit_signing_access_log_fn=_emit_signing_access_log,
    enqueue_for_signing_fn=enqueue_for_signing,
)

signing_worker_loop = chimera_signing_runtime.signing_worker_loop

# =========================================================
# 4. CIRCUIT BREAKERS (HALF-OPEN) FOR LLM & EMBEDDINGS
# =========================================================

CircuitState = chimera_drift_runtime.CircuitState
HalfOpenCircuitBreaker = chimera_drift_runtime.HalfOpenCircuitBreaker
LLM_CIRCUIT = chimera_drift_runtime.LLM_CIRCUIT
EMBEDDER_CIRCUIT = chimera_drift_runtime.EMBEDDER_CIRCUIT

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


chimera_threat_intel_store.configure_threat_intel_store(
    normalize_for_security=normalize_for_security,
)


def redact_pii(text: str, patterns: List[str]) -> str:
    """
    Regex-based PII redaction. This is intentionally conservative and can over-redact.
    """
    redacted = text
    for pat in patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


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
    allowed, reason, details = egress_check_url(url)
    if allowed:
        return

    raise HTTPException(
        status_code=403,
        detail={
            "message": "Sovereign egress policy blocked outbound request",
            "purpose": purpose,
            "url": url,
            "reason": reason,
            "details": details,
        },
    )


chimera_drift_runtime.configure_drift_runtime(
    apex_embedding_model=APEX_EMBEDDING_MODEL,
    openai_base_url=apex_config.OPENAI_BASE_URL,
    global_policy_text=GLOBAL_POLICY_TEXT,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
)

DriftBackend = chimera_drift_runtime.DriftBackend
EmbeddingProvider = chimera_drift_runtime.EmbeddingProvider
OpenAIEmbeddingProvider = chimera_drift_runtime.OpenAIEmbeddingProvider


chimera_dlp_semantic_store.configure_dlp_semantic_store(
    secret_provider=secret_provider,
    openai_embedding_provider_cls=OpenAIEmbeddingProvider,
    embedding_model=APEX_EMBEDDING_MODEL,
    dlp_semantic_enabled=APEX_DLP_SEMANTIC_ENABLED,
    dlp_semantic_max_exemplars=APEX_DLP_SEMANTIC_MAX_EXEMPLARS,
    store_deduped_content_fn=_store_deduped_content,
    severity_weight_fn=_severity_weight,
    clamp01_fn=clamp01,
)


VectorIndex = chimera_drift_runtime.VectorIndex
QdrantIndex = chimera_drift_runtime.QdrantIndex
RedisBowDriftBackend = chimera_drift_runtime.RedisBowDriftBackend
VectorDbDriftBackend = chimera_drift_runtime.VectorDbDriftBackend


DRIFT_BACKEND: Optional[DriftBackend] = None

# =========================================================
# 5b. ALERTING & XAI EXPLANATIONS
# =========================================================
chimera_risk_decisions.configure_risk_decisions(
    default_policy_baseline=DEFAULT_POLICY_BASELINE,
)

BlockExplanation = chimera_risk_decisions.BlockExplanation
explain_block = chimera_risk_decisions.explain_block
evaluate_risk = chimera_risk_decisions.evaluate_risk


chimera_siem_ir.configure_siem_ir(
    alert_webhook_url=ALERT_WEBHOOK_URL,
    apex_siem_webhook_url=APEX_SIEM_WEBHOOK_URL,
    apex_siem_send_all=APEX_SIEM_SEND_ALL,
    alert_min_tony_score=ALERT_MIN_TONY_SCORE,
    apex_siem_timeout_seconds=float(APEX_SIEM_TIMEOUT_SECONDS or 5.0),
    apex_siem_webhook_headers_json=APEX_SIEM_WEBHOOK_HEADERS_JSON,
    apex_alert_correlation_window_seconds=int(APEX_ALERT_CORRELATION_WINDOW_SECONDS or 900),
    apex_region=APEX_REGION,
    apex_chain_id=APEX_CHAIN_ID,
    get_apex_env_fn=get_apex_env,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
    sha256_hex_fn=_sha256_hex,
    enforce_sovereign_egress_or_raise_fn=enforce_sovereign_egress_or_raise,
)

send_alert_if_needed = chimera_siem_ir.send_alert_if_needed


# =========================================================
# 5c. SIEM INTEGRATION, SEVERITY, INCIDENT CORRELATION, RUNBOOKS
# =========================================================

Severity = chimera_siem_ir.Severity
_classify_severity = chimera_siem_ir.classify_severity
IR_TIMELINES_DEFAULT = chimera_siem_ir.IR_TIMELINES_DEFAULT
_ir_timelines = chimera_siem_ir.ir_timelines
_incident_active_key = chimera_siem_ir.incident_active_key
_incident_record_key = chimera_siem_ir.incident_record_key
RUNBOOKS = chimera_siem_ir.RUNBOOKS
enrich_and_send_siem_event = chimera_siem_ir.enrich_and_send_siem_event

# =========================================================
# 5b. NEURAL SAFETY LAYER (SEMANTIC UPGRADE)
# =========================================================

chimera_risk_components.configure_risk_components(
    normalize_for_security_fn=normalize_for_security,
    clamp01_fn=clamp01,
    neural_safety_mode=APEX_NEURAL_SAFETY_MODE,
    neural_safety_url=APEX_NEURAL_SAFETY_URL,
    neural_safety_timeout_seconds=APEX_NEURAL_SAFETY_TIMEOUT_SECONDS,
    neural_safety_fail_open=APEX_NEURAL_SAFETY_FAIL_OPEN,
    neural_safety_min_chars=APEX_NEURAL_SAFETY_MIN_CHARS,
)

NeuralSafetyClassifier = chimera_risk_components.NeuralSafetyClassifier
HighRiskContentClassifier = chimera_risk_components.HighRiskContentClassifier

# =========================================================
# 5c. APEX ENGINE – RISK COMPUTATION & GOVERNANCE DECISION
# =========================================================

# -- Minimal runtime stubs for missing components (safe defaults) --
# These are intentionally lightweight placeholders so the module can be
# imported and basic flows exercised without the full production implementations.
MERKLE_BATCH_SIZE = chimera_risk_components.MERKLE_BATCH_SIZE
UserRiskProfile = chimera_risk_components.UserRiskProfile
UserRiskStore = chimera_risk_components.UserRiskStore
FastRiskClassifier = chimera_risk_components.FastRiskClassifier
MerkleBatch = chimera_risk_components.MerkleBatch

chimera_apex_engine.configure_apex_engine(
    policy_store_factory=PolicyStore,
    user_risk_store_factory=UserRiskStore,
    fast_risk_classifier_cls=FastRiskClassifier,
    neural_safety_classifier_cls=NeuralSafetyClassifier,
    high_risk_content_classifier_cls=HighRiskContentClassifier,
    redis_bow_backend_cls=RedisBowDriftBackend,
    merkle_batch_cls=MerkleBatch,
    merkle_batch_size=MERKLE_BATCH_SIZE,
    threat_intel_store_factory=ThreatIntelStore,
    score_semantic_dlp_fn=score_semantic_dlp,
    normalize_for_security_fn=normalize_for_security,
    clamp01_fn=clamp01,
    default_policy_baseline=DEFAULT_POLICY_BASELINE,
    seed_policy_for_group_fn=_seed_policy_for_group,
    no_content_retention_enabled_fn=_no_content_retention_enabled,
    policy_retention_seconds_fn=_policy_retention_seconds,
    store_deduped_content_fn=_store_deduped_content,
    apex_content_dedup=APEX_CONTENT_DEDUP,
    utc_now_z_fn=chimera_policy_records.utc_now_z,
)

ApexSovereignEngine = chimera_apex_engine.ApexSovereignEngine

# =========================================================
# 6. OIDC / JWKS + AUTHORIZATION ENGINE (RBAC)
# =========================================================

JwksCache = chimera_auth_identity.JwksCache
TenantIdentity = chimera_auth_identity.TenantIdentity
IdpVerifier = chimera_auth_identity.IdpVerifier
AuthorizationDecision = chimera_auth_identity.AuthorizationDecision
AuthorizationResult = chimera_auth_identity.AuthorizationResult
AuthorizationEngine = chimera_auth_identity.AuthorizationEngine

jwks_cache, idp_verifier, authz_engine = chimera_auth_identity.create_auth_components(
    oidc_issuer=OIDC_ISSUER,
    jwks_cache_ttl_seconds=JWKS_CACHE_TTL_SECONDS,
    oidc_audience=OIDC_AUDIENCE,
    oidc_tenant_claim=OIDC_TENANT_CLAIM,
)

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
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Any] = None


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
    return chimera_message_validation.validate_text_only_messages(messages)


app = FastAPI()

IdempotencyBoundary = chimera_idempotency_runtime.IdempotencyBoundary
IDEMPOTENCY_BOUNDARY = IdempotencyBoundary()
SAFETY_GUARD = chimera_input_sanitizer.SafetyGuard()


async def get_identity(
    authorization: str = Header(alias="Authorization"),
    x_tenant_id: str = Header(default=""),
) -> TenantIdentity:
    return await idp_verifier.verify(authorization, x_tenant_id)


chimera_runtime_status_routes.register_runtime_status_routes(
    app,
    authz_engine=authz_engine,
    get_identity=get_identity,
    get_redis_client=get_redis_client,
    utc_now_z=chimera_policy_records.utc_now_z,
    ir_timelines_fn=_ir_timelines,
    runbooks=RUNBOOKS,
    incident_record_key=_incident_record_key,
    decode_optional_json_with_raw_fallback=chimera_redis_json_views.decode_optional_json_with_raw_fallback,
    get_apex_env=get_apex_env,
    apex_env_prod=ApexEnv.PROD,
    tracing_available=tracing_available,
    apex_fips_mode=APEX_FIPS_MODE,
    apex_region=APEX_REGION,
    apex_chain_id=APEX_CHAIN_ID,
    signer_health=SIGNER_HEALTH,
    self_test=SELF_TEST,
    enforce_failsafe_or_raise=_enforce_failsafe_or_raise,
    enforce_kms_dual_control_or_raise=_enforce_kms_dual_control_or_raise,
    load_signer_for_worker=load_signer_for_worker,
    get_unsigned_backlog_status=get_unsigned_backlog_status,
    max_unsigned_queue=MAX_UNSIGNED_QUEUE,
    unsigned_warn_fraction=UNSIGNED_WARN_FRACTION,
    ledger_backlog_state_label=chimera_control_plane_payloads.ledger_backlog_state_label,
)


@app.on_event("startup")
async def on_startup():
    """
    Startup hook:
    - Enforce tracing in PROD
    - Initialize Redis
    - Configure drift backend (Redis Bow or Qdrant + embeddings)
    """
    global DRIFT_BACKEND
    DRIFT_BACKEND = await chimera_startup_runtime.initialize_runtime_on_startup(
        get_apex_env_fn=get_apex_env,
        apex_env_prod=ApexEnv.PROD,
        tracing_available_fn=tracing_available,
        periodic_self_test_loop_fn=_periodic_self_test_loop,
        retention_enforcer_loop_fn=_retention_enforcer_loop,
        get_redis_client_fn=get_redis_client,
        apex_drift_backend=APEX_DRIFT_BACKEND,
        require_vector_backend_api_key_or_raise_fn=require_vector_backend_api_key_or_raise,
        openai_base_url=apex_config.OPENAI_BASE_URL,
        openai_embedding_model=APEX_EMBEDDING_MODEL,
        openai_embedding_provider_cls=OpenAIEmbeddingProvider,
        qdrant_index_cls=QdrantIndex,
        vector_db_drift_backend_cls=VectorDbDriftBackend,
        redis_bow_drift_backend_cls=RedisBowDriftBackend,
        qdrant_url=QDRANT_URL,
        qdrant_api_key=QDRANT_API_KEY,
        qdrant_collection=QDRANT_COLLECTION,
    )


STREAM_WINDOW = 128
UPSTREAM_PROVIDER_POOL = chimera_upstream_runtime.parse_upstream_provider_pool(
    providers_json=APEX_UPSTREAM_PROVIDERS_JSON,
    default_url=OPENAI_URL,
)

# =========================================================
# 7b. METRICS HELPERS (ROLLING 24H)
# =========================================================
chimera_metrics_runtime.configure_metrics_runtime(
    alert_min_tony_score=ALERT_MIN_TONY_SCORE,
)

_metrics_hour_key = chimera_metrics_runtime.metrics_hour_key
_metrics_total_key = chimera_metrics_runtime.metrics_total_key
_metrics_blocked_key = chimera_metrics_runtime.metrics_blocked_key
_metrics_highrisk_key = chimera_metrics_runtime.metrics_highrisk_key
_metrics_axis_hash_key = chimera_metrics_runtime.metrics_axis_hash_key
record_metrics_for_audit = chimera_metrics_runtime.record_metrics_for_audit

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
    request_id = str(http_request.headers.get("x-request-id") or "").strip() or str(uuid.uuid4())

    loop = asyncio.get_running_loop()
    idem_state, idem_cached, idem_inflight = IDEMPOTENCY_BOUNDARY.acquire_or_get(
        session_id=session_id,
        request_id=request_id,
        loop=loop,
    )

    async def _single_payload_stream(payload: Any):
        if isinstance(payload, bytes):
            yield payload
            return
        yield str(payload or "").encode("utf-8")

    if idem_state == "cached":
        return StreamingResponse(_single_payload_stream(idem_cached), media_type="text/plain")

    if idem_state == "inflight" and idem_inflight is not None:
        try:
            inflight_result = await idem_inflight
            return StreamingResponse(_single_payload_stream(inflight_result), media_type="text/plain")
        except Exception as exc:
            failure = chimera_failure_taxonomy.classify_failure(exc)
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "In-flight duplicate request failed",
                    "request_id": request_id,
                    "failure": failure,
                },
            )

    r = await get_redis_client()
    await _enforce_failsafe_or_raise(r)
    engine = ApexSovereignEngine(r_client=r, drift_backend=DRIFT_BACKEND)

    preflight = await chimera_stream_preflight.run_stream_preflight(
        request_obj=request,
        http_request=http_request,
        identity=identity,
        tenant_id=tenant_id,
        session_id=session_id,
        r=r,
        engine=engine,
        request_audit_context_fn=_request_audit_context,
        seed_policy_for_group_fn=_seed_policy_for_group,
        validate_text_only_messages_fn=_validate_text_only_messages,
        external_model_map=EXTERNAL_MODEL_MAP,
        policy_version=POLICY_VERSION,
        apex_region=APEX_REGION,
        apex_chain_id=APEX_CHAIN_ID,
        utc_now_z_fn=chimera_policy_records.utc_now_z,
        create_unsigned_ledger_entry_fn=create_unsigned_ledger_entry,
        record_metrics_for_audit_fn=record_metrics_for_audit,
        ledger_backpressure_error_cls=LedgerBackpressureError,
        model_allowlist=chimera_model_allowlist,
        authz_engine=authz_engine,
        authorization_decision_allow=AuthorizationDecision.ALLOW,
        no_content_retention_enabled_fn=_no_content_retention_enabled,
        policy_retention_seconds_fn=_policy_retention_seconds,
        vector_db_drift_backend_cls=VectorDbDriftBackend,
        get_tool_scoping_fn=chimera_policy_tool_scoping.get_tool_scoping,
        filter_tools_for_policy_fn=chimera_policy_tool_scoping.filter_tools_for_policy,
        default_policy_tool_scoping=DEFAULT_POLICY_TOOL_SCOPING,
        sanitize_messages_fn=chimera_input_sanitizer.sanitize_messages,
        safety_guard=SAFETY_GUARD,
        classify_failure_fn=chimera_failure_taxonomy.classify_failure,
    )

    audit_ctx = preflight["audit_ctx"]
    if not audit_ctx.get("request_id"):
        audit_ctx["request_id"] = request_id
    model_params = preflight["model_params"]
    policy = preflight["policy"]
    internal_model = preflight["internal_model"]
    tool_filter = preflight.get("tool_filter") or {}
    if int(tool_filter.get("provided") or 0) > 0:
        audit_ctx["tool_filter"] = tool_filter

    source_stream_generator = chimera_streaming_runtime.stream_llm_with_risk(
        request_obj=request,
        tenant_id=tenant_id,
        session_id=session_id,
        identity=identity,
        r=r,
        engine=engine,
        policy=policy,
        model_params=model_params,
        internal_model=internal_model,
        audit_ctx=audit_ctx,
        request_sem=REQUEST_SEM,
        llm_circuit=LLM_CIRCUIT,
        tracer=tracer,
        openai_url=OPENAI_URL,
        upstream_provider_pool=UPSTREAM_PROVIDER_POOL,
        internal_to_external_model=INTERNAL_TO_EXTERNAL_MODEL,
        model_prices_usd_per_1k=MODEL_PRICES_USD_PER_1K,
        default_policy_baseline=DEFAULT_POLICY_BASELINE,
        stream_window=STREAM_WINDOW,
        apex_region=APEX_REGION,
        apex_chain_id=APEX_CHAIN_ID,
        policy_version=POLICY_VERSION,
        enforce_sovereign_egress_or_raise_fn=enforce_sovereign_egress_or_raise,
        secret_provider=secret_provider,
        build_upstream_llm_headers_or_raise_fn=build_upstream_llm_headers_or_raise,
        decode_required_json_object_fn=chimera_redis_json_views.decode_required_json_object,
        evaluate_risk_fn=evaluate_risk,
        explain_block_fn=explain_block,
        create_unsigned_ledger_entry_fn=create_unsigned_ledger_entry,
        record_metrics_for_audit_fn=record_metrics_for_audit,
        send_alert_if_needed_fn=send_alert_if_needed,
        utc_now_z_fn=chimera_policy_records.utc_now_z,
        ledger_backpressure_error_cls=LedgerBackpressureError,
        redact_pii_fn=redact_pii,
        select_provider_order_fn=chimera_upstream_runtime.select_provider_order,
        build_provider_headers_fn=chimera_upstream_runtime.build_provider_headers,
        get_usage_quotas_fn=chimera_usage_runtime.get_usage_quotas,
        estimate_messages_tokens_fn=chimera_usage_runtime.estimate_messages_tokens,
        estimate_text_tokens_fn=chimera_usage_runtime.estimate_text_tokens,
        reserve_usage_or_raise_fn=chimera_usage_runtime.reserve_usage_or_raise,
        add_completion_usage_fn=chimera_usage_runtime.add_completion_usage,
        estimate_cost_usd_fn=chimera_usage_runtime.estimate_cost_usd,
        classify_failure_fn=chimera_failure_taxonomy.classify_failure,
    )

    if idem_state == "acquired":
        async def _idempotent_stream_wrapper():
            chunks: List[str] = []
            try:
                async for chunk in source_stream_generator:
                    if isinstance(chunk, bytes):
                        text_chunk = chunk.decode("utf-8", errors="ignore")
                        chunks.append(text_chunk)
                        yield chunk
                    else:
                        text_chunk = str(chunk or "")
                        chunks.append(text_chunk)
                        yield text_chunk.encode("utf-8")
                IDEMPOTENCY_BOUNDARY.store_result(
                    session_id=session_id,
                    request_id=request_id,
                    result="".join(chunks),
                )
            except Exception as exc:
                IDEMPOTENCY_BOUNDARY.store_error(
                    session_id=session_id,
                    request_id=request_id,
                    error=exc,
                )
                raise

        stream_generator = _idempotent_stream_wrapper()
    else:
        stream_generator = source_stream_generator

    with tracer.start_as_current_span("apex.stream.request") as span:
        span.set_attribute("tenant.id", identity.tenant_id)
        span.set_attribute("session.id", x_session_id)
        span.set_attribute("model.internal", request.model)
        span.set_attribute("auth.subject", identity.subject)
        return StreamingResponse(stream_generator, media_type="text/plain")


@app.get("/api/v1/runtime/idempotency")
async def runtime_idempotency_status(
    identity: TenantIdentity = Depends(get_identity),
    max_keys: int = 50,
    session_id: Optional[str] = None,
):
    if "admin" not in list(identity.roles or []):
        raise HTTPException(status_code=403, detail="Access denied: admin role required")
    return IDEMPOTENCY_BOUNDARY.snapshot_for_tenant(
        tenant_id=identity.tenant_id,
        max_keys=max_keys,
        session_id_filter=session_id,
    )

# =========================================================
# 7d. ADMIN / MANAGEMENT API – GOVERNANCE CONTROL PLANE
# =========================================================

async def _best_effort_governance_ledger_event(
    r: redis.Redis,
    tenant_id: str,
    actor: str,
    event_type: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    await chimera_governance_runtime.best_effort_governance_ledger_event(
        r,
        tenant_id=tenant_id,
        actor=actor,
        event_type=event_type,
        extra=extra,
        region=APEX_REGION,
        chain_id=APEX_CHAIN_ID,
        build_governance_event_payload_fn=chimera_governance_events.build_governance_event_payload,
        create_unsigned_ledger_entry_fn=create_unsigned_ledger_entry,
        ledger_backpressure_error_cls=LedgerBackpressureError,
    )


chimera_control_plane_runtime.register_control_plane_routes(
    app=app,
    authz_engine=authz_engine,
    get_identity=get_identity,
    get_redis_client=get_redis_client,
    threat_intel_store_factory=ThreatIntelStore,
    create_unsigned_ledger_entry=create_unsigned_ledger_entry,
    ledger_backpressure_error_cls=LedgerBackpressureError,
    control_plane_payloads=chimera_control_plane_payloads,
    policy_records=chimera_policy_records,
    region=APEX_REGION,
    chain_id=APEX_CHAIN_ID,
    control_plane_reads=chimera_control_plane_reads,
    read_signing_audit_stream=_read_signing_audit_stream,
    get_apex_env=get_apex_env,
    sign_audit_enabled=APEX_SIGN_AUDIT_ENABLED,
    sign_audit_stream_key=APEX_SIGN_AUDIT_STREAM_KEY,
    sign_audit_ttl_seconds=APEX_SIGN_AUDIT_TTL_SECONDS,
    threat_intel_versions_key=_threat_intel_versions_key,
    dlp_semantic_store_factory=DlpSemanticStore,
    policy_store_factory=PolicyStore,
    seed_policy_for_group=_seed_policy_for_group,
    no_content_retention_enabled=_no_content_retention_enabled,
    policy_retention_seconds=_policy_retention_seconds,
    dlp_semantic_enabled=APEX_DLP_SEMANTIC_ENABLED,
    embedding_model=APEX_EMBEDDING_MODEL,
    dlp_semantic_max_exemplars=APEX_DLP_SEMANTIC_MAX_EXEMPLARS,
    load_signer_for_worker=load_signer_for_worker,
    signer_health=SIGNER_HEALTH,
    two_person_policy=APEX_TWO_PERSON_POLICY,
    policy_version=POLICY_VERSION,
    policy_record_cls=PolicyRecord,
    policy_governance=chimera_policy_governance,
    policy_views=chimera_policy_views,
    model_allowlist=chimera_model_allowlist,
    external_model_map=EXTERNAL_MODEL_MAP,
    model_catalog=MODEL_CATALOG,
    validate_retention_policy_or_raise=_validate_retention_policy_or_raise,
    effective_retention_seconds=_effective_retention_seconds,
    compliance_mode=APEX_COMPLIANCE_MODE,
    compliance_require_ttls=APEX_COMPLIANCE_REQUIRE_TTLS,
    max_session_prompts_ttl_seconds=APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS,
    max_adversarial_corpus_ttl_seconds=APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS,
    max_content_store_ttl_seconds=APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS,
    best_effort_governance_ledger_event=_best_effort_governance_ledger_event,
    runtime_snapshot=ENV_CONFIG_SNAPSHOT,
    is_sensitive_env_key=is_sensitive_env_key,
    redact_env_value=redact_env_value,
    tenant_store_factory=TenantStore,
    drift_engine_factory=ApexSovereignEngine,
    drift_backend=DRIFT_BACKEND,
    vector_backend_cls=VectorDbDriftBackend,
    redis_bow_backend_cls=RedisBowDriftBackend,
    get_rtbf_proof_payload=chimera_rtbf_proof_views.get_rtbf_proof_payload,
    record_metrics_for_audit=record_metrics_for_audit,
    utc_now_z=chimera_policy_records.utc_now_z,
    dlp_items_key=_dlp_semantic_items_key,
    dlp_meta_key=_dlp_semantic_meta_key,
    rtbf_s3_allow=APEX_RTBF_S3_ALLOW,
    rtbf_s3_bucket=APEX_RTBF_S3_BUCKET,
    ledger_s3_bucket=LEDGER_S3_BUCKET,
    ledger_checkpoint_bucket=LEDGER_CHECKPOINT_BUCKET,
    rtbf_proof_cache_ttl_seconds=APEX_RTBF_PROOF_CACHE_TTL_SECONDS,
    ledger_verify_helpers=chimera_ledger_verify_helpers,
    decode_single_json_skip_invalid=chimera_redis_json_views.decode_single_json_skip_invalid,
    decode_optional_json_object_or_default=chimera_redis_json_views.decode_optional_json_object_or_default,
    decode_required_json_object=chimera_redis_json_views.decode_required_json_object,
    compute_entry_hash=compute_entry_hash,
    dashboard_routes=chimera_dashboard_routes,
    egress_check_url=egress_check_url,
    compile_egress_allowlist_patterns=compile_egress_allowlist_patterns,
    block_ip_literals=APEX_EGRESS_BLOCK_IP_LITERALS,
    allowlist_regex=APEX_EGRESS_ALLOWLIST_REGEX,
    audit_blocks=APEX_EGRESS_AUDIT_BLOCKS,
    dashboard_views=chimera_dashboard_views,
    retention_payload_builder=chimera_control_plane_payloads.effective_retention_view,
    dlp_embedding_model=APEX_EMBEDDING_MODEL,
    dlp_max_exemplars=APEX_DLP_SEMANTIC_MAX_EXEMPLARS,
    ledger_audit_routes=chimera_ledger_audit_routes,
    ledger_verify_routes=chimera_ledger_verify_routes,
    read_raw_ledger_entry=read_raw_ledger_entry,
    extract_entry_hash_leaves=chimera_redis_json_views.extract_entry_hash_leaves,
    compute_merkle_root_hex=compute_merkle_root_hex,
    compute_merkle_inclusion_proof_hex=compute_merkle_inclusion_proof_hex,
    get_signer_public_key_b64=get_signer_public_key_b64,
    verify_scan_limit=APEX_VERIFY_SCAN_LIMIT,
    anchor_search_limit=APEX_ANCHOR_SEARCH_LIMIT,
    policy_routes=chimera_policy_routes,
    env_config_routes=chimera_env_config_routes,
    admin_misc_routes=chimera_admin_misc_routes,
    rtbf_routes=chimera_rtbf_routes,
    admin_security_routes=chimera_admin_security_routes,
    metrics_hour_key=_metrics_hour_key,
    metrics_total_key=_metrics_total_key,
    metrics_blocked_key=_metrics_blocked_key,
    metrics_highrisk_key=_metrics_highrisk_key,
    metrics_axis_hash_key=_metrics_axis_hash_key,
    max_unsigned_queue=MAX_UNSIGNED_QUEUE,
    get_unsigned_backlog_status=get_unsigned_backlog_status,
    fips_mode=APEX_FIPS_MODE,
)

verify_ledger_chain_from_redis = chimera_ledger_verify_helpers.verify_ledger_chain_from_redis
verify_ledger_from_s3 = chimera_ledger_verify_helpers.verify_ledger_from_s3


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
