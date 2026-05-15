"""Apex Sovereign runtime configuration and startup validation helpers.

This module holds the env-driven configuration contract so the main service
module can focus on runtime behavior rather than startup wiring.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


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
APEX_COMPLIANCE_REQUIRE_TTLS = os.getenv("APEX_COMPLIANCE_REQUIRE_TTLS", "true").lower() == "true"
APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_SESSION_PROMPTS_TTL_SECONDS", "0"))
APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_ADVERSARIAL_CORPUS_TTL_SECONDS", "0"))
APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS = int(os.getenv("APEX_COMPLIANCE_MAX_CONTENT_STORE_TTL_SECONDS", "0"))

# RTBF (Right-to-be-forgotten) operational controls
APEX_RTBF_PROOF_CACHE_TTL_SECONDS = int(os.getenv("APEX_RTBF_PROOF_CACHE_TTL_SECONDS", str(30 * 24 * 3600)))
APEX_RTBF_S3_ALLOW = os.getenv("APEX_RTBF_S3_ALLOW", "false").lower() == "true"
APEX_RTBF_S3_BUCKET = os.getenv("APEX_RTBF_S3_BUCKET", "")

# Audit minimization
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
APEX_EGRESS_ALLOWLIST_REGEX = os.getenv("APEX_EGRESS_ALLOWLIST_REGEX", "").strip()
APEX_EGRESS_BLOCK_IP_LITERALS = os.getenv("APEX_EGRESS_BLOCK_IP_LITERALS", "true").lower() == "true"
APEX_EGRESS_AUDIT_BLOCKS = os.getenv("APEX_EGRESS_AUDIT_BLOCKS", "true").lower() == "true"

# === NEW: Multi-Upstream Support ===
APEX_UPSTREAM_PROVIDERS_JSON = os.getenv("APEX_UPSTREAM_PROVIDERS_JSON", "").strip()

# === NEW: Model Pricing for cost tracking ===
APEX_MODEL_PRICES_USD_PER_1K_TOKENS_JSON = os.getenv("APEX_MODEL_PRICES_USD_PER_1K_TOKENS_JSON", "").strip()

# === NEW: Local Neural Safety ===
APEX_NEURAL_SAFETY_MODE = os.getenv("APEX_NEURAL_SAFETY_MODE", "stub").lower().strip()
APEX_NEURAL_SAFETY_URL = os.getenv("APEX_NEURAL_SAFETY_URL", "http://localhost:8081/analyze").strip()
APEX_NEURAL_SAFETY_TIMEOUT_SECONDS = float(os.getenv("APEX_NEURAL_SAFETY_TIMEOUT_SECONDS", "3.0"))
APEX_NEURAL_SAFETY_FAIL_OPEN = os.getenv("APEX_NEURAL_SAFETY_FAIL_OPEN", "true").lower() == "true"
APEX_NEURAL_SAFETY_MIN_CHARS = int(os.getenv("APEX_NEURAL_SAFETY_MIN_CHARS", "32"))


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


def is_sensitive_env_key(name: str) -> bool:
    n = (name or "").upper()
    return any(tok in n for tok in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE", "CREDENTIAL", "AUTH"))


def redact_env_value(name: str, value: str) -> Dict[str, Any]:
    v = value if isinstance(value, str) else str(value)
    return {
        "redacted": True,
        "sha256": hashlib.sha256(v.encode("utf-8")).hexdigest(),
        "len": len(v),
    }


def collect_env_config_snapshot() -> Dict[str, Any]:
    allow_prefixes = ("APEX_", "OIDC_", "QDRANT_", "OPENAI_")
    deny_exact = {
        "APEX_REDIS_URL",
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

    raw.setdefault("APEX_ENV", os.getenv("APEX_ENV", ""))
    redis_url = os.getenv("APEX_REDIS_URL", "")
    raw["APEX_REDIS_URL_PRESENT"] = "true" if bool(redis_url) else "false"
    raw["APEX_REDIS_URL_SCHEME"] = redis_url.split("://", 1)[0] if "://" in redis_url else ""

    redacted_vars: Dict[str, Any] = {}
    for k in sorted(raw.keys()):
        v = raw[k]
        if is_sensitive_env_key(k):
            redacted_vars[k] = redact_env_value(k, v)
        else:
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

    version_material = json.dumps(snapshot["vars"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    snapshot["config_version"] = hashlib.sha256(version_material).hexdigest()
    snapshot["hash_alg"] = "sha256"
    return snapshot


ENV_CONFIG_SNAPSHOT: Dict[str, Any] = {}
try:
    ENV_CONFIG_SNAPSHOT = collect_env_config_snapshot()
except Exception:
    ENV_CONFIG_SNAPSHOT = {}


def _load_upstream_providers_for_validation() -> List[str]:
    """Best-effort URL list for startup posture checks."""
    urls: List[str] = []
    raw = (APEX_UPSTREAM_PROVIDERS_JSON or "").strip()
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, list):
                for it in obj:
                    if isinstance(it, dict):
                        u = it.get("url")
                        if isinstance(u, str) and u.strip():
                            urls.append(u.strip())
        except Exception:
            pass
    if not urls:
        urls = [OPENAI_URL]
    out: List[str] = []
    seen = set()
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


_UPSTREAM_URLS_FOR_VALIDATION: List[str] = _load_upstream_providers_for_validation()


def _load_model_prices_usd_per_1k_tokens() -> Dict[str, Dict[str, float]]:
    raw = (APEX_MODEL_PRICES_USD_PER_1K_TOKENS_JSON or "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out: Dict[str, Dict[str, float]] = {}
    for k, v in obj.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            continue
        try:
            prompt = float(v.get("prompt") or 0.0)
            completion = float(v.get("completion") or 0.0)
            out[k.strip()] = {"prompt": max(0.0, prompt), "completion": max(0.0, completion)}
        except Exception:
            continue
    return out


MODEL_PRICES_USD_PER_1K: Dict[str, Dict[str, float]] = _load_model_prices_usd_per_1k_tokens()


def derive_openai_base_url(chat_url: str) -> str:
    parsed = urlparse((chat_url or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""

    path = (parsed.path or "").rstrip("/")
    for suffix in ("/chat/completions", "/v1/chat/completions"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break

    if not path:
        path = "/v1"

    return parsed._replace(path=path.rstrip("/"), params="", query="", fragment="").geturl()


OPENAI_BASE_URL = derive_openai_base_url(OPENAI_URL)


def is_likely_public_hostname(url: str) -> bool:
    u = (url or "").strip().lower()
    if not u:
        return False
    if "api.openai.com" in u:
        return True
    if "://localhost" in u or "://127.0.0.1" in u or "://[::1]" in u:
        return False
    if "://10." in u or "://192.168." in u:
        return False
    if "://172." in u:
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
    return True


def validate_env_sanity() -> None:
    env = get_apex_env()
    cluster_role = os.getenv("APEX_CLUSTER_ROLE", "unknown").lower()
    if "prod" in cluster_role and env != ApexEnv.PROD:
        raise RuntimeError(f"Forbidden configuration: cluster_role={cluster_role} with APEX_ENV={env.value}")


def validate_no_internet_posture() -> None:
    if not APEX_NO_INTERNET:
        return
    if is_likely_public_hostname(OIDC_ISSUER):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_OIDC_ISSUER appears to be a public endpoint")
    if is_likely_public_hostname(OPENAI_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_OPENAI_URL appears to be a public endpoint")
    if is_likely_public_hostname(ALERT_WEBHOOK_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_ALERT_WEBHOOK_URL appears to be a public endpoint")
    if is_likely_public_hostname(APEX_SIEM_WEBHOOK_URL):
        raise RuntimeError("APEX_NO_INTERNET=true but APEX_SIEM_WEBHOOK_URL appears to be a public endpoint")


_EGRESS_ALLOWLIST_CACHE: Optional[List[re.Pattern]] = None


def compile_egress_allowlist_patterns() -> List[re.Pattern]:
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
            raise RuntimeError("Invalid regex in APEX_EGRESS_ALLOWLIST_REGEX")

    _EGRESS_ALLOWLIST_CACHE = compiled
    return compiled


def is_ip_literal_hostname(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def egress_check_url(url: str) -> Tuple[bool, str, Dict[str, Any]]:
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

    if APEX_EGRESS_BLOCK_IP_LITERALS and is_ip_literal_hostname(hostname):
        return False, "ip_literal_blocked", details

    patterns = compile_egress_allowlist_patterns()
    if patterns:
        host = str(hostname or "")
        if not any(p.search(host) for p in patterns):
            return False, "allowlist_mismatch", details

    return True, "allowed", details


def validate_egress_config_or_raise() -> None:
    compile_egress_allowlist_patterns()

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
        ok, reason, _ = egress_check_url(u)
        if not ok:
            raise RuntimeError(f"Egress blocked by policy for {purpose}: {reason}")


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
