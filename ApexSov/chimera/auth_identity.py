from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import HTTPException
from jose import jwt
from jose.exceptions import JWTError
from pydantic import BaseModel


class JwksCache:
    """Cached JWKS fetcher for IdP validation."""

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


class TenantIdentity(BaseModel):
    tenant_id: str
    subject: str
    roles: List[str] = []
    scopes: List[str] = []
    raw_token: Optional[str] = None


class IdpVerifier:
    """OIDC token verifier with tenant header consistency checks."""

    def __init__(
        self,
        *,
        oidc_issuer: str,
        oidc_audience: str,
        oidc_tenant_claim: str,
        jwks_cache: JwksCache,
    ):
        self._oidc_issuer = oidc_issuer
        self._oidc_audience = oidc_audience
        self._oidc_tenant_claim = oidc_tenant_claim
        self._jwks_cache = jwks_cache

    async def verify(self, auth_header: str, header_tenant_id: str) -> TenantIdentity:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        token = auth_header[len("Bearer ") :].strip()
        if not self._oidc_issuer or not self._oidc_audience:
            raise HTTPException(status_code=500, detail="OIDC not configured")

        try:
            key = await self._jwks_cache.get_signing_key_async(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=[key.get("alg", "RS256")],
                audience=self._oidc_audience,
                issuer=self._oidc_issuer,
            )
        except JWTError as exc:
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(exc)}")

        subject = claims.get("sub")
        tenant_from_token = claims.get(self._oidc_tenant_claim)
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


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationResult(BaseModel):
    decision: AuthorizationDecision
    reason: Optional[str] = None
    effective_model: Optional[str] = None


class AuthorizationEngine:
    """Minimal RBAC engine for model-tier and admin/audit controls."""

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

        return AuthorizationResult(
            decision=AuthorizationDecision.ALLOW,
            reason=None,
            effective_model=requested_model,
        )

    def require_admin(self, identity: TenantIdentity) -> None:
        roles_lower = {r.lower() for r in identity.roles}
        if not ({"admin", "security-admin", "ciso"} & roles_lower):
            raise HTTPException(status_code=403, detail="Admin or security role required for this operation")

    def require_audit_read(self, identity: TenantIdentity) -> None:
        roles_lower = {r.lower() for r in identity.roles}
        allowed = {"admin", "security-admin", "ciso", "auditor", "security-auditor", "compliance-auditor"}
        if not (allowed & roles_lower):
            raise HTTPException(status_code=403, detail="Audit role required for this operation")


def create_auth_components(
    *,
    oidc_issuer: str,
    jwks_cache_ttl_seconds: int,
    oidc_audience: str,
    oidc_tenant_claim: str,
) -> Tuple[JwksCache, IdpVerifier, AuthorizationEngine]:
    jwks_cache = JwksCache(issuer=oidc_issuer, ttl_seconds=jwks_cache_ttl_seconds)
    idp_verifier = IdpVerifier(
        oidc_issuer=oidc_issuer,
        oidc_audience=oidc_audience,
        oidc_tenant_claim=oidc_tenant_claim,
        jwks_cache=jwks_cache,
    )
    authz_engine = AuthorizationEngine()
    return jwks_cache, idp_verifier, authz_engine
