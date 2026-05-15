from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional


def parse_upstream_provider_pool(*, providers_json: str, default_url: str) -> List[Dict[str, Any]]:
    """Parse provider config from env with a safe single-provider fallback."""
    providers: List[Dict[str, Any]] = []
    raw = (providers_json or "").strip()

    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, list):
                for idx, item in enumerate(obj):
                    if not isinstance(item, dict):
                        continue
                    url = str(item.get("url") or "").strip()
                    if not url:
                        continue
                    auth = item.get("auth") if isinstance(item.get("auth"), dict) else {}
                    providers.append(
                        {
                            "name": str(item.get("name") or f"provider-{idx + 1}"),
                            "url": url,
                            "auth": {
                                "type": str(auth.get("type") or "bearer").strip().lower(),
                                "env": str(auth.get("env") or "OPENAI_API_KEY").strip(),
                                "header": str(auth.get("header") or "Authorization").strip(),
                            },
                        }
                    )
        except Exception:
            providers = []

    if not providers:
        providers = [
            {
                "name": "default-openai",
                "url": str(default_url or "").strip(),
                "auth": {
                    "type": "bearer",
                    "env": "OPENAI_API_KEY",
                    "header": "Authorization",
                },
            }
        ]

    return [p for p in providers if p.get("url")]


def build_provider_headers(provider: Dict[str, Any]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}

    auth = provider.get("auth") if isinstance(provider.get("auth"), dict) else {}
    auth_type = str(auth.get("type") or "bearer").strip().lower()
    key_env = str(auth.get("env") or "OPENAI_API_KEY").strip()
    header_name = str(auth.get("header") or "Authorization").strip()

    key = os.getenv(key_env, "") if key_env else ""
    if auth_type == "none":
        return headers

    if not key:
        return headers

    if auth_type == "api_key":
        headers[header_name or "api-key"] = key
    else:
        headers["Authorization"] = f"Bearer {key}"

    return headers


def select_provider_order(
    providers: List[Dict[str, Any]],
    *,
    tenant_id: str,
    session_id: str,
    model_name: str,
) -> List[Dict[str, Any]]:
    """Deterministic rotation per tenant/session/model to spread load consistently."""
    if len(providers) <= 1:
        return list(providers)

    material = f"{tenant_id}\0{session_id}\0{model_name}".encode("utf-8")
    seed = int(hashlib.sha256(material).hexdigest()[:8], 16)
    offset = seed % len(providers)
    return providers[offset:] + providers[:offset]
