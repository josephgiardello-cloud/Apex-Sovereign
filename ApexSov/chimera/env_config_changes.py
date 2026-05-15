from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Dict, Optional


def redact_env_change_value(
    name: str,
    value: Optional[str],
    *,
    is_sensitive_env_key: Callable[[str], bool],
    redact_env_value: Callable[[str, str], Dict[str, Any]],
) -> Dict[str, Any]:
    if value is None:
        return {"unset": True}
    v = value if isinstance(value, str) else str(value)
    if is_sensitive_env_key(name) or len(v) > 512:
        return redact_env_value(name, v)
    return {"redacted": False, "value": v}


def sanitize_env_changes(
    changes: Dict[str, Optional[str]],
    *,
    is_sensitive_env_key: Callable[[str], bool],
    redact_env_value: Callable[[str, str], Dict[str, Any]],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (changes or {}).items():
        if not isinstance(k, str) or not k.strip():
            continue
        key = k.strip().upper()
        if not (
            key.startswith("APEX_")
            or key.startswith("OIDC_")
            or key.startswith("QDRANT_")
            or key.startswith("OPENAI_")
        ):
            continue
        out[key] = redact_env_change_value(
            key,
            v,
            is_sensitive_env_key=is_sensitive_env_key,
            redact_env_value=redact_env_value,
        )
    return out


def env_changes_version(changes_redacted: Dict[str, Any]) -> str:
    material = json.dumps(changes_redacted, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(material).hexdigest()
