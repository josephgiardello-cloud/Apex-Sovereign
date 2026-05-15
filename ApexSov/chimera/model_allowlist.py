from __future__ import annotations

from typing import Any, Dict, List, Mapping


def normalize_requested_models(
    models: List[str],
    *,
    external_model_map: Mapping[str, str],
    model_catalog: Mapping[str, Dict[str, Any]],
) -> List[str]:
    if not isinstance(models, list) or len(models) == 0:
        raise ValueError("models must be a non-empty list")

    normalized: List[str] = []
    seen = set()

    for m in models:
        if not isinstance(m, str) or not m.strip():
            continue
        raw = m.strip()
        internal = external_model_map.get(raw, raw)
        if internal not in model_catalog:
            raise ValueError(f"Unknown model: {raw}")
        if internal not in seen:
            normalized.append(internal)
            seen.add(internal)

    if len(normalized) == 0:
        raise ValueError("No valid models provided")

    return normalized


def read_policy_allowlist(policy: Dict[str, Any]) -> List[str]:
    allowlist = (policy or {}).get("model_allowlist")
    if not isinstance(allowlist, list):
        return []
    return allowlist
