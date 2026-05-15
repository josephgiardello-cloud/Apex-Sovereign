from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def _stable_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_turn_context_hash(
    *,
    policy_hash: str,
    tool_manifest_hash: str,
    model_config_hash: str,
    request_shape_hash: str,
) -> str:
    payload = {
        "policy_hash": policy_hash,
        "tool_manifest_hash": tool_manifest_hash,
        "model_config_hash": model_config_hash,
        "request_shape_hash": request_shape_hash,
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def hash_json_dict(data: Dict[str, Any]) -> str:
    return hashlib.sha256(_stable_json(data).encode("utf-8")).hexdigest()
