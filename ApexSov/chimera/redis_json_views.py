from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional


def decode_required_json_object(raw: Any) -> Dict[str, Any]:
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("Expected JSON object")
    return obj


def decode_optional_json_or_default(raw: Any, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def decode_optional_json_object_or_default(raw: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out_default = default or {}
    obj = decode_optional_json_or_default(raw, out_default)
    return obj if isinstance(obj, dict) else out_default


def decode_optional_json_list_or_default(raw: Any, default: Optional[List[Any]] = None) -> List[Any]:
    out_default = default or []
    obj = decode_optional_json_or_default(raw, out_default)
    return obj if isinstance(obj, list) else out_default


def decode_optional_json_with_raw_fallback(raw: Any) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {"raw": raw}
    except Exception:
        return {"raw": raw}


def decode_json_items_skip_invalid(raw_items: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        obj = decode_single_json_skip_invalid(raw)
        if obj is not None:
            out.append(obj)
    return out


def decode_single_json_skip_invalid(raw: Any) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def decode_json_items_with_raw_fallback(raw_items: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for raw in raw_items or []:
        if not raw:
            continue
        obj = decode_single_json_skip_invalid(raw)
        if obj is not None:
            out.append(obj)
        else:
            out.append({"raw": raw})
    return out


def extract_entry_hash_leaves(raw_items: Iterable[Any]) -> List[str]:
    leaves: List[str] = []
    for obj in decode_json_items_skip_invalid(raw_items):
        h = obj.get("entry_hash")
        if isinstance(h, str) and len(h) == 64:
            leaves.append(h)
    return leaves
