from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def get_tool_scoping(policy: Dict[str, Any], default_tool_scoping: Dict[str, Any]) -> Dict[str, Any]:
    ts = policy.get("tool_scoping")
    if not isinstance(ts, dict):
        ts = {}
    return {**default_tool_scoping, **ts}


def normalize_tool_name(name: Any) -> str:
    return str(name or "").strip()


def tool_allowed_by_policy(*, tool_name: str, tool_scoping: Dict[str, Any]) -> Tuple[bool, str]:
    name = normalize_tool_name(tool_name)
    if not name:
        return False, "missing_tool_name"

    if not bool(tool_scoping.get("enabled", False)):
        return True, "tool_scoping_disabled"

    mode = str(tool_scoping.get("mode") or "allowlist").strip().lower()
    allowed_set = {str(x).strip() for x in tool_scoping.get("allowed_tools", []) if str(x).strip()}
    denied_set = {str(x).strip() for x in tool_scoping.get("denied_tools", []) if str(x).strip()}

    if mode == "denylist":
        return (name not in denied_set), "tool_denied" if name in denied_set else "tool_allowed"

    if not allowed_set:
        return False, "allowlist_empty"
    return (name in allowed_set), "tool_not_allowlisted" if name not in allowed_set else "tool_allowed"


def extract_tool_name_from_tool_def(tool_def: Dict[str, Any]) -> Optional[str]:
    fn = tool_def.get("function")
    if isinstance(fn, dict):
        name = fn.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()

    name = tool_def.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def filter_tools_for_policy(
    tools: Optional[List[Dict[str, Any]]],
    *,
    tool_scoping: Dict[str, Any],
) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
    if tools is None:
        return None, {"provided": 0, "kept": 0, "dropped": 0, "dropped_names": []}

    items = list(tools)
    kept: List[Dict[str, Any]] = []
    dropped_names: List[str] = []

    for tool_def in items:
        name = extract_tool_name_from_tool_def(tool_def)
        if not name:
            if not bool(tool_scoping.get("enabled", False)):
                kept.append(tool_def)
            else:
                dropped_names.append("<unknown>")
            continue

        ok, _ = tool_allowed_by_policy(tool_name=name, tool_scoping=tool_scoping)
        if ok:
            kept.append(tool_def)
        else:
            dropped_names.append(name)

    return kept, {
        "provided": len(items),
        "kept": len(kept),
        "dropped": len(dropped_names),
        "dropped_names": dropped_names[:100],
    }
