from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def validate_text_only_messages(messages: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
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
        return False, f"messages[{i}].content type={type(content).__name__}"
    return True, None
