from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Mapping


class FieldClass(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    RESTRICTED = "restricted"
    FORBIDDEN = "forbidden"


def redact_telemetry_payload(
    payload: Mapping[str, Any],
    classes: Mapping[str, FieldClass],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in payload.items():
        cls = classes.get(key, FieldClass.OPTIONAL)
        if cls == FieldClass.FORBIDDEN:
            continue
        if cls == FieldClass.RESTRICTED:
            out[key] = "[REDACTED]"
            continue
        out[key] = value
    return out
