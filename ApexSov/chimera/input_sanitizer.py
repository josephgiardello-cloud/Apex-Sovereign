"""Input sanitization helpers adapted for Apex request preflight."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Dict, List, Tuple


class SafetyGuard:
    @staticmethod
    def _sanitize_input(text: str, *, max_len: int = 16000) -> tuple[str, bool, bool]:
        raw = str(text or "")
        cleaned_chars: list[str] = []
        removed_control = False

        for ch in raw:
            if ch in {"\n", "\r", "\t"}:
                cleaned_chars.append(ch)
                continue
            if ord(ch) < 32:
                removed_control = True
                continue
            cleaned_chars.append(ch)

        normalized = "".join(cleaned_chars).strip()
        truncated = False
        if len(normalized) > int(max_len):
            normalized = normalized[: int(max_len)]
            truncated = True
        return normalized, truncated, removed_control

    def sanitize_text(
        self,
        text: str,
        *,
        scrubber: Callable[[str], tuple[str, list[str]]],
        max_len: int = 16000,
    ) -> tuple[str, dict]:
        normalized, truncated, removed_control = self._sanitize_input(text, max_len=max_len)
        scrubbed, pii_types = scrubber(str(normalized or ""))
        return scrubbed, {
            "pii_types": list(pii_types),
            "truncated": truncated,
            "control_chars_removed": removed_control,
        }


def _build_regex_scrubber(pii_patterns: List[str]) -> Callable[[str], tuple[str, list[str]]]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for idx, pattern in enumerate(pii_patterns or []):
        try:
            compiled.append((f"pattern_{idx}", re.compile(pattern, flags=re.IGNORECASE)))
        except Exception:
            continue

    def _scrub(text: str) -> tuple[str, list[str]]:
        output = str(text or "")
        matched: list[str] = []
        for label, regex in compiled:
            if regex.search(output):
                matched.append(label)
            output = regex.sub("[REDACTED]", output)
        return output, matched

    return _scrub


def sanitize_messages(
    messages: List[Dict[str, Any]],
    *,
    guard: SafetyGuard,
    pii_patterns: List[str],
    max_len: int = 16000,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    scrubber = _build_regex_scrubber(pii_patterns)
    sanitized_messages: List[Dict[str, Any]] = []

    meta: Dict[str, Any] = {
        "messages_sanitized": 0,
        "pii_types": [],
        "truncated": False,
        "control_chars_removed": False,
    }

    pii_types_seen: set[str] = set()

    for message in list(messages or []):
        msg = dict(message)
        content = msg.get("content")

        if isinstance(content, str):
            scrubbed, details = guard.sanitize_text(content, scrubber=scrubber, max_len=max_len)
            if scrubbed != content:
                meta["messages_sanitized"] = int(meta["messages_sanitized"] or 0) + 1
            msg["content"] = scrubbed
            meta["truncated"] = bool(meta["truncated"] or details.get("truncated"))
            meta["control_chars_removed"] = bool(meta["control_chars_removed"] or details.get("control_chars_removed"))
            for pii in details.get("pii_types", []):
                pii_types_seen.add(str(pii))

        elif isinstance(content, list):
            changed = False
            new_parts: List[Any] = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    original_text = str(part.get("text") or "")
                    scrubbed, details = guard.sanitize_text(original_text, scrubber=scrubber, max_len=max_len)
                    if scrubbed != original_text:
                        changed = True
                    new_part = dict(part)
                    new_part["text"] = scrubbed
                    new_parts.append(new_part)
                    meta["truncated"] = bool(meta["truncated"] or details.get("truncated"))
                    meta["control_chars_removed"] = bool(meta["control_chars_removed"] or details.get("control_chars_removed"))
                    for pii in details.get("pii_types", []):
                        pii_types_seen.add(str(pii))
                else:
                    new_parts.append(part)
            if changed:
                meta["messages_sanitized"] = int(meta["messages_sanitized"] or 0) + 1
            msg["content"] = new_parts

        sanitized_messages.append(msg)

    meta["pii_types"] = sorted(pii_types_seen)
    return sanitized_messages, meta


__all__ = ["SafetyGuard", "sanitize_messages"]
