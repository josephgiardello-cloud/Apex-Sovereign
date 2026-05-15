from __future__ import annotations

import os
from typing import Any, Callable, Dict, List

import httpx
import redis.asyncio as redis

_normalize_for_security_fn: Callable[[str], str] = lambda text: (text or "").lower().strip()
_clamp01_fn: Callable[[float], float] = lambda x: max(0.0, min(float(x), 1.0))

_neural_safety_mode: str = "stub"
_neural_safety_url: str = "http://localhost:8081/analyze"
_neural_safety_timeout_seconds: float = 3.0
_neural_safety_fail_open: bool = True
_neural_safety_min_chars: int = 32


def configure_risk_components(
    *,
    normalize_for_security_fn: Callable[[str], str],
    clamp01_fn: Callable[[float], float],
    neural_safety_mode: str = "stub",
    neural_safety_url: str = "http://localhost:8081/analyze",
    neural_safety_timeout_seconds: float = 3.0,
    neural_safety_fail_open: bool = True,
    neural_safety_min_chars: int = 32,
) -> None:
    global _normalize_for_security_fn
    global _clamp01_fn
    global _neural_safety_mode
    global _neural_safety_url
    global _neural_safety_timeout_seconds
    global _neural_safety_fail_open
    global _neural_safety_min_chars

    _normalize_for_security_fn = normalize_for_security_fn
    _clamp01_fn = clamp01_fn
    _neural_safety_mode = str(neural_safety_mode or "stub").strip().lower()
    _neural_safety_url = str(neural_safety_url or "http://localhost:8081/analyze").strip()
    _neural_safety_timeout_seconds = max(0.1, float(neural_safety_timeout_seconds or 3.0))
    _neural_safety_fail_open = bool(neural_safety_fail_open)
    _neural_safety_min_chars = max(0, int(neural_safety_min_chars or 0))


class NeuralSafetyClassifier:
    """Semantic safety classifier with stub and HTTP sidecar modes."""

    def __init__(self):
        self.enabled = True

    async def analyze_intent(self, text: str) -> Dict[str, float]:
        t = text or ""
        if not self.enabled:
            return {"semantic_injection": 0.0, "semantic_toxicity": 0.0}

        if _neural_safety_mode == "stub":
            return {"semantic_injection": 0.0, "semantic_toxicity": 0.0}

        if len(t.strip()) < _neural_safety_min_chars:
            return {"semantic_injection": 0.0, "semantic_toxicity": 0.0}

        try:
            async with httpx.AsyncClient(timeout=_neural_safety_timeout_seconds) as client:
                resp = await client.post(_neural_safety_url, json={"text": t})
                resp.raise_for_status()
                obj = resp.json()

            return {
                "semantic_injection": _clamp01_fn(float(obj.get("semantic_injection", 0.0) or 0.0)),
                "semantic_toxicity": _clamp01_fn(float(obj.get("semantic_toxicity", obj.get("toxicity", 0.0)) or 0.0)),
            }
        except Exception:
            if _neural_safety_fail_open:
                return {"semantic_injection": 0.0, "semantic_toxicity": 0.0}
            return {"semantic_injection": 1.0, "semantic_toxicity": 1.0}


class HighRiskContentClassifier:
    """Heuristic high-risk/DLP-style classifier beyond regex."""

    def __init__(self):
        self.enabled = True

        self._trade_surveillance_terms = (
            "material nonpublic",
            "mnpi",
            "insider",
            "front run",
            "front-run",
            "pump and dump",
            "pump-and-dump",
            "spoofing",
            "layering",
            "wash trade",
            "wash-trade",
        )

        self._funds_movement_terms = (
            "wire transfer",
            "send a wire",
            "ach",
            "routing number",
            "swift",
            "iban",
            "beneficiary",
            "account number",
            "bank account",
            "bank details",
        )

        self._credential_terms = (
            "password",
            "one-time code",
            "otp",
            "2fa",
            "mfa",
            "security code",
        )

    def analyze(self, text: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"dlp": 0.0, "dlp_flags": []}

        t = _normalize_for_security_fn(text or "")
        flags: List[str] = []
        score = 0.0

        if any(term in t for term in self._trade_surveillance_terms):
            flags.append("trade_surveillance")
            score += 0.65

        if any(term in t for term in self._funds_movement_terms):
            flags.append("funds_movement")
            score += 0.45

        if any(term in t for term in self._credential_terms):
            flags.append("credentials")
            score += 0.25

        if any(term in t for term in ("how do i", "how to", "steps", "instructions", "do this", "execute")):
            score *= 1.15

        return {
            "dlp": _clamp01_fn(score),
            "dlp_flags": flags,
        }


MERKLE_BATCH_SIZE = int(os.getenv("APEX_MERKLE_BATCH_SIZE", "1000000"))


class UserRiskProfile:
    def __init__(self, tenant_id: str, subject: str):
        self.tenant_id = tenant_id
        self.subject = subject
        self.total_interactions = 0
        self.block_events = 0
        self.near_misses = 0


class UserRiskStore:
    def __init__(self, r_client: redis.Redis):
        self.r = r_client

    async def get(self, tenant_id: str, subject: str) -> UserRiskProfile:
        return UserRiskProfile(tenant_id, subject)

    async def update(self, profile: UserRiskProfile) -> None:
        return


class FastRiskClassifier:
    def predict(self, text: str) -> float:
        if not text or len(text.strip()) < 20:
            return 0.0
        return 0.0


class MerkleBatch:
    def __init__(self, size_limit: int = MERKLE_BATCH_SIZE):
        self.size_limit = size_limit
        self._items: List[str] = []

    def add(self, entry_hash: str) -> None:
        self._items.append(entry_hash)

    def is_full(self) -> bool:
        return len(self._items) >= self.size_limit

    def clear(self) -> None:
        self._items = []
