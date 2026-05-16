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


def _normalize_text(text: str) -> str:
    return _normalize_for_security_fn(text or "")


def _unique_matched_phrases(text: str, phrases: Dict[str, float]) -> List[str]:
    normalized = _normalize_text(text)
    return [phrase for phrase in phrases if phrase in normalized]


def _weighted_phrase_score(text: str, phrases: Dict[str, float]) -> float:
    normalized = _normalize_text(text)
    score = 0.0
    for phrase, weight in phrases.items():
        if phrase in normalized:
            score += float(weight)
    return _clamp01_fn(score)


_NEURAL_INJECTION_PHRASES: Dict[str, float] = {
    "ignore previous instructions": 0.55,
    "ignore the previous instructions": 0.55,
    "disregard previous instructions": 0.55,
    "system prompt": 0.4,
    "developer message": 0.35,
    "jailbreak": 0.6,
    "bypass safety": 0.7,
    "override policy": 0.7,
    "reveal hidden instructions": 0.55,
    "reveal the hidden instructions": 0.55,
    "break character": 0.4,
    "prompt injection": 0.6,
}

_NEURAL_TOXICITY_PHRASES: Dict[str, float] = {
    "kill yourself": 0.95,
    "end my life": 0.9,
    "i want to die": 0.9,
    "hurt myself": 0.8,
    "kill them": 0.55,
    "i hate you": 0.45,
    "idiot": 0.25,
    "stupid": 0.2,
}


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

        local_scores = self._analyze_locally(t)
        if _neural_safety_mode in {"stub", "heuristic", "hybrid"}:
            return local_scores

        if len(t.strip()) < _neural_safety_min_chars:
            return local_scores

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
            if local_scores != {"semantic_injection": 0.0, "semantic_toxicity": 0.0}:
                return local_scores
            if _neural_safety_fail_open:
                return {"semantic_injection": 0.0, "semantic_toxicity": 0.0}
            return {"semantic_injection": 1.0, "semantic_toxicity": 1.0}

    def _analyze_locally(self, text: str) -> Dict[str, float]:
        normalized = _normalize_text(text)
        injection_score = _weighted_phrase_score(normalized, _NEURAL_INJECTION_PHRASES)
        toxicity_score = _weighted_phrase_score(normalized, _NEURAL_TOXICITY_PHRASES)

        if any(term in normalized for term in ("system prompt", "developer message", "ignore previous instructions")):
            injection_score = _clamp01_fn(injection_score + 0.15)

        if any(term in normalized for term in ("hurt myself", "end my life", "kill yourself", "i want to die")):
            toxicity_score = _clamp01_fn(max(toxicity_score, 0.9))

        return {"semantic_injection": injection_score, "semantic_toxicity": toxicity_score}


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
            "api key",
            "session token",
            "access token",
            "bearer token",
        )

        self._abuse_terms = (
            "phish",
            "phishing",
            "malware",
            "ransomware",
            "keylogger",
            "backdoor",
            "payload",
            "steal credentials",
            "steal passwords",
            "exfiltrate",
            "download all messages",
            "copy the database",
            "delete logs",
            "evade detection",
            "avoid detection",
        )

        self._family_grooming_terms = (
            "keep this secret",
            "don't tell anyone",
            "dont tell anyone",
            "are you alone",
            "how old are you",
            "meet me alone",
            "send me a photo",
        )

    def analyze(self, text: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"dlp": 0.0, "dlp_flags": []}

        t = _normalize_text(text or "")
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

        if any(term in t for term in self._abuse_terms):
            flags.append("abuse_or_exfiltration")
            score += 0.35

        if any(term in t for term in self._family_grooming_terms):
            flags.append("grooming")
            score += 0.2

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
    _high_risk_terms: Dict[str, float] = {
        "ignore previous instructions": 0.55,
        "ignore the previous instructions": 0.55,
        "disregard previous instructions": 0.55,
        "system prompt": 0.45,
        "developer message": 0.35,
        "jailbreak": 0.65,
        "bypass safety": 0.75,
        "override policy": 0.7,
        "prompt injection": 0.65,
        "phishing": 0.6,
        "phish": 0.6,
        "malware": 0.75,
        "ransomware": 0.75,
        "keylogger": 0.7,
        "backdoor": 0.6,
        "exfiltrate": 0.7,
        "steal credentials": 0.75,
        "steal passwords": 0.75,
        "delete logs": 0.55,
        "evade detection": 0.55,
        "kill yourself": 1.0,
        "i want to die": 0.95,
        "end my life": 0.95,
        "how to make a bomb": 1.0,
        "make a bomb": 1.0,
        "wire fraud": 0.9,
        "front run": 0.65,
        "wash trade": 0.65,
        "keep this secret": 0.3,
        "don't tell anyone": 0.3,
        "dont tell anyone": 0.3,
        "are you alone": 0.25,
        "how old are you": 0.25,
    }

    _escalation_terms: Dict[str, float] = {
        "how to": 0.08,
        "steps": 0.08,
        "instructions": 0.08,
        "execute": 0.08,
        "do this": 0.08,
        "now": 0.03,
        "quickly": 0.03,
    }

    def analyze(self, text: str) -> Dict[str, Any]:
        normalized = _normalize_text(text or "")
        if not normalized:
            return {"risk": 0.0, "signals": [], "matched_terms": []}

        matched_terms = [term for term in self._high_risk_terms if term in normalized]
        signals = []
        score = 0.0

        if matched_terms:
            signals.append("high_risk_intent")
            score += sum(self._high_risk_terms[term] for term in matched_terms)

        if any(term in normalized for term in ("password", "otp", "2fa", "mfa", "api key", "access token", "bearer token")):
            signals.append("credential_seeking")
            score += 0.25

        if any(term in normalized for term in ("copy the database", "download all messages", "export all chats", "exfiltrate", "steal", "scrape")):
            signals.append("data_exfiltration")
            score += 0.35

        if any(term in normalized for term in ("ignore previous instructions", "system prompt", "developer message", "prompt injection", "bypass safety")):
            signals.append("policy_evasion")
            score += 0.3

        if any(term in normalized for term in ("how to", "steps", "instructions", "do this", "execute")):
            score += 0.05

        if len(normalized.split()) > 80:
            score += 0.05

        if score > 0.0 and len(matched_terms) > 1:
            score += 0.05 * (len(matched_terms) - 1)

        return {
            "risk": _clamp01_fn(score),
            "signals": signals,
            "matched_terms": matched_terms,
        }

    def predict(self, text: str) -> float:
        if not text or len(text.strip()) < 8:
            return 0.0

        analysis = self.analyze(text)
        return float(analysis.get("risk") or 0.0)


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
