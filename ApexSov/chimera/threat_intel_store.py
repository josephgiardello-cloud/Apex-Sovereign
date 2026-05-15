from __future__ import annotations

import hashlib
import json
import time
import unicodedata
import uuid
from typing import Any, Callable, Dict, List, Literal, Optional

import redis.asyncio as redis
from fastapi import HTTPException
from pydantic import BaseModel

try:
    from . import policy_records as chimera_policy_records
except Exception:
    import chimera.policy_records as chimera_policy_records  # type: ignore[no-redef]

try:
    from . import redis_json_views as chimera_redis_json_views
except Exception:
    import chimera.redis_json_views as chimera_redis_json_views  # type: ignore[no-redef]


_THREAT_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}
_normalize_for_security: Callable[[str], str] = lambda text: unicodedata.normalize("NFKC", text or "").lower().strip()


def configure_threat_intel_store(*, normalize_for_security: Callable[[str], str]) -> None:
    global _normalize_for_security
    _normalize_for_security = normalize_for_security


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clamp01(x: float) -> float:
    return max(0.0, min(float(x), 1.0))


def _threat_intel_rules_key(tenant_id: str, feed_version: str) -> str:
    return f"apex:threat_intel:{tenant_id}:rules:{feed_version}"


def _threat_intel_versions_key(tenant_id: str) -> str:
    return f"apex:threat_intel:{tenant_id}:versions"


def _threat_intel_meta_key(tenant_id: str) -> str:
    return f"apex:threat_intel:{tenant_id}:meta"


def _severity_weight(severity: str) -> float:
    s = (severity or "").lower().strip()
    if s == "low":
        return 0.30
    if s == "medium":
        return 0.60
    if s == "high":
        return 0.90
    if s == "critical":
        return 1.00
    return 0.60


class ThreatIntelRule(BaseModel):
    """A lightweight match rule.

    `indicator` is a substring match against normalized text.
    `indicator_hash` is a strict-mode option: store only a hash of the indicator
    tokens (no plaintext). Matching is performed by hashing token windows.
    """

    rule_id: Optional[str] = None
    indicator: Optional[str] = None
    indicator_hash: Optional[str] = None
    indicator_token_count: Optional[int] = None
    indicator_hash_alg: Optional[str] = None
    tactic: str = "prompt_injection"
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = 0.7
    source: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


class ThreatIntelIngestRequest(BaseModel):
    feed_version: Optional[str] = None
    mode: Literal["replace", "append"] = "replace"
    activate: bool = True
    comment: Optional[str] = None
    hash_indicators: bool = False
    rules: List[ThreatIntelRule]


class ThreatIntelActivateRequest(BaseModel):
    feed_version: str


def _gen_feed_version() -> str:
    return f"ti_{int(time.time())}_{uuid.uuid4().hex[:12]}"


def _tokenize_indicator_for_hash(indicator: str) -> List[str]:
    norm = _normalize_for_security(indicator)
    if not norm:
        return []
    return [t for t in norm.split() if t]


def _hash_indicator_tokens(tokens: List[str]) -> str:
    joined = " ".join(tokens)
    return _sha256_hex(joined.encode("utf-8"))


def _extract_ngrams(s: str, *, n: int = 3, max_ngrams: int = 2000) -> List[str]:
    if not s:
        return []
    if len(s) < n:
        return []
    out: List[str] = []
    seen = set()
    for i in range(0, len(s) - n + 1):
        g = s[i : i + n]
        if g in seen:
            continue
        seen.add(g)
        out.append(g)
        if len(out) >= max_ngrams:
            break
    return out


def _build_ngram_index(rules: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    index: Dict[str, List[int]] = {}
    for i, rule in enumerate(rules):
        try:
            ind = str(rule.get("indicator_norm") or "")
            for g in _extract_ngrams(ind, n=3, max_ngrams=256):
                index.setdefault(g, []).append(i)
        except Exception:
            continue
    return index


def _build_hashed_indicator_index(rules: List[Dict[str, Any]]) -> Dict[int, Dict[str, List[int]]]:
    out: Dict[int, Dict[str, List[int]]] = {}
    for i, rule in enumerate(rules):
        try:
            h = rule.get("indicator_hash")
            tc = rule.get("indicator_token_count")
            if not (isinstance(h, str) and h):
                continue
            if not isinstance(tc, int) or tc <= 0 or tc > 256:
                continue
            out.setdefault(int(tc), {}).setdefault(h, []).append(i)
        except Exception:
            continue
    return out


class ThreatIntelStore:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def load_rules(self, tenant_id: str, *, force_reload: bool = False) -> Dict[str, Any]:
        now = time.time()
        cached = _THREAT_INTEL_CACHE.get(tenant_id)
        if cached and not force_reload:
            age = now - float(cached.get("loaded_at", 0.0) or 0.0)
            if age < 30.0:
                return cached

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta = chimera_redis_json_views.decode_optional_json_object_or_default(meta_raw)

        active_version = meta.get("active_feed_version")
        rules: List[Dict[str, Any]] = []
        if isinstance(active_version, str) and active_version:
            rules_raw = await self.r.get(_threat_intel_rules_key(tenant_id, active_version))
            rules = chimera_redis_json_views.decode_optional_json_list_or_default(rules_raw)

        cached = {
            "loaded_at": now,
            "rules": rules if isinstance(rules, list) else [],
            "feed_version": active_version,
            "previous_feed_version": meta.get("previous_feed_version"),
            "updated_at": meta.get("updated_at"),
        }
        cached["ngram_index"] = _build_ngram_index(cached["rules"])
        cached["hashed_index"] = _build_hashed_indicator_index(cached["rules"])
        _THREAT_INTEL_CACHE[tenant_id] = cached
        return cached

    async def activate(self, tenant_id: str, feed_version: str) -> Dict[str, Any]:
        if not feed_version:
            raise HTTPException(status_code=400, detail="feed_version is required")

        exists = await self.r.exists(_threat_intel_rules_key(tenant_id, feed_version))
        if not exists:
            raise HTTPException(status_code=404, detail="unknown feed_version")

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta = chimera_redis_json_views.decode_optional_json_object_or_default(meta_raw)

        prev = meta.get("active_feed_version")
        meta["previous_feed_version"] = prev
        meta["active_feed_version"] = feed_version
        meta["updated_at"] = chimera_policy_records.utc_now_z()

        await self.r.set(_threat_intel_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))

        try:
            await self.r.lrem(_threat_intel_versions_key(tenant_id), 0, feed_version)
            await self.r.lpush(_threat_intel_versions_key(tenant_id), feed_version)
        except Exception:
            pass

        await self.load_rules(tenant_id, force_reload=True)
        return {
            "active_feed_version": feed_version,
            "previous_feed_version": prev,
            "updated_at": meta.get("updated_at"),
        }

    async def rollback(self, tenant_id: str) -> Dict[str, Any]:
        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta = chimera_redis_json_views.decode_optional_json_object_or_default(meta_raw)

        target = meta.get("previous_feed_version")
        if not (isinstance(target, str) and target):
            try:
                candidate = await self.r.lindex(_threat_intel_versions_key(tenant_id), 1)
                if candidate:
                    target = candidate
            except Exception:
                target = None

        if not (isinstance(target, str) and target):
            raise HTTPException(status_code=409, detail="no previous feed version available")

        return await self.activate(tenant_id, target)

    async def ingest(self, tenant_id: str, req: ThreatIntelIngestRequest) -> Dict[str, Any]:
        if not req.rules:
            raise HTTPException(status_code=400, detail="rules must be non-empty")

        new_version = (req.feed_version or "").strip() or _gen_feed_version()
        if len(new_version) > 128:
            raise HTTPException(status_code=400, detail="feed_version too long")

        compiled: List[Dict[str, Any]] = []
        if req.mode == "append":
            existing = await self.load_rules(tenant_id, force_reload=True)
            compiled = list(existing.get("rules") or [])

        for r0 in req.rules:
            rid = r0.rule_id or f"ti_{uuid.uuid4().hex}"

            indicator = (r0.indicator or "").strip()
            indicator_hash = (r0.indicator_hash or "").strip()
            indicator_token_count = r0.indicator_token_count

            if req.hash_indicators:
                if indicator:
                    if len(indicator) > 400:
                        raise HTTPException(status_code=400, detail="indicator too long (max 400)")
                    tokens = _tokenize_indicator_for_hash(indicator)
                    if not tokens:
                        continue
                    indicator_token_count = len(tokens)
                    indicator_hash = _hash_indicator_tokens(tokens)
                if not indicator_hash:
                    continue
                if not isinstance(indicator_token_count, int) or indicator_token_count <= 0:
                    raise HTTPException(status_code=400, detail="indicator_token_count required for hashed indicators")

                compiled.append(
                    {
                        "rule_id": rid,
                        "indicator_hash": indicator_hash,
                        "indicator_token_count": int(indicator_token_count),
                        "indicator_hash_alg": (r0.indicator_hash_alg or "sha256"),
                        "tactic": r0.tactic,
                        "severity": r0.severity,
                        "confidence": float(r0.confidence),
                        "source": r0.source,
                        "created_at": r0.created_at or chimera_policy_records.utc_now_z(),
                        "expires_at": r0.expires_at,
                    }
                )
            else:
                if not indicator:
                    if indicator_hash:
                        if not isinstance(indicator_token_count, int) or indicator_token_count <= 0:
                            raise HTTPException(
                                status_code=400,
                                detail="indicator_token_count required when providing indicator_hash",
                            )
                        compiled.append(
                            {
                                "rule_id": rid,
                                "indicator_hash": indicator_hash,
                                "indicator_token_count": int(indicator_token_count),
                                "indicator_hash_alg": (r0.indicator_hash_alg or "sha256"),
                                "tactic": r0.tactic,
                                "severity": r0.severity,
                                "confidence": float(r0.confidence),
                                "source": r0.source,
                                "created_at": r0.created_at or chimera_policy_records.utc_now_z(),
                                "expires_at": r0.expires_at,
                            }
                        )
                    continue
                if len(indicator) > 400:
                    raise HTTPException(status_code=400, detail="indicator too long (max 400)")

                indicator_norm = _normalize_for_security(indicator)
                if not indicator_norm:
                    continue

                compiled.append(
                    {
                        "rule_id": rid,
                        "indicator": indicator,
                        "indicator_norm": indicator_norm,
                        "tactic": r0.tactic,
                        "severity": r0.severity,
                        "confidence": float(r0.confidence),
                        "source": r0.source,
                        "created_at": r0.created_at or chimera_policy_records.utc_now_z(),
                        "expires_at": r0.expires_at,
                    }
                )

        if len(compiled) > 500000:
            raise HTTPException(status_code=400, detail="too many rules (max 500000)")

        await self.r.set(
            _threat_intel_rules_key(tenant_id, new_version),
            json.dumps(compiled, separators=(",", ":")),
        )

        try:
            await self.r.lrem(_threat_intel_versions_key(tenant_id), 0, new_version)
            await self.r.lpush(_threat_intel_versions_key(tenant_id), new_version)
        except Exception:
            pass

        meta_raw = await self.r.get(_threat_intel_meta_key(tenant_id))
        meta = chimera_redis_json_views.decode_optional_json_object_or_default(meta_raw)

        meta.update(
            {
                "updated_at": chimera_policy_records.utc_now_z(),
                "mode": req.mode,
                "rule_count": len(compiled),
                "staged_feed_version": new_version,
            }
        )

        if req.activate:
            meta["previous_feed_version"] = meta.get("active_feed_version")
            meta["active_feed_version"] = new_version
            meta["staged_feed_version"] = None

        await self.r.set(_threat_intel_meta_key(tenant_id), json.dumps(meta, separators=(",", ":")))
        await self.load_rules(tenant_id, force_reload=True)

        return {
            "active_feed_version": meta.get("active_feed_version"),
            "previous_feed_version": meta.get("previous_feed_version"),
            "staged_feed_version": new_version if not req.activate else None,
            "updated_at": meta.get("updated_at"),
            "mode": req.mode,
            "rule_count": len(compiled),
        }

    async def match(
        self,
        tenant_id: str,
        text_norm: str,
        *,
        max_checked: int = 500,
        max_hits: int = 10,
    ) -> Dict[str, Any]:
        cached = await self.load_rules(tenant_id)
        rules = list(cached.get("rules") or [])
        if not rules or not text_norm:
            return {"score": 0.0, "hits": [], "feed_version": cached.get("feed_version")}

        hits: List[Dict[str, Any]] = []
        max_score = 0.0
        checked = 0
        now_iso = chimera_policy_records.utc_now_z()

        try:
            hashed_index: Dict[int, Dict[str, List[int]]] = cached.get("hashed_index") or {}
        except Exception:
            hashed_index = {}

        if hashed_index:
            tokens = [t for t in (text_norm or "").split() if t]
            seen_rule_ids = set()
            max_windows_per_token_count = 20000

            for token_count, hash_to_positions in hashed_index.items():
                if checked >= max_checked:
                    break
                if not isinstance(token_count, int) or token_count <= 0:
                    continue
                if token_count > len(tokens):
                    continue

                windows_checked = 0
                for i in range(0, len(tokens) - token_count + 1):
                    if checked >= max_checked:
                        break
                    windows_checked += 1
                    if windows_checked > max_windows_per_token_count:
                        break
                    window = " ".join(tokens[i : i + token_count])
                    wh = _sha256_hex(window.encode("utf-8"))
                    positions = hash_to_positions.get(wh)
                    if not positions:
                        continue

                    for pos in positions:
                        if checked >= max_checked:
                            break
                        try:
                            rule = rules[pos]
                            exp = rule.get("expires_at")
                            if isinstance(exp, str) and exp and exp < now_iso:
                                continue
                            rid = rule.get("rule_id")
                            if rid and rid in seen_rule_ids:
                                continue

                            sev = str(rule.get("severity") or "medium")
                            conf = float(rule.get("confidence") or 0.0)
                            score = _clamp01(conf * _severity_weight(sev))
                            max_score = max(max_score, score)
                            hits.append(
                                {
                                    "rule_id": rid,
                                    "tactic": rule.get("tactic"),
                                    "severity": sev,
                                    "confidence": conf,
                                    "score": score,
                                    "source": rule.get("source"),
                                    "match_mode": "hashed",
                                }
                            )
                            if rid:
                                seen_rule_ids.add(rid)
                            checked += 1

                            if len(hits) >= max_hits and max_score >= 0.99:
                                break
                        except Exception:
                            continue

        if len(hits) >= max_hits and max_score >= 0.99:
            return {
                "score": float(max_score),
                "hits": hits[:max_hits],
                "feed_version": cached.get("feed_version"),
                "checked": checked,
            }

        candidate_indices: List[int]
        if len(rules) <= max_checked:
            candidate_indices = list(range(len(rules)))
        else:
            idx: Dict[str, List[int]] = cached.get("ngram_index") or {}
            counts: Dict[int, int] = {}
            for g in _extract_ngrams(text_norm, n=3, max_ngrams=1500):
                positions = idx.get(g)
                if not positions:
                    continue
                for pos in positions:
                    counts[pos] = counts.get(pos, 0) + 1
            ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
            candidate_indices = [pos for pos, _ in ranked[:max_checked]]

        for pos in candidate_indices:
            if checked >= max_checked:
                break
            checked += 1
            try:
                rule = rules[pos]
                exp = rule.get("expires_at")
                if isinstance(exp, str) and exp and exp < now_iso:
                    continue
                ind = rule.get("indicator_norm") or ""
                if ind and ind in text_norm:
                    sev = str(rule.get("severity") or "medium")
                    conf = float(rule.get("confidence") or 0.0)
                    score = _clamp01(conf * _severity_weight(sev))
                    max_score = max(max_score, score)
                    hits.append(
                        {
                            "rule_id": rule.get("rule_id"),
                            "tactic": rule.get("tactic"),
                            "severity": sev,
                            "confidence": conf,
                            "score": score,
                            "source": rule.get("source"),
                            "match_mode": "plaintext",
                        }
                    )
                    if len(hits) >= max_hits and max_score >= 0.99:
                        break
            except Exception:
                continue

        return {
            "score": float(max_score),
            "hits": hits,
            "feed_version": cached.get("feed_version"),
            "checked": checked,
        }
