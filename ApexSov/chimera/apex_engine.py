from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

import redis.asyncio as redis

_policy_store_factory: Optional[Callable[[redis.Redis], Any]] = None
_user_risk_store_factory: Optional[Callable[[redis.Redis], Any]] = None
_fast_risk_classifier_cls: Optional[Callable[[], Any]] = None
_neural_safety_classifier_cls: Optional[Callable[[], Any]] = None
_high_risk_content_classifier_cls: Optional[Callable[[], Any]] = None
_redis_bow_backend_cls: Optional[Callable[[redis.Redis], Any]] = None
_merkle_batch_cls: Optional[Callable[..., Any]] = None
_merkle_batch_size: int = 100
_threat_intel_store_factory: Optional[Callable[[redis.Redis], Any]] = None
_score_semantic_dlp_fn: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None
_normalize_for_security_fn: Optional[Callable[[str], str]] = None
_clamp01_fn: Optional[Callable[[float], float]] = None
_default_policy_baseline: Dict[str, Any] = {}
_seed_policy_for_group_fn: Optional[Callable[[str], Dict[str, Any]]] = None
_no_content_retention_enabled_fn: Optional[Callable[[Dict[str, Any]], bool]] = None
_policy_retention_seconds_fn: Optional[Callable[[Dict[str, Any], str], int]] = None
_store_deduped_content_fn: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None
_apex_content_dedup: bool = True
_utc_now_z_fn: Optional[Callable[[], str]] = None


def configure_apex_engine(
    *,
    policy_store_factory: Callable[[redis.Redis], Any],
    user_risk_store_factory: Callable[[redis.Redis], Any],
    fast_risk_classifier_cls: Callable[[], Any],
    neural_safety_classifier_cls: Callable[[], Any],
    high_risk_content_classifier_cls: Callable[[], Any],
    redis_bow_backend_cls: Callable[[redis.Redis], Any],
    merkle_batch_cls: Callable[..., Any],
    merkle_batch_size: int,
    threat_intel_store_factory: Callable[[redis.Redis], Any],
    score_semantic_dlp_fn: Callable[..., Awaitable[Dict[str, Any]]],
    normalize_for_security_fn: Callable[[str], str],
    clamp01_fn: Callable[[float], float],
    default_policy_baseline: Dict[str, Any],
    seed_policy_for_group_fn: Callable[[str], Dict[str, Any]],
    no_content_retention_enabled_fn: Callable[[Dict[str, Any]], bool],
    policy_retention_seconds_fn: Callable[[Dict[str, Any], str], int],
    store_deduped_content_fn: Callable[..., Awaitable[Dict[str, Any]]],
    apex_content_dedup: bool,
    utc_now_z_fn: Callable[[], str],
) -> None:
    global _policy_store_factory
    global _user_risk_store_factory
    global _fast_risk_classifier_cls
    global _neural_safety_classifier_cls
    global _high_risk_content_classifier_cls
    global _redis_bow_backend_cls
    global _merkle_batch_cls
    global _merkle_batch_size
    global _threat_intel_store_factory
    global _score_semantic_dlp_fn
    global _normalize_for_security_fn
    global _clamp01_fn
    global _default_policy_baseline
    global _seed_policy_for_group_fn
    global _no_content_retention_enabled_fn
    global _policy_retention_seconds_fn
    global _store_deduped_content_fn
    global _apex_content_dedup
    global _utc_now_z_fn

    _policy_store_factory = policy_store_factory
    _user_risk_store_factory = user_risk_store_factory
    _fast_risk_classifier_cls = fast_risk_classifier_cls
    _neural_safety_classifier_cls = neural_safety_classifier_cls
    _high_risk_content_classifier_cls = high_risk_content_classifier_cls
    _redis_bow_backend_cls = redis_bow_backend_cls
    _merkle_batch_cls = merkle_batch_cls
    _merkle_batch_size = int(merkle_batch_size)
    _threat_intel_store_factory = threat_intel_store_factory
    _score_semantic_dlp_fn = score_semantic_dlp_fn
    _normalize_for_security_fn = normalize_for_security_fn
    _clamp01_fn = clamp01_fn
    _default_policy_baseline = dict(default_policy_baseline or {})
    _seed_policy_for_group_fn = seed_policy_for_group_fn
    _no_content_retention_enabled_fn = no_content_retention_enabled_fn
    _policy_retention_seconds_fn = policy_retention_seconds_fn
    _store_deduped_content_fn = store_deduped_content_fn
    _apex_content_dedup = bool(apex_content_dedup)
    _utc_now_z_fn = utc_now_z_fn


def _require_cfg() -> None:
    if (
        _policy_store_factory is None
        or _user_risk_store_factory is None
        or _fast_risk_classifier_cls is None
        or _neural_safety_classifier_cls is None
        or _high_risk_content_classifier_cls is None
        or _redis_bow_backend_cls is None
        or _merkle_batch_cls is None
        or _threat_intel_store_factory is None
        or _score_semantic_dlp_fn is None
        or _normalize_for_security_fn is None
        or _clamp01_fn is None
        or _seed_policy_for_group_fn is None
        or _no_content_retention_enabled_fn is None
        or _policy_retention_seconds_fn is None
        or _store_deduped_content_fn is None
        or _utc_now_z_fn is None
    ):
        raise RuntimeError("apex_engine not configured")


class ApexSovereignEngine:
    def __init__(self, r_client: redis.Redis, drift_backend: Optional[Any] = None):
        _require_cfg()
        self.r = r_client
        self.policy_store = _policy_store_factory(r_client)
        self.user_store = _user_risk_store_factory(r_client)

        self.fast_clf = _fast_risk_classifier_cls()
        self.neural_safety = _neural_safety_classifier_cls()
        self.high_risk = _high_risk_content_classifier_cls()

        if drift_backend is not None:
            self.drift_backend = drift_backend
        else:
            self.drift_backend = _redis_bow_backend_cls(r_client)

        self.merkle_batch = _merkle_batch_cls(size_limit=_merkle_batch_size)

    async def _seal_merkle_batch(self) -> None:
        try:
            self.merkle_batch.clear()
        except Exception:
            pass

    async def compute_unified_risk(
        self,
        tenant_id: str,
        subject: str,
        session_id: str,
        prompt: str,
    ) -> Dict[str, Any]:
        coarse_risk = self.fast_clf.predict(prompt)
        if coarse_risk < 0.1:
            return {
                "decision": "PASS",
                "tony": coarse_risk,
                "tier": 1,
                "risk_vec": {},
            }

        profile = await self.user_store.get(tenant_id, subject or "unknown")
        semantic_risks = await self.neural_safety.analyze_intent(prompt)

        risk_vec = await self.compute_risk_for_prompt(tenant_id, session_id, prompt)
        risk_vec.update(semantic_risks)

        policy = await self.get_tenant_policy(tenant_id)
        weights = self._adjust_axis_weights(policy.get("risk_weights", {}), profile)

        jb_score = max(risk_vec.get("jailbreak", 0.0), risk_vec.get("semantic_injection", 0.0))
        tox_score = max(risk_vec.get("toxicity", 0.0), risk_vec.get("semantic_toxicity", 0.0))

        severity_agg = (
            risk_vec["pii"] * weights.get("pii", 1.0)
            + jb_score * weights.get("jailbreak", 1.2)
            + risk_vec["grooming"] * weights.get("grooming", 0.8)
            + tox_score * weights.get("toxicity", 0.5)
            + risk_vec["drift"] * weights.get("drift", 0.3)
            + float(risk_vec.get("dlp", 0.0) or 0.0) * weights.get("dlp", 0.9)
            + float(risk_vec.get("dlp_semantic", 0.0) or 0.0) * weights.get("dlp_semantic", 1.0)
        )

        tony_score = self._apply_tony_multipliers(severity_agg, risk_vec.get("context", 0.0))
        risk_vec["tony"] = float(tony_score)

        unified_thresh = policy.get("unified_thresh", 0.65)
        decision = "PASS" if tony_score < unified_thresh else "BLOCK"

        await self._finalize_governance_metadata(
            profile, decision, tony_score, tenant_id, subject, session_id, prompt, risk_vec
        )

        return {
            "decision": decision,
            "tony": float(tony_score),
            "tier": 2,
            "risk_vec": risk_vec,
        }

    async def get_tenant_policy(self, tenant_id: str) -> Dict[str, Any]:
        record = await self.policy_store.get_policy_or_seed(
            tenant_id,
            seed_policy=_seed_policy_for_group_fn("default"),
        )
        return record.policy

    async def compute_risk_for_prompt(
        self,
        tenant_id: str,
        session_id: str,
        prompt: str,
        policy: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        policy = policy or await self.get_tenant_policy(tenant_id)
        text = prompt or ""
        norm = _normalize_for_security_fn(text)

        intel_score = 0.0
        intel_hits: List[Dict[str, Any]] = []
        intel_feed_version: Optional[str] = None
        try:
            ti = _threat_intel_store_factory(self.r)
            intel_res = await ti.match(tenant_id, norm)
            intel_score = float(intel_res.get("score") or 0.0)
            intel_hits = list(intel_res.get("hits") or [])
            intel_feed_version = intel_res.get("feed_version")
        except Exception:
            intel_score = 0.0

        dlp_sem_score = 0.0
        dlp_sem_hits: List[Dict[str, Any]] = []
        try:
            sem = await _score_semantic_dlp_fn(self.r, tenant_id=tenant_id, text=text)
            dlp_sem_score = float(sem.get("score") or 0.0)
            dlp_sem_hits = list(sem.get("hits") or [])
        except Exception:
            dlp_sem_score = 0.0

        pii_patterns = policy.get("pii_patterns") or _default_policy_baseline.get("pii_patterns") or []
        pii_hits = 0
        for pat in pii_patterns:
            try:
                if re.search(pat, norm, flags=re.IGNORECASE):
                    pii_hits += 1
            except re.error:
                continue
        pii_score = _clamp01_fn(pii_hits * 0.35)

        jailbreak_terms = (
            "ignore previous",
            "disregard previous",
            "system prompt",
            "developer message",
            "jailbreak",
            "dan",
            "bypass safety",
            "override policy",
        )
        jb_hits = sum(1 for term in jailbreak_terms if term in norm)
        jailbreak_score = _clamp01_fn(jb_hits * 0.25)

        semantic_injection_score = _clamp01_fn(intel_score)
        jailbreak_score = max(jailbreak_score, semantic_injection_score)

        grooming_terms = (
            "how old are you",
            "your age",
            "are you alone",
            "keep this secret",
            "don't tell",
            "meet up",
        )
        grooming_hits = sum(1 for term in grooming_terms if term in norm)
        grooming_score = _clamp01_fn(grooming_hits * 0.25)

        toxicity_terms = (
            "kill yourself",
            "i hate you",
            "idiot",
            "stupid",
        )
        tox_hits = sum(1 for term in toxicity_terms if term in norm)
        toxicity_score = _clamp01_fn(tox_hits * 0.35)

        dlp_meta = self.high_risk.analyze(text)
        dlp_score = float(dlp_meta.get("dlp", 0.0) or 0.0)

        drift_score = 0.0
        try:
            history_prompts = await self.drift_backend.get_history_prompts(session_id)
        except Exception:
            history_prompts = []

        if history_prompts:
            try:
                hist_text = " ".join([p for p in history_prompts if isinstance(p, str)])
                hist_norm = _normalize_for_security_fn(hist_text)
                hist_tokens = set(hist_norm.split())
                cur_tokens = set(norm.split())
                if hist_tokens and cur_tokens:
                    sim = len(hist_tokens & cur_tokens) / float(len(hist_tokens | cur_tokens))
                    drift_score = _clamp01_fn(1.0 - sim)
            except Exception:
                drift_score = 0.0

        context_score = _clamp01_fn(len(text) / 2000.0)

        weights = policy.get("risk_weights") or _default_policy_baseline.get("risk_weights") or {}
        severity_agg = (
            pii_score * float(weights.get("pii", 1.0))
            + jailbreak_score * float(weights.get("jailbreak", 1.2))
            + grooming_score * float(weights.get("grooming", 0.8))
            + toxicity_score * float(weights.get("toxicity", 0.5))
            + drift_score * float(weights.get("drift", 0.3))
            + dlp_score * float(weights.get("dlp", 0.9))
            + dlp_sem_score * float(weights.get("dlp_semantic", 1.0))
        )
        tony_score = float(self._apply_tony_multipliers(severity_agg, context_score))

        return {
            "pii": float(pii_score),
            "jailbreak": float(jailbreak_score),
            "semantic_injection": float(semantic_injection_score),
            "grooming": float(grooming_score),
            "toxicity": float(toxicity_score),
            "drift": float(drift_score),
            "context": float(context_score),
            "dlp": float(dlp_score),
            "dlp_flags": dlp_meta.get("dlp_flags", []),
            "dlp_semantic": float(dlp_sem_score),
            "dlp_semantic_hits": [h.get("exemplar_id") for h in dlp_sem_hits[:5] if isinstance(h, dict)],
            "threat_intel": float(intel_score),
            "threat_intel_feed_version": intel_feed_version,
            "threat_intel_hits": [h.get("rule_id") for h in intel_hits[:5] if isinstance(h, dict)],
            "tony": float(tony_score),
        }

    def _apply_tony_multipliers(self, severity_agg: float, context: float) -> float:
        context_mult = 1.0 + 0.2 * context
        drcf = 1 + 0.5 * 0.8 + 0.3 * 0.7 + 0.2 * 0.9
        persistence_log = 1 + math.log(1 + 2.0)
        return severity_agg * context_mult * drcf * persistence_log * 0.72 * 0.7695 * 0.765 * 1.1

    async def _finalize_governance_metadata(self, profile: Any, decision: str, score: float, t_id: str, sub: str, sess: str, text: str, risk_vec: Dict[str, Any]) -> None:
        profile.total_interactions += 1
        if decision == "BLOCK":
            profile.block_events += 1
        elif score > 0.7:
            profile.near_misses += 1
        await self.user_store.update(profile)

        entry_hash = hashlib.sha256(f"{t_id}:{sub}:{sess}:{text}".encode()).hexdigest()
        self.merkle_batch.add(entry_hash)
        if self.merkle_batch.is_full():
            await self._seal_merkle_batch()

        if decision != "PASS" or score > 0.7:
            policy: Dict[str, Any] = {}
            try:
                policy = await self.get_tenant_policy(t_id)
            except Exception:
                policy = {}

            no_content = _no_content_retention_enabled_fn(policy)

            content_ttl = _policy_retention_seconds_fn(policy, "content_store_ttl_seconds")
            adversarial_ttl = _policy_retention_seconds_fn(policy, "adversarial_corpus_ttl_seconds")

            item: Dict[str, Any] = {
                "ts": _utc_now_z_fn(),
                "tony": score,
                "risk_vec": risk_vec,
            }
            if not no_content:
                if _apex_content_dedup and isinstance(text, str) and len(text) > 0:
                    ref = await _store_deduped_content_fn(
                        self.r,
                        tenant_id=t_id,
                        kind="adversarial_text",
                        content=text,
                        ttl_seconds=content_ttl,
                    )
                    item["text_ref"] = ref
                else:
                    item["text"] = text

            per_tenant_key = f"apex:adversarial_corpus:{t_id}"
            await self.r.lpush(per_tenant_key, json.dumps(item))
            await self.r.lpush("apex:adversarial_corpus", json.dumps(item))

            if adversarial_ttl > 0:
                try:
                    await self.r.expire(per_tenant_key, adversarial_ttl)
                except Exception:
                    pass
                try:
                    await self.r.expire("apex:adversarial_corpus", adversarial_ttl)
                except Exception:
                    pass

    def _adjust_axis_weights(self, base_weights: Dict[str, float], profile: Any) -> Dict[str, float]:
        if profile.total_interactions < 20:
            return base_weights

        trust_factor = max(0.5, 1.0 - (profile.block_events / max(1, profile.total_interactions)))
        adjusted: Dict[str, float] = {}
        for axis, w in base_weights.items():
            if axis in ("pii", "grooming", "jailbreak"):
                adjusted[axis] = w
            else:
                adjusted[axis] = w * trust_factor
        return adjusted
