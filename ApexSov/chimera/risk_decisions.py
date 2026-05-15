from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel

_default_policy_baseline: Dict[str, Any] = {
    "axis_thresholds": {
        "pii": 0.2,
        "jailbreak": 0.3,
        "grooming": 0.25,
    },
    "unified_thresh": 0.65,
}


def configure_risk_decisions(*, default_policy_baseline: Dict[str, Any]) -> None:
    global _default_policy_baseline
    _default_policy_baseline = dict(default_policy_baseline or {})


class BlockExplanation(BaseModel):
    reason_code: str
    human_message: str
    remediation_hint: Optional[str] = None


def explain_block(reason_code: str, risk_vec: Dict[str, Any]) -> BlockExplanation:
    if reason_code == "axis_pii_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="Your message appears to contain sensitive personal information.",
            remediation_hint="Remove or obfuscate items like credit card numbers, SSNs, phone numbers, or addresses.",
        )
    if reason_code == "axis_jailbreak_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="Your request seems to be trying to bypass safety or system instructions.",
            remediation_hint="Rephrase the request without asking to ignore or override safety rules.",
        )
    if reason_code == "axis_grooming_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="The content looks like inappropriate or manipulative interaction.",
            remediation_hint="Avoid asking for secretive, suggestive, or age-related personal engagement.",
        )
    if reason_code == "axis_toxicity_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="The content appears toxic or abusive.",
            remediation_hint="Remove slurs, threats, or hateful language and try again.",
        )
    if reason_code == "axis_dlp_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This request appears to involve high-risk financial or sensitive operational content.",
            remediation_hint="Remove account/transfer/trading instructions or sensitive transaction details and try again.",
        )
    if reason_code == "tony_threshold":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This response crosses your organization's configured safety threshold.",
            remediation_hint="Simplify the request, remove risky details, or contact your administrator if this seems wrong.",
        )
    if reason_code == "flagged_risks":
        return BlockExplanation(
            reason_code=reason_code,
            human_message="This interaction triggered one or more critical safety flags.",
            remediation_hint="Avoid requests involving sensitive personal data, policy evasion, or abusive content.",
        )
    return BlockExplanation(
        reason_code=reason_code,
        human_message="This content has been blocked by the safety policy.",
        remediation_hint="Try removing sensitive details or potentially risky language.",
    )


def evaluate_risk(risk_vec: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[str, Optional[str], float]:
    axis_thresholds = policy.get("axis_thresholds") or {}

    pii_score = float(risk_vec.get("pii", 0.0) or 0.0)
    jb_score = float(max(risk_vec.get("jailbreak", 0.0) or 0.0, risk_vec.get("semantic_injection", 0.0) or 0.0))
    grooming_score = float(risk_vec.get("grooming", 0.0) or 0.0)
    toxicity_score = float(max(risk_vec.get("toxicity", 0.0) or 0.0, risk_vec.get("semantic_toxicity", 0.0) or 0.0))
    dlp_score = float(risk_vec.get("dlp", 0.0) or 0.0)

    baseline_axis = _default_policy_baseline.get("axis_thresholds") or {}
    pii_thresh = float(axis_thresholds.get("pii", baseline_axis.get("pii", 0.2)))
    jb_thresh = float(axis_thresholds.get("jailbreak", baseline_axis.get("jailbreak", 0.3)))
    grooming_thresh = float(axis_thresholds.get("grooming", baseline_axis.get("grooming", 0.25)))
    tox_thresh = float(axis_thresholds.get("toxicity", 0.0))
    dlp_thresh = float(axis_thresholds.get("dlp", 0.0))

    if pii_thresh > 0.0 and pii_score >= pii_thresh:
        return "BLOCK", "axis_pii_threshold", pii_score
    if jb_thresh > 0.0 and jb_score >= jb_thresh:
        return "BLOCK", "axis_jailbreak_threshold", jb_score
    if grooming_thresh > 0.0 and grooming_score >= grooming_thresh:
        return "BLOCK", "axis_grooming_threshold", grooming_score
    if tox_thresh > 0.0 and toxicity_score >= tox_thresh:
        return "BLOCK", "axis_toxicity_threshold", toxicity_score
    if dlp_thresh > 0.0 and dlp_score >= dlp_thresh:
        return "BLOCK", "axis_dlp_threshold", dlp_score

    unified_thresh = float(policy.get("unified_thresh", _default_policy_baseline.get("unified_thresh", 0.65)))
    tony_score = float(risk_vec.get("tony", 0.0) or 0.0)

    if tony_score >= unified_thresh:
        return "BLOCK", "tony_threshold", tony_score
    return "PASS", None, tony_score
