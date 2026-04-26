"""
Canonical decision tiers used by report-driven triage outputs.
"""

from __future__ import annotations

from typing import Literal, cast

DecisionTier = Literal[
    "fix_now",
    "plan_remediation",
    "mitigate",
    "monitor",
    "accept_risk",
]

VALID_DECISION_TIERS: list[DecisionTier] = [
    "fix_now",
    "plan_remediation",
    "mitigate",
    "monitor",
    "accept_risk",
]

DEFAULT_DECISION_TIER: DecisionTier = "monitor"


def is_valid_decision_tier(value: str | None) -> bool:
    """Return True when ``value`` is one of the canonical decision tiers."""
    return bool(value) and value in VALID_DECISION_TIERS


def normalize_decision_tier(
    value: str | None,
    *,
    default: DecisionTier = DEFAULT_DECISION_TIER,
) -> DecisionTier:
    """
    Normalize free-form input into a canonical decision tier.

    Unknown values fall back to ``default`` for backward compatibility.
    """
    if is_valid_decision_tier(value):
        return cast(DecisionTier, value)
    return default


def recommend_decision_tier(
    *,
    kev: bool | None,
    risk_score: float | None,
    reachability_verdict: str | None,
    fix_versions: list[str] | None,
    scope: str | None = None,
    dependency_depth: int | None = None,
    evidence_confidence: str | None = None,
) -> DecisionTier:
    """
    Recommend a pragmatic default triage tier from core risk signals.
    """
    verdict = (reachability_verdict or "").strip().lower()
    fixes = fix_versions or []
    is_reachable = verdict in {"confirmed_reachable", "likely_reachable"}
    has_fix = bool(fixes)
    risk = float(risk_score or 0.0)
    runtime_scope = (scope or "").strip().lower() in {"runtime", "required"}
    direct_dependency = dependency_depth is not None and dependency_depth <= 1
    confidence = (evidence_confidence or "").strip().lower() or "medium"

    if bool(kev) and is_reachable:
        return "fix_now"
    if is_reachable and runtime_scope and direct_dependency:
        return "fix_now"
    if risk >= 85.0 and is_reachable and has_fix:
        return "fix_now"
    if is_reachable:
        return "fix_now"
    if bool(kev) and has_fix:
        return "plan_remediation"
    if bool(kev) and not has_fix:
        return "mitigate"
    if risk >= 65.0 and has_fix:
        return "plan_remediation"
    if risk >= 70.0 and not has_fix:
        return "mitigate"
    if verdict == "no_sink_data" or confidence == "low":
        return "monitor"
    return "monitor"


def decision_tier_rationale(
    tier: DecisionTier,
    *,
    kev: bool | None,
    risk_score: float | None,
    reachability_verdict: str | None,
    fix_versions: list[str] | None,
    scope: str | None = None,
    dependency_depth: int | None = None,
    evidence_confidence: str | None = None,
) -> str:
    verdict = (reachability_verdict or "no_sink_data").strip().lower()
    fixes = fix_versions or []
    risk = float(risk_score or 0.0)
    scope_label = (scope or "unknown").strip() or "unknown"
    depth_label = "unknown" if dependency_depth is None else str(dependency_depth)
    confidence = (evidence_confidence or "medium").strip().lower()

    if tier == "fix_now":
        if bool(kev) and verdict in {"confirmed_reachable", "likely_reachable"}:
            return "KEV-listed and reachable evidence make this an immediate remediation item."
        return (
            f"High urgency due to verdict={verdict}, risk_score={risk:.1f}, "
            f"scope={scope_label}, depth={depth_label}."
        )
    if tier == "plan_remediation":
        return (
            f"Patch path exists ({len(fixes)} fix version(s)) and the case is material enough "
            f"to schedule promptly; verdict={verdict}, risk_score={risk:.1f}."
        )
    if tier == "mitigate":
        return (
            f"Risk remains notable without a ready patch or closure signal; apply compensating controls. "
            f"verdict={verdict}, risk_score={risk:.1f}."
        )
    if tier == "accept_risk":
        return "Use only for explicit human override with documented tradeoff and review cadence."
    return (
        f"Monitor because urgency is limited or evidence is weak; "
        f"verdict={verdict}, confidence={confidence}, risk_score={risk:.1f}."
    )
