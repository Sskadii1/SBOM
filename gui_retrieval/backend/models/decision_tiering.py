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
) -> DecisionTier:
    """
    Recommend a pragmatic default triage tier from core risk signals.
    """
    verdict = (reachability_verdict or "").strip().lower()
    fixes = fix_versions or []
    is_reachable = verdict in {"confirmed_reachable", "likely_reachable"}

    # Reachability-first policy:
    # if execution path is observed/likely, treat as immediate priority.
    if is_reachable:
        return "fix_now"
    if bool(kev) and fixes:
        return "plan_remediation"
    if bool(kev) and not fixes:
        return "mitigate"
    if (risk_score or 0.0) >= 65.0 and fixes:
        return "plan_remediation"
    if (risk_score or 0.0) >= 80.0 and not fixes:
        return "mitigate"
    if verdict == "no_sink_data":
        return "monitor"
    return "monitor"
