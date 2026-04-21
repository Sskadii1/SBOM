"""
Builder for Stakeholder Security Summary objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models import AlertCase, StakeholderReport


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sort_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return sorted(
        cases,
        key=lambda case: (
            0 if case.get("status") != "verified_closed" else 1,
            0 if case.get("decision_tier") == "fix_now" else 1,
            0 if case.get("kev") else 1,
            -(case.get("risk_score") or -1.0),
            -(case.get("cvss") or -1.0),
            case.get("vuln_id") or "",
            case.get("component_name") or "",
        ),
    )


_TIER_RATIONALE = {
    "fix_now": "Highest urgency cases with strong exploitability or impact evidence.",
    "plan_remediation": "Cases with clear remediation path that should be scheduled quickly.",
    "mitigate": "Cases requiring compensating controls while patch path is limited.",
    "monitor": "Lower-confidence or lower-urgency cases requiring periodic review.",
    "accept_risk": "Cases explicitly retained with documented tradeoff decisions.",
}

_TIER_ACTION_GUIDANCE = {
    "fix_now": "Patch/upgrade immediately; start emergency remediation now and validate in production.",
    "plan_remediation": "Create assigned remediation ticket, commit target release, and track to closure.",
    "mitigate": "Apply compensating controls now (hardening/rules/restrictions) while fix is unavailable.",
    "monitor": "Track advisory and reachability deltas; re-evaluate on each scan or new threat signal.",
    "accept_risk": "Document risk acceptance with owner and expiry date, then review periodically.",
}


def _action_with_fix_hint(base_action: str, fix_versions: list[str] | None) -> str:
    fixes = [str(v).strip() for v in (fix_versions or []) if str(v).strip()]
    if not fixes:
        return base_action
    preview = ", ".join(fixes[:3])
    return (
        f"{base_action} A fix is available; upgrade to a fixed version "
        f"({preview}) to reduce future risk."
    )


def _bucket_action_with_fix_hint(base_action: str, tier_cases: list[AlertCase]) -> str:
    fixable_cases = sum(1 for case in tier_cases if case.get("fix_versions"))
    if fixable_cases <= 0:
        return base_action
    return (
        f"{base_action} {fixable_cases}/{len(tier_cases)} case(s) in this tier already have "
        "known fix versions, so prioritize package upgrades in planned releases."
    )


def _top_priority_actions(cases: list[AlertCase]) -> list[dict[str, Any]]:
    active_cases = [case for case in cases if case.get("status") != "verified_closed"]
    items: list[dict[str, Any]] = []
    for case in active_cases[:5]:
        tier = str(case.get("decision_tier") or "monitor")
        base_action = _TIER_ACTION_GUIDANCE.get(tier, _TIER_ACTION_GUIDANCE["monitor"])
        items.append(
            {
                "vuln_id": case["vuln_id"],
                "component_name": case["component_name"],
                "severity": case["severity"],
                "risk_score": case.get("risk_score"),
                "decision_tier": case["decision_tier"],
                "status": case["status"],
                "rationale": _TIER_RATIONALE.get(tier, _TIER_RATIONALE["monitor"]),
                "recommended_action": _action_with_fix_hint(
                    base_action, case.get("fix_versions") or []
                ),
                "summary_note": case.get("summary_note"),
            }
        )
    return items


def _impact_summary(cases: list[AlertCase]) -> dict[str, Any]:
    runtime_affected = sum(1 for case in cases if case.get("scope") in {"runtime", "required"})
    direct_cases = sum(1 for case in cases if (case.get("dependency_depth") or 0) <= 1)
    transitive_cases = sum(1 for case in cases if (case.get("dependency_depth") or 0) > 1)
    reachable_or_likely = sum(
        1
        for case in cases
        if case.get("reachability_verdict") in {"confirmed_reachable", "likely_reachable"}
    )

    impact_note = (
        "Reachability evidence indicates active runtime exposure needs priority handling."
        if reachable_or_likely > 0
        else "Current reachability evidence does not confirm active runtime exploit paths."
    )
    return {
        "runtime_affected_cases": runtime_affected,
        "direct_dependency_cases": direct_cases,
        "transitive_dependency_cases": transitive_cases,
        "reachable_or_likely_cases": reachable_or_likely,
        "impact_note": impact_note,
    }


def _action_buckets(cases: list[AlertCase]) -> list[dict[str, Any]]:
    active_cases = [case for case in cases if case.get("status") != "verified_closed"]
    buckets: list[dict[str, Any]] = []
    for tier in ("fix_now", "plan_remediation", "mitigate", "monitor", "accept_risk"):
        tier_cases = [case for case in active_cases if case.get("decision_tier") == tier]
        if not tier_cases:
            continue
        buckets.append(
            {
                "decision_tier": tier,
                "case_count": len(tier_cases),
                "rationale": _TIER_RATIONALE[tier],
                "recommended_action": _bucket_action_with_fix_hint(
                    _TIER_ACTION_GUIDANCE[tier], tier_cases
                ),
                "related_vuln_ids": sorted({str(case["vuln_id"]) for case in tier_cases})[:12],
            }
        )
    return buckets


def _status_snapshot(cases: list[AlertCase]) -> dict[str, int]:
    keys = (
        "new",
        "under_review",
        "planned",
        "in_progress",
        "mitigated",
        "resolved_pending_verify",
        "verified_closed",
    )
    counts = {key: 0 for key in keys}
    for case in cases:
        status = str(case.get("status") or "new")
        if status in counts:
            counts[status] += 1
    return counts


def _status_snapshot_with_history(
    cases: list[AlertCase],
    case_states: dict[tuple[str, str, str | None], dict[str, Any]] | None = None,
) -> dict[str, int]:
    counts = _status_snapshot(cases)
    if not case_states:
        return counts

    current_keys = {
        (
            str(case.get("project") or ""),
            str(case.get("vuln_id") or ""),
            case.get("component_id"),
        )
        for case in cases
        if case.get("vuln_id")
    }
    for key, state in case_states.items():
        if key in current_keys:
            continue
        status = str((state or {}).get("status") or "new")
        if status in {"resolved_pending_verify", "verified_closed"}:
            counts[status] += 1
    return counts


def build_stakeholder_report(
    project_name: str,
    alert_cases: list[AlertCase],
    *,
    generated_at: str | None = None,
    case_states: dict[tuple[str, str, str | None], dict[str, Any]] | None = None,
) -> StakeholderReport:
    """
    Build a schema-complete stakeholder report from canonical AlertCase objects.
    """
    ordered_cases = _sort_cases(alert_cases)
    total_cases = len(ordered_cases)
    critical_high = sum(1 for case in ordered_cases if case.get("severity") in {"critical", "high"})
    kev_cases = sum(1 for case in ordered_cases if case.get("kev") is True)
    reachable_or_likely = sum(
        1
        for case in ordered_cases
        if case.get("reachability_verdict") in {"confirmed_reachable", "likely_reachable"}
    )
    fix_available = sum(1 for case in ordered_cases if case.get("fix_versions"))

    report: StakeholderReport = {
        "report_type": "stakeholder",
        "project": project_name,
        "generated_at": generated_at or _utc_now_iso(),
        "posture_summary": {
            "total_cases": total_cases,
            "critical_high_cases": critical_high,
            "kev_cases": kev_cases,
            "reachable_or_likely_cases": reachable_or_likely,
            "fix_available_cases": fix_available,
        },
        "top_priority_actions": _top_priority_actions(ordered_cases),
        "impact_summary": _impact_summary(ordered_cases),
        "action_buckets": _action_buckets(ordered_cases),
        "status_snapshot": _status_snapshot_with_history(ordered_cases, case_states),
        "next_verification_checkpoint": {
            "guidance": "Rerun SBOM and reachability scans after remediation merges to confirm risk reduction.",
            "trigger_conditions": [
                "Dependency version updates are merged.",
                "Security fixes are released to production branches.",
                "A new advisory/reachability signal changes exploitability assumptions.",
            ],
        },
    }
    return report
