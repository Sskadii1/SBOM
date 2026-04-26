"""
Builder for Stakeholder Security Summary objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models import AlertCase, StakeholderReport
from backend.services.report_grouping_service import cluster_cases_by_remediation
from backend.services.report_presentation_service import select_preferred_fix_version

_REACHABLE_VERDICTS = {"confirmed_reachable", "likely_reachable"}
_TOP_PRIORITY_TIERS = {"fix_now", "plan_remediation"}
_TOP_PRIORITY_EXCLUDED_STATUSES = {"resolved_pending_verify", "verified_closed"}
_NON_ACTIVE_STATUSES = {"resolved_pending_verify", "verified_closed"}

_TIER_ORDER = {
    "fix_now": 0,
    "plan_remediation": 1,
    "mitigate": 2,
    "monitor": 3,
    "accept_risk": 4,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sort_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return sorted(
        cases,
        key=lambda case: (
            0 if case.get("status") != "verified_closed" else 1,
            _TIER_ORDER.get(str(case.get("decision_tier") or "monitor"), 9),
            0 if case.get("kev") else 1,
            -(case.get("risk_score") or -1.0),
            -(case.get("cvss") or -1.0),
            str(case.get("vuln_id") or ""),
            str(case.get("component_name") or ""),
        ),
    )


def _active_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return [case for case in cases if case.get("status") not in _NON_ACTIVE_STATUSES]


def _pretty_area_name(label: str) -> str:
    parts = [part for part in label.replace("-", "_").split("_") if part]
    return " ".join(part.capitalize() for part in parts) or "General Application"


def _functional_area_from_location(location: str | None) -> str:
    path = str(location or "").strip().lower().replace("\\", "/")
    if not path:
        return "general_application"
    if any(part in path for part in ("test", "tests", "__tests__", "spec", "fixture")):
        return "quality_and_test_flows"
    if "admin" in path:
        return "admin_interface"
    if "api" in path:
        return "api_layer"
    if "frontend" in path or "/ui/" in path or path.startswith("ui/"):
        return "frontend_ui"
    if "backend" in path or "server" in path:
        return "backend_service"
    return "general_application"


def _functional_area_from_case(case: AlertCase) -> str:
    locations = [str(item) for item in (case.get("call_locations") or []) if str(item).strip()]
    production_locations = [
        location
        for location in locations
        if "test" not in location.lower() and "spec" not in location.lower()
    ]
    if production_locations:
        return _functional_area_from_location(production_locations[0])
    if locations:
        return _functional_area_from_location(locations[0])

    chain = " ".join(str(item).lower() for item in (case.get("dependency_chain") or []))
    if "frontend" in chain:
        return "frontend_ui"
    if "backend" in chain or "server" in chain:
        return "backend_service"
    if "api" in chain:
        return "api_layer"
    return "general_application"


def _affected_area_context(cases: list[AlertCase]) -> tuple[list[dict[str, Any]], dict[tuple[str, str | None], str], dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    area_by_case: dict[tuple[str, str | None], str] = {}
    unknown_area_signals = 0
    production_area_signals = 0
    active = _active_cases(cases)

    for case in active:
        area_key = _functional_area_from_case(case)
        area_name = _pretty_area_name(area_key)
        area_by_case[(str(case.get("vuln_id") or ""), case.get("component_id"))] = area_name
        if area_key == "general_application":
            unknown_area_signals += 1
        case_locations = [str(item) for item in (case.get("call_locations") or []) if str(item).strip()]
        if any(
            "test" not in location.lower() and "spec" not in location.lower()
            for location in case_locations
        ):
            production_area_signals += 1

        bucket = buckets.setdefault(
            area_key,
            {
                "area_name": area_name,
                "case_count": 0,
                "reachable_or_likely_count": 0,
                "key_cves": [],
                "focus_reason": "Exposure exists in this area and needs follow-up.",
                "_has_fix_now": False,
            },
        )
        bucket["case_count"] += 1
        if case.get("reachability_verdict") in _REACHABLE_VERDICTS:
            bucket["reachable_or_likely_count"] += 1
        vuln_id = str(case.get("vuln_id") or "").strip()
        if vuln_id and vuln_id not in bucket["key_cves"]:
            bucket["key_cves"].append(vuln_id)
        if case.get("decision_tier") == "fix_now":
            bucket["_has_fix_now"] = True
            bucket["focus_reason"] = (
                "This area contains fix-now remediation work and should be prioritized in the current window."
            )
        elif case.get("fix_versions"):
            bucket["focus_reason"] = (
                "A fix path is available in this area, so exposure can be reduced in the next scheduled upgrade."
            )
        elif case.get("reachability_verdict") in _REACHABLE_VERDICTS:
            bucket["focus_reason"] = (
                "Reachability evidence exists here, but additional impact mapping is still partial."
            )

    ranked = sorted(
        buckets.values(),
        key=lambda item: (
            0 if item.get("_has_fix_now") else 1,
            -int(item.get("reachable_or_likely_count") or 0),
            -int(item.get("case_count") or 0),
            str(item.get("area_name") or ""),
        ),
    )

    visible_items = [
        {
            "area_name": str(item.get("area_name") or "General Application"),
            "case_count": int(item.get("case_count") or 0),
            "reachable_or_likely_count": int(item.get("reachable_or_likely_count") or 0),
            "key_cves": list(item.get("key_cves") or [])[:5],
            "focus_reason": str(item.get("focus_reason") or "Exposure exists in this area."),
        }
        for item in ranked[:3]
    ]

    area_keys = set(buckets.keys())
    mapping_partial = bool(active) and (
        area_keys == {"general_application"}
        or unknown_area_signals >= max(1, len(active) // 2)
        or production_area_signals == 0
    )
    if visible_items and (
        all(item["area_name"] == "General Application" for item in visible_items)
        or production_area_signals == 0
    ):
        total_cases = sum(item["case_count"] for item in visible_items)
        total_reachable = sum(item["reachable_or_likely_count"] for item in visible_items)
        all_cves: list[str] = []
        for item in visible_items:
            for vuln_id in item["key_cves"]:
                if vuln_id not in all_cves:
                    all_cves.append(vuln_id)
        visible_items = [
            {
                "area_name": "Repository-Wide Exposure",
                "case_count": total_cases,
                "reachable_or_likely_count": total_reachable,
                "key_cves": all_cves[:5],
                "focus_reason": (
                    "Current impact mapping is still partial, so exposure should be treated as repository-wide "
                    "until deeper call-path isolation is available."
                ),
            }
        ]
        mapping_partial = True

    mapping_meta = {
        "mapping_confidence": "partial" if mapping_partial else "strong",
        "is_repository_wide": bool(
            visible_items and visible_items[0].get("area_name") == "Repository-Wide Exposure"
        ),
        "note": (
            "Impact mapping is partial; use repository-wide exposure framing where area isolation is incomplete."
            if mapping_partial
            else "Impact mapping is sufficient to highlight top affected areas."
        ),
    }
    return visible_items, area_by_case, mapping_meta


def _target_version(case: AlertCase) -> str | None:
    return select_preferred_fix_version(case.get("fix_versions"))


def _remediation_readiness(case: AlertCase) -> str:
    if case.get("fix_versions"):
        return "fix_available"
    if case.get("reachability_verdict") in _REACHABLE_VERDICTS:
        return "investigate"
    return "workaround_only"


def _priority_why_now(cluster: dict[str, Any]) -> str:
    strongest_reachability = str(cluster.get("strongest_reachability") or "no_sink_data")
    has_fix = bool(cluster.get("has_fix_available"))
    includes_kev = bool(cluster.get("includes_kev"))
    if strongest_reachability == "confirmed_reachable":
        return "Direct code-level evidence shows this package is used in an active application path."
    if strongest_reachability == "likely_reachable" and has_fix:
        return "Current scan evidence suggests relevant application use, and a fix path is already available."
    if strongest_reachability == "likely_reachable":
        return "Current scan evidence suggests relevant application use and supports action in the current planning window."
    if includes_kev:
        return "The issue is associated with known exploitation activity, so it should not wait for a later review cycle."
    if has_fix:
        return "A fix path is available now, which makes exposure reduction practical in the current release planning window."
    return "Severity and dependency exposure justify remediation planning even though evidence is still incomplete."


def _required_management_action(decision_tier: str) -> tuple[str, str, str]:
    if decision_tier == "fix_now":
        return (
            "Approve immediate remediation implementation for this cluster.",
            "release_manager",
            "immediate",
        )
    if decision_tier == "plan_remediation":
        return (
            "Prioritize this upgrade in the next remediation window.",
            "developer_team",
            "next_window",
        )
    if decision_tier == "mitigate":
        return (
            "Confirm compensating controls and mitigation ownership.",
            "platform_team",
            "next_window",
        )
    return (
        "Track this cluster through the next verification checkpoint.",
        "platform_team",
        "monitor",
    )


def _top_priority_actions(
    cases: list[AlertCase],
    *,
    area_by_case: dict[tuple[str, str | None], str],
    fix_now_count: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    active = _active_cases(cases)
    ranked_candidates = [
        case
        for case in active
        if case.get("decision_tier") in _TOP_PRIORITY_TIERS
        and case.get("status") not in _TOP_PRIORITY_EXCLUDED_STATUSES
    ]
    if not ranked_candidates:
        ranked_candidates = [
            case
            for case in active
            if case.get("decision_tier") == "mitigate"
            and case.get("status") not in _TOP_PRIORITY_EXCLUDED_STATUSES
        ]

    clusters = cluster_cases_by_remediation(ranked_candidates, area_by_case=area_by_case)
    visible_clusters = clusters[:4]
    items: list[dict[str, Any]] = []
    for cluster in visible_clusters:
        representative_case = cluster.get("representative_case") or {}
        decision_tier = str(cluster.get("decision_tier") or "monitor")
        management_action, owner_type, urgency = _required_management_action(decision_tier)
        related_cves = list(cluster.get("related_cves") or [])
        target_version = cluster.get("target_version")
        items.append(
            {
                "vuln_id": str(cluster.get("representative_vuln_id") or ""),
                "component": str(cluster.get("component") or ""),
                "current_version": cluster.get("current_version"),
                "target_version": target_version,
                "decision_tier": decision_tier,
                "why_now": _priority_why_now(cluster),
                "impact_basis": str(
                    representative_case.get("impact_summary")
                    or representative_case.get("advisory_summary")
                    or "Impact evidence is currently partial and will be rechecked in the next scan."
                ),
                "remediation_readiness": (
                    "fix_available" if target_version else _remediation_readiness(representative_case)
                ),
                "affected_area": str(cluster.get("affected_area") or "General application"),
                "severity": str(representative_case.get("severity") or "medium").lower(),
                "reachability_verdict": str(cluster.get("strongest_reachability") or "no_sink_data"),
                "kev": bool(cluster.get("includes_kev")),
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "related_cves": related_cves,
                "remediation_cluster_title": (
                    f"{cluster.get('component') or 'Dependency'} remediation cluster"
                ),
                "required_management_action": management_action,
                "required_owner_type": owner_type,
                "required_urgency": urgency,
            }
        )

    fix_now_coverage = sum(
        int(item.get("related_case_count") or 0)
        for item in items
        if item.get("decision_tier") == "fix_now"
    )
    coverage = {
        "fix_now_total": int(fix_now_count),
        "fix_now_covered_in_display": int(fix_now_coverage),
        "uncovered_fix_now_cases": max(int(fix_now_count) - int(fix_now_coverage), 0),
        "coverage_note": (
            f"Displayed clusters cover {fix_now_coverage}/{fix_now_count} current-release case(s)."
            if fix_now_count > 0
            else "No current-release cases are currently open."
        ),
    }
    return items, coverage


def _impact_summary(
    cases: list[AlertCase],
    affected_areas: list[dict[str, Any]],
    *,
    mapping_meta: dict[str, Any],
) -> dict[str, Any]:
    active = _active_cases(cases)
    direct_count = sum(1 for case in active if (case.get("dependency_depth") or 0) <= 1)
    transitive_count = sum(1 for case in active if (case.get("dependency_depth") or 0) > 1)
    reachable_or_likely_count = sum(
        1 for case in active if case.get("reachability_verdict") in _REACHABLE_VERDICTS
    )
    high_exposure_areas = [
        item["area_name"]
        for item in affected_areas
        if int(item.get("reachable_or_likely_count") or 0) > 0
    ][:3]
    if reachable_or_likely_count > 0:
        impact_note = (
            "Reachable or likely reachable dependency exposure remains active; prioritize clusters with available fixes."
        )
    else:
        impact_note = (
            "No reachable or likely reachable case is currently confirmed, but dependency exposure remains in backlog."
        )
    return {
        "transitive_count": transitive_count,
        "direct_count": direct_count,
        "reachable_or_likely_count": reachable_or_likely_count,
        "high_exposure_areas": high_exposure_areas,
        "impact_note": impact_note,
        "area_mapping_confidence": str(mapping_meta.get("mapping_confidence") or "partial"),
        "area_mapping_note": str(mapping_meta.get("note") or ""),
    }


def _current_action_snapshot(cases: list[AlertCase]) -> dict[str, int]:
    active = _active_cases(cases)
    return {
        "fix_now_count": sum(1 for case in active if case.get("decision_tier") == "fix_now"),
        "plan_remediation_count": sum(
            1 for case in active if case.get("decision_tier") == "plan_remediation"
        ),
        "mitigate_count": sum(1 for case in active if case.get("decision_tier") == "mitigate"),
        "monitor_count": sum(
            1 for case in active if case.get("decision_tier") in {"monitor", "accept_risk"}
        ),
        "fix_available_count": sum(1 for case in active if case.get("fix_versions")),
        "reachable_or_likely_count": sum(
            1 for case in active if case.get("reachability_verdict") in _REACHABLE_VERDICTS
        ),
    }


def _overall_posture(
    active_cases: list[AlertCase],
    *,
    critical_high_count: int,
    kev_count: int,
    reachable_count: int,
    likely_reachable_count: int,
    fix_now_count: int,
) -> str:
    if fix_now_count > 0 or reachable_count > 0 or kev_count > 0:
        return "elevated"
    if active_cases and (critical_high_count > 0 or likely_reachable_count > 0):
        return "moderate"
    return "low"


def _posture_summary(cases: list[AlertCase], current_action_snapshot: dict[str, int]) -> dict[str, Any]:
    active = _active_cases(cases)
    critical_high_count = sum(1 for case in active if case.get("severity") in {"critical", "high"})
    kev_count = sum(1 for case in active if case.get("kev") is True)
    reachable_count = sum(1 for case in active if case.get("reachability_verdict") == "confirmed_reachable")
    likely_reachable_count = sum(
        1 for case in active if case.get("reachability_verdict") == "likely_reachable"
    )
    fix_now_count = int(current_action_snapshot.get("fix_now_count") or 0)
    overall_posture = _overall_posture(
        active,
        critical_high_count=critical_high_count,
        kev_count=kev_count,
        reachable_count=reachable_count,
        likely_reachable_count=likely_reachable_count,
        fix_now_count=fix_now_count,
    )
    if not active:
        summary_note = "No active cases are currently open."
    elif fix_now_count > 0:
        summary_note = (
            f"{fix_now_count} case(s) need current-release action and {reachable_count + likely_reachable_count} "
            "case(s) have direct or likely use evidence."
        )
    else:
        summary_note = (
            f"{len(active)} active case(s) remain open, including {reachable_count + likely_reachable_count} "
            "with direct or likely use evidence."
        )
    return {
        "total_cases": len(active),
        "critical_high_count": critical_high_count,
        "kev_count": kev_count,
        "fix_available_count": int(current_action_snapshot.get("fix_available_count") or 0),
        "reachable_count": reachable_count,
        "likely_reachable_count": likely_reachable_count,
        "overall_posture": overall_posture,
        "summary_note": summary_note,
    }


def _recommended_management_actions(
    current_action_snapshot: dict[str, int],
    top_priority_actions: list[dict[str, Any]],
    *,
    coverage: dict[str, Any],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    fix_now_count = int(current_action_snapshot.get("fix_now_count") or 0)
    plan_count = int(current_action_snapshot.get("plan_remediation_count") or 0)
    mitigate_count = int(current_action_snapshot.get("mitigate_count") or 0)
    monitor_count = int(current_action_snapshot.get("monitor_count") or 0)
    fix_available_count = int(current_action_snapshot.get("fix_available_count") or 0)
    uncovered_fix_now = int(coverage.get("uncovered_fix_now_cases") or 0)

    if fix_now_count > 0:
        actions.append(
            {
                "action": "Approve immediate remediation for current-release clusters.",
                "reason": f"{fix_now_count} case(s) currently need action in the current release window.",
                "owner_type": "release_manager",
                "urgency": "immediate",
            }
        )
    if uncovered_fix_now > 0:
        actions.append(
            {
                "action": "Allocate additional execution capacity for remaining current-release cases.",
                "reason": f"{uncovered_fix_now} current-release case(s) are not covered by the top displayed clusters.",
                "owner_type": "developer_team",
                "urgency": "immediate",
            }
        )
    if plan_count > 0:
        actions.append(
            {
                "action": "Schedule next-window remediation clusters.",
                "reason": f"{plan_count} case(s) are already suited for the next planned remediation window.",
                "owner_type": "developer_team",
                "urgency": "next_window",
            }
        )
    if mitigate_count > 0:
        actions.append(
            {
                "action": "Confirm mitigation owners and control deadlines.",
                "reason": f"{mitigate_count} case(s) currently rely on mitigation or further investigation.",
                "owner_type": "platform_team",
                "urgency": "next_window",
            }
        )
    if (monitor_count > 0 or not actions) and len(actions) < 4:
        actions.append(
            {
                "action": "Track observed backlog exposure at the next verification checkpoint.",
                "reason": (
                    "Observed backlog items are not safe by default; they require fresh evidence to be downgraded or closed."
                ),
                "owner_type": "platform_team",
                "urgency": "monitor",
            }
        )

    if not top_priority_actions and not actions:
        return [
            {
                "action": "Maintain standard scan cadence.",
                "reason": "No high-priority stakeholder actions were identified from current report data.",
                "owner_type": "release_manager",
                "urgency": "monitor",
            }
        ]
    return actions[:4]


def _next_verification_checkpoint(
    current_action_snapshot: dict[str, int],
    verification_summary: dict[str, Any] | None,
) -> dict[str, str]:
    delta_summary = (verification_summary or {}).get("summary") or {}
    baseline_scan_id = str(delta_summary.get("baseline_scan_id") or "").strip()
    resolved_cases = int(delta_summary.get("resolved_cases") or 0)
    risk_decreased = int(delta_summary.get("risk_decreased") or 0)
    verdict_improved = int(delta_summary.get("verdict_improved") or 0)
    fix_now_count = int(current_action_snapshot.get("fix_now_count") or 0)

    if fix_now_count > 0:
        trigger = "after remediation merges"
        goal = "Confirm fix-now clusters exit reachable/likely exposure in the next scan."
        recheck = (
            "Recheck SBOM version changes, reachability verdict movement, and whether fix_now cases left the active set."
        )
    elif int(current_action_snapshot.get("plan_remediation_count") or 0) > 0:
        trigger = "after planned release"
        goal = "Validate that planned upgrades reduced active backlog."
        recheck = "Recheck upgrade adoption in regenerated SBOM and tier movement across plan_remediation/monitor."
    else:
        trigger = "next scan"
        goal = "Confirm whether monitor/mitigate exposure changed materially."
        recheck = "Recheck evidence confidence and tier movement for unresolved monitor/mitigate items."

    if baseline_scan_id and any(value > 0 for value in (resolved_cases, risk_decreased, verdict_improved)):
        note = (
            f"Baseline {baseline_scan_id} comparison is meaningful and shows remediation movement."
        )
    elif baseline_scan_id:
        note = (
            f"Baseline {baseline_scan_id} exists, but no meaningful remediation delta is visible yet."
        )
    else:
        note = "No baseline comparison is available yet; the next scan will establish the first checkpoint baseline."

    return {
        "trigger": trigger,
        "goal": goal,
        "note": note,
        "what_will_be_rechecked": recheck,
    }


def build_stakeholder_report(
    project_name: str,
    alert_cases: list[AlertCase],
    *,
    generated_at: str | None = None,
    scan_id: str | None = None,
    source_commit: str | None = None,
    verification_summary: dict[str, Any] | None = None,
) -> StakeholderReport:
    """
    Build a schema-complete stakeholder report from canonical AlertCase objects.
    """
    ordered_cases = _sort_cases(alert_cases)
    affected_areas, area_by_case, mapping_meta = _affected_area_context(ordered_cases)
    current_action_snapshot = _current_action_snapshot(ordered_cases)
    top_priority_actions, coverage = _top_priority_actions(
        ordered_cases,
        area_by_case=area_by_case,
        fix_now_count=int(current_action_snapshot.get("fix_now_count") or 0),
    )

    report: StakeholderReport = {
        "report_type": "stakeholder",
        "project": project_name,
        "generated_at": generated_at or _utc_now_iso(),
        "scan_id": scan_id,
        "source_commit": source_commit,
        "posture_summary": _posture_summary(ordered_cases, current_action_snapshot),
        "affected_areas": affected_areas,
        "top_priority_actions": top_priority_actions,
        "impact_summary": _impact_summary(
            ordered_cases,
            affected_areas,
            mapping_meta=mapping_meta,
        ),
        "current_action_snapshot": current_action_snapshot,
        "recommended_management_actions": _recommended_management_actions(
            current_action_snapshot,
            top_priority_actions,
            coverage=coverage,
        ),
        "next_verification_checkpoint": _next_verification_checkpoint(
            current_action_snapshot,
            verification_summary,
        ),
    }
    report["top_priority_action_coverage"] = coverage
    report["area_mapping"] = mapping_meta
    return report
