"""
Builder for Developer Remediation Report objects.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from backend.models import AlertCase, DeveloperReport, decision_tier_rationale
from backend.services.report_grouping_service import (
    classify_evidence_scope,
    cluster_cases_by_remediation,
    split_call_locations,
)
from backend.services.report_presentation_service import select_preferred_fix_version
from backend.services.report_vocabulary_service import reachability_legend

_REACHABLE_VERDICTS = {"confirmed_reachable", "likely_reachable"}
_BACKLOG_VERDICTS = {"no_sink_data", "likely_unreachable", "unknown"}
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


def _active_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return [case for case in cases if case.get("status") not in _NON_ACTIVE_STATUSES]


def _sort_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return sorted(
        cases,
        key=lambda case: (
            _TIER_ORDER.get(str(case.get("decision_tier") or "monitor"), 9),
            0 if case.get("kev") else 1,
            0 if case.get("reachability_verdict") == "confirmed_reachable" else 1,
            -(case.get("risk_score") or -1.0),
            -(case.get("cvss") or -1.0),
            str(case.get("vuln_id") or ""),
            str(case.get("component_name") or ""),
        ),
    )


def _top_target_version(case: AlertCase) -> str | None:
    return select_preferred_fix_version(case.get("fix_versions"))


def _nvd_url(vuln_id: str | None) -> str | None:
    value = str(vuln_id or "").strip()
    if not value:
        return None
    if value.upper().startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{value.upper()}"
    return None


def _normalize_backlog_verdict(case: AlertCase) -> str:
    verdict = str(case.get("reachability_verdict") or "unknown")
    if verdict in _BACKLOG_VERDICTS:
        return verdict
    if verdict in _REACHABLE_VERDICTS:
        return "unknown"
    return "unknown"


def _reason_not_fix_now(case: AlertCase) -> str:
    verdict = str(case.get("reachability_verdict") or "unknown")
    if verdict == "no_sink_data":
        return "Sink-level evidence is not available yet, so this stays out of the immediate queue because the evidence is incomplete, not because it is proven safe."
    if verdict == "likely_unreachable":
        return "Current scan data did not show direct use in the active path, so this can stay in planned verification unless new evidence appears."
    if case.get("decision_tier") == "mitigate":
        return "Mitigation or additional investigation is required before finalizing an upgrade."
    if case.get("fix_versions"):
        return "A fix path exists, but this item is better suited for a later remediation window than the immediate queue."
    return "Evidence or remediation detail is incomplete, so this remains backlog."


def _cluster_why_fix_now(cluster: dict[str, Any]) -> str:
    verdict = str(cluster.get("strongest_reachability") or "no_sink_data")
    evidence_scope_counts = cluster.get("evidence_scope_counts") or {}
    has_fix = bool(cluster.get("has_fix_available"))
    if verdict == "confirmed_reachable":
        return "Direct call evidence in project code places this cluster in the immediate remediation queue."
    if verdict == "likely_reachable" and evidence_scope_counts.get("production", 0) > 0:
        return "Production-path usage signals make this cluster urgent even though a direct vulnerable sink call was not confirmed."
    if verdict == "likely_reachable" and evidence_scope_counts.get("test-only", 0) > 0:
        return "Test-path evidence suggests relevant use; confirm production impact during remediation rather than treating the issue as closed."
    if has_fix:
        return "Risk and fix availability justify immediate remediation once ownership is assigned."
    return "Current tiering and evidence strength still justify immediate remediation work."


def _cluster_next_action(cluster: dict[str, Any]) -> str:
    component = str(cluster.get("component") or "dependency")
    current_version = str(cluster.get("current_version") or "current")
    target_version = cluster.get("target_version")
    if target_version:
        return (
            f"Upgrade {component} from {current_version} to {target_version}, then rerun SBOM and reachability scans."
        )
    return (
        f"Investigate runtime usage for {component}, define a safe target version, and rerun verification."
    )


def _cluster_verification_target(cluster: dict[str, Any]) -> dict[str, Any]:
    component = str(cluster.get("component") or "dependency")
    current_version = str(cluster.get("current_version") or "current")
    target_version = str(cluster.get("target_version") or "target pending")
    strongest_reachability = str(cluster.get("strongest_reachability") or "no_sink_data")
    if strongest_reachability in {"confirmed_reachable", "likely_reachable"}:
        success_criteria = (
            "Cluster leaves the reachable/likely set after upgrade and regenerated scan."
        )
    else:
        success_criteria = (
            "Cluster risk and evidence confidence improve after remediation or mitigation updates."
        )
    return {
        "cluster_id": cluster.get("cluster_id"),
        "cluster_title": f"{component} remediation cluster",
        "what_must_change": f"{component} should move from {current_version} to {target_version}.",
        "scan_recheck": (
            "Regenerate SBOM, rerun enrichment and reachability, then validate decision tier movement."
        ),
        "success_criteria": success_criteria,
    }


def _immediate_fix_item(case: AlertCase) -> dict[str, Any]:
    locations = [str(item).strip() for item in (case.get("call_locations") or []) if str(item).strip()]
    production_locations, test_locations = split_call_locations(locations)
    key_call_locations = (production_locations or test_locations)[:3]
    return {
        "vuln_id": str(case.get("vuln_id") or ""),
        "component": str(case.get("component_name") or ""),
        "current_version": case.get("component_version"),
        "target_version": _top_target_version(case),
        "severity": str(case.get("severity") or "medium").lower(),
        "decision_tier": "fix_now",
        "reachability_verdict": str(case.get("reachability_verdict") or "likely_reachable"),
        "evidence_confidence": str(case.get("evidence_confidence") or "medium"),
        "production_evidence": bool(production_locations or case.get("scope") in {"runtime", "required"}),
        "test_only_evidence": bool(test_locations) and not bool(production_locations),
        "key_call_locations": key_call_locations,
        "dependency_depth": case.get("dependency_depth"),
        "dependency_chain": list(case.get("dependency_chain") or []),
        "cvss": case.get("cvss"),
        "risk_score": case.get("risk_score"),
        "cve_description": str(case.get("advisory_summary") or case.get("summary_note") or ""),
        "nvd_url": _nvd_url(case.get("vuln_id")),
        "why_fix_now": _cluster_why_fix_now(
            {
                "strongest_reachability": case.get("reachability_verdict"),
                "evidence_scope_counts": {classify_evidence_scope(case): 1},
                "has_fix_available": bool(case.get("fix_versions")),
            }
        ),
        "next_action": _cluster_next_action(
            {
                "component": case.get("component_name"),
                "current_version": case.get("component_version"),
                "target_version": _top_target_version(case),
            }
        ),
    }


def _immediate_fix_clusters(cases: list[AlertCase]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    candidates = [
        case
        for case in cases
        if case.get("decision_tier") == "fix_now"
        and case.get("reachability_verdict") in _REACHABLE_VERDICTS
    ]
    clusters = cluster_cases_by_remediation(candidates)
    items: list[dict[str, Any]] = []
    for cluster in clusters:
        related_cves = list(cluster.get("related_cves") or [])
        evidence_scope_counts = cluster.get("evidence_scope_counts") or {}
        production_cases = int(evidence_scope_counts.get("production", 0))
        test_only_cases = int(evidence_scope_counts.get("test-only", 0))
        mixed_cases = int(evidence_scope_counts.get("mixed", 0))
        unknown_cases = int(evidence_scope_counts.get("unknown", 0))
        call_evidence: list[dict[str, Any]] = []
        for case in cluster.get("cases") or []:
            vuln_id = str(case.get("vuln_id") or "").strip()
            if not vuln_id:
                continue
            locations = [str(item).strip() for item in (case.get("call_locations") or []) if str(item).strip()]
            sink_functions = [str(item).strip() for item in (case.get("sink_functions") or []) if str(item).strip()]
            evidence_scope = classify_evidence_scope(case)
            scope_label = {
                "production": "production",
                "test-only": "test-only",
                "mixed": "mixed",
                "unknown": "unknown",
            }.get(evidence_scope, "unknown")
            call_evidence.append(
                {
                    "vuln_id": vuln_id,
                    "reachability_verdict": str(case.get("reachability_verdict") or "no_sink_data"),
                    "evidence_scope": scope_label,
                    "call_locations": locations[:5],
                    "sink_functions": sink_functions[:3],
                }
            )

        call_evidence.sort(
            key=lambda item: (
                0 if item.get("reachability_verdict") == "confirmed_reachable" else 1,
                0 if item.get("evidence_scope") == "production" else 1,
                str(item.get("vuln_id") or ""),
            )
        )
        items.append(
            {
                "cluster_id": cluster.get("cluster_id"),
                "package": str(cluster.get("component") or ""),
                "current_version": cluster.get("current_version"),
                "target_version": cluster.get("target_version"),
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "related_cves": related_cves,
                "strongest_reachability": str(cluster.get("strongest_reachability") or "likely_reachable"),
                "production_case_count": production_cases,
                "test_only_case_count": test_only_cases,
                "mixed_case_count": mixed_cases,
                "unknown_scope_case_count": unknown_cases,
                "key_call_locations": list(cluster.get("key_call_locations") or [])[:5],
                "call_evidence": call_evidence,
                "why_fix_now": _cluster_why_fix_now(cluster),
                "next_action": _cluster_next_action(cluster),
                "verification_target": _cluster_verification_target(cluster),
            }
        )

    fix_now_total = sum(1 for case in cases if case.get("decision_tier") == "fix_now")
    covered = sum(int(item.get("related_case_count") or 0) for item in items)
    return items, {
        "fix_now_total": int(fix_now_total),
        "fix_now_covered_by_clusters": int(covered),
        "uncovered_fix_now_cases": max(int(fix_now_total) - int(covered), 0),
        "coverage_note": (
            f"Immediate remediation clusters cover {covered}/{fix_now_total} immediate-queue case(s)."
            if fix_now_total > 0
            else "No immediate-queue cases are currently open."
        ),
    }


def _planned_upgrade_backlog(cases: list[AlertCase]) -> dict[str, Any]:
    backlog_cases = [
        case
        for case in cases
        if case.get("decision_tier") in {"plan_remediation", "monitor", "accept_risk", "mitigate"}
    ]
    clusters = cluster_cases_by_remediation(backlog_cases)
    backlog_clusters: list[dict[str, Any]] = []
    for cluster in clusters[:8]:
        representative_case = cluster.get("representative_case") or {}
        backlog_clusters.append(
            {
                "cluster_id": cluster.get("cluster_id"),
                "package": str(cluster.get("component") or ""),
                "current_version": cluster.get("current_version"),
                "target_version": cluster.get("target_version"),
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "related_cves": list(cluster.get("related_cves") or []),
                "decision_tier": str(cluster.get("decision_tier") or "monitor"),
                "reachability_verdict": _normalize_backlog_verdict(representative_case),
                "reason_not_fix_now": _reason_not_fix_now(representative_case),
                "recommended_next_window_action": _cluster_next_action(cluster),
            }
        )

    verdict_counts = Counter(_normalize_backlog_verdict(case) for case in backlog_cases)
    top_items = [
        {
            "vuln_id": str(item["related_cves"][0] if item.get("related_cves") else ""),
            "component": item.get("package"),
            "current_version": item.get("current_version"),
            "target_versions": [item.get("target_version")] if item.get("target_version") else [],
            "severity": "medium",
            "reachability_verdict": item.get("reachability_verdict"),
            "reason_not_fix_now": item.get("reason_not_fix_now"),
        }
        for item in backlog_clusters[:4]
    ]

    plan_count = sum(1 for case in backlog_cases if case.get("decision_tier") == "plan_remediation")
    monitor_count = sum(
        1 for case in backlog_cases if case.get("decision_tier") in {"monitor", "accept_risk"}
    )
    if backlog_clusters:
        summary_note = (
            f"Backlog is grouped into {len(backlog_clusters)} remediation cluster(s): "
            f"{plan_count} planned upgrade case(s), {monitor_count} monitor case(s), "
            f"{verdict_counts.get('no_sink_data', 0)} still missing sink-level evidence, "
            f"{verdict_counts.get('likely_unreachable', 0)} not observed as directly used."
        )
    else:
        summary_note = "No planned backlog items are currently open."
    return {
        "monitor_count": monitor_count,
        "plan_remediation_count": plan_count,
        "top_backlog_items": top_items,
        "backlog_clusters": backlog_clusters,
        "summary_note": summary_note,
    }


def _triage_summary(cases: list[AlertCase]) -> dict[str, int]:
    return {
        "total_cases": len(cases),
        "fix_now_count": sum(1 for case in cases if case.get("decision_tier") == "fix_now"),
        "plan_remediation_count": sum(
            1 for case in cases if case.get("decision_tier") == "plan_remediation"
        ),
        "mitigate_count": sum(1 for case in cases if case.get("decision_tier") == "mitigate"),
        "monitor_count": sum(
            1 for case in cases if case.get("decision_tier") in {"monitor", "accept_risk"}
        ),
        "confirmed_count": sum(
            1 for case in cases if case.get("reachability_verdict") == "confirmed_reachable"
        ),
        "likely_count": sum(
            1 for case in cases if case.get("reachability_verdict") == "likely_reachable"
        ),
        "unlikely_count": sum(
            1 for case in cases if case.get("reachability_verdict") == "likely_unreachable"
        ),
        "no_sink_data_count": sum(
            1 for case in cases if case.get("reachability_verdict") == "no_sink_data"
        ),
    }


def _verification_checklist() -> list[str]:
    return [
        "Regenerate SBOM after dependency updates for immediate remediation clusters.",
        "Rerun vulnerability enrichment to refresh advisory and version state.",
        "Rerun reachability and confirm immediate remediation clusters leave the direct-or-likely-use set.",
        "Confirm any remaining evidence is labeled production, test-only, or mixed.",
        "Move remediated cases to resolved_pending_verify, then verified_closed after follow-up validation.",
    ]


def _verification_delta(verification_delta: dict[str, Any] | None, scan_id: str | None) -> dict[str, Any]:
    summary = (verification_delta or {}).get("summary") or {}
    baseline_scan_id = summary.get("baseline_scan_id")
    current_scan_id = summary.get("current_scan_id") or scan_id
    resolved_cases = int(summary.get("resolved_cases") or 0)
    risk_decreased_cases = int(summary.get("risk_decreased") or 0)
    verdict_improved_cases = int(summary.get("verdict_improved") or 0)

    if baseline_scan_id and any(
        value > 0 for value in (resolved_cases, risk_decreased_cases, verdict_improved_cases)
    ):
        note = "Baseline comparison is meaningful and shows remediation progress."
    elif baseline_scan_id:
        note = "Baseline exists, but no meaningful remediation delta is visible yet."
    else:
        note = "No baseline comparison is available yet; wait for the next scan checkpoint."

    return {
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "resolved_cases": resolved_cases,
        "risk_decreased_cases": risk_decreased_cases,
        "verdict_improved_cases": verdict_improved_cases,
        "note": note,
    }


def _technical_finding(case: AlertCase) -> dict[str, Any]:
    call_locations = [str(item).strip() for item in (case.get("call_locations") or []) if str(item).strip()]
    impact_summary = str(
        case.get("impact_summary")
        or case.get("summary_note")
        or case.get("advisory_summary")
        or "No project-specific impact summary is currently available."
    )
    advisory_summary = str(case.get("advisory_summary") or "")
    return {
        "vuln_id": str(case.get("vuln_id") or ""),
        "component": str(case.get("component_name") or ""),
        "current_version": case.get("component_version"),
        "severity": str(case.get("severity") or "medium").lower(),
        "decision_tier": str(case.get("decision_tier") or "monitor"),
        "reachability_verdict": str(case.get("reachability_verdict") or "no_sink_data"),
        "dependency_depth": case.get("dependency_depth"),
        "cvss": case.get("cvss"),
        "risk_score": case.get("risk_score"),
        "fix_versions": list(case.get("fix_versions") or []),
        "sink_functions": list(case.get("sink_functions") or []),
        "call_locations": call_locations,
        "cve_description": advisory_summary,
        "nvd_url": _nvd_url(case.get("vuln_id")),
        "key_call_evidence": call_locations[:3],
        "impact_summary": impact_summary,
        "advisory_summary": advisory_summary,
        "why_this_tier": decision_tier_rationale(
            case.get("decision_tier"),
            kev=case.get("kev"),
            risk_score=case.get("risk_score"),
            reachability_verdict=case.get("reachability_verdict"),
            fix_versions=case.get("fix_versions"),
            scope=case.get("scope"),
            dependency_depth=case.get("dependency_depth"),
            evidence_confidence=case.get("evidence_confidence"),
        ),
    }


def _technical_appendix(cases: list[AlertCase], verification_delta: dict[str, Any] | None) -> dict[str, object]:
    production_only = 0
    test_only = 0
    mixed = 0
    for case in cases:
        production_locations, test_locations = split_call_locations(
            [str(item).strip() for item in (case.get("call_locations") or []) if str(item).strip()]
        )
        if production_locations and test_locations:
            mixed += 1
        elif production_locations:
            production_only += 1
        elif test_locations:
            test_only += 1

    _ = verification_delta
    return {
        "evidence_scope_summary": {
            "production_only_cases": production_only,
            "test_only_cases": test_only,
            "mixed_scope_cases": mixed,
        }
    }


def build_developer_report(
    project_name: str,
    alert_cases: list[AlertCase],
    *,
    generated_at: str | None = None,
    scan_id: str | None = None,
    source_commit: str | None = None,
    verification_delta: dict[str, Any] | None = None,
) -> DeveloperReport:
    """
    Build a schema-complete developer report from canonical AlertCase objects.
    """
    active_sorted_cases = _sort_cases(_active_cases(alert_cases))
    immediate_fix_queue = [
        _immediate_fix_item(case)
        for case in active_sorted_cases
        if case.get("decision_tier") == "fix_now"
        and case.get("reachability_verdict") in _REACHABLE_VERDICTS
    ]
    immediate_fix_clusters, immediate_fix_coverage = _immediate_fix_clusters(active_sorted_cases)
    planned_upgrade_backlog = _planned_upgrade_backlog(active_sorted_cases)
    cluster_verification_targets = [
        dict(item.get("verification_target") or {})
        for item in immediate_fix_clusters
        if item.get("verification_target")
    ]

    report: DeveloperReport = {
        "report_type": "developer",
        "project": project_name,
        "generated_at": generated_at or _utc_now_iso(),
        "scan_id": scan_id,
        "source_commit": source_commit,
        "triage_summary": _triage_summary(active_sorted_cases),
        "immediate_fix_queue": immediate_fix_queue,
        "planned_upgrade_backlog": planned_upgrade_backlog,
        "verification_checklist": _verification_checklist(),
        "verification_delta": _verification_delta(verification_delta, scan_id),
        "detailed_technical_findings": [_technical_finding(case) for case in active_sorted_cases],
        "technical_appendix": _technical_appendix(active_sorted_cases, verification_delta),
    }
    report["immediate_fix_clusters"] = immediate_fix_clusters
    report["immediate_fix_coverage"] = immediate_fix_coverage
    report["cluster_verification_targets"] = cluster_verification_targets
    report["reachability_legend"] = reachability_legend("developer")
    return report
