"""
Shared grouping helpers for report-centric rendering.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from backend.models import AlertCase
from backend.services.report_presentation_service import select_preferred_fix_version

_TEST_MARKERS = ("test", "tests", "__tests__", "spec", "fixture", "fixtures")
_REACHABILITY_ORDER = {
    "confirmed_reachable": 0,
    "likely_reachable": 1,
    "no_sink_data": 2,
    "likely_unreachable": 3,
    "unknown": 4,
}
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}
_TIER_ORDER = {
    "fix_now": 0,
    "plan_remediation": 1,
    "mitigate": 2,
    "monitor": 3,
    "accept_risk": 4,
}


def _is_test_path(path: str) -> bool:
    value = path.lower()
    return any(marker in value for marker in _TEST_MARKERS)


def split_call_locations(locations: list[str]) -> tuple[list[str], list[str]]:
    production: list[str] = []
    test_only: list[str] = []
    for raw in locations:
        item = str(raw).strip()
        if not item:
            continue
        if _is_test_path(item):
            test_only.append(item)
        else:
            production.append(item)
    return production, test_only


def classify_evidence_scope(case: AlertCase) -> str:
    locations = [str(item) for item in (case.get("call_locations") or []) if str(item).strip()]
    production, test_only = split_call_locations(locations)
    if production and test_only:
        return "mixed"
    if production:
        return "production"
    if test_only:
        return "test-only"
    return "unknown"


def infer_primary_evidence_area(case: AlertCase) -> str:
    locations = [str(item) for item in (case.get("call_locations") or []) if str(item).strip()]
    production, test_only = split_call_locations(locations)
    source = production or test_only
    if not source:
        return "unknown_area"

    path = source[0].replace("\\", "/").strip("/")
    if not path:
        return "unknown_area"
    first_segment = path.split("/", 1)[0].lower()
    if first_segment:
        return first_segment
    return "unknown_area"


def _representative_case(cases: list[AlertCase]) -> AlertCase:
    ranked = sorted(
        cases,
        key=lambda case: (
            _REACHABILITY_ORDER.get(str(case.get("reachability_verdict") or "unknown"), 9),
            _TIER_ORDER.get(str(case.get("decision_tier") or "monitor"), 9),
            _SEVERITY_ORDER.get(str(case.get("severity") or "low").lower(), 9),
            -(case.get("risk_score") or -1.0),
            -(case.get("cvss") or -1.0),
            str(case.get("vuln_id") or ""),
        ),
    )
    return ranked[0]


def _cluster_key(case: AlertCase, *, area_name: str | None = None) -> tuple[str, ...]:
    return (
        str(case.get("component_name") or "unknown-component").strip().lower(),
        str(case.get("component_version") or "unknown-version").strip().lower(),
        str(select_preferred_fix_version(case.get("fix_versions")) or "target_pending").strip().lower(),
        str(area_name or infer_primary_evidence_area(case)).strip().lower(),
        str(case.get("decision_tier") or "monitor").strip().lower(),
        classify_evidence_scope(case),
    )


def cluster_cases_by_remediation(
    cases: list[AlertCase],
    *,
    area_by_case: dict[tuple[str, str | None], str] | None = None,
) -> list[dict[str, Any]]:
    """
    Cluster cases by practical remediation path so one cluster can represent
    multiple CVEs that are fixed by the same upgrade/action.
    """
    buckets: dict[tuple[str, ...], list[AlertCase]] = {}
    for case in cases:
        case_key = (str(case.get("vuln_id") or ""), case.get("component_id"))
        area_name = (area_by_case or {}).get(case_key)
        key = _cluster_key(case, area_name=area_name)
        buckets.setdefault(key, []).append(case)

    clusters: list[dict[str, Any]] = []
    for key, grouped_cases in buckets.items():
        representative = _representative_case(grouped_cases)
        related_cves: list[str] = []
        for grouped in grouped_cases:
            vuln_id = str(grouped.get("vuln_id") or "").strip()
            if vuln_id and vuln_id not in related_cves:
                related_cves.append(vuln_id)

        severity_counts = Counter(
            str(grouped.get("severity") or "medium").lower()
            for grouped in grouped_cases
        )
        reachability_counts = Counter(
            str(grouped.get("reachability_verdict") or "no_sink_data")
            for grouped in grouped_cases
        )
        evidence_counts = Counter(classify_evidence_scope(grouped) for grouped in grouped_cases)

        all_locations: list[str] = []
        for grouped in grouped_cases:
            for location in (grouped.get("call_locations") or []):
                text = str(location).strip()
                if text and text not in all_locations:
                    all_locations.append(text)

        cluster = {
            "cluster_id": "|".join(key),
            "component": str(representative.get("component_name") or "unknown-component"),
            "current_version": representative.get("component_version"),
            "target_version": select_preferred_fix_version(representative.get("fix_versions")),
            "decision_tier": str(representative.get("decision_tier") or "monitor"),
            "related_case_count": len(grouped_cases),
            "related_cves": related_cves,
            "severity_counts": dict(severity_counts),
            "reachability_counts": dict(reachability_counts),
            "evidence_scope_counts": dict(evidence_counts),
            "strongest_reachability": min(
                reachability_counts.keys(),
                key=lambda verdict: _REACHABILITY_ORDER.get(verdict, 9),
            ) if reachability_counts else "no_sink_data",
            "affected_area": key[3].replace("_", " "),
            "key_call_locations": all_locations[:5],
            "has_fix_available": any(bool(grouped.get("fix_versions")) for grouped in grouped_cases),
            "max_risk_score": max((grouped.get("risk_score") or 0.0) for grouped in grouped_cases),
            "max_cvss": max((grouped.get("cvss") or 0.0) for grouped in grouped_cases),
            "includes_kev": any(bool(grouped.get("kev")) for grouped in grouped_cases),
            "representative_vuln_id": str(representative.get("vuln_id") or ""),
            "representative_case": representative,
            "cases": grouped_cases,
        }
        clusters.append(cluster)

    clusters.sort(
        key=lambda cluster: (
            _TIER_ORDER.get(str(cluster.get("decision_tier") or "monitor"), 9),
            _REACHABILITY_ORDER.get(str(cluster.get("strongest_reachability") or "unknown"), 9),
            0 if cluster.get("has_fix_available") else 1,
            -float(cluster.get("max_risk_score") or 0.0),
            -float(cluster.get("max_cvss") or 0.0),
            str(cluster.get("component") or ""),
        ),
    )
    return clusters
