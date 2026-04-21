"""
Builder for Developer Remediation Report objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models import AlertCase, DeveloperReport


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sort_cases(cases: list[AlertCase]) -> list[AlertCase]:
    return sorted(
        cases,
        key=lambda case: (
            0 if case.get("decision_tier") == "fix_now" else 1,
            0 if case.get("kev") else 1,
            -(case.get("risk_score") or -1.0),
            -(case.get("cvss") or -1.0),
            case.get("vuln_id") or "",
            case.get("component_name") or "",
        ),
    )


def _technical_finding(case: AlertCase) -> dict[str, Any]:
    return {
        "vuln_id": case["vuln_id"],
        "component_name": case["component_name"],
        "component_version": case.get("component_version"),
        "component_id": case.get("component_id"),
        "severity": case["severity"],
        "cvss": case.get("cvss"),
        "epss": case.get("epss"),
        "kev": case.get("kev"),
        "scope": case.get("scope"),
        "dependency_depth": case.get("dependency_depth"),
        "reachability_verdict": case["reachability_verdict"],
        "call_locations": case.get("call_locations") or [],
        "fix_versions": case.get("fix_versions") or [],
        "risk_score": case.get("risk_score"),
        "decision_tier": case.get("decision_tier"),
        "status": case.get("status"),
        "summary_note": case.get("summary_note"),
    }


def _dependency_context(cases: list[AlertCase]) -> dict[str, int]:
    direct = sum(1 for case in cases if (case.get("dependency_depth") or 0) <= 1)
    transitive = sum(1 for case in cases if (case.get("dependency_depth") or 0) > 1)
    unknown = sum(1 for case in cases if case.get("dependency_depth") is None)
    return {
        "direct_dependency_cases": direct,
        "transitive_dependency_cases": transitive,
        "unknown_depth_cases": unknown,
    }


def _reachability_evidence(cases: list[AlertCase]) -> dict[str, Any]:
    verdict_counts = {
        "confirmed_reachable": 0,
        "likely_reachable": 0,
        "likely_unreachable": 0,
        "no_sink_data": 0,
    }
    sample_locations: list[str] = []
    seen_locations: set[str] = set()
    for case in cases:
        verdict = str(case.get("reachability_verdict") or "no_sink_data")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        for loc in case.get("call_locations") or []:
            loc_str = str(loc).strip()
            if not loc_str or loc_str in seen_locations:
                continue
            seen_locations.add(loc_str)
            sample_locations.append(loc_str)
            if len(sample_locations) >= 12:
                break
        if len(sample_locations) >= 12:
            break
    return {
        "confirmed_reachable": verdict_counts.get("confirmed_reachable", 0),
        "likely_reachable": verdict_counts.get("likely_reachable", 0),
        "likely_unreachable": verdict_counts.get("likely_unreachable", 0),
        "no_sink_data": verdict_counts.get("no_sink_data", 0),
        "sample_call_locations": sample_locations,
    }


def _recommended_fix(cases: list[AlertCase]) -> list[dict[str, Any]]:
    prioritized = sorted(
        cases,
        key=lambda case: (
            0 if case.get("decision_tier") == "fix_now" else 1,
            0 if case.get("fix_versions") else 1,
            -(case.get("risk_score") or -1.0),
            case.get("vuln_id") or "",
        ),
    )
    fixes: list[dict[str, Any]] = []
    for case in prioritized[:25]:
        fixes.append(
            {
                "vuln_id": case["vuln_id"],
                "component_name": case["component_name"],
                "component_version": case.get("component_version"),
                "decision_tier": case["decision_tier"],
                "fix_versions": case.get("fix_versions") or [],
                "summary_note": case.get("summary_note"),
            }
        )
    return fixes


def build_developer_report(
    project_name: str,
    alert_cases: list[AlertCase],
    *,
    generated_at: str | None = None,
) -> DeveloperReport:
    """
    Build a schema-complete developer report from canonical AlertCase objects.
    """
    ordered = _sort_cases(alert_cases)
    fix_now_cases = [case for case in ordered if case.get("decision_tier") == "fix_now"]
    investigate_next_cases = [
        case for case in ordered if case.get("decision_tier") in {"plan_remediation", "mitigate"}
    ]
    monitor_cases = [
        case for case in ordered if case.get("decision_tier") in {"monitor", "accept_risk"}
    ]

    report: DeveloperReport = {
        "report_type": "developer",
        "project": project_name,
        "generated_at": generated_at or _utc_now_iso(),
        "triage_summary": {
            "total_cases": len(ordered),
            "fix_now": len(fix_now_cases),
            "investigate_next": len(investigate_next_cases),
            "monitor": len(monitor_cases),
        },
        "technical_findings": [_technical_finding(case) for case in ordered],
        "dependency_context": _dependency_context(ordered),
        "reachability_evidence": _reachability_evidence(ordered),
        "recommended_fix": _recommended_fix(ordered),
        "verification_steps": [
            "Rerun SBOM generation after dependency updates.",
            "Rerun vulnerability enrichment and refresh graph data.",
            "Rerun reachability analysis and compare verdict deltas.",
            "Verify upgraded package versions are present in the regenerated SBOM.",
            "Move remediated items to `resolved_pending_verify`, then to `verified_closed` after confirmation.",
        ],
    }
    return report
