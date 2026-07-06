"""
Verification and closure-loop helpers for report-driven workflows.
"""

from __future__ import annotations

from typing import Any

from backend.services.case_state_service import (
    get_recent_report_runs,
    get_report_case_snapshot,
    get_case_states,
    upsert_case_state,
)
from backend.services.evidence_service import build_alert_cases_for_project


_VERDICT_RANK = {
    "confirmed_reachable": 4,
    "likely_reachable": 3,
    "no_sink_data": 2,
    "likely_unreachable": 1,
}


def _case_key(case: dict[str, Any]) -> tuple[str, str | None]:
    vuln_id = str(case.get("vuln_id") or "").strip()
    raw_component_id = case.get("component_id")
    if raw_component_id is None:
        component_id = None
    else:
        text = str(raw_component_id).strip()
        component_id = text or None
    return (vuln_id, component_id)


def _index_by_case_key(cases: list[dict[str, Any]]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {_case_key(case): case for case in cases if str(case.get("vuln_id") or "").strip()}


def _compact_case(case: dict[str, Any]) -> dict[str, Any]:
    fix_available = bool(case.get("fix_available"))
    if "fix_available" not in case:
        fix_available = bool(case.get("fix_versions"))
    return {
        "project": case.get("project"),
        "vuln_id": case.get("vuln_id"),
        "component_id": case.get("component_id"),
        "scan_id": case.get("scan_id"),
        "source_commit": case.get("source_commit"),
        "risk_score": case.get("risk_score"),
        "reachability_verdict": case.get("reachability_verdict") or "no_sink_data",
        "fix_available": fix_available,
        "status": case.get("status"),
        "decision_tier": case.get("decision_tier"),
        "verification_basis": case.get("verification_basis"),
    }


def sync_case_status_with_previous_snapshot(
    project_name: str,
    current_cases: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Keep case-state rows available for current cases without run-history snapshots.
    """
    current_index = _index_by_case_key(current_cases)

    persisted_states = get_case_states(project_name)
    state_index: dict[tuple[str, str | None], dict[str, Any]] = {}
    for key, state in persisted_states.items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        _, vuln_id, component_id = key
        state_index[(str(vuln_id), component_id)] = state

    summary = {
        "baseline_case_count": 0,
        "current_case_count": len(current_index),
        "new_cases": 0,
        "reopened_cases": 0,
        "resolved_cases": 0,
        "status_updates": 0,
    }

    for key in current_index:
        vuln_id, component_id = key
        existing_row = state_index.get(key)
        if existing_row is None:
            summary["new_cases"] += 1
            summary["status_updates"] += 1
            upsert_case_state(
                project_name,
                vuln_id,
                component_id,
                status="new",
                last_seen_scan_id=current_index[key].get("scan_id"),
            )

    return summary


def _to_index(cases: list[dict[str, Any]]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {_case_key(case): _compact_case(case) for case in cases if case.get("vuln_id")}


def _rank_verdict(verdict: str | None) -> int:
    return _VERDICT_RANK.get((verdict or "no_sink_data").strip().lower(), 2)


def build_verification_delta(
    old_cases: list[dict[str, Any]],
    new_cases: list[dict[str, Any]],
    *,
    baseline_scan_id: str | None = None,
    current_scan_id: str | None = None,
) -> dict[str, Any]:
    """
    Compare two case snapshots and return closure-oriented delta summary.
    """
    old_index = _to_index(old_cases)
    new_index = _to_index(new_cases)
    all_keys = sorted(set(old_index.keys()) | set(new_index.keys()))

    changes: list[dict[str, Any]] = []
    summary = {
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "baseline_case_count": len(old_index),
        "current_case_count": len(new_index),
        "added_cases": 0,
        "resolved_cases": 0,
        "risk_increased": 0,
        "risk_decreased": 0,
        "verdict_improved": 0,
        "verdict_regressed": 0,
        "fix_available_increased": 0,
        "fix_available_decreased": 0,
        "unchanged": 0,
    }

    for key in all_keys:
        old_case = old_index.get(key)
        new_case = new_index.get(key)
        vuln_id, component_id = key
        row: dict[str, Any] = {
            "vuln_id": vuln_id,
            "component_id": component_id,
            "baseline_scan_id": old_case.get("scan_id") if old_case else baseline_scan_id,
            "current_scan_id": new_case.get("scan_id") if new_case else current_scan_id,
            "change_type": [],
            "baseline_risk_score": old_case.get("risk_score") if old_case else None,
            "current_risk_score": new_case.get("risk_score") if new_case else None,
            "baseline_verdict": old_case.get("reachability_verdict") if old_case else None,
            "current_verdict": new_case.get("reachability_verdict") if new_case else None,
        }

        if old_case is None and new_case is not None:
            summary["added_cases"] += 1
            row["change_type"].append("added")
            row["risk_delta"] = None
            row["fix_delta"] = "new_case_detected"
            row["closure_recommendation"] = "Keep open and triage from the current scan."
            changes.append(row)
            continue
        if old_case is not None and new_case is None:
            summary["resolved_cases"] += 1
            row["change_type"].append("resolved")
            row["risk_delta"] = None
            row["fix_delta"] = "case_absent_in_current_scan"
            row["closure_recommendation"] = "Move to resolved_pending_verify or verified_closed after confirmation."
            changes.append(row)
            continue

        old_risk = old_case.get("risk_score")
        new_risk = new_case.get("risk_score")
        if old_risk is not None and new_risk is not None:
            delta = round(float(new_risk) - float(old_risk), 4)
            row["risk_delta"] = delta
            if delta > 0.01:
                summary["risk_increased"] += 1
                row["change_type"].append("risk_increased")
            elif delta < -0.01:
                summary["risk_decreased"] += 1
                row["change_type"].append("risk_decreased")
        else:
            row["risk_delta"] = None

        old_rank = _rank_verdict(old_case.get("reachability_verdict"))
        new_rank = _rank_verdict(new_case.get("reachability_verdict"))
        if new_rank < old_rank:
            summary["verdict_improved"] += 1
            row["change_type"].append("verdict_improved")
        elif new_rank > old_rank:
            summary["verdict_regressed"] += 1
            row["change_type"].append("verdict_regressed")

        old_fix = bool(old_case.get("fix_available"))
        new_fix = bool(new_case.get("fix_available"))
        if not old_fix and new_fix:
            summary["fix_available_increased"] += 1
            row["change_type"].append("fix_available_increased")
            row["fix_delta"] = "fix_became_available"
        elif old_fix and not new_fix:
            summary["fix_available_decreased"] += 1
            row["change_type"].append("fix_available_decreased")
            row["fix_delta"] = "fix_no_longer_available"
        else:
            row["fix_delta"] = "unchanged"

        if not row["change_type"]:
            summary["unchanged"] += 1
            row["change_type"].append("unchanged")

        current_verdict = str(new_case.get("reachability_verdict") or "no_sink_data")
        current_fix = bool(new_case.get("fix_available"))
        if "resolved" in row["change_type"] or current_verdict == "likely_unreachable":
            row["closure_recommendation"] = "Candidate for verification closure after confirming the new scan."
        elif current_fix and current_verdict in {"confirmed_reachable", "likely_reachable"}:
            row["closure_recommendation"] = "Remediate and rerun SBOM plus reachability to confirm risk reduction."
        else:
            row["closure_recommendation"] = "Keep monitoring until remediation evidence improves."
        changes.append(row)

    changes.sort(
        key=lambda item: (
            0 if "verdict_regressed" in item["change_type"] else 1,
            0 if "risk_increased" in item["change_type"] else 1,
            -abs(float(item.get("risk_delta") or 0.0)),
            item.get("vuln_id") or "",
            item.get("component_id") or "",
        )
    )
    return {"summary": summary, "changes": changes}


def compare_current_vs_previous_report(project_name: str) -> dict[str, Any]:
    """
    Compare current project cases against the most recent previous report snapshot.
    """
    current_cases = [dict(case) for case in build_alert_cases_for_project(project_name)]
    current_scan_id = next(
        (str(case.get("scan_id")) for case in current_cases if case.get("scan_id")),
        None,
    )

    baseline_run = None
    baseline_cases: list[dict[str, Any]] = []
    for run in get_recent_report_runs(project_name, limit=10):
        if current_scan_id and str(run.get("scan_id") or "") == current_scan_id:
            continue
        snapshot = get_report_case_snapshot(str(run.get("run_id") or ""))
        if snapshot:
            baseline_run = run
            baseline_cases = snapshot
            break

    baseline_scan_id = baseline_run.get("scan_id") if baseline_run else None
    delta = build_verification_delta(
        baseline_cases,
        current_cases,
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
    )
    return {
        "project": project_name,
        "baseline_run": baseline_run,
        "baseline_case_count": len(baseline_cases),
        "current_case_count": len(current_cases),
        "baseline_scan_id": baseline_scan_id,
        "current_scan_id": current_scan_id,
        "delta": delta,
    }
