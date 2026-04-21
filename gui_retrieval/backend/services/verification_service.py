"""
Verification and closure-loop helpers for report-driven workflows.
"""

from __future__ import annotations

from typing import Any

from backend.models import DEFAULT_CASE_STATUS, normalize_case_status
from backend.services.case_state_service import (
    get_case_states,
    get_recent_report_runs,
    get_report_case_snapshot,
    upsert_case_state,
)
from backend.services.evidence_service import build_alert_cases_for_project


_VERDICT_RANK = {
    "confirmed_reachable": 4,
    "likely_reachable": 3,
    "no_sink_data": 2,
    "likely_unreachable": 1,
}

_REOPEN_STATUSES = {"resolved_pending_verify", "verified_closed"}


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


def _resolve_baseline_status(
    existing_row: dict[str, Any] | None,
    baseline_row: dict[str, Any] | None,
) -> str:
    return normalize_case_status(
        (existing_row or {}).get("status") or (baseline_row or {}).get("status"),
        default=DEFAULT_CASE_STATUS,
    )


def _compact_case(case: dict[str, Any]) -> dict[str, Any]:
    fix_available = bool(case.get("fix_available"))
    if "fix_available" not in case:
        fix_available = bool(case.get("fix_versions"))
    return {
        "project": case.get("project"),
        "vuln_id": case.get("vuln_id"),
        "component_id": case.get("component_id"),
        "risk_score": case.get("risk_score"),
        "reachability_verdict": case.get("reachability_verdict") or "no_sink_data",
        "fix_available": fix_available,
        "status": case.get("status"),
        "decision_tier": case.get("decision_tier"),
    }


def sync_case_status_with_previous_snapshot(
    project_name: str,
    current_cases: list[dict[str, Any]],
) -> dict[str, int]:
    """
    Align persisted case-status rows with latest snapshot before current run.

    Rules:
    - Current case not present in baseline snapshot => `new`
    - Current case present in baseline and currently closed/pending-verify => reopen to `under_review`
    - Baseline case missing from current run => `resolved_pending_verify` (unless already `verified_closed`)
    """
    baseline_cases: list[dict[str, Any]] = []
    for run in get_recent_report_runs(project_name, limit=20):
        snapshot = get_report_case_snapshot(run["run_id"])
        if snapshot:
            baseline_cases = snapshot
            break

    baseline_index = _index_by_case_key(baseline_cases)
    current_index = _index_by_case_key(current_cases)

    persisted_states = get_case_states(project_name)
    state_index: dict[tuple[str, str | None], dict[str, Any]] = {}
    for key, state in persisted_states.items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        _, vuln_id, component_id = key
        state_index[(str(vuln_id), component_id)] = state

    summary = {
        "baseline_case_count": len(baseline_index),
        "current_case_count": len(current_index),
        "new_cases": 0,
        "reopened_cases": 0,
        "resolved_cases": 0,
        "status_updates": 0,
    }

    for key in current_index:
        vuln_id, component_id = key
        existing_row = state_index.get(key)
        baseline_row = baseline_index.get(key)
        current_status = _resolve_baseline_status(existing_row, baseline_row)

        if baseline_row is None:
            summary["new_cases"] += 1
            target_status = "new"
        else:
            if current_status in _REOPEN_STATUSES:
                target_status = "under_review"
                summary["reopened_cases"] += 1
            else:
                target_status = current_status

        if current_status != target_status:
            summary["status_updates"] += 1
            upsert_case_state(
                project_name,
                vuln_id,
                component_id,
                status=target_status,
            )
        elif existing_row is None:
            # Ensure a state row exists even when no transition is needed.
            summary["status_updates"] += 1
            upsert_case_state(
                project_name,
                vuln_id,
                component_id,
                status=target_status,
            )

    resolved_keys = set(baseline_index.keys()) - set(current_index.keys())
    for vuln_id, component_id in resolved_keys:
        summary["resolved_cases"] += 1
        key = (vuln_id, component_id)
        existing_row = state_index.get(key)
        baseline_row = baseline_index.get(key)
        current_status = _resolve_baseline_status(existing_row, baseline_row)
        target_status = "verified_closed" if current_status == "verified_closed" else "resolved_pending_verify"

        if current_status != target_status:
            summary["status_updates"] += 1
            upsert_case_state(
                project_name,
                vuln_id,
                component_id,
                status=target_status,
            )
        elif existing_row is None:
            summary["status_updates"] += 1
            upsert_case_state(
                project_name,
                vuln_id,
                component_id,
                status=target_status,
            )

    return summary


def _to_index(cases: list[dict[str, Any]]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {_case_key(case): _compact_case(case) for case in cases if case.get("vuln_id")}


def _rank_verdict(verdict: str | None) -> int:
    return _VERDICT_RANK.get((verdict or "no_sink_data").strip().lower(), 2)


def build_verification_delta(
    old_cases: list[dict[str, Any]],
    new_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compare two case snapshots and return closure-oriented delta summary.
    """
    old_index = _to_index(old_cases)
    new_index = _to_index(new_cases)
    all_keys = sorted(set(old_index.keys()) | set(new_index.keys()))

    changes: list[dict[str, Any]] = []
    summary = {
        "old_case_count": len(old_index),
        "new_case_count": len(new_index),
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
            "change_type": [],
            "old_risk_score": old_case.get("risk_score") if old_case else None,
            "new_risk_score": new_case.get("risk_score") if new_case else None,
            "old_verdict": old_case.get("reachability_verdict") if old_case else None,
            "new_verdict": new_case.get("reachability_verdict") if new_case else None,
            "old_fix_available": old_case.get("fix_available") if old_case else None,
            "new_fix_available": new_case.get("fix_available") if new_case else None,
        }

        if old_case is None and new_case is not None:
            summary["added_cases"] += 1
            row["change_type"].append("added")
            changes.append(row)
            continue
        if old_case is not None and new_case is None:
            summary["resolved_cases"] += 1
            row["change_type"].append("resolved")
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
        elif old_fix and not new_fix:
            summary["fix_available_decreased"] += 1
            row["change_type"].append("fix_available_decreased")

        if not row["change_type"]:
            summary["unchanged"] += 1
            row["change_type"].append("unchanged")

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
    Compare current project cases against the latest available stored snapshot.
    """
    current_cases = [dict(case) for case in build_alert_cases_for_project(project_name)]

    snapshot_runs: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for run in get_recent_report_runs(project_name, limit=20):
        snapshot = get_report_case_snapshot(run["run_id"])
        if snapshot:
            snapshot_runs.append((run, snapshot))

    baseline_run = None
    baseline_cases: list[dict[str, Any]] = []
    if len(snapshot_runs) >= 2:
        # Use previous run snapshot (skip newest) for "current vs previous" semantics.
        baseline_run, baseline_cases = snapshot_runs[1]
    elif len(snapshot_runs) == 1:
        baseline_run, baseline_cases = snapshot_runs[0]

    delta = build_verification_delta(baseline_cases, current_cases)
    return {
        "project": project_name,
        "baseline_run": baseline_run,
        "baseline_case_count": len(baseline_cases),
        "current_case_count": len(current_cases),
        "delta": delta,
    }
