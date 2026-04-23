"""
Top-level orchestration service for stakeholder/developer report generation.
"""

from __future__ import annotations

from typing import Any

import backend.config as config
from backend.models import DeveloperReport, StakeholderReport
from backend.services.case_state_service import (
    get_case_states,
    record_report_case_snapshot,
    record_report_run,
)
from backend.services.developer_report_builder import build_developer_report
from backend.services.evidence_service import (
    build_alert_cases,
    recompute_and_overwrite_case_state_tiers,
)
from backend.services.report_vocabulary_service import (
    present_decision_tier,
    present_evidence_scope,
    present_reachability,
)
from backend.services.stakeholder_report_builder import build_stakeholder_report

_REPORT_VERSION = "4.0"

_STAKEHOLDER_SECTION_TITLES = {
    "what_needs_attention_now": "What Needs Attention Now",
    "why_it_matters_now": "Why It Matters Now",
    "decision_needed_next": "What Action Or Approval Is Needed Next",
    "what_remains_uncertain": "What Remains Under Observation",
}

_DEVELOPER_SECTION_TITLES = {
    "queue_overview": "Queue Overview",
    "strongest_evidence": "Strongest Evidence",
    "immediate_next_steps": "Immediate Next Steps",
    "verification_guidance": "Verification Guidance",
    "remaining_uncertainty": "What Is Still Uncertain Or Deferred",
}

_LEAK_MARKERS = (
    "let's break down",
    "the instructions say",
    "report json:",
    "return markdown with exactly these sections",
)


def get_report_runtime_version() -> str:
    """
    Public cache/version token for UI layers so report objects are regenerated when
    builder/export behavior changes.
    """
    return _REPORT_VERSION


def _paragraph(value: str) -> str:
    return " ".join(str(value or "").split()).strip()


def _join_sentences(values: list[str]) -> str:
    cleaned = [_paragraph(value) for value in values if _paragraph(value)]
    return " ".join(cleaned).strip()


def _combine_narrative(section_titles: dict[str, str], sections: dict[str, str]) -> str:
    parts: list[str] = []
    for key, title in section_titles.items():
        parts.append(f"## {title}")
        parts.append(str(sections.get(key) or "No evidence provided.").strip() or "No evidence provided.")
        parts.append("")
    return "\n".join(parts).strip()


def _build_stakeholder_narrative_sections(report: StakeholderReport) -> dict[str, str]:
    posture = report.get("posture_summary") or {}
    impact = report.get("impact_summary") or {}
    snapshot = report.get("current_action_snapshot") or {}
    affected_areas = report.get("affected_areas") or []
    top_actions = report.get("top_priority_actions") or []
    actions = report.get("recommended_management_actions") or []
    confirmed = int(posture.get("reachable_count") or 0)
    likely = int(posture.get("likely_reachable_count") or 0)
    critical_high = int(posture.get("critical_high_count") or 0)
    kev = int(posture.get("kev_count") or 0)
    total = int(posture.get("total_cases") or 0)
    fix_available = int(posture.get("fix_available_count") or 0)
    fix_now = int(snapshot.get("fix_now_count") or 0)
    monitor = int(snapshot.get("monitor_count") or 0)
    direct = int(impact.get("direct_count") or 0)
    transitive = int(impact.get("transitive_count") or 0)
    area_summary = ", ".join(
        f"{item.get('area_name')} ({int(item.get('case_count') or 0)} case(s))"
        for item in affected_areas[:2]
    )
    if not area_summary:
        area_summary = "repository-wide exposure"

    prioritized_actions = []
    for item in top_actions[:2]:
        decision_label = present_decision_tier(item.get("decision_tier"), "stakeholder")
        prioritized_actions.append(
            _join_sentences(
                [
                    f"{item.get('component') or 'Dependency'} is in the {decision_label.lower()} category.",
                    str(item.get("why_now") or ""),
                    (
                        f"Preferred version path: {item.get('current_version') or 'unknown'} -> "
                        f"{item.get('target_version') or 'target pending'}."
                    ),
                ]
            )
        )
    prioritized_text = " ".join(prioritized_actions) if prioritized_actions else "No priority remediation cluster is listed yet."

    what_needs_attention_now = _join_sentences(
        [
            (
                f"{fix_now} case(s) currently need action in the current release window, out of {total} active case(s) overall."
            ),
            (
                f"{confirmed} case(s) {present_reachability('confirmed_reachable', 'stakeholder', style='sentence')} "
                f"and {likely} case(s) {present_reachability('likely_reachable', 'stakeholder', style='sentence')}."
            ),
            prioritized_text,
        ]
    )

    why_it_matters_now = _join_sentences(
        [
            (
                f"The current exposure mix includes {critical_high} critical or high-severity case(s) and {kev} case(s) linked to known exploitation activity."
            ),
            (
                f"Current evidence spans {area_summary}, with {direct} direct and {transitive} transitive dependency case(s) still active."
            ),
            (
                f"{fix_available} case(s) already have a known fix path, so delaying action would leave avoidable exposure in place."
            ),
        ]
    )

    decision_needed_next = _join_sentences(
        [
            _join_sentences(
                [
                    str(item.get("action") or ""),
                    str(item.get("reason") or ""),
                ]
            )
            for item in actions[:3]
        ]
    ) or "No decision request is available yet."

    what_remains_uncertain = _join_sentences(
        [
            (
                f"{monitor} case(s) remain under observation and should not be treated as safe simply because the current scan is less conclusive."
            ),
            (
                str((report.get("next_verification_checkpoint") or {}).get("note") or "")
            ),
            (
                str((report.get("area_mapping") or {}).get("note") or impact.get("area_mapping_note") or "")
            ),
        ]
    )

    return {
        "what_needs_attention_now": what_needs_attention_now or "No evidence provided.",
        "why_it_matters_now": why_it_matters_now or "No evidence provided.",
        "decision_needed_next": decision_needed_next or "No evidence provided.",
        "what_remains_uncertain": what_remains_uncertain or "No evidence provided.",
    }


def _build_developer_narrative_sections(report: DeveloperReport) -> dict[str, str]:
    triage = report.get("triage_summary") or {}
    immediate_fix_queue = report.get("immediate_fix_queue") or []
    backlog = report.get("planned_upgrade_backlog") or {}
    queue_overview = _join_sentences(
        [
            (
                f"{report.get('project')} currently has {int(triage.get('fix_now_count') or 0)} item(s) in the immediate queue, "
                f"{int(triage.get('plan_remediation_count') or 0)} planned upgrade item(s), "
                f"{int(triage.get('mitigate_count') or 0)} mitigation or investigation item(s), "
                f"and {int(triage.get('monitor_count') or 0)} monitor item(s)."
            ),
            (
                f"Direct call evidence exists for {int(triage.get('confirmed_count') or 0)} case(s), and "
                f"another {int(triage.get('likely_count') or 0)} case(s) have import or usage evidence without a direct vulnerable sink call confirmation."
            ),
        ]
    )

    strongest_evidence = "No immediate remediation cluster is currently present."
    immediate_next_steps = "Keep working from the planned upgrade backlog and rerun verification after changes."
    verification_guidance = _join_sentences(list(report.get("verification_checklist") or [])[:2])

    if immediate_fix_queue:
        leading = immediate_fix_queue[0]
        evidence_scope = (
            "production"
            if leading.get("production_evidence")
            else "test-only"
            if leading.get("test_only_evidence")
            else "unknown"
        )
        strongest_evidence = _join_sentences(
            [
                (
                    f"The leading item is {leading.get('vuln_id') or 'N/A'} on {leading.get('component') or 'unknown dependency'}."
                ),
                (
                    f"It {present_reachability(leading.get('reachability_verdict'), 'developer', style='sentence')} "
                    f"with {present_evidence_scope(evidence_scope, 'developer').lower()}."
                ),
                str(leading.get("why_fix_now") or ""),
            ]
        )
        immediate_next_steps = _join_sentences(
            [
                str(leading.get("next_action") or ""),
                (
                    f"Preferred target version: {leading.get('target_version') or 'target pending'}."
                ),
            ]
        )
    elif backlog.get("summary_note"):
        strongest_evidence = str(backlog.get("summary_note") or "")

    if report.get("cluster_verification_targets"):
        first_target = (report.get("cluster_verification_targets") or [])[0]
        verification_guidance = _join_sentences(
            [
                str(first_target.get("what_must_change") or ""),
                str(first_target.get("scan_recheck") or ""),
                str(first_target.get("success_criteria") or ""),
            ]
        )

    remaining_uncertainty = _join_sentences(
        [
            (
                f"{int(triage.get('no_sink_data_count') or 0)} case(s) still lack sink-level evidence, which means practical reachability is unresolved rather than disproven."
            ),
            (
                f"{int(triage.get('unlikely_count') or 0)} case(s) were not observed as directly used in the current scan, but they should stay in view until future scans or code changes confirm the downgrade."
            ),
            str((report.get("verification_delta") or {}).get("note") or ""),
        ]
    )

    return {
        "queue_overview": queue_overview or "No evidence provided.",
        "strongest_evidence": strongest_evidence or "No evidence provided.",
        "immediate_next_steps": immediate_next_steps or "No evidence provided.",
        "verification_guidance": verification_guidance or "No evidence provided.",
        "remaining_uncertainty": remaining_uncertainty or "No evidence provided.",
    }


def _sections_are_sufficient(sections: dict[str, str], required_keys: tuple[str, ...]) -> bool:
    if any(not _paragraph(sections.get(key) or "") for key in required_keys):
        return False
    combined = " ".join(_paragraph(sections.get(key) or "") for key in required_keys).lower()
    return not any(marker in combined for marker in _LEAK_MARKERS)


def _apply_stakeholder_narrative(report: StakeholderReport, use_llm: bool) -> None:
    fallback_sections = _build_stakeholder_narrative_sections(report)
    if not use_llm:
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_STAKEHOLDER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_toggle_off"
        return
    if not config.llm_credentials_available():
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_STAKEHOLDER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "missing_llm_credentials"
        return
    try:
        from backend.services.llm_service import generate_stakeholder_report_narrative_sections

        llm_sections = generate_stakeholder_report_narrative_sections(report)
        if _sections_are_sufficient(
            llm_sections,
            (
                "what_needs_attention_now",
                "why_it_matters_now",
                "decision_needed_next",
                "what_remains_uncertain",
            ),
        ):
            report["narrative_sections"] = llm_sections
            report["narrative"] = _combine_narrative(_STAKEHOLDER_SECTION_TITLES, llm_sections)
            report["narrative_source"] = "llm"
            report["narrative_reason"] = "llm_applied"
        else:
            report["narrative_sections"] = fallback_sections
            report["narrative"] = _combine_narrative(_STAKEHOLDER_SECTION_TITLES, fallback_sections)
            report["narrative_source"] = "fallback"
            report["narrative_reason"] = "llm_output_insufficient"
    except Exception:
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_STAKEHOLDER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_runtime_error"


def _validate_stakeholder_rendering(report: StakeholderReport) -> None:
    snapshot = report.get("current_action_snapshot") or {}
    fix_now_total = int(snapshot.get("fix_now_count") or 0)
    actions = report.get("top_priority_actions") or []

    covered_fix_now = 0
    for item in actions:
        if str(item.get("decision_tier") or "") != "fix_now":
            continue
        related_count = item.get("related_case_count")
        if related_count is None:
            covered_fix_now += 1
        else:
            covered_fix_now += int(related_count or 0)
    coverage = report.get("top_priority_action_coverage") or {}
    coverage["fix_now_total"] = fix_now_total
    coverage["fix_now_covered_in_display"] = covered_fix_now
    coverage["uncovered_fix_now_cases"] = max(fix_now_total - covered_fix_now, 0)
    if fix_now_total > 0:
        coverage["coverage_note"] = (
            f"Displayed top-priority clusters cover {covered_fix_now}/{fix_now_total} current-release case(s)."
        )
    else:
        coverage["coverage_note"] = "No current-release cases are currently open."
    report["top_priority_action_coverage"] = coverage

    impact = report.get("impact_summary") or {}
    area_mapping = report.get("area_mapping") or {}
    if not area_mapping:
        area_mapping = {
            "mapping_confidence": str(impact.get("area_mapping_confidence") or "partial"),
            "note": str(impact.get("area_mapping_note") or ""),
        }
    if not area_mapping.get("note"):
        if str(area_mapping.get("mapping_confidence") or "partial") == "partial":
            area_mapping["note"] = (
                "Impact mapping is partial; use repository-wide exposure framing where area isolation is incomplete."
            )
        else:
            area_mapping["note"] = "Impact mapping is sufficient to highlight top affected areas."
    report["area_mapping"] = area_mapping


def _apply_developer_narrative(report: DeveloperReport, use_llm: bool) -> None:
    fallback_sections = _build_developer_narrative_sections(report)
    if not use_llm:
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_DEVELOPER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_toggle_off"
        return
    if not config.llm_credentials_available():
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_DEVELOPER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "missing_llm_credentials"
        return
    try:
        from backend.services.llm_service import generate_developer_report_narrative_sections

        llm_sections = generate_developer_report_narrative_sections(report)
        if _sections_are_sufficient(
            llm_sections,
            (
                "queue_overview",
                "strongest_evidence",
                "immediate_next_steps",
                "verification_guidance",
                "remaining_uncertainty",
            ),
        ):
            report["narrative_sections"] = llm_sections
            report["narrative"] = _combine_narrative(_DEVELOPER_SECTION_TITLES, llm_sections)
            report["narrative_source"] = "llm"
            report["narrative_reason"] = "llm_applied"
        else:
            report["narrative_sections"] = fallback_sections
            report["narrative"] = _combine_narrative(_DEVELOPER_SECTION_TITLES, fallback_sections)
            report["narrative_source"] = "fallback"
            report["narrative_reason"] = "llm_output_insufficient"
    except Exception:
        report["narrative_sections"] = fallback_sections
        report["narrative"] = _combine_narrative(_DEVELOPER_SECTION_TITLES, fallback_sections)
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_runtime_error"


def _validate_developer_rendering(report: DeveloperReport) -> None:
    triage = report.get("triage_summary") or {}
    fix_now_total = int(triage.get("fix_now_count") or 0)
    clusters = report.get("immediate_fix_clusters") or []
    covered = sum(int(item.get("related_case_count") or 0) for item in clusters)
    coverage = report.get("immediate_fix_coverage") or {}
    coverage["fix_now_total"] = fix_now_total
    coverage["fix_now_covered_by_clusters"] = covered
    coverage["uncovered_fix_now_cases"] = max(fix_now_total - covered, 0)
    if fix_now_total > 0:
        coverage["coverage_note"] = (
            f"Immediate remediation clusters account for {covered}/{fix_now_total} immediate-queue case(s)."
        )
    else:
        coverage["coverage_note"] = "No immediate-queue cases are currently open."
    report["immediate_fix_coverage"] = coverage

    if not report.get("cluster_verification_targets"):
        generated_targets = []
        for item in clusters:
            target = item.get("verification_target") or {}
            if target:
                generated_targets.append(target)
        report["cluster_verification_targets"] = generated_targets


def generate_stakeholder_report(
    project_name: str,
    *,
    scan_id: str | None = None,
    use_llm: bool = True,
) -> StakeholderReport:
    """
    Generate stakeholder report object from canonical alert cases.
    """
    from backend.repositories import graph_repository as repo

    bundle = repo.get_stakeholder_report_inputs(project_name, scan_id=scan_id)
    alert_rows = bundle.get("alerts") or []
    reachability_index = repo.load_reachability(project_name)
    recompute_and_overwrite_case_state_tiers(
        project_name,
        alert_rows,
        reachability_index=reachability_index,
    )
    case_states = get_case_states(project_name)

    alert_cases = build_alert_cases(
        alert_rows,
        reachability_index=reachability_index,
        case_states=case_states,
    )
    latest_scan_meta = bundle.get("latest_scan_metadata") or {}
    verification_comparison: dict[str, Any] | None = None
    try:
        from backend.services.verification_service import compare_current_vs_previous_report

        verification_comparison = compare_current_vs_previous_report(project_name)
    except Exception:
        verification_comparison = None

    report = build_stakeholder_report(
        project_name,
        alert_cases,
        scan_id=latest_scan_meta.get("scan_id"),
        source_commit=latest_scan_meta.get("source_commit"),
        verification_summary=(verification_comparison or {}).get("delta"),
    )
    run_id = record_report_run(
        project_name,
        scan_id=report.get("scan_id"),
        generated_at=report.get("generated_at"),
        source_commit=report.get("source_commit"),
        report_version=_REPORT_VERSION,
    )
    report["run_id"] = run_id
    record_report_case_snapshot(project_name, run_id, alert_cases)

    _apply_stakeholder_narrative(report, use_llm=use_llm)
    _validate_stakeholder_rendering(report)
    return report


def generate_developer_report(
    project_name: str,
    *,
    vuln_id: str | None = None,
    component_id: str | None = None,
    scan_id: str | None = None,
    use_llm: bool = True,
) -> DeveloperReport:
    """
    Generate developer report object from canonical alert cases.
    """
    from backend.repositories import graph_repository as repo

    bundle = repo.get_developer_report_inputs(
        project_name,
        vuln_id=vuln_id,
        component_id=component_id,
        scan_id=scan_id,
    )
    alert_rows = bundle.get("alerts") or []
    reachability_index = bundle.get("reachability_index") or repo.load_reachability(project_name)
    recompute_and_overwrite_case_state_tiers(
        project_name,
        alert_rows,
        reachability_index=reachability_index,
    )
    case_states = get_case_states(project_name)

    alert_cases = build_alert_cases(
        alert_rows,
        reachability_index=reachability_index,
        case_states=case_states,
    )
    if vuln_id:
        alert_cases = [case for case in alert_cases if case.get("vuln_id") == vuln_id]
    if component_id:
        alert_cases = [case for case in alert_cases if case.get("component_id") == component_id]

    verification_comparison: dict[str, Any] | None = None
    try:
        from backend.services.verification_service import compare_current_vs_previous_report

        verification_comparison = compare_current_vs_previous_report(project_name)
    except Exception:
        verification_comparison = None

    effective_scan_id = next((case.get("scan_id") for case in alert_cases if case.get("scan_id")), scan_id)
    effective_source_commit = next(
        (case.get("source_commit") for case in alert_cases if case.get("source_commit")),
        None,
    )
    report = build_developer_report(
        project_name,
        alert_cases,
        scan_id=effective_scan_id,
        source_commit=effective_source_commit,
        verification_delta=(verification_comparison or {}).get("delta"),
    )
    run_id = record_report_run(
        project_name,
        scan_id=report.get("scan_id"),
        generated_at=report.get("generated_at"),
        source_commit=report.get("source_commit"),
        report_version=_REPORT_VERSION,
    )
    report["run_id"] = run_id
    record_report_case_snapshot(project_name, run_id, alert_cases)
    _apply_developer_narrative(report, use_llm=use_llm)
    _validate_developer_rendering(report)
    return report


def generate_report_bundle(
    project_name: str,
    *,
    use_llm: bool = True,
    include_verification: bool = True,
) -> dict[str, Any]:
    """
    Generate both canonical reports for a project in one call.
    """
    stakeholder = generate_stakeholder_report(project_name, use_llm=use_llm)
    developer = generate_developer_report(project_name, use_llm=use_llm)
    verification_comparison: dict[str, Any] | None = None
    if include_verification:
        try:
            from backend.services.verification_service import compare_current_vs_previous_report

            verification_comparison = compare_current_vs_previous_report(project_name)
        except Exception:
            verification_comparison = None
    return {
        "project": project_name,
        "generated_at": stakeholder.get("generated_at"),
        "stakeholder_report": stakeholder,
        "developer_report": developer,
        "verification_comparison": verification_comparison,
    }
