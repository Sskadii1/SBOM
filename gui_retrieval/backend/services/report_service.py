"""
Top-level orchestration service for stakeholder/developer report generation.
"""

from __future__ import annotations

from typing import Any

import backend.config as config
from backend.models import DeveloperReport, StakeholderReport
from backend.services.case_state_service import (
    get_case_states,
)
from backend.services.developer_report_builder import build_developer_report
from backend.services.evidence_service import (
    build_alert_cases,
    recompute_and_overwrite_case_state_tiers,
)
from backend.services.stakeholder_report_builder import build_stakeholder_report


def _scan_source_from_bundle(bundle: dict[str, Any]) -> str | None:
    meta = bundle.get("latest_scan_metadata")
    if isinstance(meta, dict):
        scan_id = meta.get("scan_id")
        generated_at = meta.get("generated_at")
        if scan_id or generated_at:
            return f"scan_id={scan_id or 'unknown'}|generated_at={generated_at or 'unknown'}"
    return None


def _build_stakeholder_narrative_fallback(report: StakeholderReport) -> str:
    posture = report.get("posture_summary") or {}
    top_actions = report.get("top_priority_actions") or []
    impact = report.get("impact_summary") or {}
    action_buckets = report.get("action_buckets") or []
    status_snapshot = report.get("status_snapshot") or {}
    checkpoint = report.get("next_verification_checkpoint") or {}

    total_cases = int(posture.get("total_cases") or 0)
    critical_high = int(posture.get("critical_high_cases") or 0)
    reachable = int(posture.get("reachable_or_likely_cases") or 0)
    fix_available = int(posture.get("fix_available_cases") or 0)
    kev_cases = int(posture.get("kev_cases") or 0)
    runtime_affected = int(impact.get("runtime_affected_cases") or 0)
    direct_cases = int(impact.get("direct_dependency_cases") or 0)
    transitive_cases = int(impact.get("transitive_dependency_cases") or 0)

    top_action_lines = []
    for item in top_actions[:5]:
        vuln = item.get("vuln_id") or "N/A"
        component = item.get("component_name") or "N/A"
        tier = item.get("decision_tier") or "monitor"
        rationale = item.get("rationale") or "No evidence provided."
        action = item.get("recommended_action") or "No evidence provided."
        top_action_lines.append(
            f"- {vuln} on {component} -> `{tier}`. {rationale} Action now: {action}"
        )
    if not top_action_lines:
        top_action_lines = ["- No evidence provided."]
    top_action_block = "\n".join(top_action_lines)

    bucket_lines = []
    for bucket in action_buckets:
        guidance = bucket.get("recommended_action") or "No evidence provided."
        bucket_lines.append(
            f"- `{bucket.get('decision_tier', 'monitor')}`: {int(bucket.get('case_count') or 0)} case(s). "
            f"Action: {guidance}"
        )
    if not bucket_lines:
        bucket_lines = ["- No evidence provided."]
    bucket_block = "\n".join(bucket_lines)

    status_lines = []
    for key in (
        "new",
        "under_review",
        "planned",
        "in_progress",
        "mitigated",
        "resolved_pending_verify",
        "verified_closed",
    ):
        status_lines.append(f"- {key}: {int(status_snapshot.get(key) or 0)}")
    status_block = "\n".join(status_lines)
    checkpoint_note = checkpoint.get("guidance") or "No evidence provided."
    checkpoint_triggers = checkpoint.get("trigger_conditions") or []
    trigger_lines = [f"- {item}" for item in checkpoint_triggers] or ["- No evidence provided."]
    trigger_block = "\n".join(trigger_lines)

    lines = [
        "## Executive Security Summary",
        (
            f"This project currently has {total_cases} tracked vulnerability case(s), "
            f"including {critical_high} critical/high items and {kev_cases} KEV item(s)."
        ),
        (
            f"Reachability evidence indicates {reachable} case(s) are confirmed or likely reachable, "
            f"and {fix_available} case(s) already have known fix versions."
        ),
        (
            f"As of {report.get('generated_at', 'unknown time')}, leadership should prioritize "
            "action buckets with strongest exploitability and remediation readiness."
        ),
        "",
        "## Priority Actions",
        top_action_block,
        "",
        "## Impact Summary",
        (
            f"Runtime-affected cases: {runtime_affected}. Direct dependency cases: {direct_cases}. "
            f"Transitive dependency cases: {transitive_cases}."
        ),
        impact.get("impact_note") or "No evidence provided.",
        "",
        "## Action Buckets",
        bucket_block,
        "",
        "## Status Snapshot",
        status_block,
        "",
        "## Next Verification Checkpoint",
        checkpoint_note,
        trigger_block,
    ]
    return "\n".join(lines).strip()


def _is_sufficient_stakeholder_narrative(text: str) -> bool:
    words = len((text or "").split())
    has_all_headers = all(
        header in (text or "")
        for header in (
            "## Executive Security Summary",
            "## Priority Actions",
            "## Impact Summary",
            "## Action Buckets",
            "## Status Snapshot",
            "## Next Verification Checkpoint",
        )
    )
    return has_all_headers and words >= 120


def _build_developer_narrative_fallback(report: DeveloperReport) -> str:
    triage = report.get("triage_summary") or {}
    reach = report.get("reachability_evidence") or {}
    recommended_fix = report.get("recommended_fix") or []
    verification_steps = report.get("verification_steps") or []

    total_cases = int(triage.get("total_cases") or 0)
    fix_now = int(triage.get("fix_now") or 0)
    investigate_next = int(triage.get("investigate_next") or 0)
    monitor = int(triage.get("monitor") or 0)

    confirmed = int(reach.get("confirmed_reachable") or 0)
    likely = int(reach.get("likely_reachable") or 0)
    likely_unreachable = int(reach.get("likely_unreachable") or 0)
    no_sink_data = int(reach.get("no_sink_data") or 0)

    preview_lines: list[str] = []
    for item in recommended_fix[:5]:
        vuln = item.get("vuln_id") or "N/A"
        component = item.get("component_name") or "N/A"
        versions = item.get("fix_versions") or []
        target = ", ".join(versions[:2]) if versions else "No evidence provided."
        preview_lines.append(f"- {vuln} on {component}: target {target}")
    if not preview_lines:
        preview_lines = ["- No evidence provided."]
    preview_block = "\n".join(preview_lines)

    step_lines = [f"- {item}" for item in verification_steps] or ["- No evidence provided."]
    steps_block = "\n".join(step_lines)

    lines = [
        "## Developer Remediation Summary",
        (
            f"Total tracked cases: {total_cases}. Decision tiers -> "
            f"fix_now: {fix_now}, investigate_next: {investigate_next}, monitor: {monitor}."
        ),
        (
            f"Reachability signals -> confirmed_reachable: {confirmed}, likely_reachable: {likely}, "
            f"likely_unreachable: {likely_unreachable}, no_sink_data: {no_sink_data}."
        ),
        "",
        "## Recommended Fix Plan",
        "Prioritize fixes by decision tier and reachability evidence; use listed fix versions where available.",
        preview_block,
        "",
        "## Verification Steps",
        steps_block,
    ]
    return "\n".join(lines).strip()


def _is_sufficient_developer_narrative(text: str) -> bool:
    words = len((text or "").split())
    has_all_headers = all(
        header in (text or "")
        for header in (
            "## Developer Remediation Summary",
            "## Recommended Fix Plan",
            "## Verification Steps",
        )
    )
    has_reasoning_leak = any(
        marker in (text or "").lower()
        for marker in (
            "let's break down",
            "the instructions say",
            "return markdown with exactly these sections",
            "report json:",
        )
    )
    return has_all_headers and words >= 40 and not has_reasoning_leak


def _apply_stakeholder_narrative(report: StakeholderReport, use_llm: bool) -> None:
    fallback_narrative = _build_stakeholder_narrative_fallback(report)
    if not use_llm:
        report["narrative"] = fallback_narrative
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_toggle_off"
        return
    if not config.OPENROUTER_API_KEY:
        report["narrative"] = fallback_narrative
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "missing_openrouter_api_key"
        return
    try:
        from backend.services.llm_service import generate_stakeholder_report_narrative

        narrative = generate_stakeholder_report_narrative(report)
        if narrative and _is_sufficient_stakeholder_narrative(narrative):
            report["narrative"] = narrative
            report["narrative_source"] = "llm"
            report["narrative_reason"] = "llm_applied"
        else:
            report["narrative"] = fallback_narrative
            report["narrative_source"] = "fallback"
            report["narrative_reason"] = "llm_output_insufficient"
    except Exception:
        # Keep schema-first report generation resilient when LLM is unavailable.
        report["narrative"] = fallback_narrative
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_runtime_error"


def _apply_developer_narrative(report: DeveloperReport, use_llm: bool) -> None:
    fallback_narrative = _build_developer_narrative_fallback(report)
    if not use_llm:
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_toggle_off"
        return
    if not config.OPENROUTER_API_KEY:
        report["narrative"] = fallback_narrative
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "missing_openrouter_api_key"
        return
    try:
        from backend.services.llm_service import generate_developer_report_narrative

        narrative = generate_developer_report_narrative(report)
        if narrative and _is_sufficient_developer_narrative(narrative):
            report["narrative"] = narrative
            report["narrative_source"] = "llm"
            report["narrative_reason"] = "llm_applied"
        else:
            report["narrative"] = fallback_narrative
            report["narrative_source"] = "fallback"
            report["narrative_reason"] = "llm_output_insufficient"
    except Exception:
        # Keep schema-first report generation resilient when LLM is unavailable.
        report["narrative"] = fallback_narrative
        report["narrative_source"] = "fallback"
        report["narrative_reason"] = "llm_runtime_error"


def generate_stakeholder_report(
    project_name: str,
    *,
    use_llm: bool = True,
) -> StakeholderReport:
    """
    Generate stakeholder report object from canonical alert cases.
    """
    from backend.repositories import graph_repository as repo

    bundle = repo.get_stakeholder_report_inputs(project_name)
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
    report = build_stakeholder_report(project_name, alert_cases, case_states=case_states)
    report["sbom_source"] = _scan_source_from_bundle(bundle)
    report["reachability_source"] = str(config.CVE_SINKS_DB)
    report["vulnerability_source"] = "neo4j:vulnerability_graph"

    _apply_stakeholder_narrative(report, use_llm=use_llm)
    return report


def generate_developer_report(
    project_name: str,
    *,
    vuln_id: str | None = None,
    component_id: str | None = None,
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
        alert_cases = [
            case
            for case in alert_cases
            if case.get("vuln_id") == vuln_id
        ]
    if component_id:
        alert_cases = [
            case
            for case in alert_cases
            if case.get("component_id") == component_id
        ]

    report = build_developer_report(project_name, alert_cases)
    _apply_developer_narrative(report, use_llm=use_llm)
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
