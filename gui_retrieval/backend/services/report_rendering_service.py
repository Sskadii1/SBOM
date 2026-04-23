"""
Structured HTML rendering for report exports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.services.report_presentation_service import compact_findings_for_display
from backend.services.report_vocabulary_service import (
    normalize_labeled_text,
    present_decision_tier,
    present_evidence_scope,
    present_reachability,
    present_urgency,
)

_TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "templates" / "reports"

_STAKEHOLDER_SECTIONS = (
    ("what_needs_attention_now", "What Needs Attention Now"),
    ("why_it_matters_now", "Why It Matters Now"),
    ("decision_needed_next", "What Action Or Approval Is Needed Next"),
    ("what_remains_uncertain", "What Remains Under Observation"),
)

_DEVELOPER_SECTIONS = (
    ("queue_overview", "Queue Overview"),
    ("strongest_evidence", "Strongest Evidence"),
    ("immediate_next_steps", "Immediate Next Steps"),
    ("verification_guidance", "Verification Guidance"),
    ("remaining_uncertainty", "What Is Still Uncertain Or Deferred"),
)


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_ROOT)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["join_csv"] = lambda value: ", ".join(str(item) for item in (value or []) if str(item).strip())
    return env


def _load_css() -> str:
    return (_TEMPLATE_ROOT / "report.css").read_text(encoding="utf-8")


def _severity_tone(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return {
        "critical": "critical",
        "high": "warning",
        "medium": "neutral",
        "low": "muted",
    }.get(normalized, "muted")


def _reachability_tone(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return {
        "confirmed_reachable": "critical",
        "likely_reachable": "warning",
        "no_sink_data": "neutral",
        "likely_unreachable": "muted",
    }.get(normalized, "muted")


def _tier_tone(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return {
        "fix_now": "critical",
        "plan_remediation": "warning",
        "mitigate": "warning",
        "monitor": "neutral",
        "accept_risk": "muted",
    }.get(normalized, "neutral")


def _ordered_sections(section_spec: tuple[tuple[str, str], ...], sections: dict[str, Any] | None) -> list[dict[str, str]]:
    source = sections or {}
    return [
        {
            "key": key,
            "title": title,
            "body": str(source.get(key) or "No evidence provided.").strip() or "No evidence provided.",
        }
        for key, title in section_spec
    ]


def _meta_items(report: dict[str, Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = [
        {"label": "Generated", "value": str(report.get("generated_at") or "Unknown")},
        {"label": "Project", "value": str(report.get("project") or "Unknown")},
    ]
    if report.get("scan_id"):
        items.append({"label": "Scan", "value": str(report.get("scan_id"))})
    if report.get("run_id"):
        items.append({"label": "Report Run", "value": str(report.get("run_id"))})
    if report.get("source_commit"):
        items.append({"label": "Source Commit", "value": str(report.get("source_commit"))})
    narrative_source = str(report.get("narrative_source") or "fallback").strip().lower()
    items.append(
        {
            "label": "Narrative Layer",
            "value": "LLM-augmented narrative" if narrative_source == "llm" else "Deterministic fallback narrative",
        }
    )
    return items


def _stakeholder_summary_cards(report: dict[str, Any]) -> list[dict[str, str]]:
    posture = report.get("posture_summary") or {}
    snapshot = report.get("current_action_snapshot") or {}
    reachable_or_likely = int(posture.get("reachable_count") or 0) + int(
        posture.get("likely_reachable_count") or 0
    )
    return [
        {
            "label": "Active Cases",
            "value": str(int(posture.get("total_cases") or 0)),
            "tone": "neutral",
            "note": str(posture.get("summary_note") or ""),
        },
        {
            "label": "Critical / High",
            "value": str(int(posture.get("critical_high_count") or 0)),
            "tone": "critical" if int(posture.get("critical_high_count") or 0) > 0 else "neutral",
            "note": "Severity-weighted exposure currently open.",
        },
        {
            "label": "Direct or Likely Use",
            "value": str(reachable_or_likely),
            "tone": "warning" if reachable_or_likely > 0 else "muted",
            "note": "Evidence-backed cases that should shape release decisions.",
        },
        {
            "label": "Current-Release Actions",
            "value": str(int(snapshot.get("fix_now_count") or 0)),
            "tone": "critical" if int(snapshot.get("fix_now_count") or 0) > 0 else "neutral",
            "note": "Clusters that need action in the current window.",
        },
    ]


def _developer_summary_cards(report: dict[str, Any]) -> list[dict[str, str]]:
    triage = report.get("triage_summary") or {}
    return [
        {
            "label": "Immediate Queue",
            "value": str(int(triage.get("fix_now_count") or 0)),
            "tone": "critical" if int(triage.get("fix_now_count") or 0) > 0 else "neutral",
            "note": "Clusters already strong enough for immediate remediation work.",
        },
        {
            "label": "Planned Upgrades",
            "value": str(int(triage.get("plan_remediation_count") or 0)),
            "tone": "warning" if int(triage.get("plan_remediation_count") or 0) > 0 else "muted",
            "note": "Items suited for the next upgrade window.",
        },
        {
            "label": "Direct Call Evidence",
            "value": str(int(triage.get("confirmed_count") or 0)),
            "tone": "critical" if int(triage.get("confirmed_count") or 0) > 0 else "muted",
            "note": "Cases with direct call evidence in project code.",
        },
        {
            "label": "Evidence Gaps",
            "value": str(int(triage.get("no_sink_data_count") or 0)),
            "tone": "neutral" if int(triage.get("no_sink_data_count") or 0) > 0 else "muted",
            "note": "Items lacking sink-level evidence and not safe by default.",
        },
    ]


def build_stakeholder_report_view_model(report: dict[str, Any]) -> dict[str, Any]:
    posture = report.get("posture_summary") or {}
    snapshot = report.get("current_action_snapshot") or {}
    impact = report.get("impact_summary") or {}
    actions = []
    for item in report.get("top_priority_actions") or []:
        decision_tier = str(item.get("decision_tier") or "monitor")
        reachability_verdict = str(item.get("reachability_verdict") or "unknown")
        actions.append(
            {
                "title": str(item.get("remediation_cluster_title") or f"{item.get('component') or 'Dependency'} remediation cluster"),
                "component": str(item.get("component") or "Unknown dependency"),
                "version_path": f"{item.get('current_version') or 'unknown'} -> {item.get('target_version') or 'target pending'}",
                "decision_tier": present_decision_tier(decision_tier, "stakeholder"),
                "decision_tier_raw": decision_tier,
                "decision_tone": _tier_tone(decision_tier),
                "reachability": present_reachability(reachability_verdict, "stakeholder"),
                "reachability_raw": reachability_verdict,
                "reachability_tone": _reachability_tone(reachability_verdict),
                "severity": str(item.get("severity") or "medium").upper(),
                "severity_tone": _severity_tone(item.get("severity")),
                "affected_area": str(item.get("affected_area") or "Unknown area"),
                "related_case_count": int(item.get("related_case_count") or 0),
                "related_cves": list(item.get("related_cves") or []),
                "why_now": normalize_labeled_text("Why now", str(item.get("why_now") or "")) or "No evidence provided.",
                "impact_basis": str(item.get("impact_basis") or "No evidence provided."),
                "required_management_action": str(
                    item.get("required_management_action")
                    or item.get("required_owner_type")
                    or "No decision requested."
                ),
            }
        )

    management_rows = []
    for item in report.get("recommended_management_actions") or []:
        management_rows.append(
            {
                "action": str(item.get("action") or "Action pending"),
                "reason": str(item.get("reason") or "No evidence provided."),
                "owner": str(item.get("owner_type") or "owner pending").replace("_", " ").title(),
                "urgency": present_urgency(item.get("urgency")),
            }
        )

    affected_areas = []
    for item in report.get("affected_areas") or []:
        affected_areas.append(
            {
                "name": str(item.get("area_name") or "Unknown area"),
                "case_count": int(item.get("case_count") or 0),
                "reachable_or_likely_count": int(item.get("reachable_or_likely_count") or 0),
                "key_cves": list(item.get("key_cves") or []),
                "focus_reason": str(item.get("focus_reason") or "No evidence provided."),
            }
        )

    return {
        "title": "Stakeholder Security Summary",
        "subtitle": "Decision-focused security posture summary for release, engineering, and product stakeholders.",
        "report_type": "stakeholder",
        "css": _load_css(),
        "meta_items": _meta_items(report),
        "summary_cards": _stakeholder_summary_cards(report),
        "narrative_sections": _ordered_sections(_STAKEHOLDER_SECTIONS, report.get("narrative_sections")),
        "top_priority_actions": actions,
        "affected_areas": affected_areas,
        "action_snapshot": [
            {"label": "Current-release actions", "value": int(snapshot.get("fix_now_count") or 0)},
            {"label": "Next-window upgrades", "value": int(snapshot.get("plan_remediation_count") or 0)},
            {"label": "Mitigation work", "value": int(snapshot.get("mitigate_count") or 0)},
            {"label": "Under observation", "value": int(snapshot.get("monitor_count") or 0)},
            {"label": "Fix path available", "value": int(snapshot.get("fix_available_count") or 0)},
            {"label": "Direct or likely use", "value": int(snapshot.get("reachable_or_likely_count") or 0)},
        ],
        "impact_rows": [
            {"label": "Critical / high", "value": int(posture.get("critical_high_count") or 0)},
            {"label": "Known exploited (KEV)", "value": int(posture.get("kev_count") or 0)},
            {"label": "Direct dependencies", "value": int(impact.get("direct_count") or 0)},
            {"label": "Transitive dependencies", "value": int(impact.get("transitive_count") or 0)},
        ],
        "impact_note": str(impact.get("impact_note") or "No evidence provided."),
        "management_rows": management_rows,
        "verification": {
            "trigger": str((report.get("next_verification_checkpoint") or {}).get("trigger") or "next scan"),
            "goal": str((report.get("next_verification_checkpoint") or {}).get("goal") or "No evidence provided."),
            "recheck": str(
                (report.get("next_verification_checkpoint") or {}).get("what_will_be_rechecked")
                or "No evidence provided."
            ),
            "note": str((report.get("next_verification_checkpoint") or {}).get("note") or "No evidence provided."),
        },
        "mapping_note": str((report.get("area_mapping") or {}).get("note") or ""),
    }


def build_developer_report_view_model(report: dict[str, Any]) -> dict[str, Any]:
    triage = report.get("triage_summary") or {}
    clusters = []
    for cluster in report.get("immediate_fix_clusters") or []:
        verdict = str(cluster.get("strongest_reachability") or "unknown")
        call_evidence = []
        for evidence in cluster.get("call_evidence") or []:
            evidence_verdict = str(evidence.get("reachability_verdict") or "unknown")
            call_evidence.append(
                {
                    "vuln_id": str(evidence.get("vuln_id") or "N/A"),
                    "reachability": present_reachability(evidence_verdict, "developer"),
                    "reachability_raw": evidence_verdict,
                    "scope": present_evidence_scope(evidence.get("evidence_scope"), "developer"),
                    "locations": list(evidence.get("call_locations") or []),
                    "sinks": list(evidence.get("sink_functions") or []),
                }
            )
        clusters.append(
            {
                "title": f"{cluster.get('package') or 'Unknown package'} remediation cluster",
                "package": str(cluster.get("package") or "Unknown package"),
                "version_path": f"{cluster.get('current_version') or 'unknown'} -> {cluster.get('target_version') or 'target pending'}",
                "queue_label": present_decision_tier("fix_now", "developer"),
                "queue_tone": "critical",
                "reachability": present_reachability(verdict, "developer"),
                "reachability_raw": verdict,
                "reachability_tone": _reachability_tone(verdict),
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "related_cves": list(cluster.get("related_cves") or []),
                "why_fix_now": normalize_labeled_text("Why fix now", str(cluster.get("why_fix_now") or "")) or "No evidence provided.",
                "next_action": str(cluster.get("next_action") or "No evidence provided."),
                "verification_target": str(
                    ((cluster.get("verification_target") or {}).get("success_criteria") or "No evidence provided.")
                ),
                "scope_rows": [
                    {"label": "Production", "value": int(cluster.get("production_case_count") or 0)},
                    {"label": "Test-only", "value": int(cluster.get("test_only_case_count") or 0)},
                    {"label": "Mixed", "value": int(cluster.get("mixed_case_count") or 0)},
                    {"label": "Unknown", "value": int(cluster.get("unknown_scope_case_count") or 0)},
                ],
                "call_evidence": call_evidence,
            }
        )

    backlog_rows = []
    for cluster in (report.get("planned_upgrade_backlog") or {}).get("backlog_clusters") or []:
        verdict = str(cluster.get("reachability_verdict") or "unknown")
        decision_tier = str(cluster.get("decision_tier") or "monitor")
        backlog_rows.append(
            {
                "package": str(cluster.get("package") or "Unknown package"),
                "current_version": str(cluster.get("current_version") or "unknown"),
                "target_version": str(cluster.get("target_version") or "target pending"),
                "queue_label": present_decision_tier(decision_tier, "developer"),
                "queue_tone": _tier_tone(decision_tier),
                "reachability": present_reachability(verdict, "developer"),
                "reachability_raw": verdict,
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "reason": str(cluster.get("reason_not_fix_now") or "No evidence provided."),
                "next_action": str(cluster.get("recommended_next_window_action") or "No evidence provided."),
            }
        )

    findings_rows = []
    for finding in compact_findings_for_display(report.get("detailed_technical_findings") or [], limit=8):
        verdict = str(finding.get("reachability_verdict") or "unknown")
        tier = str(finding.get("decision_tier") or "monitor")
        findings_rows.append(
            {
                "vuln_id": str(finding.get("vuln_id") or "N/A"),
                "component": str(finding.get("component") or "Unknown dependency"),
                "version": str(finding.get("current_version") or "unknown"),
                "severity": str(finding.get("severity") or "medium").upper(),
                "severity_tone": _severity_tone(finding.get("severity")),
                "queue_label": present_decision_tier(tier, "developer"),
                "queue_raw": tier,
                "queue_tone": _tier_tone(tier),
                "reachability": present_reachability(verdict, "developer"),
                "reachability_raw": verdict,
                "reachability_tone": _reachability_tone(verdict),
                "fix_versions": list(finding.get("fix_versions") or []),
                "impact_summary": str(finding.get("impact_summary") or "No evidence provided."),
            }
        )

    return {
        "title": "Developer Remediation Report",
        "subtitle": "Evidence-first remediation and verification guide for engineering teams.",
        "report_type": "developer",
        "css": _load_css(),
        "meta_items": _meta_items(report),
        "summary_cards": _developer_summary_cards(report),
        "narrative_sections": _ordered_sections(_DEVELOPER_SECTIONS, report.get("narrative_sections")),
        "triage_rows": [
            {"label": "Immediate queue", "value": int(triage.get("fix_now_count") or 0)},
            {"label": "Planned upgrades", "value": int(triage.get("plan_remediation_count") or 0)},
            {"label": "Mitigation / investigation", "value": int(triage.get("mitigate_count") or 0)},
            {"label": "Monitor", "value": int(triage.get("monitor_count") or 0)},
            {"label": "Direct call evidence", "value": int(triage.get("confirmed_count") or 0)},
            {"label": "Import / usage evidence", "value": int(triage.get("likely_count") or 0)},
            {"label": "No direct use observed", "value": int(triage.get("unlikely_count") or 0)},
            {"label": "Sink evidence missing", "value": int(triage.get("no_sink_data_count") or 0)},
        ],
        "immediate_fix_clusters": clusters,
        "coverage_note": str((report.get("immediate_fix_coverage") or {}).get("coverage_note") or ""),
        "backlog_note": str((report.get("planned_upgrade_backlog") or {}).get("summary_note") or ""),
        "backlog_rows": backlog_rows,
        "verification_checklist": list(report.get("verification_checklist") or []),
        "verification": {
            "baseline_scan_id": str((report.get("verification_delta") or {}).get("baseline_scan_id") or "None"),
            "current_scan_id": str((report.get("verification_delta") or {}).get("current_scan_id") or "Unknown"),
            "resolved_cases": int((report.get("verification_delta") or {}).get("resolved_cases") or 0),
            "risk_decreased_cases": int((report.get("verification_delta") or {}).get("risk_decreased_cases") or 0),
            "verdict_improved_cases": int((report.get("verification_delta") or {}).get("verdict_improved_cases") or 0),
            "note": str((report.get("verification_delta") or {}).get("note") or "No evidence provided."),
        },
        "verification_targets": list(report.get("cluster_verification_targets") or []),
        "findings_rows": findings_rows,
    }


def render_stakeholder_report_html(report: dict[str, Any]) -> str:
    template = _environment().get_template("stakeholder_report.html")
    return template.render(view_model=build_stakeholder_report_view_model(report))


def render_developer_report_html(report: dict[str, Any]) -> str:
    template = _environment().get_template("developer_report.html")
    return template.render(view_model=build_developer_report_view_model(report))
