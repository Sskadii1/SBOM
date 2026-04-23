"""
Structured HTML rendering for report exports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.services.report_presentation_service import (
    compact_findings_for_display,
    compact_text,
    format_version_path,
    plain_text_from_markdown,
    unique_text_items,
)
from backend.services.report_rich_text_service import render_report_rich_text
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


def _compact_list(values: list[Any] | None, *, limit: int = 4) -> list[str]:
    return unique_text_items(list(values or []), limit=limit)


def _csv_display(values: list[Any] | None, *, limit: int = 4, fallback: str = "None listed") -> str:
    items = _compact_list(values, limit=limit)
    return ", ".join(items) if items else fallback


def _compact_reason(value: Any, *, fallback: str = "No evidence provided.", max_length: int = 120) -> str:
    return compact_text(value, fallback=fallback, max_length=max_length)


def _appendix_note(finding: dict[str, Any]) -> str:
    note = compact_text(finding.get("impact_summary"), fallback="", max_length=110)
    if note:
        return note
    if finding.get("fix_versions"):
        return f"Fix path available: {_csv_display(finding.get('fix_versions'), limit=3)}"
    return "Evidence metadata preserved for operator follow-up."


def _cluster_location_groups(call_evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    for evidence in call_evidence:
        locations = _compact_list(evidence.get("call_locations") or evidence.get("locations"), limit=5)
        if not locations:
            continue
        groups.append(
            {
                "label": str(evidence.get("vuln_id") or "Observed locations"),
                "locations": locations,
            }
        )
    return groups


def _dedupe_verification_targets(targets: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in targets or []:
        signature = "|".join(
            [
                compact_text(item.get("cluster_title"), fallback=""),
                compact_text(item.get("what_must_change"), fallback=""),
                compact_text(item.get("scan_recheck"), fallback=""),
                compact_text(item.get("success_criteria"), fallback=""),
            ]
        ).lower()
        if not signature or signature in seen:
            continue
        seen.add(signature)
        unique.append(dict(item))
    return unique


def _ordered_sections(section_spec: tuple[tuple[str, str], ...], sections: dict[str, Any] | None) -> list[dict[str, Any]]:
    source = sections or {}
    return [
        {
            "key": key,
            "title": title,
            "body": str(source.get(key) or "No evidence provided.").strip() or "No evidence provided.",
            "body_html": render_report_rich_text(source.get(key) or "No evidence provided."),
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
        why_now = normalize_labeled_text("Why now", str(item.get("why_now") or "")) or "No evidence provided."
        impact_basis_source = item.get("impact_basis") or "Impact evidence will be rechecked in the next scan."
        impact_basis = compact_text(impact_basis_source, fallback="Impact evidence will be rechecked in the next scan.")
        decision_requested = compact_text(
            item.get("required_management_action") or item.get("required_owner_type"),
            fallback="No decision requested.",
        )
        actions.append(
            {
                "title": str(item.get("remediation_cluster_title") or f"{item.get('component') or 'Dependency'} remediation cluster"),
                "component": str(item.get("component") or "Unknown dependency"),
                "version_path": format_version_path(item.get("current_version"), item.get("target_version")),
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
                "related_cves": _compact_list(item.get("related_cves"), limit=5),
                "related_cves_display": _csv_display(item.get("related_cves"), limit=5),
                "why_now": why_now,
                "why_now_html": render_report_rich_text(why_now),
                "impact_basis": impact_basis,
                "impact_basis_html": render_report_rich_text(impact_basis_source),
                "required_management_action": decision_requested,
                "required_management_action_html": render_report_rich_text(decision_requested),
                "summary_rows": [
                    {"label": "Component", "value": str(item.get("component") or "Unknown dependency")},
                    {"label": "Version path", "value": format_version_path(item.get("current_version"), item.get("target_version"))},
                    {"label": "Evidence", "value": present_reachability(reachability_verdict, "stakeholder")},
                    {"label": "Related CVEs", "value": _csv_display(item.get("related_cves"), limit=5)},
                ],
            }
        )

    management_rows = []
    for item in report.get("recommended_management_actions") or []:
        management_rows.append(
            {
                "action": str(item.get("action") or "Action pending"),
                "reason": _compact_reason(item.get("reason"), fallback="No evidence provided.", max_length=140),
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
                "key_cves": _compact_list(item.get("key_cves"), limit=4),
                "key_cves_display": _csv_display(item.get("key_cves"), limit=4),
                "focus_reason": _compact_reason(item.get("focus_reason"), fallback="No evidence provided.", max_length=150),
            }
        )

    narrative_sections = _ordered_sections(_STAKEHOLDER_SECTIONS, report.get("narrative_sections"))
    lead_narrative_sections = [
        section
        for section in narrative_sections
        if section["key"] in {"what_needs_attention_now", "why_it_matters_now"}
    ]
    decision_section = next(
        (
            section
            for section in narrative_sections
            if section["key"] == "decision_needed_next"
        ),
        {"title": "What Action Or Approval Is Needed Next", "body": "No evidence provided.", "body_html": "<p>No evidence provided.</p>"},
    )
    observation_section = next(
        (
            section
            for section in narrative_sections
            if section["key"] == "what_remains_uncertain"
        ),
        {"title": "What Remains Under Observation", "body": "No evidence provided.", "body_html": "<p>No evidence provided.</p>"},
    )

    return {
        "title": "Stakeholder Security Summary",
        "subtitle": "Decision-focused security posture summary for release, engineering, and product stakeholders.",
        "report_type": "stakeholder",
        "css": _load_css(),
        "meta_items": _meta_items(report),
        "summary_cards": _stakeholder_summary_cards(report),
        "narrative_sections": narrative_sections,
        "lead_narrative_sections": lead_narrative_sections,
        "decision_section": decision_section,
        "observation_section": observation_section,
        "top_priority_actions": actions,
        "affected_areas": affected_areas,
        "metric_rows": [
            {"label": "Current-release actions", "value": int(snapshot.get("fix_now_count") or 0), "group": "Action snapshot"},
            {"label": "Next-window upgrades", "value": int(snapshot.get("plan_remediation_count") or 0), "group": "Action snapshot"},
            {"label": "Mitigation work", "value": int(snapshot.get("mitigate_count") or 0), "group": "Action snapshot"},
            {"label": "Under observation", "value": int(snapshot.get("monitor_count") or 0), "group": "Action snapshot"},
            {"label": "Critical / high", "value": int(posture.get("critical_high_count") or 0), "group": "Impact metrics"},
            {"label": "Known exploited (KEV)", "value": int(posture.get("kev_count") or 0), "group": "Impact metrics"},
            {"label": "Direct dependencies", "value": int(impact.get("direct_count") or 0), "group": "Impact metrics"},
            {"label": "Transitive dependencies", "value": int(impact.get("transitive_count") or 0), "group": "Impact metrics"},
        ],
        "impact_note": compact_text(impact.get("impact_note"), fallback="Current impact metrics summarize where active exposure remains."),
        "management_rows": management_rows,
        "verification": {
            "trigger": str((report.get("next_verification_checkpoint") or {}).get("trigger") or "next scan"),
            "goal": compact_text((report.get("next_verification_checkpoint") or {}).get("goal"), fallback="No evidence provided."),
            "recheck": str(
                (report.get("next_verification_checkpoint") or {}).get("what_will_be_rechecked")
                or "No evidence provided."
            ),
            "note": compact_text((report.get("next_verification_checkpoint") or {}).get("note"), fallback="No evidence provided."),
        },
        "mapping_note": compact_text((report.get("area_mapping") or {}).get("note"), fallback=""),
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
                    "locations": _compact_list(evidence.get("call_locations"), limit=5),
                    "sinks": _compact_list(evidence.get("sink_functions"), limit=3),
                    "sinks_display": _csv_display(evidence.get("sink_functions"), limit=3, fallback="None captured"),
                }
            )
        why_fix_now = normalize_labeled_text("Why fix now", str(cluster.get("why_fix_now") or "")) or "No evidence provided."
        next_action = compact_text(cluster.get("next_action"), fallback="No evidence provided.")
        verification_target = compact_text(
            ((cluster.get("verification_target") or {}).get("success_criteria")),
            fallback="No evidence provided.",
        )
        clusters.append(
            {
                "title": f"{cluster.get('package') or 'Unknown package'} remediation cluster",
                "package": str(cluster.get("package") or "Unknown package"),
                "version_path": format_version_path(cluster.get("current_version"), cluster.get("target_version")),
                "queue_label": present_decision_tier("fix_now", "developer"),
                "queue_tone": "critical",
                "reachability": present_reachability(verdict, "developer"),
                "reachability_raw": verdict,
                "reachability_tone": _reachability_tone(verdict),
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "related_cves": _compact_list(cluster.get("related_cves"), limit=6),
                "related_cves_display": _csv_display(cluster.get("related_cves"), limit=6),
                "why_fix_now": why_fix_now,
                "why_fix_now_html": render_report_rich_text(why_fix_now),
                "next_action": next_action,
                "next_action_html": render_report_rich_text(next_action),
                "verification_target": verification_target,
                "verification_target_html": render_report_rich_text(verification_target),
                "scope_display": ", ".join(
                    f"{row['label']}: {row['value']}"
                    for row in [
                        {"label": "Production", "value": int(cluster.get("production_case_count") or 0)},
                        {"label": "Test-only", "value": int(cluster.get("test_only_case_count") or 0)},
                        {"label": "Mixed", "value": int(cluster.get("mixed_case_count") or 0)},
                        {"label": "Unknown", "value": int(cluster.get("unknown_scope_case_count") or 0)},
                    ]
                    if int(row["value"]) > 0
                ) or "Scope not yet classified.",
                "evidence_rows": call_evidence,
                "location_groups": _cluster_location_groups(call_evidence),
                "summary_rows": [
                    {"label": "Package", "value": str(cluster.get("package") or "Unknown package")},
                    {"label": "Version path", "value": format_version_path(cluster.get("current_version"), cluster.get("target_version"))},
                    {"label": "Evidence category", "value": present_reachability(verdict, "developer")},
                    {"label": "Related CVEs", "value": _csv_display(cluster.get("related_cves"), limit=6)},
                ],
            }
        )

    backlog_rows = []
    for cluster in (report.get("planned_upgrade_backlog") or {}).get("backlog_clusters") or []:
        verdict = str(cluster.get("reachability_verdict") or "unknown")
        decision_tier = str(cluster.get("decision_tier") or "monitor")
        backlog_rows.append(
            {
                "package": str(cluster.get("package") or "Unknown package"),
                "version_path": format_version_path(cluster.get("current_version"), cluster.get("target_version")),
                "queue_label": present_decision_tier(decision_tier, "developer"),
                "queue_tone": _tier_tone(decision_tier),
                "reachability": present_reachability(verdict, "developer"),
                "reachability_raw": verdict,
                "related_case_count": int(cluster.get("related_case_count") or 0),
                "reason": _compact_reason(cluster.get("reason_not_fix_now"), max_length=110),
                "next_action": _compact_reason(cluster.get("recommended_next_window_action"), max_length=110),
            }
        )

    findings_rows = []
    for finding in compact_findings_for_display(report.get("detailed_technical_findings") or [], limit=8):
        verdict = str(finding.get("reachability_verdict") or "unknown")
        tier = str(finding.get("decision_tier") or "monitor")
        findings_rows.append(
            {
                "vuln_id": str(finding.get("vuln_id") or "N/A"),
                "component_version": f"{str(finding.get('component') or 'Unknown dependency')} {str(finding.get('current_version') or 'unknown')}".strip(),
                "queue_label": present_decision_tier(tier, "developer"),
                "reachability": present_reachability(verdict, "developer"),
                "fix_versions_display": _csv_display(finding.get("fix_versions"), limit=3),
                "note": _appendix_note(dict(finding)),
            }
        )

    narrative_sections = _ordered_sections(_DEVELOPER_SECTIONS, report.get("narrative_sections"))
    verification_targets = _dedupe_verification_targets(list(report.get("cluster_verification_targets") or []))
    leading_cluster = clusters[0] if clusters else None
    verification_plan_rows = [
        {
            "step": "Regenerate SBOM",
            "action": "Run SBOM generation after the upgrade path is applied.",
            "expected_change": "The report should capture the new package version path.",
            "success": "The immediate remediation package shows the intended target version.",
        },
        {
            "step": "Rerun enrichment and reachability",
            "action": compact_text(
                (verification_targets[0].get("scan_recheck") if verification_targets else None),
                fallback="Rerun vulnerability enrichment and reachability analysis for the changed packages.",
            ),
            "expected_change": "Urgent clusters should leave the direct-or-likely-use set or move to a lower tier.",
            "success": compact_text(
                (verification_targets[0].get("success_criteria") if verification_targets else None),
                fallback="Reachability or queue placement improves in the next report run.",
            ),
        },
        {
            "step": "Review queue movement",
            "action": "Validate case-state updates and close the implementation loop with one follow-up review.",
            "expected_change": "Cases move to verification or closure states instead of staying in the immediate queue.",
            "success": "Resolved or improved counts appear in the verification delta.",
        },
    ]
    executive_summary_rows = [
        {
            "label": "Needs fixing now",
            "value": f"{len(clusters)} remediation cluster(s) currently sit in the immediate queue.",
        },
        {
            "label": "Highest-value upgrade path",
            "value": plain_text_from_markdown(
                leading_cluster.get("next_action") if leading_cluster else None,
                fallback="No immediate remediation cluster is currently open.",
            ),
        },
        {
            "label": "Verification rerun",
            "value": plain_text_from_markdown(verification_plan_rows[1]["action"]),
        },
    ]

    return {
        "title": "Developer Remediation Report",
        "subtitle": "Evidence-first remediation and verification guide for engineering teams.",
        "report_type": "developer",
        "css": _load_css(),
        "meta_items": _meta_items(report),
        "summary_cards": _developer_summary_cards(report),
        "narrative_sections": narrative_sections,
        "briefing_rows": [
            section
            for section in narrative_sections
            if section["key"] in {"queue_overview", "strongest_evidence", "remaining_uncertainty"}
        ],
        "executive_summary_rows": executive_summary_rows,
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
        "remediation_rows": clusters,
        "coverage_note": compact_text((report.get("immediate_fix_coverage") or {}).get("coverage_note"), fallback=""),
        "backlog_note": compact_text((report.get("planned_upgrade_backlog") or {}).get("summary_note"), fallback=""),
        "backlog_rows": backlog_rows,
        "verification_checklist": list(report.get("verification_checklist") or []),
        "verification_plan_rows": verification_plan_rows,
        "verification": {
            "baseline_scan_id": str((report.get("verification_delta") or {}).get("baseline_scan_id") or "None"),
            "current_scan_id": str((report.get("verification_delta") or {}).get("current_scan_id") or "Unknown"),
            "resolved_cases": int((report.get("verification_delta") or {}).get("resolved_cases") or 0),
            "risk_decreased_cases": int((report.get("verification_delta") or {}).get("risk_decreased_cases") or 0),
            "verdict_improved_cases": int((report.get("verification_delta") or {}).get("verdict_improved_cases") or 0),
            "note": compact_text((report.get("verification_delta") or {}).get("note"), fallback="No evidence provided."),
        },
        "verification_targets": verification_targets,
        "appendix_rows": findings_rows,
        "appendix_scope_rows": [
            {
                "label": "Production-only evidence",
                "value": int(((report.get("technical_appendix") or {}).get("evidence_scope_summary") or {}).get("production_only_cases") or 0),
            },
            {
                "label": "Test-only evidence",
                "value": int(((report.get("technical_appendix") or {}).get("evidence_scope_summary") or {}).get("test_only_cases") or 0),
            },
            {
                "label": "Mixed evidence",
                "value": int(((report.get("technical_appendix") or {}).get("evidence_scope_summary") or {}).get("mixed_scope_cases") or 0),
            },
        ],
    }


def render_stakeholder_report_html(report: dict[str, Any]) -> str:
    template = _environment().get_template("stakeholder_report.html")
    return template.render(view_model=build_stakeholder_report_view_model(report))


def render_developer_report_html(report: dict[str, Any]) -> str:
    template = _environment().get_template("developer_report.html")
    return template.render(view_model=build_developer_report_view_model(report))
