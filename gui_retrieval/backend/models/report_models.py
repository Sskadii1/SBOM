"""
Canonical domain schemas for report-driven outputs.
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

from backend.models.decision_tiering import DecisionTier
from backend.models.report_status import CaseStatus


class AlertCase(TypedDict):
    project: str
    scan_id: str | None
    source_commit: str | None
    vuln_id: str
    component_name: str
    component_version: str | None
    component_id: str | None
    severity: str
    cvss: float | None
    epss: float | None
    kev: bool | None
    scope: str | None
    dependency_depth: int | None
    dependency_chain: list[str]
    reachability_verdict: str
    call_locations: list[str]
    sink_functions: list[str]
    fix_versions: list[str]
    risk_score: float | None
    evidence_confidence: Literal["high", "medium", "low"]
    advisory_summary: str | None
    impact_summary: str | None
    verification_basis: str | None
    last_seen_scan_id: str | None
    decision_tier: DecisionTier
    status: CaseStatus
    summary_note: str | None


class StakeholderPostureSummary(TypedDict):
    total_cases: int
    critical_high_count: int
    kev_count: int
    fix_available_count: int
    reachable_count: int
    likely_reachable_count: int
    overall_posture: Literal["elevated", "moderate", "low"]
    summary_note: str


class StakeholderAffectedArea(TypedDict):
    area_name: str
    case_count: int
    reachable_or_likely_count: int
    key_cves: list[str]
    focus_reason: str


class StakeholderTopPriorityAction(TypedDict):
    vuln_id: str
    component: str
    current_version: str | None
    target_version: str | None
    decision_tier: DecisionTier
    why_now: str
    impact_basis: str
    remediation_readiness: Literal["fix_available", "workaround_only", "investigate"]
    affected_area: str
    severity: NotRequired[Literal["critical", "high", "medium", "low"]]
    reachability_verdict: NotRequired[str]
    kev: NotRequired[bool]
    related_case_count: NotRequired[int]
    related_cves: NotRequired[list[str]]
    remediation_cluster_title: NotRequired[str]
    required_management_action: NotRequired[str]
    required_owner_type: NotRequired[Literal["developer_team", "platform_team", "release_manager"]]
    required_urgency: NotRequired[Literal["immediate", "next_window", "monitor"]]


class StakeholderImpactSummary(TypedDict):
    transitive_count: int
    direct_count: int
    reachable_or_likely_count: int
    high_exposure_areas: list[str]
    impact_note: str
    area_mapping_confidence: NotRequired[Literal["strong", "partial"]]
    area_mapping_note: NotRequired[str]


class StakeholderCurrentActionSnapshot(TypedDict):
    fix_now_count: int
    plan_remediation_count: int
    mitigate_count: int
    monitor_count: int
    fix_available_count: int
    reachable_or_likely_count: int


class StakeholderManagementAction(TypedDict):
    action: str
    reason: str
    owner_type: Literal["developer_team", "platform_team", "release_manager"]
    urgency: Literal["immediate", "next_window", "monitor"]


class StakeholderNextVerificationCheckpoint(TypedDict):
    trigger: str
    goal: str
    note: str
    what_will_be_rechecked: NotRequired[str]


class StakeholderNarrativeSections(TypedDict):
    what_needs_attention_now: str
    why_it_matters_now: str
    decision_needed_next: str
    what_remains_uncertain: str


class VerificationDeltaEntry(TypedDict):
    vuln_id: str
    component_id: str | None
    baseline_scan_id: str | None
    current_scan_id: str | None
    baseline_verdict: str | None
    current_verdict: str | None
    baseline_risk_score: float | None
    current_risk_score: float | None
    risk_delta: float | None
    fix_delta: str
    closure_recommendation: str
    change_type: list[str]


class VerificationDeltaSummary(TypedDict):
    baseline_scan_id: str | None
    current_scan_id: str | None
    baseline_case_count: int
    current_case_count: int
    added_cases: int
    resolved_cases: int
    risk_increased: int
    risk_decreased: int
    verdict_improved: int
    verdict_regressed: int
    fix_available_increased: int
    fix_available_decreased: int
    unchanged: int


class VerificationDelta(TypedDict):
    summary: VerificationDeltaSummary
    changes: list[VerificationDeltaEntry]


class StakeholderReport(TypedDict):
    report_type: Literal["stakeholder"]
    project: str
    generated_at: str
    run_id: NotRequired[str]
    scan_id: str | None
    source_commit: str | None
    posture_summary: StakeholderPostureSummary
    affected_areas: list[StakeholderAffectedArea]
    top_priority_actions: list[StakeholderTopPriorityAction]
    impact_summary: StakeholderImpactSummary
    current_action_snapshot: StakeholderCurrentActionSnapshot
    recommended_management_actions: list[StakeholderManagementAction]
    next_verification_checkpoint: StakeholderNextVerificationCheckpoint
    top_priority_action_coverage: NotRequired[dict[str, Any]]
    area_mapping: NotRequired[dict[str, Any]]
    narrative: NotRequired[str]
    narrative_sections: NotRequired[StakeholderNarrativeSections]
    narrative_source: NotRequired[Literal["llm", "fallback"]]
    narrative_reason: NotRequired[str]


class DeveloperTriageSummary(TypedDict):
    total_cases: int
    fix_now_count: int
    plan_remediation_count: int
    mitigate_count: int
    monitor_count: int
    confirmed_count: int
    likely_count: int
    unlikely_count: int
    no_sink_data_count: int


class DeveloperImmediateFixItem(TypedDict):
    vuln_id: str
    component: str
    current_version: str | None
    target_version: str | None
    severity: Literal["critical", "high", "medium", "low"]
    decision_tier: Literal["fix_now"]
    reachability_verdict: Literal["confirmed_reachable", "likely_reachable"]
    evidence_confidence: Literal["high", "medium", "low"]
    production_evidence: bool
    test_only_evidence: bool
    key_call_locations: list[str]
    dependency_depth: int | None
    dependency_chain: list[str]
    cvss: NotRequired[float | None]
    risk_score: NotRequired[float | None]
    cve_description: NotRequired[str]
    nvd_url: NotRequired[str]
    why_fix_now: str
    next_action: str


class DeveloperBacklogItem(TypedDict):
    vuln_id: str
    component: str
    current_version: str | None
    target_versions: list[str]
    severity: Literal["critical", "high", "medium", "low"]
    reachability_verdict: Literal["no_sink_data", "likely_unreachable", "unknown"]
    reason_not_fix_now: str
    related_case_count: NotRequired[int]
    related_cves: NotRequired[list[str]]


class DeveloperPlannedUpgradeBacklog(TypedDict):
    monitor_count: int
    plan_remediation_count: int
    top_backlog_items: list[DeveloperBacklogItem]
    summary_note: str
    backlog_clusters: NotRequired[list[dict[str, Any]]]


class DeveloperVerificationDelta(TypedDict):
    baseline_scan_id: str | None
    current_scan_id: str | None
    resolved_cases: int
    risk_decreased_cases: int
    verdict_improved_cases: int
    note: str


class DeveloperTechnicalFinding(TypedDict):
    vuln_id: str
    component: str
    current_version: str | None
    severity: Literal["critical", "high", "medium", "low"]
    decision_tier: DecisionTier
    reachability_verdict: Literal[
        "confirmed_reachable",
        "likely_reachable",
        "likely_unreachable",
        "no_sink_data",
    ]
    dependency_depth: int | None
    cvss: NotRequired[float | None]
    risk_score: NotRequired[float | None]
    fix_versions: list[str]
    sink_functions: list[str]
    call_locations: list[str]
    cve_description: NotRequired[str]
    nvd_url: NotRequired[str]
    key_call_evidence: NotRequired[list[str]]
    impact_summary: NotRequired[str]
    advisory_summary: NotRequired[str]
    why_this_tier: str


class DeveloperNarrativeSections(TypedDict):
    queue_overview: str
    strongest_evidence: str
    immediate_next_steps: str
    verification_guidance: str
    remaining_uncertainty: str


class DeveloperReport(TypedDict):
    report_type: Literal["developer"]
    project: str
    generated_at: str
    run_id: NotRequired[str]
    scan_id: str | None
    source_commit: str | None
    triage_summary: DeveloperTriageSummary
    immediate_fix_queue: list[DeveloperImmediateFixItem]
    planned_upgrade_backlog: DeveloperPlannedUpgradeBacklog
    verification_checklist: list[str]
    verification_delta: DeveloperVerificationDelta
    detailed_technical_findings: list[DeveloperTechnicalFinding]
    technical_appendix: dict[str, object]
    immediate_fix_clusters: NotRequired[list[dict[str, Any]]]
    immediate_fix_coverage: NotRequired[dict[str, Any]]
    cluster_verification_targets: NotRequired[list[dict[str, Any]]]
    reachability_legend: NotRequired[dict[str, str]]
    narrative: NotRequired[str]
    narrative_sections: NotRequired[DeveloperNarrativeSections]
    narrative_source: NotRequired[Literal["llm", "fallback"]]
    narrative_reason: NotRequired[str]
