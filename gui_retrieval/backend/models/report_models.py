"""
Canonical domain schemas for report-driven outputs.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

from backend.models.decision_tiering import DecisionTier
from backend.models.report_status import CaseStatus


class AlertCase(TypedDict):
    project: str
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
    reachability_verdict: str
    call_locations: list[str]
    fix_versions: list[str]
    risk_score: float | None
    decision_tier: DecisionTier
    status: CaseStatus
    summary_note: str | None


class StakeholderPostureSummary(TypedDict):
    total_cases: int
    critical_high_cases: int
    kev_cases: int
    reachable_or_likely_cases: int
    fix_available_cases: int


class StakeholderTopPriorityAction(TypedDict):
    vuln_id: str
    component_name: str
    severity: str
    risk_score: float | None
    decision_tier: DecisionTier
    status: CaseStatus
    rationale: str
    recommended_action: str
    summary_note: str | None


class StakeholderImpactSummary(TypedDict):
    runtime_affected_cases: int
    direct_dependency_cases: int
    transitive_dependency_cases: int
    reachable_or_likely_cases: int
    impact_note: str


class StakeholderActionBucket(TypedDict):
    decision_tier: DecisionTier
    case_count: int
    rationale: str
    recommended_action: str
    related_vuln_ids: list[str]


class StakeholderStatusSnapshot(TypedDict):
    new: int
    under_review: int
    planned: int
    in_progress: int
    mitigated: int
    resolved_pending_verify: int
    verified_closed: int


class StakeholderNextVerificationCheckpoint(TypedDict):
    guidance: str
    trigger_conditions: list[str]


class StakeholderReport(TypedDict):
    report_type: Literal["stakeholder"]
    project: str
    generated_at: str
    posture_summary: StakeholderPostureSummary
    top_priority_actions: list[StakeholderTopPriorityAction]
    impact_summary: StakeholderImpactSummary
    action_buckets: list[StakeholderActionBucket]
    status_snapshot: StakeholderStatusSnapshot
    next_verification_checkpoint: StakeholderNextVerificationCheckpoint
    run_id: NotRequired[str]
    sbom_source: NotRequired[str | None]
    reachability_source: NotRequired[str | None]
    vulnerability_source: NotRequired[str | None]
    narrative: NotRequired[str]
    narrative_source: NotRequired[Literal["llm", "fallback"]]
    narrative_reason: NotRequired[str]


class DeveloperTriageSummary(TypedDict):
    total_cases: int
    fix_now: int
    investigate_next: int
    monitor: int


class DeveloperTechnicalFinding(TypedDict):
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
    reachability_verdict: str
    call_locations: list[str]
    fix_versions: list[str]
    risk_score: float | None
    decision_tier: DecisionTier
    status: CaseStatus
    summary_note: str | None


class DeveloperDependencyContext(TypedDict):
    direct_dependency_cases: int
    transitive_dependency_cases: int
    unknown_depth_cases: int


class DeveloperReachabilityEvidence(TypedDict):
    confirmed_reachable: int
    likely_reachable: int
    likely_unreachable: int
    no_sink_data: int
    sample_call_locations: list[str]


class DeveloperRecommendedFix(TypedDict):
    vuln_id: str
    component_name: str
    component_version: str | None
    decision_tier: DecisionTier
    fix_versions: list[str]
    summary_note: str | None


class DeveloperReport(TypedDict):
    report_type: Literal["developer"]
    project: str
    generated_at: str
    triage_summary: DeveloperTriageSummary
    technical_findings: list[DeveloperTechnicalFinding]
    dependency_context: DeveloperDependencyContext
    reachability_evidence: DeveloperReachabilityEvidence
    recommended_fix: list[DeveloperRecommendedFix]
    verification_steps: list[str]
    run_id: NotRequired[str]
    narrative: NotRequired[str]
    narrative_source: NotRequired[Literal["llm", "fallback"]]
    narrative_reason: NotRequired[str]
