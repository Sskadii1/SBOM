"""
frontend/views/developer_report.py - Developer Remediation Report UI.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from backend.services.report_presentation_service import verification_delta_is_meaningful
from backend.services.report_export_service import export_developer_report_pdf_for_project
from backend.services.report_service import generate_developer_report, get_report_runtime_version
from backend.services.report_vocabulary_service import present_decision_tier, present_reachability
from frontend.views.report_download_helpers import trigger_pdf_download


def _dedupe_records(records: list[dict[str, Any]], key_builder: Any) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = str(key_builder(record) or "").strip().lower()
        if not key:
            key = str(len(unique))
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique


def _cluster_signature(item: dict[str, Any]) -> str:
    return str(item.get("cluster_id") or "").strip().lower()


def _finding_signature(item: dict[str, Any]) -> str:
    return (
        f"{str(item.get('vuln_id') or '').strip().lower()}|"
        f"{str(item.get('component') or item.get('component_name') or '').strip().lower()}|"
        f"{str(item.get('current_version') or '').strip().lower()}"
    )


def _render_triage_strip(report: dict[str, Any]) -> None:
    st.markdown("#### Triage Strip")
    triage = report.get("triage_summary") or {}
    top = st.columns(5)
    top[0].metric("Total Cases", int(triage.get("total_cases") or 0))
    top[1].metric("Fix Now", int(triage.get("fix_now_count") or 0))
    top[2].metric("Plan Remediation", int(triage.get("plan_remediation_count") or 0))
    top[3].metric("Mitigate", int(triage.get("mitigate_count") or 0))
    top[4].metric("Monitor", int(triage.get("monitor_count") or 0))

    reach = st.columns(4)
    reach[0].metric("Confirmed Reachable", int(triage.get("confirmed_count") or 0))
    reach[1].metric("Likely Reachable", int(triage.get("likely_count") or 0))
    reach[2].metric("Likely Unreachable", int(triage.get("unlikely_count") or 0))
    reach[3].metric("No Sink Data", int(triage.get("no_sink_data_count") or 0))


def _render_legend(report: dict[str, Any]) -> None:
    st.markdown("#### Reachability Legend")
    legend = report.get("reachability_legend") or {}
    if not legend:
        legend = {
            "confirmed_reachable": present_reachability("confirmed_reachable", "developer", style="sentence"),
            "likely_reachable": present_reachability("likely_reachable", "developer", style="sentence"),
            "no_sink_data": present_reachability("no_sink_data", "developer", style="sentence"),
        }
    st.caption(
        " | ".join(
            f"{key} = {value}"
            for key, value in legend.items()
        )
    )


def _render_immediate_fix_clusters(report: dict[str, Any]) -> None:
    st.markdown("#### Immediate Fix Clusters")
    clusters = _dedupe_records(
        [dict(item) for item in (report.get("immediate_fix_clusters") or [])],
        _cluster_signature,
    )
    coverage = report.get("immediate_fix_coverage") or {}
    if coverage.get("coverage_note"):
        st.caption(str(coverage.get("coverage_note")))

    if not clusters:
        st.info("No immediate fix clusters are available yet.")
        return

    for cluster in clusters:
        with st.container(border=True):
            st.markdown(f"**{cluster.get('package') or 'Unknown package'} remediation cluster**")
            top = st.columns(3)
            top[0].markdown(
                f"`cases: {int(cluster.get('related_case_count') or 0)} ({len(cluster.get('related_cves') or [])} CVEs)`"
            )
            top[1].markdown(
                f"`version: {cluster.get('current_version') or 'unknown'} -> {cluster.get('target_version') or 'target pending'}`"
            )
            top[2].markdown(
                f"`evidence: {present_reachability(str(cluster.get('strongest_reachability') or 'no_sink_data'), 'developer')}`"
            )

            if cluster.get("related_cves"):
                st.caption(f"Related CVEs: {', '.join(cluster.get('related_cves') or [])}")

            scope_cols = st.columns(4)
            scope_cols[0].metric("Production", int(cluster.get("production_case_count") or 0))
            scope_cols[1].metric("Test-only", int(cluster.get("test_only_case_count") or 0))
            scope_cols[2].metric("Mixed", int(cluster.get("mixed_case_count") or 0))
            scope_cols[3].metric("Unknown Scope", int(cluster.get("unknown_scope_case_count") or 0))

            call_evidence = [dict(item) for item in (cluster.get("call_evidence") or [])]
            if call_evidence:
                st.markdown("**Call Evidence (per CVE)**")
                for evidence in call_evidence[:6]:
                    vuln_id = evidence.get("vuln_id") or "N/A"
                    verdict = evidence.get("reachability_verdict") or "no_sink_data"
                    scope = evidence.get("evidence_scope") or "unknown"
                    st.caption(
                        f"{vuln_id} | {present_reachability(str(verdict), 'developer')} | scope={scope}"
                    )
                    locations = evidence.get("call_locations") or []
                    if locations:
                        for location in locations:
                            st.markdown(f"- `{location}`")
                    else:
                        st.markdown("- `No call location captured yet`")
                    sinks = evidence.get("sink_functions") or []
                    if sinks:
                        st.caption("Sink evidence: " + ", ".join(sinks))
            elif cluster.get("key_call_locations"):
                st.markdown("**Call Evidence**")
                for location in (cluster.get("key_call_locations") or []):
                    st.markdown(f"- `{location}`")
            else:
                st.caption("Call evidence is not available yet for this cluster.")

            st.write(str(cluster.get("why_fix_now") or "No rationale available."))
            st.markdown(f"**Exact next action:** {cluster.get('next_action') or 'Action pending'}")
            verification_target = cluster.get("verification_target") or {}
            if verification_target.get("success_criteria"):
                st.markdown(f"**Verification target:** {verification_target.get('success_criteria')}")


def _render_backlog_clusters(report: dict[str, Any]) -> None:
    st.markdown("#### Planned Upgrade Backlog")
    backlog = report.get("planned_upgrade_backlog") or {}
    clusters = _dedupe_records(
        [dict(item) for item in (backlog.get("backlog_clusters") or [])],
        _cluster_signature,
    )
    if backlog.get("summary_note"):
        st.caption(str(backlog.get("summary_note")))

    if not clusters:
        st.info("No backlog cluster is currently available.")
        return

    for cluster in clusters:
        with st.container(border=True):
            st.markdown(f"**{cluster.get('package') or 'Unknown package'}**")
            c1, c2, c3 = st.columns(3)
            c1.markdown(
                f"`queue: {present_decision_tier(str(cluster.get('decision_tier') or 'monitor'), 'developer')}`"
            )
            c2.markdown(f"`cases: {int(cluster.get('related_case_count') or 0)}`")
            c3.markdown(
                f"`target: {cluster.get('target_version') or 'target pending'}`"
            )
            if cluster.get("related_cves"):
                st.caption(f"Related CVEs: {', '.join(cluster.get('related_cves') or [])}")
            st.write(str(cluster.get("reason_not_fix_now") or "Reason pending."))
            st.markdown(
                f"**Next-window action:** {cluster.get('recommended_next_window_action') or 'Action pending'}"
            )


def _render_verification_panel(report: dict[str, Any]) -> None:
    st.markdown("#### Verification Panel")
    verification_targets = [dict(item) for item in (report.get("cluster_verification_targets") or [])]
    if verification_targets:
        for item in verification_targets:
            with st.container(border=True):
                st.markdown(f"**{item.get('cluster_title') or 'Remediation cluster'}**")
                st.markdown(f"**What must change:** {item.get('what_must_change') or 'Pending'}")
                st.markdown(f"**What scan should confirm it:** {item.get('scan_recheck') or 'Pending'}")
                st.markdown(f"**Success criteria:** {item.get('success_criteria') or 'Pending'}")
    else:
        st.info("Cluster-specific verification targets are not available yet.")

    verification_delta = report.get("verification_delta") or {}
    baseline_scan = str(verification_delta.get("baseline_scan_id") or "").strip().lower()
    current_scan = str(verification_delta.get("current_scan_id") or "").strip().lower()
    scans_are_present = baseline_scan not in {"", "none", "unknown"} and current_scan not in {"", "none", "unknown"}
    if verification_delta_is_meaningful(verification_delta) and scans_are_present:
        d1, d2, d3, d4, d5 = st.columns(5)
        d1.metric("Baseline Scan", verification_delta.get("baseline_scan_id") or "none")
        d2.metric("Current Scan", verification_delta.get("current_scan_id") or "unknown")
        d3.metric("Resolved", int(verification_delta.get("resolved_cases") or 0))
        d4.metric("Risk Decreased", int(verification_delta.get("risk_decreased_cases") or 0))
        d5.metric("Verdict Improved", int(verification_delta.get("verdict_improved_cases") or 0))
    if verification_delta.get("note"):
        st.caption(str(verification_delta.get("note")))


def _render_technical_appendix(report: dict[str, Any]) -> None:
    with st.expander("Technical Appendix", expanded=False):
        findings = _dedupe_records(
            [dict(item) for item in (report.get("detailed_technical_findings") or [])],
            _finding_signature,
        )
        if not findings:
            st.info("No technical finding data is available.")
            return

        st.markdown("**Per-CVE finding list**")
        for finding in findings:
            with st.container(border=True):
                st.markdown(
                    f"**{finding.get('vuln_id') or 'N/A'} | {finding.get('component') or 'unknown'} {finding.get('current_version') or 'unknown'}**"
                )
                st.caption(
                    f"tier={finding.get('decision_tier') or 'monitor'} | "
                    f"reachability={finding.get('reachability_verdict') or 'no_sink_data'} | "
                    f"severity={finding.get('severity') or 'medium'}"
                )
                if finding.get("impact_summary"):
                    st.write(str(finding.get("impact_summary")))
                if finding.get("key_call_evidence"):
                    st.caption("Call locations: " + ", ".join(finding.get("key_call_evidence") or []))
                if finding.get("nvd_url"):
                    st.markdown(f"NVD: [{finding.get('nvd_url')}]({finding.get('nvd_url')})")

        appendix = report.get("technical_appendix") or {}
        evidence_scope = appendix.get("evidence_scope_summary") or {}
        st.markdown("**Evidence scope summary**")
        s1, s2, s3 = st.columns(3)
        s1.metric("Production-only", int(evidence_scope.get("production_only_cases") or 0))
        s2.metric("Test-only", int(evidence_scope.get("test_only_cases") or 0))
        s3.metric("Mixed", int(evidence_scope.get("mixed_scope_cases") or 0))


def render_developer_report_tab(project_name: str) -> None:
    st.markdown('<div class="gh-section-heading">Developer Remediation Report</div>', unsafe_allow_html=True)
    st.caption("Remediation work-queue view: where issues are, how strong evidence is, what to fix, and how to verify.")

    cache_key = f"developer_report::{project_name}"
    cache_meta_key = f"{cache_key}::meta"
    report_version = get_report_runtime_version()

    control_col_left, control_col_right = st.columns([7, 1])
    with control_col_right:
        with st.popover("Report Controls", width="stretch"):
            use_llm = st.checkbox(
                "Augment with LLM narrative",
                value=False,
                key=f"developer_use_llm::{project_name}",
            )
            export_clicked = st.button(
                "Export PDF",
                key=f"developer_pdf_export::{project_name}",
                width="stretch",
            )
    with control_col_left:
        st.caption("Interactive report is optimized for cluster-based triage and fix execution.")

    cached_report = st.session_state.get(cache_key)
    cached_meta = st.session_state.get(cache_meta_key, {})
    should_regenerate = (
        cached_report is None
        or cached_meta.get("use_llm") != use_llm
        or cached_meta.get("report_version") != report_version
    )

    if should_regenerate:
        with st.spinner("Building developer report..."):
            report = generate_developer_report(project_name, use_llm=use_llm)
        st.session_state[cache_key] = report
        st.session_state[cache_meta_key] = {
            "use_llm": use_llm,
            "report_version": report_version,
        }
    else:
        report = cached_report

    if export_clicked:
        try:
            with st.spinner("Generating polished developer PDF..."):
                prepared_pdf = export_developer_report_pdf_for_project(project_name)
            trigger_pdf_download(
                f"developer_report_{project_name.replace('/', '_')}.pdf",
                prepared_pdf,
                key=f"developer_pdf_autodownload::{project_name}",
            )
        except Exception as exc:
            st.error(f"Cannot export PDF: {exc}")

    _render_triage_strip(report)
    _render_legend(report)
    _render_immediate_fix_clusters(report)
    _render_backlog_clusters(report)
    _render_verification_panel(report)
    _render_technical_appendix(report)
