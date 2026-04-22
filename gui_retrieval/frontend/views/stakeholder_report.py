"""
frontend/views/stakeholder_report.py - Stakeholder Security Summary UI.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from backend.services.report_export_service import export_stakeholder_report_pdf
from backend.services.report_service import generate_stakeholder_report, get_report_runtime_version


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


def _priority_action_signature(item: dict[str, Any]) -> str:
    return (
        f"{str(item.get('component') or '').strip().lower()}|"
        f"{str(item.get('current_version') or '').strip().lower()}|"
        f"{str(item.get('target_version') or '').strip().lower()}|"
        f"{str(item.get('decision_tier') or '').strip().lower()}|"
        f"{','.join(sorted(str(v) for v in (item.get('related_cves') or [])))}"
    )


def _management_action_signature(item: dict[str, Any]) -> str:
    return (
        f"{str(item.get('action') or '').strip().lower()}|"
        f"{str(item.get('owner_type') or '').strip().lower()}|"
        f"{str(item.get('urgency') or '').strip().lower()}"
    )


def _render_summary_ribbon(report: dict[str, Any]) -> None:
    posture = report.get("posture_summary") or {}
    snapshot = report.get("current_action_snapshot") or {}
    reachable_likely = int(posture.get("reachable_count") or 0) + int(
        posture.get("likely_reachable_count") or 0
    )

    st.markdown("#### Summary Ribbon")
    cols = st.columns(6)
    cols[0].metric("Total Cases", int(posture.get("total_cases") or 0))
    cols[1].metric("Critical/High", int(posture.get("critical_high_count") or 0))
    cols[2].metric("Reachable/Likely", reachable_likely)
    cols[3].metric("Fix Now", int(snapshot.get("fix_now_count") or 0))
    cols[4].metric("Fix Available", int(snapshot.get("fix_available_count") or 0))
    cols[5].metric("Overall Posture", str(posture.get("overall_posture") or "unknown").upper())
    if posture.get("summary_note"):
        st.caption(str(posture.get("summary_note")))


def _render_top_actions(report: dict[str, Any]) -> None:
    st.markdown("#### What Needs Approval Now")
    actions = _dedupe_records(
        [dict(item) for item in (report.get("top_priority_actions") or [])],
        _priority_action_signature,
    )
    coverage = report.get("top_priority_action_coverage") or {}
    if coverage.get("coverage_note"):
        st.caption(str(coverage.get("coverage_note")))

    if not actions:
        st.info("No high-priority action card is available yet.")
        return

    for item in actions[:4]:
        with st.container(border=True):
            title = str(item.get("remediation_cluster_title") or f"{item.get('component') or 'Dependency'} remediation cluster")
            st.markdown(f"**{title}**")
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"`tier: {item.get('decision_tier') or 'monitor'}`")
            c2.markdown(
                f"`cases: {int(item.get('related_case_count') or 0)} ({len(item.get('related_cves') or [])} CVEs)`"
            )
            c3.markdown(f"`area: {item.get('affected_area') or 'unknown'}`")

            st.caption(
                f"Version path: `{item.get('current_version') or 'unknown'}` -> `{item.get('target_version') or 'target pending'}`"
            )
            if item.get("related_cves"):
                st.caption(f"Related CVEs: {', '.join(item.get('related_cves') or [])}")

            st.write(str(item.get("why_now") or "Why now data is not available yet."))
            st.write(str(item.get("impact_basis") or "Impact summary is not available yet."))
            st.markdown(
                f"**Required management action:** {item.get('required_management_action') or item.get('required_owner_type') or 'Define owner'}"
            )


def _render_exposure_context(report: dict[str, Any]) -> None:
    st.markdown("#### Exposure Context")
    affected_areas = [dict(item) for item in (report.get("affected_areas") or [])]
    impact = report.get("impact_summary") or {}
    mapping_note = str(
        (report.get("area_mapping") or {}).get("note")
        or impact.get("area_mapping_note")
        or ""
    ).strip()

    if mapping_note:
        st.caption(mapping_note)

    if not affected_areas:
        st.info("Affected area context is not available yet.")
        return

    for item in affected_areas:
        with st.container(border=True):
            st.markdown(f"**{item.get('area_name') or 'Unknown area'}**")
            a1, a2 = st.columns(2)
            a1.metric("Cases", int(item.get("case_count") or 0))
            a2.metric("Reachable/Likely", int(item.get("reachable_or_likely_count") or 0))
            if item.get("key_cves"):
                st.caption(f"Key CVEs: {', '.join(item.get('key_cves') or [])}")
            focus_reason = str(item.get("focus_reason") or "").strip()
            if focus_reason:
                st.write(focus_reason)


def _render_action_snapshot(report: dict[str, Any]) -> None:
    st.markdown("#### Action Snapshot")
    snapshot = report.get("current_action_snapshot") or {}
    cols = st.columns(4)
    cols[0].metric("fix_now", int(snapshot.get("fix_now_count") or 0))
    cols[1].metric("plan_remediation", int(snapshot.get("plan_remediation_count") or 0))
    cols[2].metric("mitigate", int(snapshot.get("mitigate_count") or 0))
    cols[3].metric("monitor", int(snapshot.get("monitor_count") or 0))


def _render_management_actions(report: dict[str, Any]) -> None:
    st.markdown("#### Recommended Management Actions")
    actions = _dedupe_records(
        [dict(item) for item in (report.get("recommended_management_actions") or [])],
        _management_action_signature,
    )
    if not actions:
        st.info("No management action card is available yet.")
        return

    for item in actions[:4]:
        with st.container(border=True):
            st.markdown(f"**{item.get('action') or 'Action pending'}**")
            st.caption(f"Owner: {item.get('owner_type') or 'owner pending'} | Urgency: {item.get('urgency') or 'monitor'}")
            if item.get("reason"):
                st.write(str(item.get("reason")))


def _render_verification_checkpoint(report: dict[str, Any]) -> None:
    st.markdown("#### Next Verification Checkpoint")
    checkpoint = report.get("next_verification_checkpoint") or {}
    if not checkpoint:
        st.info("Verification checkpoint data is not available yet.")
        return

    with st.container(border=True):
        st.markdown(f"**Trigger:** {checkpoint.get('trigger') or 'next scan'}")
        st.markdown(f"**Goal:** {checkpoint.get('goal') or 'validate remediation movement'}")
        if checkpoint.get("what_will_be_rechecked"):
            st.markdown(f"**What will be rechecked:** {checkpoint.get('what_will_be_rechecked')}")
        if checkpoint.get("note"):
            st.caption(str(checkpoint.get("note")))


def render_stakeholder_report_tab(project_name: str) -> None:
    st.markdown('<div class="gh-section-heading">Stakeholder Security Summary</div>', unsafe_allow_html=True)
    st.caption("Decision-focused view: what is risky now, why it matters now, and what needs approval next.")

    cache_key = f"stakeholder_report::{project_name}"
    cache_meta_key = f"{cache_key}::meta"
    report_version = get_report_runtime_version()

    control_col_left, control_col_right = st.columns([7, 1])
    with control_col_right:
        with st.popover("Report Controls", use_container_width=True):
            use_llm = st.checkbox(
                "Augment with LLM narrative",
                value=False,
                key=f"stakeholder_use_llm::{project_name}",
            )
            export_clicked = st.button(
                "Prepare PDF Export",
                key=f"stakeholder_pdf_export::{project_name}",
                use_container_width=True,
            )
    with control_col_left:
        st.caption("Interactive report prioritizes grouped actions and decision tiers over long narrative prose.")

    cached_report = st.session_state.get(cache_key)
    cached_meta = st.session_state.get(cache_meta_key, {})
    should_regenerate = (
        cached_report is None
        or cached_meta.get("use_llm") != use_llm
        or cached_meta.get("report_version") != report_version
    )

    if should_regenerate:
        with st.spinner("Building stakeholder report..."):
            report = generate_stakeholder_report(project_name, use_llm=use_llm)
        st.session_state[cache_key] = report
        st.session_state[cache_meta_key] = {
            "use_llm": use_llm,
            "report_version": report_version,
        }
    else:
        report = cached_report

    prepared_pdf: bytes | None = None
    pdf_error: str | None = None
    if export_clicked:
        try:
            prepared_pdf = export_stakeholder_report_pdf(report)
        except Exception as exc:
            pdf_error = str(exc)
    if pdf_error:
        st.error(f"Cannot export PDF: {pdf_error}")
    if prepared_pdf:
        st.download_button(
            "Download Stakeholder PDF",
            data=prepared_pdf,
            file_name=f"stakeholder_report_{project_name.replace('/', '_')}.pdf",
            mime="application/pdf",
            key=f"stakeholder_pdf_download::{project_name}",
            on_click="ignore",
        )

    _render_summary_ribbon(report)
    _render_top_actions(report)
    _render_exposure_context(report)
    _render_action_snapshot(report)
    _render_management_actions(report)
    _render_verification_checkpoint(report)
