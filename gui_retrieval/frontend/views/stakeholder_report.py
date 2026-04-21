"""
frontend/views/stakeholder_report.py - Stakeholder Security Summary UI.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from backend.services.report_export_service import export_stakeholder_report_pdf
from backend.services.report_service import generate_stakeholder_report
from frontend.views.analysis import render_analysis_tab


def _vega_bar(values: list[dict[str, Any]], x_field: str, y_field: str, color: str) -> None:
    st.vega_lite_chart(
        {
            "data": {"values": values},
            "mark": {"type": "bar", "cornerRadiusTopRight": 6, "cornerRadiusBottomRight": 6},
            "width": "container",
            "height": 260,
            "encoding": {
                "x": {"field": x_field, "type": "quantitative", "title": None},
                "y": {"field": y_field, "type": "nominal", "sort": "-x", "title": None},
                "color": {"value": color},
                "tooltip": [
                    {"field": y_field, "type": "nominal"},
                    {"field": x_field, "type": "quantitative"},
                ],
            },
            "view": {"stroke": None},
        },
        use_container_width=True,
    )


def render_stakeholder_report_tab(project_name: str) -> None:
    st.markdown('<div class="gh-section-heading">Stakeholder Security Summary</div>', unsafe_allow_html=True)
    st.caption("Decision-focused view for posture, priority actions, impact, and verification checkpoint.")

    cache_key = f"stakeholder_report::{project_name}"
    cache_meta_key = f"{cache_key}::meta"

    control_left, control_export = st.columns([3, 1])
    with control_left:
        use_llm = st.checkbox(
            "Augment with LLM narrative",
            value=True,
            key=f"stakeholder_use_llm::{project_name}",
        )
    with control_export:
        export_clicked = st.button("Export PDF", key=f"stakeholder_pdf_export::{project_name}")

    cached_report = st.session_state.get(cache_key)
    cached_meta = st.session_state.get(cache_meta_key, {})
    should_regenerate = cached_report is None or cached_meta.get("use_llm") != use_llm

    if should_regenerate:
        with st.spinner("Building stakeholder report..."):
            report = generate_stakeholder_report(project_name, use_llm=use_llm)
        st.session_state[cache_key] = report
        st.session_state[cache_meta_key] = {"use_llm": use_llm}
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
            "Export Stakeholder PDF",
            data=prepared_pdf,
            file_name=f"stakeholder_report_{project_name.replace('/', '_')}.pdf",
            mime="application/pdf",
            key=f"stakeholder_pdf_download::{project_name}",
            on_click="ignore",
        )

    if report.get("narrative"):
        source = str(report.get("narrative_source") or "fallback")
        reason = str(report.get("narrative_reason") or "")
        if source == "llm":
            st.caption("Narrative source: LLM augmentation")
        else:
            st.caption("Narrative source: deterministic fallback")
            if use_llm and reason == "missing_openrouter_api_key":
                st.info("LLM toggle is ON but `OPENROUTER_API_KEY` is missing, so fallback narrative is used.")
            elif use_llm and reason in {"llm_output_insufficient", "llm_runtime_error"}:
                st.info("LLM toggle is ON but response was unavailable/invalid, so fallback narrative is used.")
        st.markdown("**Executive Security Summary**")
        st.markdown(report["narrative"])

    posture = report.get("posture_summary") or {}
    cols = st.columns(5)
    cols[0].metric("Total Cases", posture.get("total_cases", 0))
    cols[1].metric("Critical/High", posture.get("critical_high_cases", 0))
    cols[2].metric("KEV Cases", posture.get("kev_cases", 0))
    cols[3].metric("Reachable/Likely", posture.get("reachable_or_likely_cases", 0))
    cols[4].metric("Fix Available", posture.get("fix_available_cases", 0))

    st.markdown("**Top Priority Actions**")
    top_actions = report.get("top_priority_actions") or []
    if top_actions:
        st.dataframe(top_actions, use_container_width=True, hide_index=True)
    else:
        st.info("No top priority actions available.")

    st.markdown("**Impact Summary**")
    impact = report.get("impact_summary") or {}
    i1, i2, i3, i4 = st.columns(4)
    i1.metric("Runtime Affected", impact.get("runtime_affected_cases", 0))
    i2.metric("Direct Dependency Cases", impact.get("direct_dependency_cases", 0))
    i3.metric("Transitive Dependency Cases", impact.get("transitive_dependency_cases", 0))
    i4.metric("Reachable/Likely", impact.get("reachable_or_likely_cases", 0))
    st.caption(impact.get("impact_note") or "No impact note available.")

    st.markdown("**Action Buckets**")
    action_buckets = report.get("action_buckets") or []
    if action_buckets:
        st.dataframe(action_buckets, use_container_width=True, hide_index=True)
        _vega_bar(
            [{"label": item.get("decision_tier"), "count": item.get("case_count", 0)} for item in action_buckets],
            "count",
            "label",
            "#bc4c00",
        )
    else:
        st.info("No action bucket data.")

    st.markdown("**Tier Action Guidance**")
    if action_buckets:
        guidance_rows = [
            {
                "decision_tier": item.get("decision_tier"),
                "current_case_count": item.get("case_count", 0),
                "recommended_action": item.get("recommended_action", "No guidance provided."),
            }
            for item in action_buckets
        ]
        st.dataframe(guidance_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No tier guidance available.")

    st.markdown("**Status Snapshot**")
    status_snapshot = report.get("status_snapshot") or {}
    status_values = [
        {"label": "new", "count": int(status_snapshot.get("new", 0))},
        {"label": "under_review", "count": int(status_snapshot.get("under_review", 0))},
        {"label": "planned", "count": int(status_snapshot.get("planned", 0))},
        {"label": "in_progress", "count": int(status_snapshot.get("in_progress", 0))},
        {"label": "mitigated", "count": int(status_snapshot.get("mitigated", 0))},
        {"label": "resolved_pending_verify", "count": int(status_snapshot.get("resolved_pending_verify", 0))},
        {"label": "verified_closed", "count": int(status_snapshot.get("verified_closed", 0))},
    ]
    _vega_bar(status_values, "count", "label", "#2563eb")

    st.markdown("**Next Verification Checkpoint**")
    checkpoint = report.get("next_verification_checkpoint") or {}
    st.markdown(checkpoint.get("guidance") or "No guidance provided.")
    triggers = checkpoint.get("trigger_conditions") or []
    if triggers:
        for item in triggers:
            st.markdown(f"- {item}")
    else:
        st.info("No trigger conditions configured.")

    with st.expander("Internal/Debug: Legacy LLM Analysis", expanded=False):
        st.caption("Legacy scenario-driven analysis retained for troubleshooting only.")
        render_analysis_tab(project_name)
