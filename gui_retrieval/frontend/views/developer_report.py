"""
frontend/views/developer_report.py - Developer Remediation Report UI.
"""

from __future__ import annotations

import streamlit as st

from backend.services.report_service import generate_developer_report
from frontend.views.analysis import render_analysis_tab


def render_developer_report_tab(project_name: str) -> None:
    st.markdown('<div class="gh-section-heading">Developer Remediation Report</div>', unsafe_allow_html=True)
    st.caption("Technical findings, dependency/reachability context, remediation plan, and verification steps.")

    cache_key = f"developer_report::{project_name}"
    cache_meta_key = f"{cache_key}::meta"

    use_llm = st.checkbox(
        "Augment with LLM narrative",
        value=True,
        key=f"developer_use_llm::{project_name}",
    )

    cached_report = st.session_state.get(cache_key)
    cached_meta = st.session_state.get(cache_meta_key, {})
    should_regenerate = cached_report is None or cached_meta.get("use_llm") != use_llm

    if should_regenerate:
        with st.spinner("Building developer report..."):
            report = generate_developer_report(project_name, use_llm=use_llm)
        st.session_state[cache_key] = report
        st.session_state[cache_meta_key] = {"use_llm": use_llm}
    else:
        report = cached_report

    triage = report.get("triage_summary") or {}
    cols = st.columns(4)
    cols[0].metric("Total Cases", triage.get("total_cases", 0))
    cols[1].metric("Fix Now", triage.get("fix_now", 0))
    cols[2].metric("Investigate Next", triage.get("investigate_next", 0))
    cols[3].metric("Monitor", triage.get("monitor", 0))

    st.markdown("**Technical Findings**")
    findings = report.get("technical_findings") or []
    if findings:
        st.dataframe(findings, use_container_width=True, hide_index=True)
    else:
        st.info("No technical findings available.")

    st.markdown("**Dependency Context**")
    dep = report.get("dependency_context") or {}
    d1, d2, d3 = st.columns(3)
    d1.metric("Direct Dependency Cases", dep.get("direct_dependency_cases", 0))
    d2.metric("Transitive Dependency Cases", dep.get("transitive_dependency_cases", 0))
    d3.metric("Unknown Depth Cases", dep.get("unknown_depth_cases", 0))

    st.markdown("**Reachability Evidence**")
    reach = report.get("reachability_evidence") or {}
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Confirmed Reachable", reach.get("confirmed_reachable", 0))
    r2.metric("Likely Reachable", reach.get("likely_reachable", 0))
    r3.metric("Likely Unreachable", reach.get("likely_unreachable", 0))
    r4.metric("No Sink Data", reach.get("no_sink_data", 0))
    sample_locations = reach.get("sample_call_locations") or []
    with st.expander("Sample Call Locations", expanded=False):
        if sample_locations:
            for item in sample_locations:
                st.markdown(f"- `{item}`")
        else:
            st.info("No call locations available.")

    st.markdown("**Recommended Fix**")
    recommended_fix = report.get("recommended_fix") or []
    if recommended_fix:
        st.dataframe(recommended_fix, use_container_width=True, hide_index=True)
    else:
        st.info("No fix recommendation entries available.")

    st.markdown("**Verification Steps**")
    verification_steps = report.get("verification_steps") or []
    if verification_steps:
        for item in verification_steps:
            st.markdown(f"- {item}")
    else:
        st.info("No verification steps available.")

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
        st.markdown("**Narrative Guidance**")
        st.markdown(report["narrative"])
    elif use_llm:
        reason = str(report.get("narrative_reason") or "")
        if reason in {"missing_openrouter_api_key", "llm_output_insufficient", "llm_runtime_error"}:
            st.info("Narrative Guidance is unavailable for this run; structured report sections above are still valid.")

    with st.expander("Internal/Debug: Legacy LLM Analysis", expanded=False):
        st.caption("Legacy scenario-driven analysis retained for troubleshooting only.")
        render_analysis_tab(project_name)
