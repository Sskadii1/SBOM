"""
frontend/views/analysis.py — LLM-powered scenario analysis tab.
"""
import streamlit as st
import frontend.data_access as db


def render_analysis_tab(project_name: str) -> None:
    """LLM-powered scenario analysis tab."""
    from backend.services.llm_service import run_pipeline, get_scenarios

    scenarios = {
        key: label
        for key, label in get_scenarios().items()
        if key != "project_overview"
    }

    st.markdown('<div class="gh-section-heading">Security Analysis & Querying</div>', unsafe_allow_html=True)
    st.caption("Ask specific questions about the project's vulnerability landscape.")

    scenario_name = st.selectbox(
        "Analysis Scenario",
        options=list(scenarios.keys()),
        format_func=lambda k: scenarios[k],
    )

    overrides = {"project_name": project_name}

    drilldown_scenarios = {"dev_explain", "explainability_mode", "multi_audience", "arch_impact"}

    if scenario_name in drilldown_scenarios:
        cves = db.fetch_cves(project_name)
        if cves:
            selected_cve = st.selectbox("Select CVE", options=cves)
            overrides["vuln_id"] = selected_cve
        else:
            st.warning("No CVEs found for this project.")
            return
        comps = db.fetch_components(project_name, selected_cve)
        if comps:
            c_opts = [f"{c['name']}@{c['version']} ({c['component_id']})" for c in comps]
            sel_c = st.selectbox("Select affected component", options=c_opts)
            if sel_c:
                import re
                m = re.search(r'\(([^)]+)\)$', sel_c)
                if m:
                    overrides["component_id"] = m.group(1)
        else:
            st.warning("No affected components found for this CVE.")
            return

    st.caption("Currently showing project-only scenarios. Portfolio scenarios are temporarily hidden.")

    st.markdown("---")

    if st.button("▶ Run Analysis", type="primary", key="btn_run"):
        with st.spinner("Running graph retrieval and LLM analysis…"):
            result = run_pipeline(scenario_name, overrides)

        st.markdown('<div class="gh-section-heading">Analysis Result</div>', unsafe_allow_html=True)
        st.markdown(result["explanation"])

        with st.expander("Query diagnostics", expanded=False):
            st.json(result["query_meta"])

        with st.expander("Evidence records", expanded=False):
            st.json(result["evidence"][:10])
