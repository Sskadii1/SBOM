"""
frontend/views/analysis.py — LLM-powered scenario analysis tab.
"""
import streamlit as st
import frontend.data_access as db


def render_analysis_tab(project_name: str) -> None:
    """LLM-powered scenario analysis tab."""
    from backend.services.llm_service import run_pipeline, get_scenarios

    scenarios = get_scenarios()

    st.markdown('<div class="gh-section-heading">Security Analysis & Querying</div>', unsafe_allow_html=True)
    st.caption("Ask specific questions about the project's vulnerability landscape.")

    scenario_name = st.selectbox(
        "Analysis Scenario",
        options=list(scenarios.keys()),
        format_func=lambda k: scenarios[k],
    )

    overrides = {"project_name": project_name}

    if scenario_name == "dev_explain":
        cves = db.fetch_cves(project_name)
        if cves:
            overrides["vuln_id"] = st.selectbox("Select CVE to explain", options=cves)
        else:
            st.warning("No CVEs found for this project.")
            return

    elif scenario_name == "arch_impact":
        default_cve = db.fetch_cves(project_name)[0] if db.fetch_cves(project_name) else ""
        vid = st.text_input("Vulnerability ID (e.g. CVE-2022-3517)", value=default_cve).strip()
        if not vid:
            return

        comps = db.fetch_components(project_name, vid)
        if comps:
            c_opts = [f"{c['name']}@{c['version']} ({c['component_id']})" for c in comps]
            sel_c = st.selectbox("Select affected starting component", options=c_opts)
            if sel_c:
                import re
                m = re.search(r'\(([^)]+)\)$', sel_c)
                if m:
                    overrides["vuln_id"] = vid
                    overrides["component_id"] = m.group(1)
        else:
            st.warning("No affected components found for this CVE.")
            return

    elif scenario_name == "project_overview":
        pass

    elif scenario_name == "custom":
        custom_q = st.text_area("Your Question", value="What is the most critical vulnerability affecting this project?")
        overrides["question"] = custom_q

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
