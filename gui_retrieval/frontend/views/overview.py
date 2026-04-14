"""
frontend/views/overview.py — Security Posture Overview Tab.
"""
import streamlit as st


def render_overview_tab(project_name: str) -> None:
    """Project-wide automated security posture overview."""
    st.markdown('<div class="gh-section-heading">Security Posture Overview</div>', unsafe_allow_html=True)
    st.caption("Automated LLM summary of the project's overall vulnerability health.")

    if st.button("Generate Overview", type="primary", key="btn_overview"):
        from backend.services.llm_service import run_pipeline
        with st.spinner("Analysing project security posture with LLM…"):
            result = run_pipeline("project_overview", {"project_name": project_name})

        st.markdown(result["explanation"])

        with st.expander("Query diagnostics", expanded=False):
            st.json(result["query_meta"])
