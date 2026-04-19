"""
main.py — Streamlit Web GUI for enterprise + repository security analysis.

Displays SBOM vulnerability data from Neo4j in a clean, GitHub-inspired UI.
"""
import streamlit as st
import backend.config as config
from frontend.styles import GITHUB_CSS
import frontend.data_access as db
from frontend.views.alerts import render_dependabot_tab
from frontend.views.analysis import render_analysis_tab
from frontend.views.enterprise_overview import render_enterprise_overview_tab
from frontend.views.upload_repository import render_upload_repository_tab


def main() -> None:
    st.set_page_config(
        page_title="Enterprise Security Dashboard",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(GITHUB_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="gh-page-header">'
        '<svg class="gh-page-header-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true">'
        '<path d="M8.21 1.04a.75.75 0 0 0-.42 0l-5.25 1.5A.75.75 0 0 0 2 3.26v3.98c0 3.2 1.84 5.9 5.53 7.61a.75.75 0 0 0 .94 0C12.16 13.14 14 10.44 14 7.24V3.26a.75.75 0 0 0-.54-.72l-5.25-1.5Z" fill="#dbeafe"></path>'
        '<path d="M8 2.24 3.5 3.53v3.71c0 2.52 1.37 4.68 4.5 6.24 3.13-1.56 4.5-3.72 4.5-6.24V3.53L8 2.24Z" fill="#60a5fa"></path>'
        '<path d="M8 2.24v11.24c3.13-1.56 4.5-3.72 4.5-6.24V3.53L8 2.24Z" fill="#2563eb"></path>'
        '</svg>'
        '<div>'
        '<div class="gh-page-title">Enterprise Security Dashboard</div>'
        '<div class="gh-page-subtitle">Portfolio overview, repository analysis, and one-click ingestion</div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Project selector
    try:
        projects = db.fetch_projects()
    except Exception as exc:
        st.error(f"Cannot connect to Neo4j: {exc}")
        return

    st.markdown('<div class="gh-primary-tabs-anchor"></div>', unsafe_allow_html=True)
    tab_enterprise, tab_repository, tab_upload = st.tabs([
        "Enterprise Security Overview",
        "Repository Analysis",
        "Upload Repository",
    ])

    with tab_enterprise:
        render_enterprise_overview_tab(projects)

    with tab_repository:
        if projects:
            st.markdown('<div class="gh-repository-selector-anchor"></div>', unsafe_allow_html=True)
            query_project = st.query_params.get("project")
            if query_project and query_project in projects:
                default_idx = projects.index(query_project)
            else:
                default_idx = projects.index(config.DEMO_PROJECT_NAME) if config.DEMO_PROJECT_NAME in projects else 0

            project_name = st.selectbox(
                "Repository",
                options=projects,
                index=default_idx,
                key="project_sel",
            )
            if query_project != project_name:
                st.query_params["project"] = project_name
        else:
            project_name = st.text_input("Project full_name", value=config.DEMO_PROJECT_NAME).strip()

        st.markdown('<div class="gh-repo-tabs-anchor"></div>', unsafe_allow_html=True)
        repo_tab_alerts, repo_tab_analysis = st.tabs([
            "Security Alerts",
            "LLM Analysis",
        ])

        with repo_tab_alerts:
            render_dependabot_tab(project_name, total_repo_count=len(projects) if projects else 0)

        with repo_tab_analysis:
            render_analysis_tab(project_name)

    with tab_upload:
        render_upload_repository_tab()

if __name__ == "__main__":
    main()
