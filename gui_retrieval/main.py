"""
main.py — Streamlit Web GUI for enterprise + repository security analysis.

Displays SBOM vulnerability data from Neo4j in a clean, GitHub-inspired UI.
"""
import streamlit as st
import backend.config as config
from frontend.styles import GITHUB_CSS
import frontend.components.ui_components as ui
import frontend.data_access as db
from frontend.views.alerts import render_dependabot_tab
from frontend.views.developer_report import render_developer_report_tab
from frontend.views.enterprise_overview import render_enterprise_overview_tab
from frontend.views.stakeholder_report import render_stakeholder_report_tab
from frontend.views.upload_repository import render_upload_repository_tab


TOP_LEVEL_PAGES = {
    "enterprise": "Enterprise Security Overview",
    "repository": "Repository Analysis",
    "upload": "Upload Repository",
}

REPOSITORY_SECTIONS = {
    "alerts": "Security Alerts",
    "stakeholder_report": "Stakeholder Report",
    "developer_report": "Developer Report",
}


def _set_query_params(**kwargs: str) -> None:
    st.query_params.clear()
    for key, value in kwargs.items():
        if value not in (None, ""):
            st.query_params[key] = value


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

    query_page = (st.query_params.get("page") or "").strip().lower()
    query_project = st.query_params.get("project")
    query_section = (st.query_params.get("section") or "").strip().lower()
    query_alert = st.query_params.get("alert")

    if query_alert:
        query_page = "repository"
        query_section = "alerts"

    current_page = query_page if query_page in TOP_LEVEL_PAGES else ("repository" if query_project else "enterprise")

    st.markdown('<div class="gh-primary-tabs-anchor"></div>', unsafe_allow_html=True)
    selected_page_label = st.radio(
        "Primary Navigation",
        options=list(TOP_LEVEL_PAGES.values()),
        index=list(TOP_LEVEL_PAGES.keys()).index(current_page),
        horizontal=True,
        label_visibility="collapsed",
        key="primary_nav",
    )
    selected_page = next(key for key, label in TOP_LEVEL_PAGES.items() if label == selected_page_label)

    if selected_page != current_page:
        if selected_page == "enterprise":
            _set_query_params(page="enterprise")
        elif selected_page == "upload":
            _set_query_params(page="upload")
        else:
            target_project = query_project
            if not target_project and projects:
                target_project = config.DEMO_PROJECT_NAME if config.DEMO_PROJECT_NAME in projects else projects[0]
            _set_query_params(page="repository", section="alerts", project=target_project)
        st.rerun()

    if selected_page == "enterprise":
        render_enterprise_overview_tab(projects)
        return

    if selected_page == "upload":
        render_upload_repository_tab()
        return

    if projects:
        st.markdown('<div class="gh-repository-selector-anchor"></div>', unsafe_allow_html=True)
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
    else:
        project_name = st.text_input("Project full_name", value=config.DEMO_PROJECT_NAME).strip()

    if query_project != project_name:
        _set_query_params(
            page="repository",
            section="alerts" if query_section not in REPOSITORY_SECTIONS else query_section,
            project=project_name,
            alert=query_alert if query_alert else None,
        )
        st.rerun()

    current_section = query_section if query_section in REPOSITORY_SECTIONS else "alerts"

    ui.render_project_assessment_panel()

    st.markdown('<div class="gh-repo-tabs-anchor"></div>', unsafe_allow_html=True)
    selected_section_label = st.radio(
        "Repository Navigation",
        options=list(REPOSITORY_SECTIONS.values()),
        index=list(REPOSITORY_SECTIONS.keys()).index(current_section),
        horizontal=True,
        label_visibility="collapsed",
        key="repository_nav",
    )
    selected_section = next(key for key, label in REPOSITORY_SECTIONS.items() if label == selected_section_label)

    if selected_section != current_section:
        _set_query_params(
            page="repository",
            section=selected_section,
            project=project_name,
        )
        st.rerun()

    if selected_section == "alerts":
        render_dependabot_tab(project_name, total_repo_count=len(projects) if projects else 0)
    elif selected_section == "stakeholder_report":
        render_stakeholder_report_tab(project_name)
    else:
        render_developer_report_tab(project_name)

if __name__ == "__main__":
    main()
