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

VISIBLE_TOP_LEVEL_PAGES = ("enterprise", "repository", "upload")

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


def _set_page(page: str, project: str | None = None, section: str | None = None, alert: str | None = None) -> None:
    next_page = page if page in TOP_LEVEL_PAGES else "enterprise"
    next_section = section if section in REPOSITORY_SECTIONS else "alerts"

    st.session_state["active_page"] = next_page
    if next_page == "repository":
        st.session_state["active_repository_section"] = next_section
        _set_query_params(page="repository", section=next_section, project=project, alert=alert)
    else:
        _set_query_params(page=next_page)
    st.rerun()


def _render_dashboard_header() -> None:
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


def _render_primary_nav(active_page: str, repository_project: str | None, repository_section: str, query_alert: str | None) -> None:
    visible_tabs = [(key, TOP_LEVEL_PAGES[key]) for key in VISIBLE_TOP_LEVEL_PAGES]
    st.markdown('<div class="gh-primary-tabs-anchor"></div>', unsafe_allow_html=True)
    cols = st.columns(len(visible_tabs), gap="small")
    clicked_page = None

    for (key, label), col in zip(visible_tabs, cols):
        with col:
            if st.button(
                label,
                key=f"primary_nav_{key}",
                type="primary" if key == active_page else "secondary",
                use_container_width=True,
            ):
                clicked_page = key

    if clicked_page == "repository":
        _set_page(
            page="repository",
            project=repository_project,
            section=repository_section,
            alert=query_alert if repository_section == "alerts" else None,
        )
    elif clicked_page:
        _set_page(page=clicked_page)


def _render_repo_nav(active_section: str, project_name: str) -> None:
    st.markdown('<div class="gh-repo-nav-anchor"></div>', unsafe_allow_html=True)
    cols = st.columns(len(REPOSITORY_SECTIONS), gap="small")
    clicked_section = None

    for (key, label), col in zip(REPOSITORY_SECTIONS.items(), cols):
        with col:
            if st.button(
                label,
                key=f"repository_nav_{key}",
                type="primary" if key == active_section else "secondary",
                use_container_width=True,
            ):
                clicked_section = key

    if clicked_section:
        _set_page(page="repository", project=project_name, section=clicked_section)


def render_content_shell_start() -> None:
    st.markdown('<div class="gh-content-shell-anchor"></div>', unsafe_allow_html=True)


def render_content_shell_end() -> None:
    st.markdown('<div class="gh-content-shell-end"></div>', unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(
        page_title="Enterprise Security Dashboard",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(GITHUB_CSS, unsafe_allow_html=True)

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

    session_page = st.session_state.get("active_page")
    session_section = st.session_state.get("active_repository_section")

    visible_page_keys = set(VISIBLE_TOP_LEVEL_PAGES)

    candidate_page = query_page if query_page in TOP_LEVEL_PAGES else (
        session_page if session_page in TOP_LEVEL_PAGES else ("repository" if query_project else "enterprise")
    )
    current_page = candidate_page if candidate_page in visible_page_keys else "enterprise"

    if query_page and query_page in TOP_LEVEL_PAGES and query_page not in visible_page_keys:
        _set_query_params(page="enterprise")
        st.rerun()

    current_section = query_section if query_section in REPOSITORY_SECTIONS else (
        session_section if session_section in REPOSITORY_SECTIONS else "alerts"
    )

    st.session_state["active_page"] = current_page
    st.session_state["active_repository_section"] = current_section

    repository_target_project = query_project if query_project else None
    if not repository_target_project and projects:
        repository_target_project = (
            config.DEMO_PROJECT_NAME if config.DEMO_PROJECT_NAME in projects else projects[0]
        )

    with st.container():
        st.markdown('<div class="gh-dashboard-shell-anchor"></div>', unsafe_allow_html=True)
        _render_dashboard_header()
        _render_primary_nav(
            active_page=current_page,
            repository_project=repository_target_project,
            repository_section=current_section,
            query_alert=query_alert,
        )

    with st.container(key="gh-content-shell"):
        render_content_shell_start()
        if current_page == "enterprise":
            render_enterprise_overview_tab(projects)

        elif current_page == "upload":
            render_upload_repository_tab()

        elif current_page == "workbench":
            render_query_workbench_tab(projects) # type: ignore

        else:
            if projects:
                st.markdown('<div class="gh-repository-selector-anchor"></div>', unsafe_allow_html=True)
                if query_project and query_project in projects:
                    default_idx = projects.index(query_project)
                else:
                    default_idx = projects.index(config.DEMO_PROJECT_NAME) if config.DEMO_PROJECT_NAME in projects else 0
                default_project = projects[default_idx]
                if "project_sel_initialized" not in st.session_state:
                    st.session_state["project_sel"] = default_project
                    st.session_state["project_sel_initialized"] = True

                raw_project_name = st.selectbox(
                    "Repository",
                    options=projects,
                    index=None,
                    key="project_sel",
                    accept_new_options=False,
                    filter_mode="contains",
                    placeholder="Search repository...",
                )
                selected_project = (raw_project_name or "").strip()
                if selected_project in projects:
                    project_name = selected_project
                else:
                    # Keep the current valid project until a real repository is selected.
                    project_name = default_project
            else:
                project_name = st.text_input("Project full_name", value=config.DEMO_PROJECT_NAME).strip()

            if query_project != project_name:
                _set_query_params(
                    page="repository",
                    section=current_section,
                    project=project_name,
                    alert=query_alert if query_alert else None,
                )
                st.rerun()


            _render_repo_nav(active_section=current_section, project_name=project_name)

            if current_section == "alerts":
                render_dependabot_tab(project_name, total_repo_count=len(projects) if projects else 0)
            elif current_section == "stakeholder_report":
                render_stakeholder_report_tab(project_name)
            else:
                render_developer_report_tab(project_name)

        render_content_shell_end()

if __name__ == "__main__":
    main()
