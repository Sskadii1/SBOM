"""
main.py — Streamlit Web GUI styled after GitHub Dependabot Security Alerts.

Displays SBOM vulnerability data from Neo4j in a clean, GitHub-inspired UI.
"""
import streamlit as st
from urllib.parse import quote_plus
import backend.config as config
from frontend.styles import GITHUB_CSS
import frontend.data_access as db
from frontend.views.alerts import render_dependabot_tab
from frontend.views.analysis import render_analysis_tab
from frontend.views.overview import render_overview_tab
from backend.services.repo_pipeline_service import run_full_repo_pipeline


def main() -> None:
    st.set_page_config(
        page_title="Security Alerts — SBOM Dashboard",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(GITHUB_CSS, unsafe_allow_html=True)



    st.markdown(
        '<div class="gh-page-header">'
        '<span style="font-size:24px">🛡️</span>'
        '<div>'
        '<div class="gh-page-title">Dependabot Alerts</div>'
        '<div class="gh-page-subtitle">GraphRAG-powered SBOM Vulnerability Dashboard</div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    with st.expander("Ingest New Repository", expanded=False):
        with st.form("repo_ingest_form"):
            repo_input = st.text_input(
                "GitHub repository",
                placeholder="https://github.com/owner/repo or owner/repo",
            ).strip()
            ai_fallback = st.checkbox(
                "Enable AI fallback for missing sink data",
                value=True,
                help="If enabled, missing CVE sink metadata is auto-extracted before Semgrep scan.",
            )
            submitted = st.form_submit_button("Run Full Pipeline", type="primary")

        if submitted:
            if not repo_input:
                st.error("Please provide a repository link.")
            else:
                log_lines: list[str] = []
                log_view = st.empty()

                def _append_log(message: str) -> None:
                    log_lines.append(message)
                    log_view.code("\n".join(log_lines[-200:]), language="text")

                _append_log("[UI] Pipeline started...")
                with st.spinner("Running full pipeline. This may take a few minutes..."):
                    try:
                        result = run_full_repo_pipeline(
                            repo_input=repo_input,
                            enable_ai_sink_fallback=ai_fallback,
                            log=_append_log,
                        )
                    except Exception as exc:
                        _append_log(f"[ERROR] {exc}")
                        st.error(f"Pipeline failed: {exc}")
                    else:
                        _append_log("[UI] Pipeline completed successfully.")
                        st.success(
                            f"Completed for {result['project_name']} in {result['duration_seconds']}s "
                            f"(vulns: {result['vulnerability_count']}, semgrep entries: {result['semgrep_entry_count']})."
                        )
                        st.json(result)
                        st.cache_data.clear()
                        # Prefer native Streamlit navigation over JS redirect
                        # (JS redirect can fail silently in some deployments).
                        st.query_params["project"] = result["project_name"]
                        st.rerun()

    # Project selector
    try:
        projects = db.fetch_projects()
    except Exception as exc:
        st.error(f"Cannot connect to Neo4j: {exc}")
        return

    if projects:
        # Read the project URL param if present
        query_project = st.query_params.get("project")
        
        # Determine default index
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
        
        # Ensure URL always reflects the selected project
        if query_project != project_name:
            st.query_params["project"] = project_name
            
    else:
        project_name = st.text_input("Project full_name", value=config.DEMO_PROJECT_NAME).strip()

    # Tabs
    tab_alerts, tab_analysis, tab_overview = st.tabs([
        "🔒 Security Alerts",
        "🤖 LLM Analysis",
        "📊 Overview",
    ])

    with tab_alerts:
        render_dependabot_tab(project_name, total_repo_count=len(projects) if projects else 0)

    with tab_analysis:
        render_analysis_tab(project_name)

    with tab_overview:
        render_overview_tab(project_name)

if __name__ == "__main__":
    main()
