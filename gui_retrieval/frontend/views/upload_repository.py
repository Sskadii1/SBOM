"""
frontend/views/upload_repository.py — Upload/ingest repository tab.
"""
import streamlit as st

from backend.services.repo_pipeline_service import run_full_repo_pipeline


def render_upload_repository_tab() -> None:
    """Run the full single-repository ingest pipeline from the UI."""
    st.markdown('<div class="gh-section-heading">Upload Repository</div>', unsafe_allow_html=True)
    st.caption("Clone or update a GitHub repository, generate SBOM data, import vulnerabilities, and refresh Neo4j.")

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

    if not submitted:
        return

    if not repo_input:
        st.error("Please provide a repository link.")
        return

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
            return

    _append_log("[UI] Pipeline completed successfully.")
    st.success(
        f"Completed for {result['project_name']} in {result['duration_seconds']}s "
        f"(vulns: {result['vulnerability_count']}, semgrep entries: {result['semgrep_entry_count']})."
    )
    st.json(result)
    st.cache_data.clear()
    st.query_params.clear()
    st.query_params["page"] = "repository"
    st.query_params["section"] = "alerts"
    st.query_params["project"] = result["project_name"]
    st.rerun()
