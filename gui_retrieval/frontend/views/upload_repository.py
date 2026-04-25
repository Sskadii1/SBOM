"""
frontend/views/upload_repository.py — Upload/ingest repository tab.
"""
import streamlit as st

from backend.services.repo_pipeline_service import run_full_repo_pipeline


def render_upload_repository_tab() -> None:
    """Run the full single-repository ingest pipeline from the UI."""
    st.markdown('<div class="gh-section-heading">Upload Repository</div>', unsafe_allow_html=True)
    st.caption("Clone or update a GitHub repository, generate SBOM data, import vulnerabilities, and refresh Neo4j.")

    source_mode = st.radio(
        "Source mode",
        options=[
            "GitHub Repository (Latest Commit)",
            "GitHub Repository (Custom Commit)",
        ],
        help=(
            "Latest Commit scans the newest commit on the default branch. "
            "Custom Commit scans the exact commit hash you provide."
        ),
    )
    is_custom_commit = source_mode == "GitHub Repository (Custom Commit)"
    submit_label = "Run Pipeline for Custom Commit" if is_custom_commit else "Run Pipeline for Latest Commit"

    with st.form("repo_ingest_form"):
        repo_input = st.text_input(
            "GitHub repository",
            placeholder="https://github.com/owner/repo or owner/repo",
        ).strip()
        commit_hash = None
        use_parent_commit = False
        if is_custom_commit:
            commit_hash = st.text_input(
                "Commit hash",
                placeholder="Full or short Git commit SHA",
                help="Provide the exact commit hash to ingest instead of the latest default-branch commit.",
            ).strip()
            use_parent_commit = st.checkbox(
                "Use parent commit (state before this commit)",
                value=False,
                help=(
                    "Use this when the commit you have is the fix/bump commit and you want the code state "
                    "immediately before that change."
                ),
            )
            if use_parent_commit:
                submit_label = "Run Pipeline for Parent of Custom Commit"
        ai_fallback = st.checkbox(
            "Enable AI fallback for missing sink data",
            value=True,
            help="If enabled, missing CVE sink metadata is auto-extracted before Semgrep scan.",
        )
        submitted = st.form_submit_button(submit_label, type="primary")

    if not submitted:
        return

    if not repo_input:
        st.error("Please provide a repository link.")
        return
    if is_custom_commit and not commit_hash:
        st.error("Please provide a commit hash.")
        return

    pipeline_source_mode = (
        "github_commit"
        if is_custom_commit
        else "github_latest"
    )

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
                source_mode=pipeline_source_mode,
                commit_hash=commit_hash,
                use_parent_commit=use_parent_commit,
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
