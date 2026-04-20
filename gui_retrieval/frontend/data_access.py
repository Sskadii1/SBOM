"""
frontend/data_access.py — Streamlit-cached wrapper over backend graph_repository.

This is the only place @st.cache_data is used, keeping caching at the UI layer.
"""
from typing import Any
import streamlit as st
from backend.repositories import graph_repository as repo


def fetch_data_fingerprint() -> str:
    """Cheap version token used to invalidate heavier cached datasets."""
    return repo.get_data_fingerprint()


@st.cache_data(ttl=60)
def fetch_projects() -> list[str]:
    return repo.get_projects()


@st.cache_data(ttl=60)
def fetch_project_catalog() -> list[dict[str, Any]]:
    return repo.get_project_catalog()


@st.cache_data(ttl=60)
def fetch_alerts(project_name: str) -> list[dict[str, Any]]:
    return repo.get_alerts(project_name)


@st.cache_data(ttl=60)
def fetch_project_stats(project_name: str) -> dict[str, int]:
    return repo.get_project_stats(project_name)


@st.cache_data(ttl=60)
def fetch_vuln_detail(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    return repo.get_vuln_detail(project_name, vuln_id)


@st.cache_data(ttl=60)
def fetch_dep_chain(project_name: str, component_id: str) -> list[dict[str, Any]]:
    return repo.get_dep_chain(project_name, component_id)


@st.cache_data(ttl=60)
def fetch_vuln_dep_chains(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    return repo.get_vuln_dep_chains(project_name, vuln_id)


@st.cache_data(ttl=60)
def fetch_cves(project_name: str) -> list[str]:
    return repo.get_cves(project_name)


@st.cache_data(ttl=60)
def fetch_components(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    return repo.get_components_for_cve(project_name, vuln_id)


@st.cache_data(ttl=60)
def fetch_reachability(project_name: str) -> dict[str, dict]:
    """Returns reachability index {vuln_id: {verdict, call_locations}} from pipeline scan."""
    return repo.load_reachability(project_name)


@st.cache_data(show_spinner=False)
def fetch_enterprise_overview_inputs(
    projects: tuple[str, ...],
    data_fingerprint: str,
) -> dict[str, Any]:
    """
    Expensive enterprise overview inputs cached until the upstream data
    fingerprint changes.
    """
    _ = data_fingerprint
    return repo.get_enterprise_overview_inputs(list(projects))
