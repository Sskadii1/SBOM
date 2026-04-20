"""
frontend/query_workbench_data_access.py - Cached data access for Query Workbench.
"""
from typing import Any

import streamlit as st

from backend.repositories import graph_repository as repo


@st.cache_data(show_spinner=False)
def fetch_query_workbench_rows(
    projects: tuple[str, ...],
    data_fingerprint: str,
) -> list[dict[str, Any]]:
    """Fetch query-workbench rows from a dedicated backend path."""
    _ = data_fingerprint
    return repo.get_query_workbench_rows(list(projects))
