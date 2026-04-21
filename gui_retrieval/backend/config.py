"""
backend/config.py - Central configuration for the GraphRAG SBOM demo system.

Sensitive values are loaded from .env via python-dotenv.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

_ROOT = Path(__file__).resolve().parents[2]  # SBOM Retrieval/

try:
    from dotenv import load_dotenv

    # Load root .env first, then gui_retrieval/.env as highest-priority local override.
    _root_env_path = _ROOT / ".env"
    _gui_env_path = Path(__file__).resolve().parent.parent / ".env"
    if _root_env_path.exists():
        load_dotenv(dotenv_path=_root_env_path, override=False)
    if _gui_env_path.exists():
        load_dotenv(dotenv_path=_gui_env_path, override=True)
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Neo4j connection
# ---------------------------------------------------------------------------
REACHABILITY_DIR: Path = _ROOT / "knowledge_graph" / "data" / "reachability"
CVE_SINKS_DB: Path = Path(
    os.environ.get(
        "CVE_SINKS_DB",
        str(_ROOT / "knowledge_graph" / "data" / "cve_sinks.db"),
    )
)

def _running_inside_container() -> bool:
    return Path("/.dockerenv").exists()


def _normalize_neo4j_uri_for_container(uri: str) -> str:
    """
    When running inside Docker, localhost/127.0.0.1 points to the container itself.
    Auto-rewrite to host.docker.internal for resilience.
    """
    parsed = urlparse(uri)
    if not parsed.scheme or not parsed.netloc:
        return uri

    host = parsed.hostname or ""
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return uri

    port = parsed.port
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        auth += "@"
    port_suffix = f":{port}" if port else ""
    netloc = f"{auth}host.docker.internal{port_suffix}"
    return urlunparse(parsed._replace(netloc=netloc))


_raw_neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7688")
NEO4J_URI: str = (
    _normalize_neo4j_uri_for_container(_raw_neo4j_uri)
    if _running_inside_container()
    else _raw_neo4j_uri
)
NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "password")
NEO4J_DATABASE: str = os.environ.get("NEO4J_DATABASE", "neo4j")


# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------
GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "")


# ---------------------------------------------------------------------------
# LLM - OpenRouter
# ---------------------------------------------------------------------------
OPENROUTER_API_KEY: str = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL: str = os.environ.get(
    "OPENROUTER_BASE_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)
LLM_MODEL: str = os.environ.get("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
LLM_TEMPERATURE: float = float(os.environ.get("LLM_TEMPERATURE", "0.1"))
LLM_MAX_TOKENS: int = int(os.environ.get("LLM_MAX_TOKENS", "2048"))


# ---------------------------------------------------------------------------
# Scenario registry: name -> human-readable label
# ---------------------------------------------------------------------------
SCENARIOS: dict[str, str] = {
    "dev_explain": "Developer-focused vulnerability explanation",
    "manager_brief": "Manager briefing (decision support)",
    "triage_queue": "Triage recommendation engine",
    "explainability_mode": "Explainability with confidence score",
    "multi_audience": "Multi-audience output in one pass",
    "arch_impact": "Blast Radius Analysis",
}


# ---------------------------------------------------------------------------
# Demo parameters (used as defaults when scenarios need graph inputs)
# ---------------------------------------------------------------------------
DEMO_PROJECT_NAME: str = os.environ.get("DEMO_PROJECT_NAME", "gulpjs/gulp")
DEMO_VULN_ID: str = os.environ.get("DEMO_VULN_ID", "CVE-2021-44228")
DEMO_COMPONENT_ID: str = os.environ.get("DEMO_COMPONENT_ID", "pkg:npm/lodash@4.17.20")
DEMO_COMPONENT_NAME: str = os.environ.get("DEMO_COMPONENT_NAME", "lodash")
DEMO_FROM_ISO: str = os.environ.get("DEMO_FROM_ISO", "2026-01-01T00:00:00Z")
