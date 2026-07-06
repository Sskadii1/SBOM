"""
modules/agents/config.py - Configuration for the agent pipeline.

All secrets come from environment variables (or .env).
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    # Try knowledge_graph/.env first, then project root
    _kg_env = Path(__file__).resolve().parents[2] / ".env"
    _root_env = Path(__file__).resolve().parents[3] / ".env"
    for p in (_kg_env, _root_env):
        if p.exists():
            load_dotenv(dotenv_path=p, override=True)
            break
except ImportError:
    pass


# ---------------------------------------------------------------------------
# LLM (OpenRouter) — used by VulnIntelAgent for sink extraction
# ---------------------------------------------------------------------------
OPENROUTER_API_KEY: str = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL: str = os.environ.get(
    "OPENROUTER_BASE_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)
LLM_MODEL: str = os.environ.get("AGENT_LLM_MODEL", os.environ.get("LLM_MODEL", ""))
LLM_TEMPERATURE: float = float(os.environ.get("AGENT_LLM_TEMPERATURE", "0.1"))
LLM_MAX_TOKENS: int = int(os.environ.get("AGENT_LLM_MAX_TOKENS", "2048"))

# ---------------------------------------------------------------------------
# OSV API — used by VulnIntelAgent to fetch advisory details
# ---------------------------------------------------------------------------
OSV_API_BASE: str = "https://api.osv.dev/v1"



# ---------------------------------------------------------------------------
# Neo4j — for reading existing vulnerability/component data
# ---------------------------------------------------------------------------
NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://localhost:7689")
NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "change_me")
NEO4J_DATABASE: str = os.environ.get("NEO4J_DATABASE", "neo4j")

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
AGENT_OUTPUT_DIR: Path = _DATA_DIR / "agent_results"

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# OSV API: public, unauthenticated — stay conservative
OSV_RATE_LIMIT_RPS: float = float(os.environ.get("OSV_RATE_LIMIT_RPS", "5.0"))
# OpenRouter / LLM: per-minute limit converted to per-second
LLM_RATE_LIMIT_RPM: float = float(os.environ.get("LLM_RATE_LIMIT_RPM", "20.0"))
LLM_RATE_LIMIT_RPS: float = LLM_RATE_LIMIT_RPM / 60.0
# Retry settings (applies to all rate-limited callers)
RATE_LIMIT_MAX_RETRIES: int = int(os.environ.get("RATE_LIMIT_MAX_RETRIES", "3"))

# ---------------------------------------------------------------------------
# Risk scoring weights (enhanced with reachability)
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    "cvss":         0.20,
    "exploitability": 0.30,
    "complexity":   0.15,
    "scope":        0.10,
    "depth":        0.10,
    "reachability": 0.15,
}

# Reachability score mapping
REACHABILITY_SCORES = {
    "confirmed_reachable":   1.0,
    "likely_reachable":      0.7,
    "likely_unreachable":    0.3,
    "no_sink_data":          0.5,
}
