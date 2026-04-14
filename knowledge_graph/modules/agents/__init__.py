"""
modules/agents - Multi-agent vulnerability analysis pipeline.

Agent 1 (VulnIntelAgent):  Extract vulnerable sinks from OSV/NVD advisories via LLM.
Agent 2 (SemgrepAgent):    Generate Semgrep rules from sinks and scan repo for reachability.
"""

__all__ = [
    "config",
    "rate_limiter",
    "sink_db",
    "vuln_intel_agent",
    "semgrep_agent",
]
