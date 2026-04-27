"""
frontend/components/ui_components.py - Shared UI helper functions and rendering components.
"""
import html
from typing import Any

import streamlit as st


# ---------------------------------------------------------------------------
# Styling Helpers
# ---------------------------------------------------------------------------

def _severity_from_cvss(cvss: float | None, kev: bool = False) -> str:
    """Determine string severity level from score/kev for CSS classing."""
    if kev:
        return "critical"
    if cvss is None:
        return "low"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _severity_label(sev: str) -> str:
    return {"critical": "Critical", "high": "High", "medium": "Moderate", "low": "Low"}.get(sev, "Low")


def _shield_svg(sev: str) -> str:
    """Return an SVG shield icon colored by severity."""
    color = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700", "low": "#636c76"}.get(sev, "#636c76")
    return f'''<svg class="gh-shield" viewBox="0 0 16 16" width="16" height="16" fill="{color}">
  <path fill-rule="evenodd" d="M8.533.133a1.75 1.75 0 00-1.066 0l-5.6 2.1A1.75 1.75 0 00.75 3.866v4.618c0 3.736 2.457 7.087 6.008 8.435L8 17.382l1.242-.463c3.551-1.348 6.008-4.7 6.008-8.435V3.866a1.75 1.75 0 00-1.117-1.633l-5.6-2.1zM8 1.558l5.6 2.1v4.618c0 3.037-1.996 5.76-4.881 6.853L8 15.421l-.719-.292C4.396 14.036 2.4 11.313 2.4 8.276V3.658l5.6-2.1z"></path>
</svg>'''


def _render_stats_bar(stats: dict, active_filter: str, total_repos: int | None = None) -> None:
    """Render the top stats pill bar."""
    total = stats.get("total_count", 0)
    crits = stats.get("critical_count", 0)
    highs = stats.get("high_count", 0)
    meds = stats.get("medium_count", 0)
    lows = stats.get("low_count", 0)
    kev = stats.get("kev_count", 0)
    reachable = stats.get("confirmed_reachable_count", 0)

    pills = [
        f'<span class="gh-stat-pill pill-total"><span class="gh-stat-pill-total-icon">&#128737;</span> {total} VULNERABILITIES</span>'
    ]
    if crits > 0:
        pills.append(f'<span class="gh-stat-pill pill-critical">{crits} | CRITICAL</span>')
    if highs > 0:
        pills.append(f'<span class="gh-stat-pill pill-high">{highs} | HIGH</span>')
    if meds > 0:
        pills.append(f'<span class="gh-stat-pill pill-medium">{meds} | MODERATE</span>')
    if lows > 0:
        pills.append(f'<span class="gh-stat-pill pill-low">{lows} | LOW</span>')
    if reachable > 0:
        pills.append(f'<span class="gh-stat-pill pill-reachable">{reachable} | REACHABLE</span>')
    if kev > 0:
        pills.append(f'<span class="gh-stat-pill pill-kev">{kev} | KEV</span>')

    html_str = f'<div class="gh-stats-bar">{"".join(pills)}</div>'
    st.markdown(html_str, unsafe_allow_html=True)


def _dep_chain_html(chain: list[str], target_name: str) -> str:
    """Render dependency chain as visual node path with tooltips."""
    if not chain:
        return ""
    parts: list[str] = []
    for i, component in enumerate(chain):
        is_target = i == len(chain) - 1 and component == target_name
        cls = "gh-dep-target" if is_target else "gh-dep-root" if i == 0 else ""
        role = "Vulnerable Target" if is_target else "Root Dependency" if i == 0 else "Transitive Dependency"
        title = f"{html.escape(component)} ({role})"
        parts.append(f'<span class="gh-dep-node {cls}" title="{title}">{html.escape(component)}</span>')
        if i < len(chain) - 1:
            parts.append('<span class="gh-dep-arrow">-&gt;</span>')
    return '<div class="gh-dep-chain">' + " ".join(parts) + "</div>"


def _dep_chain_card_html(chain_row: dict[str, Any]) -> str:
    """Render one dependency-chain card with metadata for the UI."""
    chain = [str(x) for x in (chain_row.get("chain") or []) if x is not None]
    component = str(chain_row.get("component") or (chain[-1] if chain else "Unknown"))
    version = chain_row.get("version") or ""
    target_depth = chain_row.get("target_depth")
    hops = chain_row.get("hops")

    meta_parts = [f'<span class="gh-chain-chip">Target: <code>{html.escape(component)}</code></span>']
    if version:
        meta_parts.append(f'<span class="gh-chain-chip">Version: <code>{html.escape(str(version))}</code></span>')
    if target_depth is not None and hops is not None:
        hops_int = int(hops)
        if hops_int == 0:
            meta_parts.append(
                f'<span class="gh-chain-chip" style="background:#DDFBE8;color:#1a7f37;border-color:#1a7f3730">'
                f'Direct dependency (depth {target_depth})</span>'
            )
        else:
            root_depth = int(target_depth) - hops_int
            root_name = html.escape(chain[0]) if chain else "root"
            meta_parts.append(
                f'<span class="gh-chain-chip" title="{root_name} is at depth {root_depth}, '
                f'+ {hops_int} hop{"s" if hops_int != 1 else ""} = depth {target_depth}">'
                f'Depth: <b>{target_depth}</b></span>'
            )
    elif target_depth is not None:
        meta_parts.append(f'<span class="gh-chain-chip">Depth: {html.escape(str(target_depth))}</span>')

    chain_html = _dep_chain_html(chain, component)
    return (
        '<div class="gh-chain-card">'
        f'<div class="gh-chain-meta">{"".join(meta_parts)}</div>'
        f"{chain_html}"
        "</div>"
    )
