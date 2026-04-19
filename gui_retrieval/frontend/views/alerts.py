"""
frontend/views/alerts.py - Dependabot-style Security Alerts Tab Logic.
"""
from urllib.parse import quote_plus

import streamlit as st

import frontend.components.ui_components as ui
import frontend.data_access as db


REACHABILITY_LABELS = {
    "confirmed_reachable": "Reachable",
    "likely_reachable": "Likely reachable",
    "likely_unreachable": "Likely unreachable",
    "no_sink_data": "No sink data",
}

SEVERITY_OPTIONS = ["Critical", "High", "Moderate", "Low"]
FIX_STATUS_OPTIONS = ["Fix available", "No fix"]


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    return [value]


def render_alert_detail_page(project_name: str, internal_id: str) -> None:
    """Full Dependabot-style CVE detail page."""
    col_back, _ = st.columns([1, 8])
    with col_back:
        if st.button("<- Alerts", key="btn_back_detail"):
            st.query_params.clear()
            st.rerun()

    with st.spinner("Loading vulnerability details..."):
        detail_rows = db.fetch_vuln_detail(project_name, internal_id)

    if not detail_rows:
        st.warning("No detailed data found for this vulnerability in this project.")
        return

    first = detail_rows[0]
    vuln_id_display = first.get("vuln_id") or internal_id

    # Preserve backend-computed reachability fields; only backfill if needed.
    _reach_index = db.fetch_reachability(project_name)
    _reach = _reach_index.get(vuln_id_display) or _reach_index.get(internal_id) or {}
    _backend_verdict = first.get("reachability_verdict")
    _local_verdict = _reach.get("verdict")
    if _backend_verdict in (None, "") and _local_verdict:
        first["reachability_verdict"] = _local_verdict
    else:
        first["reachability_verdict"] = _backend_verdict or _local_verdict or "no_sink_data"
    first["call_locations"] = first.get("call_locations") or _reach.get("call_locations", [])
    if first.get("reachability_factor") is None or (
        _backend_verdict in (None, "") and _local_verdict
    ):
        first["reachability_factor"] = {
            "confirmed_reachable": 1,
            "likely_reachable": 0.7,
            "likely_unreachable": 0.3,
            "no_sink_data": 0.5,
        }.get(first["reachability_verdict"], 0.5)
    cvss = first.get("cvss")
    kev = bool(first.get("kev"))
    epss = first.get("epss")
    dependency_depth = first.get("dependency_depth")
    sev = ui._severity_from_cvss(cvss, kev)
    sev_label = ui._severity_label(sev)

    st.html(
        f'<div class="gh-breadcrumb">'
        f"<span>{project_name}</span>"
        f'<span class="gh-breadcrumb-sep">/</span>'
        f"<strong>Security Alerts</strong>"
        f'<span class="gh-breadcrumb-sep">/</span>'
        f'<strong style="color:#1f2328">{vuln_id_display}</strong>'
        f"</div>"
    )

    shield = ui._shield_svg(sev)
    badge = f'<span class="gh-badge badge-{sev}">{sev_label}</span>'
    if kev:
        badge += ' <span class="gh-badge badge-kev">KEV</span>'

    fix_vers = _as_list(first.get("fix_versions"))
    if fix_vers:
        fix_chip = f'<span class="gh-fix-chip">Fix available: {fix_vers[0]}</span>'
    else:
        fix_chip = '<span class="gh-fix-chip-none">No fix available</span>'

    cvss_color = dict(critical="#cf222e", high="#bc4c00", medium="#9a6700", low="#636c76").get(sev, "#636c76")
    published = (first.get("published") or "")[:10] or "N/A"
    modified = (first.get("modified") or "")[:10] or "N/A"

    cwe_list = _as_list(first.get("cwe"))
    aliases = _as_list(first.get("aliases"))
    cwe_html_tags = "".join(f'<span class="gh-cwe-tag">{c}</span>' for c in cwe_list) if cwe_list else "N/A"
    aliases_html = ", ".join(f"<code>{a}</code>" for a in aliases) if aliases else "N/A"

    # Build per-(name, version) info from all detail rows (deduplicated by component_id)
    _seen_cids: set = set()
    _comp_ver_depth: list = []  # [(name, version, depth)]
    for _row in detail_rows:
        _cid = _row.get("component_id") or _row.get("component")
        if _cid and _cid not in _seen_cids:
            _seen_cids.add(_cid)
            _comp_ver_depth.append((
                _row.get("component") or "",
                _row.get("version") or "",
                _row.get("dependency_depth"),
            ))

    # Affected component chips — one chip per (name, version) pair
    _chip_style = (
        "background:#DDFBE8;color:#1a7f37;padding:2px 10px;border-radius:12px;"
        "font-size:13px;font-weight:600;border:1px solid #1a7f3730;white-space:nowrap"
    )
    affected_html = " ".join(
        f'<span style="{_chip_style}">{n}{"@" + v if v else ""}</span>'
        for n, v, _ in _comp_ver_depth
        if n
    )

    # Closest depth: per-version inline list when multiple versions, single value otherwise
    if len(_comp_ver_depth) > 1:
        _depth_parts = []
        for _n, _v, _d in _comp_ver_depth:
            _label = f"@{_v}" if _v else _n
            _d_str = str(_d) if _d is not None else "N/A"
            _depth_parts.append(
                f'<span style="white-space:nowrap">'
                f'<code style="font-size:11px;background:#f6f8fa;padding:1px 5px;border-radius:3px;border:1px solid #d0d7de">{_label}</code>'
                f'&nbsp;{_d_str}</span>'
            )
        _depth_display = ' <span style="color:#d0d7de;margin:0 3px">|</span> '.join(_depth_parts)
    else:
        _depth_display = str(dependency_depth) if dependency_depth is not None else "N/A"

    # Structured meta rows for alignment
    meta_items = [
        ("CVSS", f'<b style="color:{cvss_color}">{cvss:.1f}</b>' if cvss is not None else "N/A"),
        ("Published", published),
        ("EPSS", f"{epss:.2%}" if epss else "N/A"),
        ("Modified", modified),
        ("Closest depth", _depth_display),
    ]
    meta_grid = "".join(
        f'<div style="display:inline-flex;align-items:baseline;gap:4px;margin-right:20px;margin-bottom:6px">'
        f'<span style="color:#636c76;font-size:12px">{label}:</span>'
        f'<span style="font-size:13px;font-weight:600;color:#1f2328">{val}</span></div>'
        for label, val in meta_items
    )

    st.html(
        f'<div class="gh-detail-hero">'
        f'  <div class="gh-detail-title">{shield} {vuln_id_display} {badge} {fix_chip} {affected_html}</div>'
        f'  <div style="padding:8px 0;line-height:2">{meta_grid}</div>'
        f'  <div class="gh-detail-meta" style="margin-top:16px; padding-top:16px; border-top:1px solid #d0d7de;">'
        f'    <div style="flex-basis: 100%; margin-bottom: 4px;"><b>CWE:</b> {cwe_html_tags}</div>'
        f'    <div style="flex-basis: 100%;"><b>Aliases:</b> {aliases_html}</div>'
        f"  </div>"
        f"</div>"
    )

    # --- Risk Score Breakdown Card ---
    risk_score = first.get("risk_score")
    scope_raw = first.get("scope")
    _rs_cvss = cvss if cvss is not None else 0
    _rs_epss = epss if epss else 0
    _rs_kev = kev
    # Reachability factor follows the backend verdict-to-score mapping.
    reach_verdict = first.get("reachability_verdict", "no_sink_data")
    u_val = first.get("reachability_factor", 0.5)
    call_locations = first.get("call_locations") or []
    # Compute each sub-score using Risk_enh formula
    s_sev = _rs_cvss / 10.0
    s_exp = 1.0 if _rs_kev else _rs_epss
    if scope_raw in ("required", "runtime"):
        s_scope = 1.0
    elif scope_raw in ("optional", "dev", "test"):
        s_scope = 0.3
    else:
        s_scope = 0.6
    weighted_sum = 0.25 * s_sev + 0.25 * s_exp + 0.15 * s_scope + 0.35 * u_val
    computed_risk = round(100.0 * weighted_sum, 2)

    if computed_risk >= 85:
        rs_color = "#cf222e"; rs_bg = "#FFEBE9"; rs_label = "Critical"
    elif computed_risk >= 70:
        rs_color = "#bc4c00"; rs_bg = "#FFF8C5"; rs_label = "High"
    elif computed_risk >= 40:
        rs_color = "#9a6700"; rs_bg = "#FFF8C5"; rs_label = "Medium"
    else:
        rs_color = "#636c76"; rs_bg = "#f6f8fa"; rs_label = "Low"

    def _param_row(name: str, raw: str, score: float, weight: float) -> str:
        contrib = score * weight * 100
        pct = weight * 100
        bar_w = min(max(contrib, 0), 100)
        return (
            f'<tr style="border-bottom:1px solid #f0f0f0">'
            f'<td style="padding:10px 12px;font-weight:600;color:#1f2328;white-space:nowrap">{name}</td>'
            f'<td style="padding:10px 12px;color:#1f2328">{raw}</td>'
            f'<td style="padding:10px 12px;text-align:center;font-family:monospace;font-weight:600">{score:.2f}</td>'
            f'<td style="padding:10px 12px;text-align:center;color:#636c76;font-family:monospace">{pct:.0f}%</td>'
            f'<td style="padding:10px 12px;text-align:right;font-weight:700;color:#1f2328;font-family:monospace">{contrib:.1f}</td>'
            f'<td style="padding:10px 12px;width:100px">'
            f'<div style="background:#eee;border-radius:4px;height:8px;width:90px">'
            f'<div style="background:{rs_color};border-radius:4px;height:8px;width:{bar_w * 0.9:.0f}px"></div>'
            f'</div></td>'
            f'</tr>'
        )

    scope_display = scope_raw if scope_raw else "unknown"

    _reach_labels = {
        "confirmed_reachable": "confirmed reachable",
        "likely_reachable": "likely reachable",
        "likely_unreachable": "likely unreachable",
        "no_sink_data": "no sink data",
    }
    _reach_label = _reach_labels.get(reach_verdict, reach_verdict)
    param_rows = (
        _param_row("S_sev", f"CVSS = {_rs_cvss:.1f} &rarr; {_rs_cvss:.1f}/10", s_sev, 0.25)
        + _param_row("S_exp", f"KEV = {'Yes &rarr; 1.0' if _rs_kev else 'No &rarr; EPSS = ' + f'{_rs_epss:.4f}'  }", s_exp, 0.25)
        + _param_row("S_scope", f"scope = {scope_display} &rarr; {s_scope:.1f}", s_scope, 0.15)
        + _param_row("S_reach", f"{_reach_label} &rarr; {u_val:.1f}", u_val, 0.35)
    )

    st.html(
        f'<div class="gh-detail-card">'
        f'<div class="gh-detail-card-header" style="display:flex;justify-content:space-between;align-items:center">'
        f'<span>Risk Score Breakdown</span>'
        f'<span style="font-size:24px;font-weight:800;color:{rs_color};background:{rs_bg};'
        f'padding:4px 16px;border-radius:16px;border:2px solid {rs_color}40">'
        f'{computed_risk:.1f} <span style="font-size:12px;font-weight:600">{rs_label}</span></span>'
        f'</div>'
        f'<div class="gh-detail-card-body" style="padding:0">'
        f'<div style="padding:12px 16px;background:#f6f8fa;border-bottom:1px solid #d0d7de;font-size:12px;color:#636c76;font-family:monospace">'
        f'Risk<sub>enh</sub> = 100 &times; (0.25&times;S_sev + 0.25&times;S_exp + 0.15&times;S_scope + 0.35&times;S_reach)'
        f'<br>Contribution = score &times; weight &times; 100'
        f'</div>'
        f'<table style="width:100%;border-collapse:collapse">'
        f'<thead><tr style="border-bottom:2px solid #d0d7de;font-size:11px;color:#636c76;text-transform:uppercase">'
        f'<th style="padding:8px 12px;text-align:left">Parameter</th>'
        f'<th style="padding:8px 12px;text-align:left">Value</th>'
        f'<th style="padding:8px 12px;text-align:center">Score (0-1)</th>'
        f'<th style="padding:8px 12px;text-align:center">Weight</th>'
        f'<th style="padding:8px 12px;text-align:right">Points (/100)</th>'
        f'<th style="padding:8px 12px;text-align:left"></th>'
        f'</tr></thead>'
        f'<tbody>{param_rows}</tbody>'
        f'<tfoot><tr style="border-top:2px solid #d0d7de;background:#f6f8fa">'
        f'<td colspan="4" style="padding:10px 12px;font-weight:700;color:#1f2328">Total Risk Score</td>'
        f'<td style="padding:10px 12px;text-align:right;font-size:18px;font-weight:800;color:{rs_color}">{computed_risk:.1f}</td>'
        f'<td style="padding:10px 12px"><span style="font-size:11px;color:{rs_color};font-weight:600">/100</span></td>'
        f'</tr></tfoot>'
        f'</table></div></div>'
    )

    # Reachable sinks card — only shown when Semgrep found a match
    if reach_verdict == "confirmed_reachable" and call_locations:
        locs_html = "".join(
            f'<div style="margin-bottom:6px">'
            f'<code style="font-size:12px;background:#FFEBE9;padding:4px 10px;border-radius:4px;'
            f'border:1px solid #cf222e40;color:#cf222e;font-weight:500;display:inline-block">'
            f'{loc}</code></div>'
            for loc in call_locations
        )
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header" style="color:#cf222e">⚡ Confirmed Reachable Sinks</div>'
            '<div class="gh-detail-card-body">'
            '<p style="margin:0 0 10px 0;font-size:13px;color:#57606a">'
            'Semgrep found a call to the vulnerable sink in this repository:</p>'
            f'{locs_html}'
            '</div></div>'
        )
    elif reach_verdict == "likely_reachable":
        locs_html = ""
        if call_locations:
            locs_html = "".join(
                f'<div style="margin-bottom:6px">'
                f'<code style="font-size:12px;background:#FFF8C5;padding:4px 10px;border-radius:4px;'
                f'border:1px solid #d4a72c40;color:#9a6700;font-weight:500;display:inline-block">'
                f'{loc}</code></div>'
                for loc in call_locations
            )
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header" style="color:#9a6700">⚠ Likely Reachable</div>'
            '<div class="gh-detail-card-body" style="font-size:13px;color:#57606a">'
            '<p style="margin:0 0 8px 0">The vulnerable sink pattern was detected but full reachability could not be confirmed. '
            'Manual review is recommended.</p>'
            + (f'{locs_html}' if locs_html else '') +
            '</div></div>'
        )
    elif reach_verdict == "likely_unreachable":
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header" style="color:#57606a">Reachability: Not Confirmed</div>'
            '<div class="gh-detail-card-body" style="color:#636c76;font-size:13px">'
            'Semgrep scanned this repository but did not find a call to the vulnerable sink. '
            'The risk may still exist if the pattern was not captured by the current rule set.'
            '</div></div>'
        )
    elif reach_verdict == "no_sink_data":
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header" style="color:#57606a">Reachability: Limited Evidence</div>'
            '<div class="gh-detail-card-body" style="color:#636c76;font-size:13px">'
            'The pipeline does not currently have sink data for this CVE, so reachability could not be evaluated precisely.'
            '</div></div>'
        )

    description = first.get("detail_summary") or ""
    if description:
        desc_body = description[:1500] + ("..." if len(description) > 1500 else "")
    else:
        desc_body = "*No description available for this vulnerability.*"

    with st.expander("Full Description", expanded=True):
        st.markdown(desc_body)

    comp_map: dict[str, dict] = {}
    for row in detail_rows:
        cid = row.get("component_id") or row.get("component", "?")
        entry = comp_map.setdefault(
            cid,
            {
                "name": row.get("component"),
                "version": row.get("version"),
                "component_id": cid,
                "dependency_depth": row.get("dependency_depth"),
                "locations": [],
            },
        )
        paths = row.get("location_paths") or []
        lines = row.get("location_lines") or []
        for path, line in zip(paths, lines):
            location = {"path": path, "line": line}
            if path and location not in entry["locations"]:
                entry["locations"].append(location)

    pkg_rows_html = ""
    for _, comp in sorted(
        comp_map.items(),
        key=lambda item: (item[1].get("dependency_depth") is None, item[1].get("dependency_depth") or 0, item[1].get("name") or ""),
    ):
        locs_html = ""
        for loc in comp["locations"][:10]:
            line_txt = f":{loc['line']}" if loc.get("line") else ""
            locs_html += (
                '<div style="margin-bottom:6px;">'
                '<code style="font-size:12px;background:#f6f8fa;padding:4px 8px;border-radius:4px;border:1px solid #d0d7de;color:#0969da;font-weight:500;white-space:nowrap;display:inline-block;">'
                f'{loc["path"]}{line_txt}'
                "</code></div>"
            )
        depth_txt = comp.get("dependency_depth")
        pkg_rows_html += (
            "<tr>"
            f'<td style="padding:12px 16px; vertical-align:top;"><code>{comp["name"]}</code></td>'
            f'<td style="padding:12px 16px; vertical-align:top;"><code>{comp["version"]}</code></td>'
            f'<td style="padding:12px 16px; vertical-align:top;">{"Direct/root" if depth_txt == 0 else f"Depth {depth_txt}" if depth_txt is not None else "N/A"}</td>'
            f'<td style="padding:12px 16px; vertical-align:top;">{locs_html or "N/A"}</td>'
            "</tr>"
        )

    st.html(
        '<div class="gh-detail-card">'
        '<div class="gh-detail-card-header">Affected Packages</div>'
        '<div class="gh-detail-card-body" style="padding:0">'
        '<table style="width:100%;border-collapse:collapse">'
        '<thead><tr style="border-bottom:1px solid #d0d7de;font-size:12px;color:#636c76">'
        '<th style="padding:8px 16px;text-align:left;width:20%;">Package</th>'
        '<th style="padding:8px 16px;text-align:left;width:15%;">Version</th>'
        '<th style="padding:8px 16px;text-align:left;width:15%;">Depth</th>'
        '<th style="padding:8px 16px;text-align:left;width:50%;">Declared at</th>'
        "</tr></thead>"
        f"<tbody>{pkg_rows_html}</tbody>"
        "</table></div></div>"
    )

    chain_rows = db.fetch_vuln_dep_chains(project_name, vuln_id_display)
    if chain_rows:
        chains_html = "".join(ui._dep_chain_card_html(row) for row in chain_rows)
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header">Dependency Chain</div>'
            '<div class="gh-detail-card-body">'
            '<p style="margin:0 0 12px 0;color:#636c76;">Showing affected components closest to the project root in the latest SBOM.</p>'
            f"{chains_html}"
            "</div>"
            "</div>"
        )
    elif first.get("component_id"):
        fallback_rows = db.fetch_dep_chain(project_name, first["component_id"])
        if fallback_rows:
            fallback_html = "".join(ui._dep_chain_card_html(row) for row in fallback_rows)
            st.html(
                '<div class="gh-detail-card">'
                '<div class="gh-detail-card-header">Dependency Chain</div>'
                f'<div class="gh-detail-card-body">{fallback_html}</div>'
                "</div>"
            )

    if fix_vers:
        fix_tags_html = "".join(f'<span class="gh-fix-tag">{v}</span>' for v in fix_vers)
        if len(_comp_ver_depth) > 1:
            # Per-version table: each affected version row with its fix targets
            _fix_rows = "".join(
                f'<tr style="border-bottom:1px solid #f0f0f0">'
                f'<td style="padding:10px 16px;font-family:monospace;font-size:13px;white-space:nowrap">{n}{"@" + v if v else ""}</td>'
                f'<td style="padding:10px 16px">{fix_tags_html}</td>'
                f'</tr>'
                for n, v, _ in _comp_ver_depth if n
            )
            st.html(
                '<div class="gh-detail-card">'
                '<div class="gh-detail-card-header">Fix Versions</div>'
                '<div class="gh-detail-card-body" style="padding:0">'
                '<table style="width:100%;border-collapse:collapse">'
                '<thead><tr style="border-bottom:1px solid #d0d7de;font-size:11px;color:#636c76">'
                '<th style="padding:8px 16px;text-align:left">Affected version</th>'
                '<th style="padding:8px 16px;text-align:left">Upgrade to</th>'
                '</tr></thead>'
                f'<tbody>{_fix_rows}</tbody>'
                '</table></div></div>'
            )
        else:
            st.html(
                '<div class="gh-detail-card">'
                '<div class="gh-detail-card-header">Fix Versions</div>'
                '<div class="gh-detail-card-body">'
                '<p style="color:#636c76;font-size:12px;margin-bottom:8px">Update the affected package to any of the following versions:</p>'
                f'<div class="gh-fix-list">{fix_tags_html}</div>'
                "</div></div>"
            )
    else:
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header">Fix Versions</div>'
            '<div class="gh-detail-card-body" style="color:#636c76">No patch is currently available. Apply manual mitigations based on the CWE category.</div>'
            "</div>"
        )

    vectors = _as_list(first.get("severity_vectors"))
    if vectors:
        vector_html = "".join(
            f'<code style="font-size:11px;display:block;background:#f6f8fa;padding:4px 8px;border-radius:3px;margin:2px 0">{v}</code>'
            for v in vectors
        )
        st.html(
            '<div class="gh-detail-card">'
            '<div class="gh-detail-card-header">CVSS Vectors</div>'
            f'<div class="gh-detail-card-body">{vector_html}</div>'
            "</div>"
        )

    st.divider()
    with st.expander("Query diagnostics (raw retrieval data)", expanded=False):
        st.caption("Raw rows returned from Neo4j for vulnerability detail and dependency chains.")
        st.markdown("**Vulnerability detail rows:**")
        st.json(detail_rows)
        st.markdown("**Dependency chain rows:**")
        st.json(chain_rows)

    with st.expander("Evidence records (pre-LLM format)", expanded=False):
        st.caption("Evidence records after evidence_service normalization.")
        from backend.services.evidence_service import build_evidence

        ev = build_evidence([("vuln_detail", detail_rows), ("dep_chain", chain_rows)])
        st.json(ev)

    st.html('<div class="gh-section-heading">LLM Analysis</div>')
    st.caption("Investigate this specific vulnerability using the codebase graph structure.")

    if st.button("Run GraphRAG Analysis", type="primary", key="btn_vuln_rag"):
        from backend.services.llm_service import run_pipeline

        with st.spinner("Analyzing propagation and impact..."):
            result = run_pipeline("dev_explain", {"vuln_id": internal_id, "project_name": project_name})

        st.markdown(result["explanation"])
        with st.expander("Query diagnostics", expanded=False):
            st.json(result["query_meta"])


def _render_alert_row(row: dict, i: int, project_name: str) -> str:
    """Render a single alert as a standalone markdown card wrapped in a hyperlink."""
    vuln_id = row.get("vuln_id") or "Unknown"
    internal_id = row.get("internal_id") or vuln_id
    all_components = row.get("all_components") or []
    all_versions = row.get("all_versions") or []
    comp_count = row.get("component_count") or 1
    closest_depth = row.get("closest_depth")

    cvss = row.get("cvss")
    kev = bool(row.get("kev"))
    epss = row.get("epss")
    risk_score = row.get("risk_score")
    fix_vers = _as_list(row.get("fix_versions"))
    sev = ui._severity_from_cvss(cvss, kev)
    sev_label = ui._severity_label(sev)
    shield = ui._shield_svg(sev)

    badge = f'<span class="gh-badge badge-{sev}">{sev_label}</span>'
    if kev:
        badge += ' <span class="gh-badge badge-kev">KEV</span>'
    reach_verdict = row.get("reachability_verdict", "no_sink_data")
    if reach_verdict == "confirmed_reachable":
        badge += ' <span style="font-size:11px;font-weight:700;color:#fff;background:#cf222e;padding:2px 7px;border-radius:10px;white-space:nowrap;">⚡ Reachable</span>'
    elif reach_verdict == "likely_reachable":
        badge += ' <span style="font-size:11px;font-weight:700;color:#9a6700;background:#FFF8C5;padding:2px 7px;border-radius:10px;border:1px solid #d4a72c;white-space:nowrap;">⚠ Likely Reachable</span>'
    elif reach_verdict == "likely_unreachable":
        badge += ' <span style="font-size:11px;font-weight:600;color:#57606a;background:#f6f8fa;padding:2px 7px;border-radius:10px;border:1px solid #d0d7de;white-space:nowrap;">Unreachable</span>'
    elif reach_verdict == "no_sink_data":
        badge += ' <span style="font-size:11px;font-weight:600;color:#57606a;background:#f6f8fa;padding:2px 7px;border-radius:10px;border:1px solid #d0d7de;white-space:nowrap;">? Unknown</span>'
    if risk_score is not None:
        if risk_score >= 85:
            risk_color = "#cf222e"; risk_bg = "#FFEBE9"
        elif risk_score >= 70:
            risk_color = "#bc4c00"; risk_bg = "#FFF8C5"
        elif risk_score >= 40:
            risk_color = "#9a6700"; risk_bg = "#FFF8C5"
        else:
            risk_color = "#636c76"; risk_bg = "#f6f8fa"
        badge += (
            f' <span style="font-size:12px;font-weight:700;color:{risk_color};'
            f'background:{risk_bg};padding:2px 8px;border-radius:12px;'
            f'border:1px solid {risk_color}30;white-space:nowrap;">'
            f'Risk {risk_score:.1f}</span>'
        )

    if fix_vers:
        first_fix = fix_vers[0] if isinstance(fix_vers, list) else fix_vers
        fix_chip = f'<span class="gh-fix-chip">Fix: {first_fix}</span>'
    else:
        fix_chip = ""

    if len(all_components) > 1:
        comp_str = f"Multiple components ({comp_count} affected)"
    elif len(all_components) == 1:
        comp_name = all_components[0]
        if comp_count > 1 and all_versions:
            vers_list = sorted(set(all_versions))
            vers_str = f"{vers_list[0]}, {vers_list[1]}... (+{len(vers_list) - 2} more)" if len(vers_list) > 3 else ", ".join(vers_list)
            comp_str = f"{comp_name}@{vers_str}"
        else:
            version = all_versions[0] if all_versions else ""
            comp_str = f"{comp_name}@{version}" if version else comp_name
    else:
        comp_str = "Unknown Component"

    meta_parts = [f'<span>Package: {comp_str}</span>']
    if epss:
        meta_parts.append(f"<span>EPSS {epss:.2%}</span>")
    if closest_depth is not None:
        meta_parts.append(f"<span>Depth {closest_depth}</span>")

    content = f"""<div class="gh-alert-row">
  {shield}
  <div style="flex: 1; min-width: 0;">
    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
        <span style="font-weight:600; color:#0969da; font-size:14px;">{vuln_id}</span>
        {badge}
        {fix_chip}
      </div>
      <span style="color:{dict(critical='#cf222e', high='#bc4c00', medium='#9a6700', low='#636c76').get(sev, '#636c76')}; font-size:12px; font-weight:600; white-space:nowrap;">
        CVSS {f'{cvss:.1f}' if cvss is not None else 'N/A'}
      </span>
    </div>
    <div class="gh-alert-meta">
      {' '.join(meta_parts)}
    </div>
  </div>
</div>"""

    content = " ".join(content.split())
    safe_proj = quote_plus(project_name)
    safe_alert = quote_plus(str(internal_id))
    return f'<a href="?alert={safe_alert}&project={safe_proj}" style="text-decoration:none; color:inherit; display:block;" target="_self">{content}</a>'


def render_dependabot_tab(project_name: str, total_repo_count: int | None = None) -> None:
    """Render the main Dependabot-style security alert list (or detail view)."""
    alert_id = st.query_params.get("alert")
    if alert_id:
        render_alert_detail_page(project_name, alert_id)
        return

    with st.spinner("Loading security alerts..."):
        try:
            alerts = db.fetch_alerts(project_name)
            stats = db.fetch_project_stats(project_name)
        except Exception as exc:
            st.error(f"Cannot load data from Neo4j: {exc}")
            return

    ui._render_stats_bar(stats, "all", total_repos=total_repo_count)

    active_filter_count = (
        int(bool(st.session_state.get("kev_filter", False)))
        + len(st.session_state.get("reachability_filter", []))
        + len(st.session_state.get("severity_filter", []))
        + len(st.session_state.get("fix_status_filter", []))
    )
    filter_label = "Filter" if active_filter_count == 0 else f"Filter ({active_filter_count})"

    toolbar = st.container()
    with toolbar:
        st.markdown('<div class="gh-alert-toolbar-anchor"></div>', unsafe_allow_html=True)
        col_filter, col_sort, col_search = st.columns([1.5, 1.4, 2.3])
        with col_filter:
            st.markdown('<div class="gh-alert-toolbar-label">Filter</div>', unsafe_allow_html=True)
            with st.popover(filter_label, use_container_width=True):
                kev_only = st.checkbox("KEV only", key="kev_filter")
                reachability_filter = st.multiselect(
                    "Reachability",
                    options=list(REACHABILITY_LABELS.keys()),
                    format_func=lambda verdict: REACHABILITY_LABELS.get(verdict, str(verdict)),
                    key="reachability_filter",
                    placeholder="All reachability states",
                )
                severity_filter = st.multiselect(
                    "Severity",
                    options=SEVERITY_OPTIONS,
                    key="severity_filter",
                    placeholder="All severities",
                )
                fix_status_filter = st.multiselect(
                    "Fixing status",
                    options=FIX_STATUS_OPTIONS,
                    key="fix_status_filter",
                    placeholder="All fixing statuses",
                )
        with col_sort:
            sort_by = st.selectbox(
                "Sort by",
                options=["Risk Score", "Severity", "Depth"],
                key="sort_filter",
            )
        with col_search:
            search_text = st.text_input(
                "Search",
                placeholder="Search by component or vulnerability...",
                key="search_filter",
            )

    filtered = alerts
    if severity_filter:
        sev_map = {"Critical": "critical", "High": "high", "Moderate": "medium", "Low": "low"}
        target_severities = {sev_map[sev] for sev in severity_filter}
        filtered = [
            r for r in filtered
            if ui._severity_from_cvss(r.get("cvss"), bool(r.get("kev"))) in target_severities
        ]
    if kev_only:
        filtered = [r for r in filtered if r.get("kev")]
    if reachability_filter:
        target_reachability = set(reachability_filter)
        filtered = [r for r in filtered if r.get("reachability_verdict", "no_sink_data") in target_reachability]
    if fix_status_filter:
        filtered_by_fix: list[dict] = []
        for row in filtered:
            has_fix = bool(row.get("fix_versions"))
            if has_fix and "Fix available" in fix_status_filter:
                filtered_by_fix.append(row)
            elif not has_fix and "No fix" in fix_status_filter:
                filtered_by_fix.append(row)
        filtered = filtered_by_fix
    if search_text:
        q = search_text.lower()
        filtered = [
            r for r in filtered
            if q in " ".join(str(x).lower() for x in (r.get("all_components") or []))
            or q in str(r.get("vuln_id") or "").lower()
        ]

    if sort_by == "Risk Score":
        filtered = sorted(filtered, key=lambda r: r.get("risk_score") or 0, reverse=True)
    elif sort_by == "Severity":
        filtered = sorted(filtered, key=lambda r: r.get("cvss") or 0, reverse=True)
    elif sort_by == "Depth":
        filtered = sorted(
            filtered,
            key=lambda r: (r.get("closest_depth") is None, r.get("closest_depth") or 0),
        )

    open_count = len(filtered)
    total_count = len(alerts)

    list_header = (
        f'<div class="gh-alert-list-header">'
        f"<span>{open_count} Open</span>"
        f'<span style="color:#636c76">{total_count} total alerts for this project</span>'
        f"</div>"
    )

    if filtered:
        st.html(list_header)
        for i, row in enumerate(filtered):
            st.html(_render_alert_row(row, i, project_name))
    else:
        st.html(
            list_header
            + '<div style="border:1px solid #d0d7de;border-radius:6px;text-align:center;padding:48px 16px;color:#636c76;">'
            + "<div>No security alerts match the current filters.</div>"
            + "</div>"
        )

    st.divider()
    with st.expander("Query diagnostics (list retrieval)", expanded=False):
        st.caption("Raw rows for the alert list and stats.")
        st.markdown("**Stats data:**")
        st.json(stats)
        st.markdown("**Alerts (top 10):**")
        st.json(alerts[:10])
