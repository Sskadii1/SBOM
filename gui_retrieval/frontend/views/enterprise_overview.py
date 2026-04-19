"""
frontend/views/enterprise_overview.py — Enterprise-wide security posture dashboard.
"""
from collections import Counter, defaultdict
from typing import Any

import streamlit as st

import frontend.data_access as db


_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
_REACHABILITY_LABELS = {
    "confirmed_reachable": "Confirmed reachable",
    "likely_reachable": "Likely reachable",
    "uncertain": "Uncertain",
    "likely_unreachable": "Likely unreachable",
    "no_sink_data": "No sink data",
}
_LANGUAGE_BY_PURL = {
    "npm": "JavaScript/TypeScript",
    "pypi": "Python",
    "maven": "Java",
    "cargo": "Rust",
    "gem": "Ruby",
    "golang": "Go",
    "go": "Go",
    "nuget": ".NET",
}


def _severity_from_cvss(cvss: Any) -> str:
    score = float(cvss or 0)
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _normalize_language(raw: Any) -> str:
    language = str(raw or "").strip()
    return language if language else "Unknown"


def _infer_language(project_meta: dict[str, Any], alerts: list[dict[str, Any]]) -> str:
    language = _normalize_language(project_meta.get("language"))
    if language != "Unknown":
        return language

    package_manager = str(project_meta.get("package_manager") or "").strip().lower()
    if package_manager:
        return _LANGUAGE_BY_PURL.get(package_manager, package_manager.title())

    for alert in alerts:
        for component_id in alert.get("all_component_ids") or []:
            if isinstance(component_id, str) and component_id.startswith("pkg:"):
                purl_type = component_id[4:].split("/", 1)[0].lower()
                return _LANGUAGE_BY_PURL.get(purl_type, purl_type.title())
    return "Unknown"


def _vega_pie(title: str, values: list[dict[str, Any]], color_scale: list[str]) -> None:
    st.vega_lite_chart(
        {
            "data": {"values": values},
            "mark": {"type": "arc", "innerRadius": 55},
            "width": "container",
            "height": 280,
            "encoding": {
                "theta": {"field": "count", "type": "quantitative"},
                "color": {
                    "field": "label",
                    "type": "nominal",
                    "scale": {"range": color_scale},
                    "legend": {"title": None, "orient": "bottom"},
                },
                "tooltip": [
                    {"field": "label", "type": "nominal", "title": title},
                    {"field": "count", "type": "quantitative", "title": "Count"},
                ],
            },
            "view": {"stroke": None},
        },
        use_container_width=True,
    )


def _vega_bar(values: list[dict[str, Any]], x_field: str, y_field: str, color: str, height: int = 320) -> None:
    st.vega_lite_chart(
        {
            "data": {"values": values},
            "mark": {"type": "bar", "cornerRadiusTopRight": 6, "cornerRadiusBottomRight": 6},
            "width": "container",
            "height": height,
            "encoding": {
                "x": {"field": x_field, "type": "quantitative", "title": None},
                "y": {
                    "field": y_field,
                    "type": "nominal",
                    "sort": "-x",
                    "title": None,
                    "axis": {"labelLimit": 220},
                },
                "color": {"value": color},
                "tooltip": [{"field": y_field, "type": "nominal"}, {"field": x_field, "type": "quantitative"}],
            },
            "view": {"stroke": None},
        },
        use_container_width=True,
    )


def _vega_heatmap(values: list[dict[str, Any]]) -> None:
    st.vega_lite_chart(
        {
            "data": {"values": values},
            "mark": "rect",
            "width": "container",
            "height": 260,
            "encoding": {
                "x": {"field": "severity", "type": "ordinal", "sort": _SEVERITY_ORDER, "title": None},
                "y": {"field": "language", "type": "ordinal", "title": None, "sort": "-x"},
                "color": {
                    "field": "risk",
                    "type": "quantitative",
                    "title": "Risk",
                    "scale": {"scheme": "orangered"},
                },
                "tooltip": [
                    {"field": "language", "type": "nominal"},
                    {"field": "severity", "type": "nominal"},
                    {"field": "risk", "type": "quantitative", "format": ".1f", "title": "Cumulative risk"},
                    {"field": "count", "type": "quantitative", "title": "Alert count"},
                ],
            },
            "view": {"stroke": None},
        },
        use_container_width=True,
    )


def render_enterprise_overview_tab(projects: list[str]) -> None:
    """Enterprise-wide security overview across all repositories."""
    st.markdown('<div class="gh-section-heading">Enterprise Security Overview</div>', unsafe_allow_html=True)
    st.caption("Portfolio-level security posture snapshot across all ingested repositories.")

    if not projects:
        st.info("No repositories are available yet. Use Upload Repository to ingest one first.")
        return

    with st.spinner("Aggregating enterprise security posture..."):
        catalog = {row["full_name"]: row for row in db.fetch_project_catalog()}
        project_alerts = {project: db.fetch_alerts(project) for project in projects}

    all_alerts: list[dict[str, Any]] = []
    severity_counts: Counter[str] = Counter()
    reachability_counts: Counter[str] = Counter()
    project_rollups: list[dict[str, Any]] = []
    dependency_risk: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "risk": 0.0, "projects": set()})
    cve_risk: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "max_risk": 0.0,
            "sum_risk": 0.0,
            "count": 0,
            "projects": set(),
            "max_cvss": 0.0,
            "kev": False,
            "reachable_count": 0,
        }
    )
    language_heatmap: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"risk": 0.0, "count": 0})

    for project in projects:
        alerts = project_alerts.get(project, [])
        project_language = _infer_language(catalog.get(project, {}), alerts)
        total_risk = round(sum(float(alert.get("risk_score") or 0) for alert in alerts), 2)
        avg_risk = round(total_risk / len(alerts), 2) if alerts else 0.0
        project_rollups.append(
            {
                "project": project,
                "alert_count": len(alerts),
                "total_risk": total_risk,
                "avg_risk": avg_risk,
                "language": project_language,
            }
        )

        for alert in alerts:
            risk = float(alert.get("risk_score") or 0)
            severity = _severity_from_cvss(alert.get("cvss"))
            reachability = str(alert.get("reachability_verdict") or "no_sink_data")
            vuln_id = str(alert.get("vuln_id") or alert.get("internal_id") or "Unknown")

            severity_counts[severity] += 1
            reachability_counts[reachability] += 1
            all_alerts.append(alert)

            cve_entry = cve_risk[vuln_id]
            cve_entry["max_risk"] = max(cve_entry["max_risk"], risk)
            cve_entry["sum_risk"] += risk
            cve_entry["count"] += 1
            cve_entry["projects"].add(project)
            cve_entry["max_cvss"] = max(cve_entry["max_cvss"], float(alert.get("cvss") or 0))
            cve_entry["kev"] = cve_entry["kev"] or bool(alert.get("kev"))
            if reachability == "confirmed_reachable":
                cve_entry["reachable_count"] += 1

            for component_name in set(alert.get("all_components") or []):
                dep_entry = dependency_risk[component_name]
                dep_entry["count"] += 1
                dep_entry["risk"] += risk
                dep_entry["projects"].add(project)

            heatmap_entry = language_heatmap[(project_language, severity)]
            heatmap_entry["risk"] += risk
            heatmap_entry["count"] += 1

    total_projects = len(projects)
    total_alerts = len(all_alerts)
    critical_alerts = severity_counts["Critical"]
    confirmed_reachable = reachability_counts["confirmed_reachable"]
    projects_with_kev = sum(1 for alerts in project_alerts.values() if any(bool(alert.get("kev")) for alert in alerts))
    avg_portfolio_risk = round(sum(row["avg_risk"] for row in project_rollups) / total_projects, 2) if total_projects else 0.0

    st.markdown('<div class="gh-enterprise-kpi-anchor"></div>', unsafe_allow_html=True)
    metric_cols = st.columns(6)
    metric_cols[0].metric("Repositories", total_projects)
    metric_cols[1].metric("Open Alerts", total_alerts)
    metric_cols[2].metric("Critical", critical_alerts)
    metric_cols[3].metric("Projects with KEV", projects_with_kev)
    metric_cols[4].metric("Confirmed Reachable", confirmed_reachable)
    metric_cols[5].metric("Avg Repo Risk", avg_portfolio_risk)

    severity_values = [{"label": key, "count": severity_counts.get(key, 0)} for key in _SEVERITY_ORDER if severity_counts.get(key, 0) > 0]
    reachability_values = [
        {"label": _REACHABILITY_LABELS[key], "count": count}
        for key, count in reachability_counts.most_common()
    ]

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("**Vulnerability Severity Distribution**")
        if severity_values:
            _vega_pie("Severity", severity_values, ["#cf222e", "#fb8500", "#f4b942", "#8c959f"])
        else:
            st.info("No severity data available.")
    with chart_right:
        st.markdown("**Reachability Status**")
        if reachability_values:
            _vega_bar(reachability_values, "count", "label", "#f28c52", height=280)
        else:
            st.info("No reachability data available.")

    st.markdown("**Top 10 Most Dangerous CVEs**")
    cve_rows = sorted(
        [
            {
                "CVE": vuln_id,
                "Max Risk": round(entry["max_risk"], 2),
                "Avg Risk": round(entry["sum_risk"] / entry["count"], 2),
                "Affected Projects": len(entry["projects"]),
                "Max CVSS": round(entry["max_cvss"], 1),
                "KEV": "Yes" if entry["kev"] else "No",
                "Confirmed Reachable": entry["reachable_count"],
            }
            for vuln_id, entry in cve_risk.items()
        ],
        key=lambda row: (row["Max Risk"], row["Affected Projects"], row["Max CVSS"]),
        reverse=True,
    )[:10]
    if cve_rows:
        st.dataframe(cve_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No CVE data available.")

    st.markdown("**Risk Distribution Across Projects**")
    project_risk_values = sorted(project_rollups, key=lambda row: row["total_risk"], reverse=True)[:12]
    if project_risk_values:
        _vega_bar(project_risk_values, "total_risk", "project", "#f28c52", height=360)
    else:
        st.info("No project risk data available.")

    bottom_left, bottom_right = st.columns(2)
    with bottom_left:
        st.markdown("**Top Vulnerable Dependencies**")
        dependency_values = sorted(
            [
                {
                    "dependency": dep_name,
                    "cumulative_risk": round(entry["risk"], 2),
                    "count": entry["count"],
                    "projects": len(entry["projects"]),
                }
                for dep_name, entry in dependency_risk.items()
            ],
            key=lambda row: (row["cumulative_risk"], row["count"]),
            reverse=True,
        )[:10]
        if dependency_values:
            _vega_bar(dependency_values, "cumulative_risk", "dependency", "#bc4c00", height=320)
        else:
            st.info("No dependency exposure data available.")

    with bottom_right:
        st.markdown("**Language Risk Heatmap**")
        heatmap_values = [
            {
                "language": language,
                "severity": severity,
                "risk": round(entry["risk"], 2),
                "count": entry["count"],
            }
            for (language, severity), entry in language_heatmap.items()
        ]
        if heatmap_values:
            _vega_heatmap(heatmap_values)
        else:
            st.info("No language-level risk data available.")
