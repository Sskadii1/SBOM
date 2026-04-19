"""
frontend/views/query_workbench.py - Portfolio-wide security query workbench.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import streamlit as st

import frontend.data_access as db
from frontend.query_builder import (
    ENUM_OPTIONS,
    FIELD_GROUPS,
    FIELD_SPEC_BY_NAME,
    build_query_from_rules,
    operators_for_field,
)
from frontend.query_language import QuerySyntaxError, evaluate_expression, parse_query


WORKBENCH_NAME = "Query Workbench"

DEFAULT_QUERY = 'severity in ("critical", "high") AND fix_available = true'

OPERATORS = {
    "Comparison": ["=", "!=", ">", ">=", "<", "<="],
    "Text": ["contains", "starts_with", "ends_with"],
    "Membership": ["in", "contains_any", "contains_all"],
    "Presence": ["exists"],
    "Logic": ["AND", "OR", "NOT", "(", ")"],
}

EXAMPLE_QUERIES = [
    'severity in ("critical", "high") AND fix_available = true',
    'kev = true OR reachability_verdict = "confirmed_reachable"',
    'project = "AnnAngela/eslint-packages" AND risk_score >= 60',
    'cwe contains "CWE-79" AND published >= "2024-01-01"',
    'all_scopes contains_any ("required", "runtime") AND closest_depth <= 2',
]


def _severity_from_alert(alert: dict[str, Any]) -> str:
    cvss = float(alert.get("cvss") or 0)
    if bool(alert.get("kev")) or cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _days_ago(raw: Any) -> int | None:
    if not raw:
        return None
    text = str(raw)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _normalize_alert_rows(projects: list[str]) -> list[dict[str, Any]]:
    fingerprint = db.fetch_data_fingerprint()
    data = db.fetch_enterprise_overview_inputs(tuple(projects), fingerprint)
    catalog = data["catalog"]
    project_alerts = data["project_alerts"]

    rows: list[dict[str, Any]] = []
    for project in projects:
        meta = catalog.get(project, {})
        for alert in project_alerts.get(project, []):
            scopes = [str(scope) for scope in (alert.get("all_scopes") or []) if scope]
            fix_versions = [str(version) for version in (alert.get("fix_versions") or []) if version]
            call_locations = [str(loc) for loc in (alert.get("call_locations") or []) if loc]
            cwe = [str(item) for item in (alert.get("cwe") or []) if item]
            components = [str(item) for item in (alert.get("all_components") or []) if item]
            component_ids = [str(item) for item in (alert.get("all_component_ids") or []) if item]

            row = {
                "project": project,
                "project_name": meta.get("name") or project.split("/", 1)[-1],
                "language": meta.get("language") or "Unknown",
                "package_manager": meta.get("package_manager") or "Unknown",
                "vuln_id": alert.get("vuln_id"),
                "internal_id": alert.get("internal_id"),
                "severity": _severity_from_alert(alert),
                "cvss": alert.get("cvss"),
                "epss": alert.get("epss"),
                "kev": bool(alert.get("kev")),
                "risk_score": alert.get("risk_score"),
                "reachability_verdict": alert.get("reachability_verdict") or "no_sink_data",
                "is_reachable": (alert.get("reachability_verdict") or "") in {"confirmed_reachable", "likely_reachable"},
                "fix_available": bool(fix_versions),
                "fix_versions_count": len(fix_versions),
                "fix_versions": fix_versions,
                "closest_depth": alert.get("closest_depth"),
                "component_count": alert.get("component_count"),
                "all_components": components,
                "all_component_ids": component_ids,
                "all_scopes": scopes,
                "is_runtime": any(scope in {"required", "runtime"} for scope in scopes),
                "published": alert.get("published"),
                "modified": alert.get("modified"),
                "published_days_ago": _days_ago(alert.get("published")),
                "modified_days_ago": _days_ago(alert.get("modified")),
                "cwe": cwe,
                "call_locations": call_locations,
                "call_locations_count": len(call_locations),
            }
            rows.append(row)
    return rows


def _display_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    display_rows: list[dict[str, Any]] = []
    for row in rows:
        display_rows.append(
            {
                "Project": row["project"],
                "Vulnerability": row["vuln_id"],
                "Severity": str(row["severity"]).upper(),
                "CVSS": row["cvss"],
                "EPSS": row["epss"],
                "KEV": row["kev"],
                "Risk Score": row["risk_score"],
                "Reachability": row["reachability_verdict"],
                "Fix": row["fix_available"],
                "Depth": row["closest_depth"],
                "Components": ", ".join(row["all_components"][:3]) + (" ..." if len(row["all_components"]) > 3 else ""),
                "CWEs": ", ".join(row["cwe"][:3]),
                "Published": row["published"],
            }
        )
    return display_rows


def _reference_block() -> None:
    left, right = st.columns(2)
    with left:
        st.markdown("**Available Fields**")
        for group, fields in FIELD_GROUPS.items():
            st.markdown(f"`{group}`: " + ", ".join(f"`{field}`" for field in fields))
    with right:
        st.markdown("**Supported Operators**")
        for group, ops in OPERATORS.items():
            st.markdown(f"`{group}`: " + ", ".join(f"`{op}`" for op in ops))

    st.markdown("**Examples**")
    for example in EXAMPLE_QUERIES:
        st.code(example, language="text")


def _default_rule() -> dict[str, Any]:
    return {"field": "severity", "operator": "in", "value": "critical, high", "negated": False}


def _default_value_for_field(field_name: str, operator: str) -> Any:
    spec = FIELD_SPEC_BY_NAME[field_name]
    if operator == "exists":
        return ""
    if spec.kind == "boolean":
        return True
    if field_name == "severity":
        return ["critical", "high"] if operator == "in" else "critical"
    if field_name == "reachability_verdict":
        return ["confirmed_reachable", "likely_reachable"] if operator == "in" else "confirmed_reachable"
    if spec.kind == "date":
        return "2024-01-01"
    if spec.kind == "number":
        return "50"
    if field_name == "project":
        return "AnnAngela/eslint-packages"
    if field_name == "cwe":
        return "CWE-79"
    if operator in {"in", "contains_any", "contains_all"}:
        return "required, runtime" if field_name == "all_scopes" else "value1, value2"
    return ""


def _value_guidance(field_name: str, operator: str) -> tuple[str, str]:
    spec = FIELD_SPEC_BY_NAME[field_name]
    if operator == "exists":
        return "No value needed for `exists`.", ""
    if spec.kind == "date":
        return "Use ISO date format like `YYYY-MM-DD` or a full ISO timestamp.", "2024-01-01"
    if spec.kind == "number":
        return "Use numeric values only, for example `50` or `7.5`.", "50"
    if spec.kind == "boolean":
        return "Choose `true` or `false`.", ""
    if operator in {"in", "contains_any", "contains_all"}:
        return "Enter multiple values as a comma-separated list.", "critical, high"
    if spec.kind == "array_string":
        return "Match a single value inside the list, for example `CWE-79`.", "CWE-79"
    if field_name == "project":
        return "Use the full repository name, for example `AnnAngela/eslint-packages`.", "AnnAngela/eslint-packages"
    return "Text values will be quoted automatically in the generated query.", ""


def _render_builder() -> str:
    if "query_builder_rules" not in st.session_state:
        st.session_state["query_builder_rules"] = [_default_rule()]
    if "query_builder_conjunction" not in st.session_state:
        st.session_state["query_builder_conjunction"] = "AND"

    st.markdown("**Rule Builder**")
    st.caption("Build the query visually first. The generated query syntax updates live below.")
    toolbar_left, toolbar_right = st.columns([3, 1])
    with toolbar_left:
        st.session_state["query_builder_conjunction"] = st.selectbox(
            "Combine rules with",
            options=["AND", "OR"],
            index=0 if st.session_state["query_builder_conjunction"] == "AND" else 1,
            key="query_builder_conjunction_select",
        )
    with toolbar_right:
        if st.button("Add Rule", use_container_width=True):
            st.session_state["query_builder_rules"] = [
                *st.session_state["query_builder_rules"],
                _default_rule(),
            ]

    updated_rules: list[dict[str, Any]] = []
    remove_index: int | None = None
    for idx, existing in enumerate(st.session_state["query_builder_rules"]):
        header_cols = st.columns([0.45, 5.55])
        with header_cols[0]:
            remove_disabled = len(st.session_state["query_builder_rules"]) == 1
            if st.button("✕", key=f"query_builder_remove_{idx}", use_container_width=True, disabled=remove_disabled, help="Remove this rule"):
                remove_index = idx
        with header_cols[1]:
            st.markdown(f"`Rule {idx + 1}`")

        cols = st.columns([2.1, 1.45, 2.75, 0.7])

        field_name = cols[0].selectbox(
            "Field",
            options=[spec.name for spec in FIELD_SPEC_BY_NAME.values()],
            format_func=lambda name: f"{FIELD_SPEC_BY_NAME[name].label} ({name})",
            index=list(FIELD_SPEC_BY_NAME).index(existing.get("field", "severity")),
            key=f"query_builder_field_{idx}",
        )
        operator_options = operators_for_field(field_name)
        current_operator = existing.get("operator")
        operator_index = operator_options.index(current_operator) if current_operator in operator_options else 0
        operator = cols[1].selectbox(
            "Operator",
            options=operator_options,
            index=operator_index,
            key=f"query_builder_operator_{idx}",
        )

        spec = FIELD_SPEC_BY_NAME[field_name]
        guidance, placeholder = _value_guidance(field_name, operator)
        if operator == "exists":
            cols[2].text_input("Value", value="", disabled=True, help=guidance, key=f"query_builder_value_{idx}")
            value: Any = ""
        elif spec.kind == "boolean":
            value = cols[2].selectbox(
                "Value",
                options=[True, False],
                index=0 if bool(existing.get("value", True)) else 1,
                format_func=lambda raw: "true" if raw else "false",
                help=guidance,
                key=f"query_builder_value_{idx}",
            )
        elif spec.name in ENUM_OPTIONS and operator in {"=", "!=", "in"}:
            if operator == "in":
                existing_value = existing.get("value", _default_value_for_field(field_name, operator))
                if isinstance(existing_value, str):
                    default_values = [item.strip() for item in existing_value.split(",") if item.strip()]
                else:
                    default_values = [str(item).strip() for item in existing_value if str(item).strip()]
                value = cols[2].multiselect(
                    "Value",
                    options=ENUM_OPTIONS[spec.name],
                    default=[item for item in default_values if item in ENUM_OPTIONS[spec.name]],
                    help=guidance,
                    key=f"query_builder_value_{idx}",
                )
            else:
                options = ENUM_OPTIONS[spec.name]
                default_value = existing.get("value", _default_value_for_field(field_name, operator))
                value = cols[2].selectbox(
                    "Value",
                    options=options,
                    index=options.index(default_value) if default_value in options else 0,
                    help=guidance,
                    key=f"query_builder_value_{idx}",
                )
        else:
            default_value = existing.get("value", _default_value_for_field(field_name, operator))
            if isinstance(default_value, list):
                default_value = ", ".join(str(item) for item in default_value)
            value = cols[2].text_input(
                "Value",
                value=str(default_value),
                placeholder=placeholder,
                help=guidance,
                key=f"query_builder_value_{idx}",
            )
        negated = cols[3].checkbox("NOT", value=bool(existing.get("negated")), key=f"query_builder_negated_{idx}")
        updated_rules.append({"field": field_name, "operator": operator, "value": value, "negated": negated})
        st.caption(guidance)

    if remove_index is not None and len(updated_rules) > 1:
        updated_rules.pop(remove_index)
    st.session_state["query_builder_rules"] = updated_rules
    generated_query = build_query_from_rules(updated_rules, st.session_state["query_builder_conjunction"])
    st.code(generated_query or "-- builder is empty --", language="text")
    return generated_query


def render_query_workbench_tab(projects: list[str]) -> None:
    st.markdown('<div class="gh-section-heading">Query Workbench</div>', unsafe_allow_html=True)
    st.caption("Search the full vulnerability dataset with a compact, type-aware query syntax.")

    if not projects:
        st.info("No repositories are available yet. Use Upload Repository to ingest one first.")
        return

    mode = st.radio(
        "Query Input Mode",
        options=["Builder", "Text"],
        index=0,
        horizontal=True,
        key="query_workbench_mode",
    )

    builder_query = ""
    if mode == "Builder":
        builder_query = _render_builder()
        if builder_query:
            st.session_state["query_workbench_text"] = builder_query

    query_text = st.text_area(
        "Query",
        value=st.session_state.get("query_workbench_text", DEFAULT_QUERY),
        height=110,
        help="Use quoted strings for text values. Dates should use ISO format like YYYY-MM-DD.",
        key="query_workbench_text",
    )

    if mode == "Builder" and builder_query and query_text != builder_query:
        st.info("Builder preview is shown above. Edit the text box only if you want to fine-tune the generated query manually.")

    action_col, hint_col = st.columns([1, 3])
    with action_col:
        run_query = st.button("Run Query", type="primary", use_container_width=True)
    with hint_col:
        st.caption("Use `AND`, `OR`, `NOT`, quoted strings for text, and ISO dates like `2024-01-01`. List syntax: `( \"critical\", \"high\" )`.")

    with st.expander("Syntax Reference", expanded=False):
        _reference_block()

    if run_query:
        try:
            expression = parse_query(query_text.strip())
        except QuerySyntaxError as exc:
            st.error(f"Query syntax error: {exc}")
            return

        with st.spinner("Scanning portfolio data..."):
            rows = _normalize_alert_rows(projects)
            matches = [row for row in rows if evaluate_expression(expression, row)]

        st.session_state["query_workbench_last_query"] = query_text.strip()
        st.session_state["query_workbench_last_matches"] = matches
        st.session_state["query_workbench_total_rows"] = len(rows)

    matches = st.session_state.get("query_workbench_last_matches")
    total_rows = st.session_state.get("query_workbench_total_rows")
    if matches is None or total_rows is None:
        return

    st.markdown(
        f'<div class="gh-section-heading">Results</div>',
        unsafe_allow_html=True,
    )
    st.caption(f"Matched {len(matches)} of {total_rows} vulnerability records across {len(projects)} repositories.")

    if not matches:
        st.info("No records matched the current query.")
        return

    sort_key = st.selectbox(
        "Sort results by",
        options=["risk_score", "published", "cvss", "project", "severity", "closest_depth"],
        index=0,
    )
    sort_desc = st.toggle("Descending", value=True)
    def _sort_value(row: dict[str, Any]) -> Any:
        value = row.get(sort_key)
        if sort_key == "published":
            return value or ""
        if sort_key == "project":
            return value or ""
        if sort_key == "severity":
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            return order.get(str(value).lower(), 0)
        return value if value is not None else -1

    matches = sorted(matches, key=_sort_value, reverse=sort_desc)

    st.dataframe(_display_rows(matches), use_container_width=True, hide_index=True)

    with st.expander("Raw matched records", expanded=False):
        st.json(matches[:50])
