"""
frontend/views/query_workbench.py - Portfolio-wide security query workbench.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import streamlit as st

import frontend.data_access as db
import frontend.query_workbench_data_access as query_db
from frontend.query_builder import (
    ENUM_OPTIONS,
    FIELD_GROUPS,
    FIELD_SPEC_BY_NAME,
    build_query_from_tree,
    default_group_node,
    default_rule_node,
    operators_for_field,
    validate_expression_tree,
)
from frontend.query_language import QuerySyntaxError, evaluate_expression, parse_query


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
    '(severity = "critical" OR severity = "high") AND fix_available = true',
    'project = "AnnAngela/eslint-packages" AND risk_score >= 60',
]


def _builder_styles() -> None:
    st.markdown(
        """
        <div class="qb-style-anchor"></div>
        <style>
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-shell {
            background:
                radial-gradient(circle at top left, rgba(47, 111, 235, 0.08), transparent 32%),
                linear-gradient(180deg, rgba(15, 23, 42, 0.03), rgba(15, 23, 42, 0.01));
            border: 1px solid rgba(15, 23, 42, 0.08);
            border-radius: 24px;
            padding: 18px 18px 8px 18px;
            margin: 10px 0 14px 0;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-root-title {
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 2px;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-root-subtitle,
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-muted {
            color: #57606a;
            font-size: 12px;
            line-height: 1.45;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-badge,
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-connector-pill,
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-node-path {
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 3px 9px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-badge-group {
            color: #0b57d0;
            background: rgba(47, 111, 235, 0.12);
            border: 1px solid rgba(47, 111, 235, 0.2);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-badge-rule {
            color: #b54708;
            background: rgba(242, 140, 82, 0.14);
            border: 1px solid rgba(242, 140, 82, 0.22);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-connector-pill {
            color: #0f172a;
            background: rgba(15, 23, 42, 0.05);
            border: 1px solid rgba(15, 23, 42, 0.08);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-node-path {
            color: #57606a;
            background: rgba(15, 23, 42, 0.03);
            border: 1px solid rgba(15, 23, 42, 0.08);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-node-title {
            font-size: 13px;
            font-weight: 700;
            color: #0f172a;
            margin: 6px 0 2px 0;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-node-summary {
            color: #334155;
            font-size: 12px;
            margin-bottom: 4px;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-branch {
            margin-top: 10px;
            padding-left: 14px;
            border-left: 2px solid rgba(47, 111, 235, 0.16);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-branch-rail {
            min-height: 100%;
            padding-top: 8px;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-branch-line {
            width: 100%;
            min-height: 56px;
            border-left: 2px solid rgba(47, 111, 235, 0.18);
            position: relative;
            margin-left: 14px;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-branch-line:before {
            content: "";
            position: absolute;
            top: 16px;
            left: -2px;
            width: 16px;
            border-top: 2px solid rgba(47, 111, 235, 0.18);
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-branch-line-last {
            border-left-color: transparent;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-empty {
            color: #57606a;
            font-size: 12px;
            padding: 4px 0 2px 0;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) label[data-testid="stWidgetLabel"] p {
            color: #57606a !important;
            font-size: 10px !important;
            font-weight: 600 !important;
            margin-bottom: 2px !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) div[data-baseweb="select"] > div,
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) [data-testid="stTextInput"] input {
            min-height: 38px !important;
            border-radius: 12px !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) div[data-testid="stButton"] button {
            min-height: 28px !important;
            height: 28px !important;
            padding: 0 10px !important;
            border-radius: 999px !important;
            font-size: 11px !important;
            font-weight: 600 !important;
            line-height: 1 !important;
            box-shadow: none !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) div[data-testid="stButton"] {
            margin-top: 0 !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-add button {
            background: rgba(255, 255, 255, 0.86) !important;
            border: 1px solid rgba(31, 35, 40, 0.10) !important;
            color: #1f2328 !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-add button:hover {
            border-color: rgba(47, 111, 235, 0.24) !important;
            color: #0958d9 !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-move button {
            min-width: 32px !important;
            width: 32px !important;
            height: 32px !important;
            background: transparent !important;
            border: none !important;
            color: #98a2b3 !important;
            font-size: 20px !important;
            font-weight: 500 !important;
            padding: 0 !important;
            border-radius: 8px !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-move button:hover {
            background: rgba(15, 23, 42, 0.04) !important;
            color: #475467 !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-delete button {
            min-width: 32px !important;
            width: 32px !important;
            height: 32px !important;
            background: transparent !important;
            border: none !important;
            color: #98a2b3 !important;
            font-size: 22px !important;
            font-weight: 400 !important;
            padding: 0 !important;
            border-radius: 8px !important;
        }
        div[data-testid="stVerticalBlock"]:has(.qb-style-anchor) .qb-btn-delete button:hover {
            background: rgba(207, 34, 46, 0.08) !important;
            color: #cf222e !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _display_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
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
        for row in rows
    ]


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


def _path_key(path: list[int]) -> str:
    return "root" if not path else "_".join(str(part) for part in path)


def _get_node(tree: dict[str, Any], path: list[int]) -> dict[str, Any]:
    node = tree
    for idx in path:
        node = node["children"][idx]
    return node


def _get_parent_and_index(tree: dict[str, Any], path: list[int]) -> tuple[dict[str, Any], int]:
    return _get_node(tree, path[:-1]), path[-1]


def _update_tree(action: callable) -> None:
    tree = deepcopy(st.session_state["query_builder_tree"])
    action(tree)
    st.session_state["query_builder_tree"] = tree
    st.rerun()


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
        return "No value is needed for `exists`.", ""
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
    return "Text values are quoted automatically in the generated query.", ""


def _render_value_input(existing: dict[str, Any], key_prefix: str, field_name: str, operator: str) -> tuple[Any, str]:
    spec = FIELD_SPEC_BY_NAME[field_name]
    guidance, placeholder = _value_guidance(field_name, operator)
    if operator == "exists":
        st.text_input("Value", value="", disabled=True, help=guidance, key=f"query_builder_value_{key_prefix}")
        return "", guidance
    if spec.kind == "boolean":
        value = st.selectbox(
            "Value",
            options=[True, False],
            index=0 if bool(existing.get("value", True)) else 1,
            format_func=lambda raw: "true" if raw else "false",
            help=guidance,
            key=f"query_builder_value_{key_prefix}",
        )
        return value, guidance
    if spec.name in ENUM_OPTIONS and operator in {"=", "!=", "in"}:
        if operator == "in":
            existing_value = existing.get("value", _default_value_for_field(field_name, operator))
            if isinstance(existing_value, str):
                default_values = [item.strip() for item in existing_value.split(",") if item.strip()]
            else:
                default_values = [str(item).strip() for item in existing_value if str(item).strip()]
            value = st.multiselect(
                "Value",
                options=ENUM_OPTIONS[spec.name],
                default=[item for item in default_values if item in ENUM_OPTIONS[spec.name]],
                help=guidance,
                key=f"query_builder_value_{key_prefix}",
            )
            return value, guidance
        options = ENUM_OPTIONS[spec.name]
        default_value = existing.get("value", _default_value_for_field(field_name, operator))
        value = st.selectbox(
            "Value",
            options=options,
            index=options.index(default_value) if default_value in options else 0,
            help=guidance,
            key=f"query_builder_value_{key_prefix}",
        )
        return value, guidance
    default_value = existing.get("value", _default_value_for_field(field_name, operator))
    if isinstance(default_value, list):
        default_value = ", ".join(str(item) for item in default_value)
    value = st.text_input(
        "Value",
        value=str(default_value),
        placeholder=placeholder,
        help=guidance,
        key=f"query_builder_value_{key_prefix}",
    )
    return value, guidance


def _render_header_actions(path: list[int], child_count: int, index: int) -> None:
    cols = st.columns([0.20, 0.20, 0.20])
    with cols[0]:
        st.markdown('<div class="qb-btn-move"></div>', unsafe_allow_html=True)
        if st.button("˄", key=f"query_builder_up_{_path_key(path)}", disabled=index == 0):
            def _move_up(tree: dict[str, Any]) -> None:
                parent, idx = _get_parent_and_index(tree, path)
                parent["children"][idx - 1], parent["children"][idx] = parent["children"][idx], parent["children"][idx - 1]
            _update_tree(_move_up)
    with cols[1]:
        st.markdown('<div class="qb-btn-move"></div>', unsafe_allow_html=True)
        if st.button("˅", key=f"query_builder_down_{_path_key(path)}", disabled=index >= child_count - 1):
            def _move_down(tree: dict[str, Any]) -> None:
                parent, idx = _get_parent_and_index(tree, path)
                parent["children"][idx + 1], parent["children"][idx] = parent["children"][idx], parent["children"][idx + 1]
            _update_tree(_move_down)
    with cols[2]:
        st.markdown('<div class="qb-btn-delete"></div>', unsafe_allow_html=True)
        if st.button("✕", key=f"query_builder_delete_{_path_key(path)}"):
            def _delete(tree: dict[str, Any]) -> None:
                parent, idx = _get_parent_and_index(tree, path)
                parent["children"].pop(idx)
            _update_tree(_delete)


def _node_path_label(path: list[int]) -> str:
    return "root" if not path else ".".join(str(part + 1) for part in path)


def _rule_summary(field_name: str, operator: str) -> str:
    label = FIELD_SPEC_BY_NAME[field_name].label
    return f"{label} {operator}"


def _render_rule_node(node: dict[str, Any], path: list[int], child_count: int, index: int) -> dict[str, Any]:
    key_prefix = _path_key(path)
    with st.container(border=True):
        meta = st.columns([0.9, 1.0, 1.2, 0.48])
        meta[0].markdown('<span class="qb-badge qb-badge-rule">Rule</span>', unsafe_allow_html=True)
        meta[1].markdown(f'<span class="qb-node-path">{_node_path_label(path)}</span>', unsafe_allow_html=True)
        meta[2].markdown(
            f'<div class="qb-node-summary">{_rule_summary(str(node.get("field", "severity")), str(node.get("operator", "in")))}</div>',
            unsafe_allow_html=True,
        )
        with meta[3]:
            _render_header_actions(path, child_count, index)

        cols = st.columns([1.8, 1.0, 1.8, 0.55])
        field_name = cols[0].selectbox(
            "Field",
            options=[spec.name for spec in FIELD_SPEC_BY_NAME.values()],
            format_func=lambda name: f"{FIELD_SPEC_BY_NAME[name].label} ({name})",
            index=list(FIELD_SPEC_BY_NAME).index(node.get("field", "severity")),
            key=f"query_builder_field_{key_prefix}",
        )
        operator_options = operators_for_field(field_name)
        current_operator = node.get("operator")
        operator_index = operator_options.index(current_operator) if current_operator in operator_options else 0
        operator = cols[1].selectbox("Operator", options=operator_options, index=operator_index, key=f"query_builder_operator_{key_prefix}")
        with cols[2]:
            value, guidance = _render_value_input(node, key_prefix, field_name, operator)
        negated = cols[3].checkbox("NOT", value=bool(node.get("negated")), key=f"query_builder_negated_{key_prefix}")
        st.markdown(f'<div class="qb-muted">{guidance}</div>', unsafe_allow_html=True)
    return {"type": "rule", "field": field_name, "operator": operator, "value": value, "negated": negated}


def _render_group_node(node: dict[str, Any], path: list[int], child_count: int, index: int) -> dict[str, Any]:
    key_prefix = _path_key(path)
    with st.container(border=True):
        top = st.columns([0.72, 1.0, 1.35, 0.55, 0.7, 0.7, 0.48])
        top[0].markdown('<span class="qb-badge qb-badge-group">Group</span>', unsafe_allow_html=True)
        top[1].markdown(f'<span class="qb-node-path">{_node_path_label(path)}</span>', unsafe_allow_html=True)
        top[2].markdown('<div class="qb-node-title">Nested expression</div>', unsafe_allow_html=True)
        connector = top[3].selectbox(
            "Connector",
            options=["AND", "OR"],
            index=0 if str(node.get("connector") or "AND").upper() == "AND" else 1,
            key=f"query_builder_connector_{key_prefix}",
        )
        negated = top[4].checkbox("NOT", value=bool(node.get("negated")), key=f"query_builder_group_negated_{key_prefix}")
        with top[5]:
            st.markdown('<div class="qb-btn-add"></div>', unsafe_allow_html=True)
            if st.button("+ Rule", key=f"query_builder_add_rule_{key_prefix}", width="stretch"):
                def _add_rule(tree: dict[str, Any]) -> None:
                    _get_node(tree, path)["children"].append(default_rule_node())
                _update_tree(_add_rule)
        with top[6]:
            _render_header_actions(path, child_count, index)

        action_row = st.columns([0.62, 0.38])
        action_row[0].markdown(
            f'<div class="qb-node-summary">Children in this group are joined with '
            f'<span class="qb-connector-pill">{connector}</span>.</div>',
            unsafe_allow_html=True,
        )
        with action_row[1]:
            st.markdown('<div class="qb-btn-add"></div>', unsafe_allow_html=True)
            if st.button("+ Group", key=f"query_builder_add_group_{key_prefix}", width="stretch"):
                def _add_group(tree: dict[str, Any]) -> None:
                    _get_node(tree, path)["children"].append(default_group_node(connector))
                _update_tree(_add_group)

        children = node.get("children") or []
        st.markdown('<div class="qb-branch">', unsafe_allow_html=True)
        updated_children = [_render_child_node(child, [*path, idx], len(children), idx) for idx, child in enumerate(children)]
        if not children:
            st.markdown('<div class="qb-empty">This group is empty. Add a rule or another group.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    return {"type": "group", "connector": connector, "negated": negated, "children": updated_children}


def _render_child_node(child: dict[str, Any], path: list[int], child_count: int, index: int) -> dict[str, Any]:
    rail_col, content_col = st.columns([0.08, 0.92], vertical_alignment="top")
    line_class = "qb-branch-line qb-branch-line-last" if index == child_count - 1 else "qb-branch-line"
    with rail_col:
        st.markdown(f'<div class="qb-branch-rail"><div class="{line_class}"></div></div>', unsafe_allow_html=True)
    with content_col:
        if child.get("type") == "group":
            return _render_group_node(child, path, child_count, index)
        return _render_rule_node(child, path, child_count, index)


def _render_builder() -> str:
    if "query_builder_tree" not in st.session_state:
        st.session_state["query_builder_tree"] = default_group_node("AND")

    _builder_styles()
    st.markdown("**Expression Builder**")
    st.caption("Arrange conditions as an expression tree. Use groups when you need explicit precedence or nested logic.")

    tree = st.session_state["query_builder_tree"]
    with st.container(border=True):
        st.markdown('<div class="qb-root-title">Root Expression</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="qb-root-subtitle">All top-level conditions are joined by the connector below. '
            'Nested groups make precedence and branching easier to read.</div>',
            unsafe_allow_html=True,
        )
        top = st.columns([1.5, 0.75, 0.75])
        connector = top[0].selectbox(
            "Top-level connector",
            options=["AND", "OR"],
            index=0 if str(tree.get("connector") or "AND").upper() == "AND" else 1,
            key="query_builder_root_connector",
        )
        with top[1]:
            st.markdown('<div class="qb-btn-add"></div>', unsafe_allow_html=True)
            if st.button("+ Rule", key="query_builder_root_add_rule", width="stretch"):
                _update_tree(lambda draft: draft["children"].append(default_rule_node()))
        with top[2]:
            st.markdown('<div class="qb-btn-add"></div>', unsafe_allow_html=True)
            if st.button("+ Group", key="query_builder_root_add_group", width="stretch"):
                _update_tree(lambda draft: draft["children"].append(default_group_node(connector)))

        st.markdown(
            f'<div class="qb-node-summary">Root currently joins all direct children with '
            f'<span class="qb-connector-pill">{connector}</span>.</div>',
            unsafe_allow_html=True,
        )

        updated_children: list[dict[str, Any]] = []
        children = tree.get("children") or []
        for idx, child in enumerate(children):
            updated_children.append(_render_child_node(child, [idx], len(children), idx))
        if not children:
            st.markdown('<div class="qb-empty">No rules yet. Add a rule or create a group first.</div>', unsafe_allow_html=True)

    updated_tree = {"type": "group", "connector": connector, "negated": False, "children": updated_children}
    st.session_state["query_builder_tree"] = updated_tree

    validation_error = validate_expression_tree(updated_tree, is_root=True)
    generated_query = build_query_from_tree(updated_tree, is_root=True)
    if validation_error:
        st.error(validation_error)
    elif generated_query:
        try:
            parse_query(generated_query)
        except QuerySyntaxError as exc:
            st.error(f"Builder generated invalid query: {exc}")

    st.markdown("**Generated Query**")
    st.code(generated_query or "-- query is empty --", language="text")
    return generated_query


def render_query_workbench_tab(projects: list[str]) -> None:
    st.markdown('<div class="gh-section-heading">Query Workbench</div>', unsafe_allow_html=True)
    st.caption("Search the full vulnerability dataset with a compact, type-aware query syntax.")

    if not projects:
        st.info("No repositories are available yet. Use Upload Repository to ingest one first.")
        return

    mode = st.radio("Query Input Mode", options=["Builder", "Text"], index=0, horizontal=True, key="query_workbench_mode")
    if mode == "Builder":
        query_text = _render_builder() or st.session_state.get("query_workbench_text", DEFAULT_QUERY)
        st.session_state["query_workbench_text"] = query_text
    else:
        query_text = st.text_area(
            "Query",
            value=st.session_state.get("query_workbench_text", DEFAULT_QUERY),
            height=140,
            help="Use quoted strings for text values. Dates should use ISO format like YYYY-MM-DD.",
            key="query_workbench_text",
        )

    action_col, hint_col = st.columns([1, 3])
    with action_col:
        run_query = st.button("Run Query", type="primary", width="stretch")
    with hint_col:
        if mode == "Builder":
            st.caption("You can clear the builder completely, but an empty query cannot be executed.")
        else:
            st.caption("Use `AND`, `OR`, `NOT`, quoted strings for text, and ISO dates like `2024-01-01`.")

    if mode == "Text":
        with st.expander("Syntax Reference", expanded=False):
            _reference_block()

    if run_query:
        if not query_text or not query_text.strip():
            st.error("Query is empty. Add at least one rule or enter a text query before running.")
            return
        try:
            expression = parse_query(query_text.strip())
        except QuerySyntaxError as exc:
            st.error(f"Query syntax error: {exc}")
            return

        with st.spinner("Scanning portfolio data..."):
            fingerprint = db.fetch_data_fingerprint()
            rows = query_db.fetch_query_workbench_rows(tuple(projects), fingerprint)
            matches = [row for row in rows if evaluate_expression(expression, row)]

        st.session_state["query_workbench_last_query"] = query_text.strip()
        st.session_state["query_workbench_last_matches"] = matches
        st.session_state["query_workbench_total_rows"] = len(rows)

    matches = st.session_state.get("query_workbench_last_matches")
    total_rows = st.session_state.get("query_workbench_total_rows")
    if matches is None or total_rows is None:
        return

    st.markdown('<div class="gh-section-heading">Results</div>', unsafe_allow_html=True)
    st.caption(f"Matched {len(matches)} of {total_rows} vulnerability records across {len(projects)} repositories.")
    if not matches:
        st.info("No records matched the current query.")
        return

    sort_key = st.selectbox("Sort results by", options=["risk_score", "published", "cvss", "project", "severity", "closest_depth"], index=0)
    sort_desc = st.toggle("Descending", value=True)

    def _sort_value(row: dict[str, Any]) -> Any:
        value = row.get(sort_key)
        if sort_key in {"published", "project"}:
            return value or ""
        if sort_key == "severity":
            return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(value).lower(), 0)
        return value if value is not None else -1

    matches = sorted(matches, key=_sort_value, reverse=sort_desc)
    st.dataframe(_display_rows(matches), width="stretch", hide_index=True)

    with st.expander("Raw matched records", expanded=False):
        st.json(matches[:50])
