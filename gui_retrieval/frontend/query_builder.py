"""
frontend/query_builder.py - Query builder metadata and expression-tree generation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    kind: str
    group: str


FIELD_SPECS: list[FieldSpec] = [
    FieldSpec("project", "Project", "string", "Identity"),
    FieldSpec("project_name", "Project Name", "string", "Identity"),
    FieldSpec("language", "Language", "string", "Identity"),
    FieldSpec("package_manager", "Package Manager", "string", "Identity"),
    FieldSpec("vuln_id", "Vulnerability ID", "string", "Identity"),
    FieldSpec("internal_id", "Internal ID", "string", "Identity"),
    FieldSpec("severity", "Severity", "enum", "Risk"),
    FieldSpec("cvss", "CVSS", "number", "Risk"),
    FieldSpec("epss", "EPSS", "number", "Risk"),
    FieldSpec("kev", "KEV", "boolean", "Risk"),
    FieldSpec("risk_score", "Risk Score", "number", "Risk"),
    FieldSpec("reachability_verdict", "Reachability Verdict", "enum", "Risk"),
    FieldSpec("is_reachable", "Reachable", "boolean", "Risk"),
    FieldSpec("fix_available", "Fix Available", "boolean", "Risk"),
    FieldSpec("fix_versions_count", "Fix Versions Count", "number", "Risk"),
    FieldSpec("closest_depth", "Closest Depth", "number", "Dependency"),
    FieldSpec("component_count", "Component Count", "number", "Dependency"),
    FieldSpec("all_components", "Components", "array_string", "Dependency"),
    FieldSpec("all_component_ids", "Component IDs", "array_string", "Dependency"),
    FieldSpec("all_scopes", "Scopes", "array_string", "Dependency"),
    FieldSpec("is_runtime", "Runtime Scope", "boolean", "Dependency"),
    FieldSpec("published", "Published", "date", "Dates"),
    FieldSpec("modified", "Modified", "date", "Dates"),
    FieldSpec("published_days_ago", "Published Days Ago", "number", "Dates"),
    FieldSpec("modified_days_ago", "Modified Days Ago", "number", "Dates"),
    FieldSpec("cwe", "CWE", "array_string", "Evidence"),
    FieldSpec("call_locations", "Call Locations", "array_string", "Evidence"),
    FieldSpec("call_locations_count", "Call Locations Count", "number", "Evidence"),
]


FIELD_SPEC_BY_NAME = {spec.name: spec for spec in FIELD_SPECS}

FIELD_GROUPS: dict[str, list[str]] = {}
for spec in FIELD_SPECS:
    FIELD_GROUPS.setdefault(spec.group, []).append(spec.name)


OPERATORS_BY_KIND = {
    "string": ["=", "!=", "contains", "starts_with", "ends_with", "in", "exists"],
    "enum": ["=", "!=", "in", "exists"],
    "number": ["=", "!=", ">", ">=", "<", "<=", "in", "exists"],
    "boolean": ["=", "!=", "exists"],
    "date": ["=", "!=", ">", ">=", "<", "<=", "exists"],
    "array_string": ["contains", "contains_any", "contains_all", "exists"],
}


ENUM_OPTIONS = {
    "severity": ["critical", "high", "medium", "low"],
    "reachability_verdict": [
        "confirmed_reachable",
        "likely_reachable",
        "uncertain",
        "likely_unreachable",
        "no_sink_data",
    ],
}


def operators_for_field(field_name: str) -> list[str]:
    spec = FIELD_SPEC_BY_NAME[field_name]
    return OPERATORS_BY_KIND[spec.kind]


def default_rule_node() -> dict[str, Any]:
    return {
        "type": "rule",
        "field": "severity",
        "operator": "in",
        "value": ["critical", "high"],
        "negated": False,
    }


def default_group_node(connector: str = "AND") -> dict[str, Any]:
    return {
        "type": "group",
        "connector": connector,
        "negated": False,
        "children": [default_rule_node()],
    }


def format_query_value(field_name: str, operator: str, raw_value: Any) -> str:
    spec = FIELD_SPEC_BY_NAME[field_name]
    if operator == "exists":
        return ""

    if operator in {"in", "contains_any", "contains_all"}:
        if isinstance(raw_value, str):
            items = [item.strip() for item in raw_value.split(",") if item.strip()]
        else:
            items = [str(item).strip() for item in (raw_value or []) if str(item).strip()]
        formatted = ", ".join(_format_scalar(spec.kind, item) for item in items)
        return f"({formatted})"

    return _format_scalar(spec.kind, raw_value)


def build_rule_query(rule: dict[str, Any]) -> str:
    field_name = str(rule.get("field") or "").strip()
    operator = str(rule.get("operator") or "").strip()
    if not field_name or not operator:
        return ""
    value_part = format_query_value(field_name, operator, rule.get("value"))
    base = f"{field_name} {operator}"
    if value_part:
        base += f" {value_part}"
    if rule.get("negated"):
        return f"NOT ({base})"
    return base


def build_query_from_tree(node: dict[str, Any], *, is_root: bool = False) -> str:
    node_type = str(node.get("type") or "")
    if node_type == "rule":
        return build_rule_query(node)

    if node_type != "group":
        return ""

    connector = str(node.get("connector") or "AND").strip().upper()
    if connector not in {"AND", "OR"}:
        connector = "AND"

    child_parts = [
        build_query_from_tree(child)
        for child in (node.get("children") or [])
    ]
    child_parts = [part for part in child_parts if part]
    if not child_parts:
        return ""

    joined = f" {connector} ".join(child_parts)
    if not is_root:
        joined = f"({joined})"
    if node.get("negated"):
        joined = f"NOT {joined}"
    return joined


def build_query_from_rules(
    rules: list[dict[str, Any]],
    *,
    conjunction: str = "AND",
) -> str:
    """
    Backward-compatible adapter for legacy tests/callers.

    The newer builder uses an expression tree; this helper maps a flat rule list
    into one root group and returns the same query syntax as before.
    """
    connector = (conjunction or "AND").strip().upper()
    if connector not in {"AND", "OR"}:
        connector = "AND"
    normalized_children: list[dict[str, Any]] = []
    for rule in list(rules or []):
        child = dict(rule)
        child.setdefault("type", "rule")
        normalized_children.append(child)

    tree = {
        "type": "group",
        "connector": connector,
        "negated": False,
        "children": normalized_children,
    }
    return build_query_from_tree(tree, is_root=True)


def validate_expression_tree(node: dict[str, Any], *, is_root: bool = False) -> str | None:
    node_type = str(node.get("type") or "")
    if node_type == "rule":
        field_name = str(node.get("field") or "").strip()
        operator = str(node.get("operator") or "").strip()
        if not field_name or field_name not in FIELD_SPEC_BY_NAME:
            return "A rule is missing a valid field."
        if not operator or operator not in operators_for_field(field_name):
            return f"Rule for `{field_name}` is missing a valid operator."
        return None

    if node_type != "group":
        return "Builder contains an unsupported node."

    children = node.get("children") or []
    if not is_root and not children:
        return "A group cannot be empty."
    for child in children:
        error = validate_expression_tree(child)
        if error:
            return error
    return None


def _format_scalar(kind: str, value: Any) -> str:
    if kind == "boolean":
        return "true" if bool(value) else "false"
    if kind == "number":
        return str(value).strip()
    escaped = str(value).replace('"', '\\"').strip()
    return f'"{escaped}"'
