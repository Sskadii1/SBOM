"""
frontend/query_builder.py - Query builder metadata and query string generation.
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


def build_query_from_rules(rules: list[dict[str, Any]], conjunction: str = "AND") -> str:
    built = [build_rule_query(rule) for rule in rules if build_rule_query(rule)]
    if not built:
        return ""
    glue = f" {conjunction.strip().upper()} "
    return glue.join(built)


def _format_scalar(kind: str, value: Any) -> str:
    if kind == "boolean":
        return "true" if bool(value) else "false"
    if kind == "number":
        return str(value).strip()
    escaped = str(value).replace('"', '\\"').strip()
    return f'"{escaped}"'
