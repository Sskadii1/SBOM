"""
backend/services/evidence_service.py — Converts raw Neo4j row dicts into the
strict evidence JSON schema required by the LLM explanation engine.
"""

from __future__ import annotations
from typing import Any
import re

from backend.models import (
    DEFAULT_CASE_STATUS,
    AlertCase,
    decision_tier_rationale,
    normalize_case_status,
    normalize_decision_tier,
    recommend_decision_tier,
)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

EvidenceRecord = dict[str, Any]


# ---------------------------------------------------------------------------
# Evidence schema template
# ---------------------------------------------------------------------------

def _empty_record() -> EvidenceRecord:
    return {
        "project":          None,
        "component":        None,
        "version":          None,
        "vulnerability":    None,
        "cvss":             None,
        "kev":              None,
        "epss":             None,
        "fix_versions":     [],
        "location_path":    None,
        "location_line":    None,
        "dependency_chain": [],
        "depth":            None,
        "risk_score":       None,
        "detail_summary":   None,
        "aliases":          [],
        "has_public_poc":   None,
        "impact_summary":   None,
        "poc_summary":      None,
    }


# ---------------------------------------------------------------------------
# Field extractors
# ---------------------------------------------------------------------------

def _get(row: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in row and row[k] is not None:
            return row[k]
    return None


def _float_or_none(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return round(float(v), 4)
    except (ValueError, TypeError):
        return None


def _int_or_none(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _bool_or_none(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


def _list_of_strings(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x is not None]
    return [str(v)]


def _extract_nested(obj: Any, *fields: str) -> Any:
    current = obj
    for f in fields:
        if isinstance(current, dict):
            current = current.get(f)
        else:
            return None
    return current


def _clean_text_snippet(value: Any, max_len: int = 420) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value)).strip()
    if not text:
        return None
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def _detect_public_poc(detail_summary: Any) -> bool | None:
    if detail_summary is None:
        return None
    text = str(detail_summary).lower()
    if not text.strip():
        return None
    poc_markers = (
        "proof-of-concept",
        "proof of concept",
        "poc",
        "public exploit",
        "working exploit",
    )
    return any(marker in text for marker in poc_markers)


def _extract_section_snippet(value: Any, heading: str, max_len: int = 420) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value)).strip()
    if not text:
        return None
    lowered = text.lower()
    marker = heading.lower()
    idx = lowered.find(marker)
    if idx == -1:
        return None
    snippet = text[idx:]
    if len(snippet) <= max_len:
        return snippet
    return snippet[: max_len - 3].rstrip() + "..."


def _severity_from_metrics(cvss: float | None, kev: bool | None) -> str:
    if kev:
        return "critical"
    score = cvss or 0.0
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _estimate_evidence_confidence(
    *,
    reachability_verdict: str,
    call_locations: list[str],
    dependency_chain: list[str],
    fix_versions: list[str],
) -> str:
    if reachability_verdict == "confirmed_reachable" and call_locations:
        return "high"
    if reachability_verdict in {"confirmed_reachable", "likely_reachable"}:
        return "high" if dependency_chain else "medium"
    if dependency_chain or fix_versions:
        return "medium"
    return "low"


def _first_non_empty(values: list[Any]) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _first_item(values: Any) -> Any:
    if isinstance(values, list) and values:
        return values[0]
    return None


def _resolve_case_state(
    case_states: dict[Any, Any] | None,
    project: str,
    vuln_id: str,
    component_id: str | None,
) -> dict[str, Any] | None:
    if not case_states:
        return None

    keys_to_try = [
        (project, vuln_id, component_id),
        (project, vuln_id, None),
        (vuln_id, component_id),
        vuln_id,
        f"{project}|{vuln_id}|{component_id or ''}",
        f"{project}|{vuln_id}",
    ]
    for key in keys_to_try:
        value = case_states.get(key)
        if isinstance(value, dict):
            return value
    return None


def normalize_alert_case(
    row: dict[str, Any],
    reachability_index: dict[str, dict[str, Any]] | None = None,
    case_state: dict[str, Any] | None = None,
    *,
    force_recompute_decision_tier: bool = False,
) -> AlertCase:
    """
    Canonicalize heterogeneous graph/evidence rows into a single AlertCase shape.
    """
    project = str(_first_non_empty([_get(row, "project", "full_name"), "unknown-project"]))
    vuln_id = str(
        _first_non_empty(
            [
                _get(row, "vuln_id", "vulnerability", "internal_id"),
                "unknown-vulnerability",
            ]
        )
    )
    internal_id = _get(row, "internal_id")

    component_name = _first_non_empty([_get(row, "component"), _first_item(_get(row, "all_components"))])
    component_name = str(component_name) if component_name else "unknown-component"

    component_version = _first_non_empty(
        [
            _get(row, "version", "component_version", "current_version"),
            _first_item(_get(row, "all_versions")),
        ]
    )
    if component_version is not None:
        component_version = str(component_version)

    component_id_raw = _first_non_empty([_get(row, "component_id"), _first_item(_get(row, "all_component_ids"))])
    component_id = str(component_id_raw) if component_id_raw is not None else None
    scan_id_raw = _get(row, "scan_id")
    scan_id = str(scan_id_raw) if scan_id_raw is not None else None
    source_commit_raw = _get(row, "source_commit")
    source_commit = str(source_commit_raw) if source_commit_raw is not None else None

    cvss = _float_or_none(_get(row, "cvss", "cvss_score"))
    epss = _float_or_none(_get(row, "epss"))
    kev = _bool_or_none(_get(row, "kev"))

    fix_versions = _list_of_strings(_get(row, "fix_versions", "suggested_fix_versions"))
    dependency_depth = _int_or_none(_get(row, "dependency_depth", "closest_depth", "depth", "target_depth"))
    scope_raw = _first_non_empty([_get(row, "scope"), _first_item(_get(row, "all_scopes"))])
    scope = str(scope_raw) if scope_raw is not None else None

    reachability = reachability_index or {}
    reach_entry = (
        reachability.get(vuln_id)
        or reachability.get(str(internal_id))
        or {}
    )
    reachability_verdict = str(
        _first_non_empty(
            [
                _get(row, "reachability_verdict", "semgrep_verdict"),
                reach_entry.get("verdict"),
                "no_sink_data",
            ]
        )
    )
    call_locations = _list_of_strings(
        _first_non_empty(
            [
                _get(row, "call_locations", "semgrep_call_locations"),
                reach_entry.get("call_locations"),
                [],
            ]
        )
    )
    dependency_chain = _list_of_strings(_get(row, "dependency_chain", "chain"))
    sink_functions = _list_of_strings(_get(row, "sink_functions", "semgrep_sink_functions"))

    risk_score = _float_or_none(_get(row, "risk_score"))
    severity = str(_get(row, "severity") or _severity_from_metrics(cvss, kev))
    evidence_confidence = _estimate_evidence_confidence(
        reachability_verdict=reachability_verdict,
        call_locations=call_locations,
        dependency_chain=dependency_chain,
        fix_versions=fix_versions,
    )
    default_decision_tier = recommend_decision_tier(
        kev=kev,
        risk_score=risk_score,
        reachability_verdict=reachability_verdict,
        fix_versions=fix_versions,
        scope=scope,
        dependency_depth=dependency_depth,
        evidence_confidence=evidence_confidence,
    )

    merged_state = case_state or {}
    advisory_summary = _clean_text_snippet(_get(row, "detail_summary", "advisory_summary"), max_len=420)
    impact_summary = _clean_text_snippet(
        _first_non_empty([_get(row, "impact_summary"), advisory_summary]),
        max_len=320,
    )
    summary_note = _clean_text_snippet(
        _first_non_empty([_get(row, "summary_note"), impact_summary, advisory_summary]),
        max_len=380,
    )
    verification_basis = _clean_text_snippet(
        _first_non_empty(
            [
                _get(row, "verification_basis"),
                f"Compare scan_id={scan_id or 'unknown'} against the previous snapshot after remediation.",
            ]
        ),
        max_len=220,
    )
    last_seen_scan_id_raw = _first_non_empty([merged_state.get("last_seen_scan_id"), scan_id])
    last_seen_scan_id = str(last_seen_scan_id_raw) if last_seen_scan_id_raw is not None else None

    if force_recompute_decision_tier:
        resolved_decision_tier = default_decision_tier
    else:
        resolved_decision_tier = normalize_decision_tier(
            _first_non_empty([merged_state.get("decision_tier"), row.get("decision_tier")]),
            default=default_decision_tier,
        )

    case: AlertCase = {
        "project": project,
        "scan_id": scan_id,
        "source_commit": source_commit,
        "vuln_id": vuln_id,
        "component_name": component_name,
        "component_version": component_version,
        "component_id": component_id,
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "severity": severity,
        "fix_versions": fix_versions,
        "dependency_depth": dependency_depth,
        "dependency_chain": dependency_chain,
        "scope": scope,
        "reachability_verdict": reachability_verdict,
        "call_locations": call_locations,
        "sink_functions": sink_functions,
        "risk_score": risk_score,
        "evidence_confidence": evidence_confidence,  # type: ignore[typeddict-item]
        "advisory_summary": advisory_summary,
        "impact_summary": impact_summary,
        "verification_basis": verification_basis,
        "last_seen_scan_id": last_seen_scan_id,
        "decision_tier": resolved_decision_tier,
        "status": normalize_case_status(
            _first_non_empty([merged_state.get("status"), row.get("status")]),
            default=DEFAULT_CASE_STATUS,
        ),
        "summary_note": summary_note,
    }

    return case


def build_alert_cases(
    rows: list[dict[str, Any]],
    *,
    reachability_index: dict[str, dict[str, Any]] | None = None,
    case_states: dict[Any, Any] | None = None,
) -> list[AlertCase]:
    """
    Normalize multiple rows into canonical AlertCase objects.
    """
    cases: list[AlertCase] = []
    for row in rows:
        project = str(_get(row, "project", "full_name") or "unknown-project")
        vuln_id = str(
            _first_non_empty(
                [
                    _get(row, "vuln_id", "vulnerability", "internal_id"),
                    "unknown-vulnerability",
                ]
            )
        )
        component_id_raw = _first_non_empty([_get(row, "component_id"), _first_item(_get(row, "all_component_ids"))])
        component_id = str(component_id_raw) if component_id_raw is not None else None
        state = _resolve_case_state(case_states, project, vuln_id, component_id)
        cases.append(
            normalize_alert_case(
                row,
                reachability_index=reachability_index,
                case_state=state,
            )
        )
    return cases


def build_alert_cases_for_project(
    project_name: str,
    case_states: dict[Any, Any] | None = None,
) -> list[AlertCase]:
    """
    Build canonical alert cases for an entire project.

    This is the report-driven normalization entrypoint used by upcoming
    stakeholder/developer report builders.
    """
    from backend.repositories import graph_repository as repo

    bundle = repo.get_developer_report_inputs(project_name)
    rows = bundle.get("alerts") or []
    reachability_index = bundle.get("reachability_index") or repo.load_reachability(project_name)
    resolved_case_states = case_states
    if resolved_case_states is None:
        try:
            from backend.services.case_state_service import get_case_states

            resolved_case_states = get_case_states(project_name)
        except Exception:
            resolved_case_states = {}

    cases = build_alert_cases(
        rows,
        reachability_index=reachability_index,
        case_states=resolved_case_states,
    )

    if case_states is None:
        try:
            from backend.services.case_state_service import bootstrap_default_states

            bootstrap_default_states(project_name, cases)
        except Exception:
            pass

    return cases


def recompute_and_overwrite_case_state_tiers(
    project_name: str,
    rows: list[dict[str, Any]],
    *,
    reachability_index: dict[str, dict[str, Any]] | None = None,
) -> dict[str, int]:
    """
    Recompute decision tiers from current evidence and overwrite persisted case-state tiers.

    This intentionally ignores legacy persisted tier values and enforces the latest
    recommendation policy for all known cases in the project.
    """
    if not rows:
        return {"total": 0, "changed": 0}

    from backend.services.case_state_service import get_case_states, upsert_case_state

    existing_states = get_case_states(project_name)
    normalized_cases = [
        normalize_alert_case(
            row,
            reachability_index=reachability_index,
            case_state={},
            force_recompute_decision_tier=True,
        )
        for row in rows
    ]

    changed = 0
    total = 0
    for case in normalized_cases:
        key = (project_name, case["vuln_id"], case.get("component_id"))
        previous_tier = (existing_states.get(key) or {}).get("decision_tier")
        next_tier = case["decision_tier"]
        if previous_tier != next_tier:
            changed += 1
        upsert_case_state(
            project_name,
            case["vuln_id"],
            case.get("component_id"),
            decision_tier=next_tier,
            last_seen_scan_id=case.get("scan_id"),
        )
        total += 1
    return {"total": total, "changed": changed}


# ---------------------------------------------------------------------------
# Row interpreter
# ---------------------------------------------------------------------------

def _interpret_row(row: dict[str, Any], query_label: str) -> EvidenceRecord:
    rec = _empty_record()

    p_node = _get(row, "p")
    rec["project"] = _get(row, "project", "full_name") \
                     or _extract_nested(p_node, "full_name") \
                     or _extract_nested(p_node, "name")

    c_node = _get(row, "c")
    rec["component"] = _get(row, "component") or _extract_nested(c_node, "name")
    rec["version"]   = _get(row, "current_version", "version", "component_version") \
                       or _extract_nested(c_node, "version")

    v_node = _get(row, "v")
    rec["vulnerability"] = _get(row, "vulnerability") or _extract_nested(v_node, "id")
    rec["cvss"]          = _float_or_none(
        _get(row, "cvss", "cvss_score") or _extract_nested(v_node, "cvss_score")
    )
    rec["kev"]           = _bool_or_none(
        _get(row, "kev") or _extract_nested(v_node, "kev")
    )
    rec["epss"]          = _float_or_none(
        _get(row, "epss") or _extract_nested(v_node, "epss")
    )
    rec["fix_versions"]  = _list_of_strings(
        _get(row, "suggested_fix_versions", "fix_versions")
        or _extract_nested(v_node, "fix_versions")
    )
    full_detail_summary = _get(row, "detail_summary") or _extract_nested(v_node, "detail_summary")
    rec["detail_summary"] = _clean_text_snippet(full_detail_summary, max_len=1200)
    rec["aliases"] = _list_of_strings(
        _get(row, "aliases") or _extract_nested(v_node, "aliases")
    )
    rec["has_public_poc"] = _detect_public_poc(full_detail_summary)
    rec["impact_summary"] = _clean_text_snippet(full_detail_summary, max_len=700)
    rec["poc_summary"] = (
        _extract_section_snippet(full_detail_summary, "## Proof of Concept", max_len=500)
        or _extract_section_snippet(full_detail_summary, "Proof of Concept", max_len=500)
    )

    l_node = _get(row, "l", "stop_location")
    paths  = _get(row, "touched_paths")
    lines  = _get(row, "touched_lines")

    if isinstance(paths, list) and paths:
        rec["location_path"] = paths[0]
    else:
        rec["location_path"] = _extract_nested(l_node, "path")

    if isinstance(lines, list) and lines:
        try:
            rec["location_line"] = int(lines[0])
        except (TypeError, ValueError):
            rec["location_line"] = None
    else:
        raw_line = _extract_nested(l_node, "line")
        try:
            rec["location_line"] = int(raw_line) if raw_line is not None else None
        except (TypeError, ValueError):
            rec["location_line"] = None

    chain_val = _get(row, "dependency_chain", "chain")
    if isinstance(chain_val, list):
        rec["dependency_chain"] = [str(x) for x in chain_val if x is not None]
    else:
        path_val = _get(row, "path")
        if isinstance(path_val, list):
            chain: list[str] = []
            for node in path_val:
                if isinstance(node, dict):
                    cid = node.get("component_id") or node.get("name") or str(node)
                    chain.append(cid)
            rec["dependency_chain"] = chain

    rec["depth"] = _int_or_none(_get(row, "depth", "dependency_depth", "target_depth"))
    rec["risk_score"] = _float_or_none(_get(row, "risk_score"))

    if _get(row, "is_root") is not None:
        rec["is_root"] = _bool_or_none(_get(row, "is_root"))
    if _get(row, "is_direct_dependency") is not None:
        rec["is_direct_dependency"] = _bool_or_none(_get(row, "is_direct_dependency"))

    icc = _get(row, "impacted_component_count")
    if icc is not None:
        rec["impacted_component_count"] = int(icc)

    for col in ("vulnerable_components", "vulnerabilities", "kev_hits"):
        val = _get(row, col)
        if val is not None:
            rec[col] = int(val)

    avg_epss = _get(row, "avg_epss")
    if avg_epss is not None:
        rec["avg_epss_project"] = _float_or_none(avg_epss)

    cvss_sum = _get(row, "cvss_sum")
    if cvss_sum is not None:
        rec["cvss_sum"] = _float_or_none(cvss_sum)

    cwe_val = _get(row, "cwe")
    if cwe_val:
        rec["cwe"] = _list_of_strings(cwe_val)

    for col in ("total_vulns", "total_components", "critical_high_count"):
        val = _get(row, col)
        if val is not None:
            rec[col] = int(val)

    tr = _get(row, "top_risks")
    if tr is not None:
        rec["top_risks"] = tr

    return rec



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_evidence(
    query_results: list[tuple[str, list[dict[str, Any]]]]
) -> list[EvidenceRecord]:
    """Convert multi-query results into a flat list of evidence records."""
    evidence: list[EvidenceRecord] = []
    for label, rows in query_results:
        for row in rows:
            rec = _interpret_row(row, label)
            rec["_query"] = label
            evidence.append(rec)
    return evidence


def summarise_evidence(evidence: list[EvidenceRecord]) -> dict[str, Any]:
    """Produce a compact meta-summary over the full evidence list."""
    total = len(evidence)
    has_kev = sum(1 for r in evidence if r.get("kev") is True)
    has_fix = sum(1 for r in evidence if r.get("fix_versions"))
    no_fix  = sum(1 for r in evidence if not r.get("fix_versions") and r.get("vulnerability"))
    cvss_vals = [r["cvss"] for r in evidence if r.get("cvss") is not None]
    max_cvss  = max(cvss_vals) if cvss_vals else None
    missing_location = sum(
        1 for r in evidence
        if r.get("vulnerability") and r.get("location_path") is None
    )
    return {
        "total_records":            total,
        "kev_count":                has_kev,
        "has_fix_count":            has_fix,
        "no_fix_count":             no_fix,
        "max_cvss":                 _float_or_none(max_cvss),
        "records_missing_location": missing_location,
    }


class KnowledgeRetriever:
    """
    Orchestrates retrieving Graph data for a scenario and transforming it
    into structured LLM evidence.
    """
    def build_evidence(
        self, scenario_name: str, params: dict[str, Any]
    ) -> tuple[list[EvidenceRecord], dict[str, Any], dict[str, Any]]:
        from backend.retrieval_scenarios import get_scenario
        from backend.graph_service import GraphService
        import time

        try:
            scenario = get_scenario(scenario_name)
        except Exception as e:
            raise ValueError(f"Unknown scenario: {scenario_name} - {e}")

        query_results = []
        meta = {"queries": []}

        with GraphService() as gs:
            for q in scenario.queries:
                exec_params = dict(q.params)
                exec_params.update(params)

                t0 = time.time()
                rows = gs.run_query(q.cypher, exec_params)
                t1 = time.time()

                query_results.append((q.label, rows))
                meta["queries"].append({
                    "label": q.label,
                    "rows_returned": len(rows),
                    "time_ms": round((t1 - t0) * 1000, 2),
                })

        evidence = build_evidence(query_results)
        summary = summarise_evidence(evidence)

        return evidence, summary, meta
