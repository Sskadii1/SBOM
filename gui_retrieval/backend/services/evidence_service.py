"""
backend/services/evidence_service.py — Converts raw Neo4j row dicts into the
strict evidence JSON schema required by the LLM explanation engine.
"""

from __future__ import annotations
from typing import Any
import re


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
