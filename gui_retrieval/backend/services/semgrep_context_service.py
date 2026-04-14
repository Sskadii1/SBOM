"""
backend/services/semgrep_context_service.py - Semgrep/Sink context enrichment.

Adds CVE sink and reachability evidence from:
  1) knowledge_graph/data/cve_sinks.db
  2) knowledge_graph/data/reachability/{project}_reachability.json
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import backend.config as config

_VERDICT_ORDER = {
    "confirmed_reachable": 4,
    "likely_reachable": 3,
    "no_sink_data": 2,
    "likely_unreachable": 1
}


def _canonical_project_name(project_name: str) -> str:
    """
    Normalize project names from graph metadata.
    Example: "owner/repo@<commit_sha>" -> "owner/repo".
    """
    name = (project_name or "").strip()
    if "@" in name:
        name = name.split("@", 1)[0].strip()
    return name


def _safe_project_name(project_name: str) -> str:
    canonical = _canonical_project_name(project_name)
    return canonical.replace("/", "_").replace("\\", "_")


def _pick_best_verdict(verdicts: list[str]) -> str:
    if not verdicts:
        return "no_sink_data"
    return max(verdicts, key=lambda v: _VERDICT_ORDER.get(v, -1))


def _parse_json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def _load_reachability_json(project_name: str) -> list[dict[str, Any]]:
    safe = _safe_project_name(project_name)
    path = config.REACHABILITY_DIR / f"{safe}_reachability.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        results = payload.get("results", [])
        return results if isinstance(results, list) else []
    except Exception:
        return []


def _load_sqlite_context(
    project_name: str,
    vuln_ids: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    sinks_by_vuln: dict[str, list[dict[str, Any]]] = {}
    reach_by_vuln: dict[str, list[dict[str, Any]]] = {}
    if not vuln_ids:
        return sinks_by_vuln, reach_by_vuln

    db_path = config.CVE_SINKS_DB
    if not Path(db_path).exists():
        return sinks_by_vuln, reach_by_vuln

    placeholders = ",".join("?" * len(vuln_ids))
    vuln_params = sorted(vuln_ids)

    canonical_project = _canonical_project_name(project_name)

    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        sink_rows = con.execute(
            f"""
            SELECT vuln_id, package_name, function_name, sink_type, call_pattern, confidence
            FROM cve_sinks
            WHERE vuln_id IN ({placeholders})
            """,
            vuln_params,
        ).fetchall()
        for row in sink_rows:
            item = dict(row)
            sinks_by_vuln.setdefault(item["vuln_id"], []).append(item)

        reach_rows = con.execute(
            f"""
            SELECT project_name, vuln_id, package_name, sink_function, verdict,
                   reach_score, call_locations, semgrep_rule_id, scanned_at
            FROM reachability_results
            WHERE project_name = ? AND vuln_id IN ({placeholders})
            """,
            [canonical_project] + vuln_params,
        ).fetchall()
        for row in reach_rows:
            item = dict(row)
            item["call_locations"] = _parse_json_list(item.get("call_locations"))
            reach_by_vuln.setdefault(item["vuln_id"], []).append(item)
    finally:
        con.close()

    return sinks_by_vuln, reach_by_vuln


def _merge_json_reachability(
    reach_by_vuln: dict[str, list[dict[str, Any]]],
    project_name: str,
    vuln_ids: set[str],
) -> dict[str, list[dict[str, Any]]]:
    canonical_project = _canonical_project_name(project_name)
    out = dict(reach_by_vuln)
    for item in _load_reachability_json(canonical_project):
        vuln_id = item.get("vuln_id")
        if not vuln_id or vuln_id not in vuln_ids:
            continue
        out.setdefault(vuln_id, []).append(
            {
                "project_name": canonical_project,
                "vuln_id": vuln_id,
                "package_name": item.get("package_name"),
                "sink_function": item.get("sink_function"),
                "verdict": item.get("verdict", "no_sink_data"),
                "reach_score": item.get("reach_score"),
                "call_locations": item.get("call_locations") or [],
                "semgrep_rule_id": item.get("semgrep_rule_id"),
                "scanned_at": item.get("scanned_at"),
            }
        )
    return out


def _summarize_semgrep(
    rec: dict[str, Any],
    sinks: list[dict[str, Any]],
    reach_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    component = (rec.get("component") or "").lower().strip()
    filtered_sinks = sinks
    if component:
        matched = [s for s in sinks if (s.get("package_name") or "").lower() == component]
        if matched:
            filtered_sinks = matched

    filtered_reach = reach_rows
    if component:
        matched = [r for r in reach_rows if (r.get("package_name") or "").lower() == component]
        if matched:
            filtered_reach = matched

    sink_functions = sorted(
        {
            s.get("function_name")
            for s in filtered_sinks
            if s.get("function_name")
        }
    )

    verdicts = [r.get("verdict", "no_sink_data") for r in filtered_reach]
    call_locations: list[str] = []
    rule_ids: list[str] = []
    evidence_lines: list[str] = []

    for row in filtered_reach:
        for loc in row.get("call_locations") or []:
            if loc and loc not in call_locations:
                call_locations.append(loc)
        rid = row.get("semgrep_rule_id")
        if rid and rid not in rule_ids:
            rule_ids.append(rid)

    best_verdict = _pick_best_verdict(verdicts)
    if not filtered_sinks:
        best_verdict = "no_sink_data"
    elif not filtered_reach:
        best_verdict = "no_sink_data"

    if sink_functions:
        evidence_lines.append(f"sink_functions={', '.join(sink_functions[:5])}")
    if call_locations:
        evidence_lines.append(f"call_locations={len(call_locations)}")
    if rule_ids:
        evidence_lines.append(f"semgrep_rules={len(rule_ids)}")

    return {
        "reachability_verdict": best_verdict,
        "semgrep_sink_count": len(filtered_sinks),
        "semgrep_sink_functions": sink_functions,
        "semgrep_call_locations": call_locations,
        "semgrep_rule_ids": rule_ids,
        "semgrep_evidence_summary": "; ".join(evidence_lines) if evidence_lines else "No Semgrep evidence provided.",
    }


def enrich_evidence_with_semgrep(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich evidence records with Semgrep context from sink DB and reachability data.
    """
    if not evidence:
        return evidence

    projects = {str(e.get("project")) for e in evidence if e.get("project")}
    vuln_ids = {str(e.get("vulnerability")) for e in evidence if e.get("vulnerability")}
    if not projects or not vuln_ids:
        return evidence

    # Build per-project context cache once.
    project_ctx: dict[str, tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]] = {}
    for project in projects:
        sinks_by_vuln, reach_by_vuln = _load_sqlite_context(project, vuln_ids)
        reach_by_vuln = _merge_json_reachability(reach_by_vuln, project, vuln_ids)
        project_ctx[project] = (sinks_by_vuln, reach_by_vuln)

    enriched: list[dict[str, Any]] = []
    for rec in evidence:
        project = rec.get("project")
        vuln_id = rec.get("vulnerability")
        if not project or not vuln_id or project not in project_ctx:
            enriched.append(rec)
            continue

        sinks_by_vuln, reach_by_vuln = project_ctx[project]
        sinks = sinks_by_vuln.get(str(vuln_id), [])
        reach_rows = reach_by_vuln.get(str(vuln_id), [])
        semgrep_ctx = _summarize_semgrep(rec, sinks, reach_rows)

        merged = dict(rec)
        merged.update(semgrep_ctx)
        enriched.append(merged)

    return enriched
