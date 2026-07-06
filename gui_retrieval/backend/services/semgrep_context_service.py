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

_METADATA_FILES = [
    config._ROOT / "knowledge_graph" / "data" / "metadata" / "vulnerable_repos_metadata.json",
    config._ROOT / "knowledge_graph" / "data" / "metadata" / "repos_metadata.json",
]


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


def _load_repo_path_index() -> dict[str, Path]:
    index: dict[str, Path] = {}
    for metadata_file in _METADATA_FILES:
        if not metadata_file.exists():
            continue
        try:
            payload = json.loads(metadata_file.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            project = item.get("full_name")
            local_path = item.get("local_path")
            if not project or not local_path or project in index:
                continue
            abs_path = config._ROOT / str(local_path)
            index[str(project)] = abs_path
    return index


_REPO_PATH_INDEX = _load_repo_path_index()


def _resolve_repo_path(project_name: str) -> Path | None:
    canonical = _canonical_project_name(project_name)
    path = _REPO_PATH_INDEX.get(canonical)
    if path and path.exists():
        return path
    return None


def _extract_code_snippet(repo_path: Path | None, rel_path: str | None, line_number: int | None, radius: int = 2) -> dict[str, Any] | None:
    if not repo_path or not rel_path:
        return None
    try:
        candidate = (repo_path / rel_path).resolve()
        candidate.relative_to(repo_path.resolve())
    except Exception:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    try:
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    if not lines:
        return None
    if line_number is None or line_number <= 0:
        start = 0
        end = min(len(lines), 6)
        focus = None
    else:
        focus = min(line_number, len(lines))
        start = max(0, focus - radius - 1)
        end = min(len(lines), focus + radius)
    snippet_lines: list[str] = []
    for idx in range(start, end):
        prefix = ">>" if focus is not None and idx + 1 == focus else "  "
        snippet_lines.append(f"{prefix} {idx + 1}: {lines[idx]}")
    return {
        "path": rel_path.replace("\\", "/"),
        "line": focus,
        "snippet": "\n".join(snippet_lines),
    }


def _parse_location_ref(value: str) -> tuple[str | None, int | None]:
    text = (value or "").strip().replace("\\", "/")
    if not text:
        return None, None
    if ":" not in text:
        return text, None
    path, maybe_line = text.rsplit(":", 1)
    try:
        return path, int(maybe_line)
    except ValueError:
        return text, None


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
        sink_query = f"""
            SELECT vuln_id, package_name, function_name, sink_type, call_pattern, confidence
            FROM cve_sinks
            WHERE vuln_id IN ({placeholders})
            """  # nosec B608
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
        sink_rows = con.execute(sink_query, vuln_params).fetchall()
        for row in sink_rows:
            item = dict(row)
            sinks_by_vuln.setdefault(item["vuln_id"], []).append(item)

        reach_query = f"""
            SELECT project_name, vuln_id, package_name, sink_function, verdict,
                   reach_score, call_locations, semgrep_rule_id, scanned_at
            FROM reachability_results
            WHERE project_name = ? AND vuln_id IN ({placeholders})
            """  # nosec B608
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
        reach_rows = con.execute(reach_query, [canonical_project] + vuln_params).fetchall()
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
    project_snippets: list[dict[str, Any]] = []
    repo_path = _resolve_repo_path(str(rec.get("project") or ""))

    for row in filtered_reach:
        for loc in row.get("call_locations") or []:
            if loc and loc not in call_locations:
                call_locations.append(loc)
        rid = row.get("semgrep_rule_id")
        if rid and rid not in rule_ids:
            rule_ids.append(rid)

    raw_refs: list[tuple[str | None, int | None]] = []
    for loc in call_locations[:3]:
        raw_refs.append(_parse_location_ref(loc))
    if rec.get("location_path"):
        raw_refs.append((str(rec.get("location_path")), rec.get("location_line")))

    seen_refs: set[tuple[str | None, int | None]] = set()
    for rel_path, line_number in raw_refs:
        key = (rel_path, line_number)
        if key in seen_refs:
            continue
        seen_refs.add(key)
        snippet = _extract_code_snippet(repo_path, rel_path, line_number)
        if snippet:
            project_snippets.append(snippet)

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
    if project_snippets:
        evidence_lines.append(f"project_snippets={len(project_snippets)}")

    return {
        "reachability_verdict": best_verdict,
        "semgrep_sink_count": len(filtered_sinks),
        "semgrep_sink_functions": sink_functions,
        "semgrep_call_locations": call_locations,
        "project_code_snippets": project_snippets,
        "project_exposure_summary": (
            f"Found {len(project_snippets)} project code snippet(s) relevant to this vulnerability."
            if project_snippets
            else "No direct project code snippet was resolved from Semgrep or dependency evidence."
        ),
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
