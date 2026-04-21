"""
backend/repositories/graph_repository.py - Pure-Python Neo4j data fetcher.

No Streamlit imports here. Caching is handled at the frontend layer.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import backend.config as config
from backend.graph_service import GraphService


_CYPHER_PROJECT_LIST = """
MATCH (p:Project)
RETURN p.full_name AS full_name, p.name AS name
ORDER BY p.full_name
"""

_CYPHER_DATA_FINGERPRINT = """
MATCH (p:Project)
OPTIONAL MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
OPTIONAL MATCH (s)-[:HAS_COMPONENT]->(:Component)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN
  count(DISTINCT p) AS project_count,
  count(DISTINCT s) AS sbom_count,
  count(DISTINCT v) AS vulnerability_count,
  max(s.generated_at) AS latest_sbom_generated_at,
  max(v.modified) AS latest_vulnerability_modified
"""

_CYPHER_PROJECT_CATALOG = """
MATCH (p:Project)
RETURN
  p.full_name AS full_name,
  p.name AS name,
  p.language AS language,
  p.package_manager AS package_manager
ORDER BY p.full_name
"""

_CYPHER_ALL_ALERTS = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH p, hc, c, v,
     coalesce(
       head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
       v.id,
       head(coalesce(v.aliases, []))
     ) AS vuln_id
RETURN
  p.full_name AS project,
  collect(DISTINCT c.name) AS all_components,
  collect(DISTINCT c.version) AS all_versions,
  collect(DISTINCT c.component_id) AS all_component_ids,
  count(DISTINCT c) AS component_count,
  vuln_id AS vuln_id,
  min(v.id) AS internal_id,
  max(v.cvss_score) AS cvss,
  max(v.epss) AS epss,
  max(v.kev) AS kev,
  min(v.cwe) AS cwe,
  min(v.severity_vectors) AS severity_vectors,
  min(v.published) AS published,
  max(v.modified) AS modified,
  reduce(acc = [], fv IN collect(DISTINCT v.fix_versions) | acc + coalesce(fv, [])) AS fix_versions,
  min(hc.dependency_depth) AS closest_depth,
  collect(DISTINCT c.scope) AS all_scopes,
  round(
    100.0 * (
      0.25 * coalesce(max(v.cvss_score), 0) / 10.0
      + 0.25 * CASE
                 WHEN max(v.kev) = true THEN 1.0
                 ELSE coalesce(max(v.epss), 0)
               END
      + 0.15 * CASE
                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['required', 'runtime']) THEN 1
                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['optional', 'dev', 'test']) THEN 0.3
                 ELSE 0.6
               END
      + 0.35 * 0.5
    ),
    2
  ) AS risk_score
ORDER BY risk_score DESC, closest_depth ASC, published DESC
"""

_CYPHER_ENTERPRISE_OVERVIEW_ALERTS = """
UNWIND $project_names AS project_name
MATCH (p:Project {full_name: project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
OPTIONAL MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH p, hc, c, v,
     CASE
       WHEN v IS NULL THEN NULL
       ELSE coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       )
     END AS vuln_id
RETURN
  p.full_name AS project,
  collect(DISTINCT c.name) AS all_components,
  collect(DISTINCT c.version) AS all_versions,
  collect(DISTINCT c.component_id) AS all_component_ids,
  count(DISTINCT c) AS component_count,
  vuln_id AS vuln_id,
  min(v.id) AS internal_id,
  max(v.cvss_score) AS cvss,
  max(v.epss) AS epss,
  max(v.kev) AS kev,
  min(v.cwe) AS cwe,
  min(v.severity_vectors) AS severity_vectors,
  min(v.published) AS published,
  max(v.modified) AS modified,
  reduce(acc = [], fv IN collect(DISTINCT v.fix_versions) | acc + coalesce(fv, [])) AS fix_versions,
  min(hc.dependency_depth) AS closest_depth,
  collect(DISTINCT c.scope) AS all_scopes,
  round(
    100.0 * (
      0.25 * coalesce(max(v.cvss_score), 0) / 10.0
      + 0.25 * CASE
                 WHEN max(v.kev) = true THEN 1.0
                 ELSE coalesce(max(v.epss), 0)
               END
      + 0.15 * CASE
                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['required', 'runtime']) THEN 1
                 WHEN any(sc IN collect(DISTINCT c.scope) WHERE sc IN ['optional', 'dev', 'test']) THEN 0.3
                 ELSE 0.6
               END
      + 0.35 * 0.5
    ),
    2
  ) AS risk_score
ORDER BY project, risk_score DESC, closest_depth ASC, published DESC
"""

_CYPHER_QUERY_WORKBENCH_ROWS = """
UNWIND $project_names AS project_name
MATCH (p:Project {full_name: project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
OPTIONAL MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH p, hc, c, v,
     CASE
       WHEN v IS NULL THEN NULL
       ELSE coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       )
     END AS vuln_id
RETURN
  p.full_name AS project,
  p.name AS project_name,
  p.language AS language,
  p.package_manager AS package_manager,
  collect(DISTINCT c.name) AS all_components,
  collect(DISTINCT c.version) AS all_versions,
  collect(DISTINCT c.component_id) AS all_component_ids,
  count(DISTINCT c) AS component_count,
  vuln_id AS vuln_id,
  min(v.id) AS internal_id,
  max(v.cvss_score) AS cvss,
  max(v.epss) AS epss,
  max(v.kev) AS kev,
  min(v.cwe) AS cwe,
  min(v.severity_vectors) AS severity_vectors,
  min(v.published) AS published,
  max(v.modified) AS modified,
  reduce(acc = [], fv IN collect(DISTINCT v.fix_versions) | acc + coalesce(fv, [])) AS fix_versions,
  min(hc.dependency_depth) AS closest_depth,
  collect(DISTINCT c.scope) AS all_scopes
ORDER BY project, published DESC, vuln_id
"""

_CYPHER_PROJECT_STATS = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH coalesce(
       head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
       v.id,
       head(coalesce(v.aliases, []))
     ) AS vuln_id,
     v
WITH vuln_id, max(v.cvss_score) AS max_cvss, max(v.kev) AS kev
RETURN
  count(DISTINCT vuln_id) AS total_count,
  sum(CASE WHEN kev = true THEN 1 ELSE 0 END) AS kev_count,
  sum(CASE WHEN coalesce(max_cvss, 0) >= 9.0 THEN 1 ELSE 0 END) AS critical_count,
  sum(CASE WHEN coalesce(max_cvss, 0) >= 7.0 AND coalesce(max_cvss, 0) < 9.0 THEN 1 ELSE 0 END) AS high_count,
  sum(CASE WHEN coalesce(max_cvss, 0) >= 4.0 AND coalesce(max_cvss, 0) < 7.0 THEN 1 ELSE 0 END) AS medium_count,
  sum(CASE WHEN coalesce(max_cvss, 0) < 4.0 OR max_cvss IS NULL THEN 1 ELSE 0 END) AS low_count
"""

_CYPHER_LATEST_SCAN_METADATA = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
OPTIONAL MATCH (s)-[:HAS_COMPONENT]->(:Component)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN
  p.full_name AS project,
  s.scan_id AS scan_id,
  s.generated_at AS generated_at,
  count(DISTINCT v) AS vulnerability_count,
  max(v.modified) AS latest_vulnerability_modified
"""

_CYPHER_LIST_COMPONENTS_FOR_CVE = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE $vuln_id = v.id OR $vuln_id IN coalesce(v.aliases, [])
RETURN DISTINCT
  c.component_id AS component_id,
  c.name AS name,
  c.version AS version,
  hc.dependency_depth AS dependency_depth,
  hc.is_root AS is_root,
  hc.is_direct_dependency AS is_direct_dependency
ORDER BY dependency_depth ASC, c.name
"""

_CYPHER_VULN_DETAIL = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE $vuln_id = v.id OR $vuln_id IN coalesce(v.aliases, [])
OPTIONAL MATCH (c)-[:DECLARED_IN]->(l:Location)
WHERE l.scan_id = s.scan_id
WITH p, s, hc, c, v,
     coalesce(
       head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
       v.id,
       head(coalesce(v.aliases, []))
     ) AS final_vuln_id,
     collect(DISTINCT l.path) AS location_paths,
     collect(DISTINCT l.line) AS location_lines
RETURN
  p.full_name AS project,
  s.scan_id AS scan_id,
  c.name AS component,
  c.version AS version,
  c.component_id AS component_id,
  min(v.id) AS internal_id,
  final_vuln_id AS vuln_id,
  max(v.cvss_score) AS cvss,
  max(v.epss) AS epss,
  max(v.kev) AS kev,
  v.cwe AS cwe,
  v.severity_vectors AS severity_vectors,
  min(v.published) AS published,
  max(v.modified) AS modified,
  v.fix_versions AS fix_versions,
  v.detail_summary AS detail_summary,
  v.aliases AS aliases,
  location_paths,
  location_lines,
  hc.dependency_depth AS dependency_depth,
  hc.dependency_depth AS depth,
  hc.is_root AS is_root,
  hc.is_direct_dependency AS is_direct_dependency,
  c.scope AS scope,
  round(
    100.0 * (
      0.25 * coalesce(max(v.cvss_score), 0) / 10.0
      + 0.25 * CASE
                 WHEN max(v.kev) = true THEN 1.0
                 ELSE coalesce(max(v.epss), 0)
               END
      + 0.15 * CASE
                 WHEN c.scope IN ['required', 'runtime'] THEN 1
                 WHEN c.scope IN ['optional', 'dev', 'test'] THEN 0.3
                 ELSE 0.6
               END
      + 0.35 * 0.5
    ),
    2
  ) AS risk_score
"""

_CYPHER_DEP_CHAIN = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[target_rel:HAS_COMPONENT]->(target:Component {component_id: $component_id})
CALL (p, s, target, target_rel) {
  // Case 1: target is a direct dependency — show as single-node chain
  With p, s, target, target_rel
  WHERE (p)-[:USES_DIRECT]->(target)
  RETURN
    target.name AS component,
    target.component_id AS component_id,
    target.version AS version,
    coalesce(target_rel.dependency_depth, 1) AS target_depth,
    [coalesce(target.name, target.component_id)] AS chain,
    0 AS hops
  UNION
  // Case 2: reachable from a direct dependency via DEPENDS_ON
  WITH p, s, target, target_rel
  MATCH (p)-[:USES_DIRECT]->(root:Component)
  WHERE (s)-[:HAS_COMPONENT]->(root) AND root <> target
  MATCH (s)-[root_rel:HAS_COMPONENT]->(root)
  MATCH path = shortestPath((root)-[:DEPENDS_ON*1..12]->(target))
  WHERE all(rel IN relationships(path) WHERE rel.scan_id = s.scan_id)
  RETURN
    target.name AS component,
    target.component_id AS component_id,
    target.version AS version,
    coalesce(root_rel.dependency_depth, 0) + length(path) AS target_depth,
    [n IN nodes(path) | coalesce(n.name, n.component_id)] AS chain,
    length(path) AS hops
}
RETURN DISTINCT component, component_id, version, target_depth, chain, hops
ORDER BY target_depth ASC, hops ASC, size(chain) ASC
LIMIT 5
"""

_CYPHER_VULN_DEP_CHAINS = """
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[target_rel:HAS_COMPONENT]->(target:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE $vuln_id = v.id OR $vuln_id IN coalesce(v.aliases, [])
WITH p, s, v, target, target_rel
ORDER BY target_rel.dependency_depth ASC
WITH p, s, v, collect(target)[0..3] AS closest_targets, collect(target_rel)[0..3] AS closest_rels
UNWIND range(0, size(closest_targets) - 1) AS idx
WITH p, s, v, closest_targets[idx] AS target, closest_rels[idx] AS target_rel
CALL (p, s, v, target, target_rel) {
  // Case 1: target is a direct dependency
  WITH p, s, v, target, target_rel
  WHERE (p)-[:USES_DIRECT]->(target)
  RETURN
    coalesce(
      head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
      v.id, head(coalesce(v.aliases, []))
    ) AS vuln_id,
    target.name AS component,
    target.component_id AS component_id,
    target.version AS version,
    coalesce(target_rel.dependency_depth, 1) AS target_depth,
    [coalesce(target.name, target.component_id)] AS chain,
    0 AS hops
  UNION
  // Case 2: reachable via DEPENDS_ON from a direct dependency
  WITH p, s, v, target, target_rel
  MATCH (p)-[:USES_DIRECT]->(root:Component)
  WHERE (s)-[:HAS_COMPONENT]->(root) AND root <> target
  MATCH (s)-[root_rel:HAS_COMPONENT]->(root)
  MATCH path = shortestPath((root)-[:DEPENDS_ON*1..12]->(target))
  WHERE all(rel IN relationships(path) WHERE rel.scan_id = s.scan_id)
  RETURN
    coalesce(
      head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
      v.id, head(coalesce(v.aliases, []))
    ) AS vuln_id,
    target.name AS component,
    target.component_id AS component_id,
    target.version AS version,
    coalesce(root_rel.dependency_depth, 0) + length(path) AS target_depth,
    [n IN nodes(path) | coalesce(n.name, n.component_id)] AS chain,
    length(path) AS hops
}
RETURN DISTINCT vuln_id, component, component_id, version, target_depth, chain, hops
ORDER BY target_depth ASC, hops ASC, component ASC
LIMIT 8
"""

_VERDICT_ORDER = {
    "confirmed_reachable": 4,
    "likely_reachable": 3,
    "uncertain": 2,
    "likely_unreachable": 1,
    "no_sink_data": 0,
}


def get_projects() -> list[str]:
    with GraphService() as gs:
        res = gs.run_query(_CYPHER_PROJECT_LIST)
        return [row["full_name"] for row in res]


def get_data_fingerprint() -> str:
    """
    Return a lightweight version token that changes when Neo4j or local
    reachability artifacts change. Intended for cache invalidation only.
    """
    neo4j_part = "neo4j:unavailable"
    try:
        with GraphService() as gs:
            rows = gs.run_query(_CYPHER_DATA_FINGERPRINT)
        row = rows[0] if rows else {}
        neo4j_part = "|".join(
            [
                "neo4j",
                str(row.get("project_count", 0)),
                str(row.get("sbom_count", 0)),
                str(row.get("vulnerability_count", 0)),
                str(row.get("latest_sbom_generated_at") or ""),
                str(row.get("latest_vulnerability_modified") or ""),
            ]
        )
    except Exception:
        pass

    sqlite_part = "sqlite:missing"
    db_path = Path(config.CVE_SINKS_DB)
    if db_path.exists():
        stat = db_path.stat()
        sqlite_part = f"sqlite|{int(stat.st_mtime_ns)}|{stat.st_size}"

    reachability_part = "reachability:missing"
    if config.REACHABILITY_DIR.exists():
        json_files = sorted(config.REACHABILITY_DIR.glob("*.json"))
        latest_mtime_ns = max((path.stat().st_mtime_ns for path in json_files), default=0)
        total_size = sum(path.stat().st_size for path in json_files)
        reachability_part = f"reachability|{len(json_files)}|{latest_mtime_ns}|{total_size}"

    return "||".join([neo4j_part, sqlite_part, reachability_part])


def get_project_catalog() -> list[dict[str, Any]]:
    with GraphService() as gs:
        return gs.run_query(_CYPHER_PROJECT_CATALOG)


def _canonical_project_name(project_name: str) -> str:
    """
    Normalize project names from graph metadata.
    Example: "owner/repo@<commit_sha>" -> "owner/repo".
    """
    name = (project_name or "").strip()
    if "@" in name:
        name = name.split("@", 1)[0].strip()
    return name


def _load_reachability(project_name: str) -> dict[str, dict]:
    """
    Load reachability scan results for a project from SQLite first, then JSON fallback.
    Returns {vuln_id: {"verdict": str, "call_locations": list[str]}}.
    Returns empty dict if no scan has been run for this project.
    """
    canonical = _canonical_project_name(project_name)
    index: dict[str, dict] = {}

    def _parse_call_locations(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(v) for v in value if v]
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return [str(v) for v in parsed if v]
            except Exception:
                return []
        return []

    def _merge_row(vuln_id: str, verdict: str, call_locations: list[str]) -> None:
        existing = index.get(vuln_id)
        if not existing:
            index[vuln_id] = {
                "verdict": verdict or "no_sink_data",
                "call_locations": call_locations or [],
            }
            return
        current_verdict = existing.get("verdict", "no_sink_data")
        next_verdict = verdict or "no_sink_data"
        if _VERDICT_ORDER.get(next_verdict, -1) > _VERDICT_ORDER.get(current_verdict, -1):
            existing["verdict"] = next_verdict
        if call_locations:
            merged_calls = list(dict.fromkeys((existing.get("call_locations") or []) + call_locations))
            existing["call_locations"] = merged_calls

    db_path = Path(config.CVE_SINKS_DB)
    if db_path.exists():
        try:
            con = sqlite3.connect(str(db_path))
            con.row_factory = sqlite3.Row
            try:
                rows = con.execute(
                    """
                    SELECT vuln_id, verdict, call_locations
                    FROM reachability_results
                    WHERE project_name = ?
                    """,
                    (canonical,),
                ).fetchall()
                for row in rows:
                    vid = row["vuln_id"]
                    if vid:
                        _merge_row(
                            str(vid),
                            str(row["verdict"] or "no_sink_data"),
                            _parse_call_locations(row["call_locations"]),
                        )
            finally:
                con.close()
        except Exception:
            pass

    safe = canonical.replace("/", "_").replace("\\", "_")
    path = config.REACHABILITY_DIR / f"{safe}_reachability.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for result in data.get("results", []):
                vid = result.get("vuln_id")
                if vid:
                    _merge_row(
                        str(vid),
                        str(result.get("verdict", "no_sink_data")),
                        _parse_call_locations(result.get("call_locations", [])),
                    )
        except Exception:
            pass

    return index


def _reachability_factor(verdict: str) -> float:
    """Map reachability verdict to a 0-1 score used in risk formula."""
    mapping = {
        "confirmed_reachable": 1,
        "likely_reachable": 0.7,
        "likely_unreachable": 0.3,
        "no_sink_data": 0.5,
    }
    return mapping.get(verdict, 0.5)


def _resolve_reachability(
    reach_index: dict[str, dict],
    *candidate_ids: Any,
) -> tuple[dict[str, Any], str, float]:
    """Find reachability data by trying canonical vuln ids before falling back."""
    for candidate in candidate_ids:
        if candidate:
            reach = reach_index.get(str(candidate), {})
            if reach:
                verdict = reach.get("verdict", "no_sink_data")
                return reach, verdict, _reachability_factor(verdict)
    return {}, "no_sink_data", 0.5


def _recompute_risk(row: dict[str, Any], reach_factor: float) -> float:
    """Recompute risk_score using Risk_enh formula from a-2.pdf."""
    cvss = row.get("cvss") or 0
    epss = row.get("epss") or 0
    kev = bool(row.get("kev"))
    scopes = row.get("all_scopes") or []

    s_sev = cvss / 10.0
    s_exp = 1.0 if kev else epss

    if any(s in ("required", "runtime") for s in scopes):
        s_scope = 1.0
    elif any(s in ("optional", "dev", "test") for s in scopes):
        s_scope = 0.3
    else:
        s_scope = 0.6

    return round(100.0 * (
        0.25 * s_sev +
        0.25 * s_exp +
        0.15 * s_scope +
        0.35 * reach_factor
    ), 2)


def _severity_from_row(row: dict[str, Any]) -> str:
    cvss = float(row.get("cvss") or 0)
    if bool(row.get("kev")) or cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _days_ago(value: Any) -> int | None:
    if not value:
        return None
    raw = str(value)
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = datetime.fromisoformat(raw[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _apply_reachability_to_alert_rows(project_name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge reachability and re-sort rows to match the legacy alert output."""
    reach_index = _load_reachability(project_name)
    for row in rows:
        vid = row.get("vuln_id") or ""
        internal_id = row.get("internal_id")
        reach, verdict, factor = _resolve_reachability(reach_index, vid, internal_id)
        row["reachability_verdict"] = verdict
        row["call_locations"] = reach.get("call_locations", [])
        row["reachability_factor"] = factor
        row["risk_score"] = _recompute_risk(row, factor)

    rows.sort(key=lambda row: row.get("published") or "", reverse=True)
    rows.sort(
        key=lambda row: row.get("closest_depth")
        if row.get("closest_depth") is not None
        else float("inf")
    )
    rows.sort(key=lambda row: row.get("risk_score") or 0, reverse=True)
    return rows


def get_alerts(project_name: str) -> list[dict[str, Any]]:
    with GraphService() as gs:
        rows = gs.run_query(_CYPHER_ALL_ALERTS, {"project_name": project_name})
    return _apply_reachability_to_alert_rows(project_name, rows)


def get_enterprise_overview_inputs(project_names: list[str]) -> dict[str, Any]:
    """
    Fetch enterprise overview inputs in bulk to avoid one Neo4j alerts query
    per project while preserving the legacy return shape.
    """
    if not project_names:
        return {"catalog": {}, "project_alerts": {}}

    with GraphService() as gs:
        catalog_rows = gs.run_query(_CYPHER_PROJECT_CATALOG)
        alert_rows = gs.run_query(
            _CYPHER_ENTERPRISE_OVERVIEW_ALERTS,
            {"project_names": project_names},
        )

    catalog = {row["full_name"]: row for row in catalog_rows}
    project_alerts = {project: [] for project in project_names}
    grouped_rows: dict[str, list[dict[str, Any]]] = {project: [] for project in project_names}

    for row in alert_rows:
        project = str(row.get("project") or "")
        if project not in grouped_rows:
            grouped_rows[project] = []

        # Projects without vulnerabilities still produce one null-ish row from
        # the OPTIONAL MATCH. Keep the empty project bucket but drop the row.
        if not row.get("vuln_id") and not row.get("internal_id") and not row.get("component_count"):
            continue
        grouped_rows[project].append(row)

    for project in project_names:
        project_alerts[project] = _apply_reachability_to_alert_rows(
            project,
            grouped_rows.get(project, []),
        )

    return {
        "catalog": catalog,
        "project_alerts": project_alerts,
    }


def get_query_workbench_rows(project_names: list[str]) -> list[dict[str, Any]]:
    """Fetch normalized query-workbench rows without reusing enterprise overview data."""
    if not project_names:
        return []

    with GraphService() as gs:
        rows = gs.run_query(
            _CYPHER_QUERY_WORKBENCH_ROWS,
            {"project_names": project_names},
        )

    grouped_rows: dict[str, list[dict[str, Any]]] = {project: [] for project in project_names}
    for row in rows:
        project = str(row.get("project") or "")
        if project not in grouped_rows:
            grouped_rows[project] = []

        if not row.get("vuln_id") and not row.get("internal_id") and not row.get("component_count"):
            continue
        grouped_rows[project].append(row)

    normalized_rows: list[dict[str, Any]] = []
    for project in project_names:
        project_rows = _apply_reachability_to_alert_rows(project, grouped_rows.get(project, []))
        for row in project_rows:
            scopes = [str(scope) for scope in (row.get("all_scopes") or []) if scope]
            fix_versions = [str(version) for version in (row.get("fix_versions") or []) if version]
            call_locations = [str(loc) for loc in (row.get("call_locations") or []) if loc]
            cwe = [str(item) for item in (row.get("cwe") or []) if item]
            components = [str(item) for item in (row.get("all_components") or []) if item]
            component_ids = [str(item) for item in (row.get("all_component_ids") or []) if item]

            normalized_rows.append(
                {
                    "project": project,
                    "project_name": row.get("project_name") or project.split("/", 1)[-1],
                    "language": row.get("language") or "Unknown",
                    "package_manager": row.get("package_manager") or "Unknown",
                    "vuln_id": row.get("vuln_id"),
                    "internal_id": row.get("internal_id"),
                    "severity": _severity_from_row(row),
                    "cvss": row.get("cvss"),
                    "epss": row.get("epss"),
                    "kev": bool(row.get("kev")),
                    "risk_score": row.get("risk_score"),
                    "reachability_verdict": row.get("reachability_verdict") or "no_sink_data",
                    "is_reachable": (row.get("reachability_verdict") or "") in {"confirmed_reachable", "likely_reachable"},
                    "fix_available": bool(fix_versions),
                    "fix_versions_count": len(fix_versions),
                    "fix_versions": fix_versions,
                    "closest_depth": row.get("closest_depth"),
                    "component_count": row.get("component_count"),
                    "all_components": components,
                    "all_component_ids": component_ids,
                    "all_scopes": scopes,
                    "is_runtime": any(scope in {"required", "runtime"} for scope in scopes),
                    "published": row.get("published"),
                    "modified": row.get("modified"),
                    "published_days_ago": _days_ago(row.get("published")),
                    "modified_days_ago": _days_ago(row.get("modified")),
                    "cwe": cwe,
                    "call_locations": call_locations,
                    "call_locations_count": len(call_locations),
                }
            )
    return normalized_rows


def get_project_stats(project_name: str) -> dict[str, int]:
    with GraphService() as gs:
        res = gs.run_query(_CYPHER_PROJECT_STATS, {"project_name": project_name})
        if not res:
            return {"total_count": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "kev_count": 0}
        return res[0]


def get_vuln_detail(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    with GraphService() as gs:
        rows = gs.run_query(_CYPHER_VULN_DETAIL, {"project_name": project_name, "vuln_id": vuln_id})

    reach_index = _load_reachability(project_name)

    for row in rows:
        canonical_vuln_id = row.get("vuln_id")
        internal_id = row.get("internal_id")
        reach, verdict, factor = _resolve_reachability(
            reach_index,
            canonical_vuln_id,
            vuln_id,
            internal_id,
        )
        row["reachability_verdict"] = verdict
        row["call_locations"] = reach.get("call_locations", [])
        row["reachability_factor"] = factor

        # Prepare params to match what _recompute_risk expects:
        row["all_scopes"] = [row.get("scope")] if row.get("scope") else []
        row["closest_depth"] = row.get("depth")

        row["risk_score"] = _recompute_risk(row, factor)

    return rows


def get_dep_chain(project_name: str, component_id: str) -> list[dict[str, Any]]:
    with GraphService() as gs:
        return gs.run_query(_CYPHER_DEP_CHAIN, {"project_name": project_name, "component_id": component_id})


def get_vuln_dep_chains(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    with GraphService() as gs:
        return gs.run_query(_CYPHER_VULN_DEP_CHAINS, {"project_name": project_name, "vuln_id": vuln_id})


def get_components_for_cve(project_name: str, vuln_id: str) -> list[dict[str, Any]]:
    with GraphService() as gs:
        return gs.run_query(_CYPHER_LIST_COMPONENTS_FOR_CVE, {"project_name": project_name, "vuln_id": vuln_id})


def get_stakeholder_report_inputs(project_name: str) -> dict[str, Any]:
    """
    Build a report-driven data bundle for stakeholder-level reporting.
    """
    alerts = get_alerts(project_name)

    critical_high_count = 0
    kev_count = 0
    reachability_distribution: dict[str, int] = {}
    fix_available_count = 0
    component_counter: dict[str, int] = {}

    for row in alerts:
        sev = _severity_from_row(row)
        if sev in {"critical", "high"}:
            critical_high_count += 1
        if bool(row.get("kev")):
            kev_count += 1

        verdict = str(row.get("reachability_verdict") or "no_sink_data")
        reachability_distribution[verdict] = reachability_distribution.get(verdict, 0) + 1

        if row.get("fix_versions"):
            fix_available_count += 1

        for component in row.get("all_components") or []:
            comp = str(component).strip()
            if comp:
                component_counter[comp] = component_counter.get(comp, 0) + 1

    top_risky_cves = alerts[:10]
    top_affected_components = [
        {"component": name, "alert_count": count}
        for name, count in sorted(
            component_counter.items(),
            key=lambda item: (-item[1], item[0]),
        )[:20]
    ]

    latest_scan: dict[str, Any] = {}
    with GraphService() as gs:
        rows = gs.run_query(_CYPHER_LATEST_SCAN_METADATA, {"project_name": project_name})
        if rows:
            latest_scan = rows[0]

    return {
        "project": project_name,
        "total_alerts": len(alerts),
        "critical_high_count": critical_high_count,
        "kev_count": kev_count,
        "reachability_distribution": reachability_distribution,
        "fix_availability_summary": {
            "fix_available": fix_available_count,
            "no_fix_available": len(alerts) - fix_available_count,
        },
        "top_risky_cves": top_risky_cves,
        "top_affected_components": top_affected_components,
        "latest_scan_metadata": latest_scan,
        "alerts": alerts,
    }


def get_developer_report_inputs(
    project_name: str,
    vuln_id: str | None = None,
    component_id: str | None = None,
) -> dict[str, Any]:
    """
    Build a report-driven data bundle for developer remediation reporting.
    """
    alerts = get_alerts(project_name)
    reachability_index = _load_reachability(project_name)

    detail_rows: list[dict[str, Any]] = []
    affected_components: list[dict[str, Any]] = []
    dependency_chains: list[dict[str, Any]] = []
    component_dep_chain: list[dict[str, Any]] = []

    if vuln_id:
        detail_rows = get_vuln_detail(project_name, vuln_id)
        affected_components = get_components_for_cve(project_name, vuln_id)
        dependency_chains = get_vuln_dep_chains(project_name, vuln_id)

    if component_id:
        component_dep_chain = get_dep_chain(project_name, component_id)

    advisory_detail_summary = ""
    for row in detail_rows:
        text = str(row.get("detail_summary") or "").strip()
        if text:
            advisory_detail_summary = text
            break

    return {
        "project": project_name,
        "vuln_id": vuln_id,
        "component_id": component_id,
        "alerts": alerts,
        "vulnerability_detail": detail_rows,
        "affected_components": affected_components,
        "dependency_chains": dependency_chains,
        "component_dependency_chain": component_dep_chain,
        "reachability_index": reachability_index,
        "advisory_detail_summary": advisory_detail_summary,
    }


def load_reachability(project_name: str) -> dict[str, dict]:
    """Public wrapper — returns reachability index for a project."""
    return _load_reachability(project_name)


def get_cves(project_name: str) -> list[str]:
    alerts = get_alerts(project_name)
    cves = sorted(list(set(a.get("vuln_id") or a.get("internal_id") for a in alerts)))
    return [c for c in cves if c]
