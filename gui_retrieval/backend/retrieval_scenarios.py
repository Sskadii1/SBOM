"""
backend/retrieval_scenarios.py - Scenario to Cypher query mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import backend.config as config


@dataclass
class QueryDef:
    label: str
    cypher: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    name: str
    description: str
    queries: list[QueryDef]


_Q1_TOP_RISKY = QueryDef(
    label="Top risky projects",
    cypher="""
MATCH (p:Project)
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH p,
     count(DISTINCT c) AS vulnerable_components,
     count(DISTINCT v) AS vulnerabilities,
     sum(coalesce(v.cvss_score, 0.0)) AS cvss_sum,
     sum(CASE WHEN coalesce(v.kev, false) THEN 1 ELSE 0 END) AS kev_hits,
     avg(coalesce(v.epss, 0.0)) AS avg_epss
WITH p,
     vulnerable_components,
     vulnerabilities,
     cvss_sum,
     kev_hits,
     avg_epss,
     (cvss_sum + kev_hits * 10 + avg_epss * 100) AS risk_score
RETURN p.name AS project,
       p.full_name AS full_name,
       vulnerable_components,
       vulnerabilities,
       round(cvss_sum, 2) AS cvss_sum,
       kev_hits,
       round(avg_epss, 4) AS avg_epss,
       round(risk_score, 2) AS risk_score
ORDER BY risk_score DESC
LIMIT 20
""",
)


def _q2_impact(project_name: str, vuln_id: str) -> QueryDef:
    return QueryDef(
        label="Project-specific vulnerability impact",
        cypher="""
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
RETURN p,
       c,
       v,
       l,
       c.name AS component,
       c.version AS version,
       coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ) AS vulnerability,
       v.cvss_score AS cvss,
       v.kev AS kev,
       v.epss AS epss,
       v.fix_versions AS fix_versions,
       v.detail_summary AS detail_summary,
       v.aliases AS aliases,
       v.cwe AS cwe,
       l.path AS location_path,
       l.line AS location_line,
       hc.dependency_depth AS depth,
       hc.is_root AS is_root,
       hc.is_direct_dependency AS is_direct_dependency
""",
        params={"project_name": project_name, "vuln_id": vuln_id},
    )


_Q3_QUICK_WINS = QueryDef(
    label="Actionable quick wins (patch available, high severity)",
    cypher="""
MATCH (p:Project)
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE coalesce(v.cvss_score, 0.0) >= 7.0
  AND size(coalesce(v.fix_versions, [])) > 0
RETURN p.full_name AS project,
       c.name AS component,
       c.version AS current_version,
       coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ) AS vulnerability,
       v.cvss_score AS cvss,
       v.kev AS kev,
       v.fix_versions AS suggested_fix_versions
ORDER BY kev DESC, cvss DESC
LIMIT 50
""",
)


_Q4_NO_FIX = QueryDef(
    label="No-fix critical risks",
    cypher="""
MATCH (p:Project)
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE coalesce(v.cvss_score, 0.0) >= 7.0
  AND size(coalesce(v.fix_versions, [])) = 0
RETURN p.full_name AS project,
       c.name AS component,
       c.version AS component_version,
       coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ) AS vulnerability,
       v.cvss_score AS cvss,
       v.kev AS kev,
       coalesce(v.cwe, []) AS cwe
ORDER BY kev DESC, cvss DESC
LIMIT 50
""",
)


def _q6_dep_chain(project_name: str, component_id: str) -> QueryDef:
    return QueryDef(
        label="Dependency chain to vulnerable component",
        cypher="""
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (p)-[:USES_DIRECT]->(root:Component)
WHERE (s)-[:HAS_COMPONENT]->(root)
MATCH (s)-[target_rel:HAS_COMPONENT]->(target:Component {component_id: $component_id})
MATCH path = shortestPath((root)-[:DEPENDS_ON*0..12]->(target))
WHERE all(rel IN relationships(path) WHERE rel.scan_id = s.scan_id)
MATCH (target)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN p,
       target AS c,
       v,
       [n IN nodes(path) | coalesce(n.component_id, n.name)] AS chain,
       target_rel.dependency_depth AS target_depth,
       length(path) AS depth
ORDER BY target_rel.dependency_depth ASC, depth ASC
LIMIT 5
""",
        params={"project_name": project_name, "component_id": component_id},
    )


_Q7_KEV_QUEUE = QueryDef(
    label="CISA KEV urgent queue",
    cypher="""
MATCH (p:Project)
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE coalesce(v.kev, false) = true
RETURN p.full_name AS project,
       c.name AS component,
       c.version AS version,
       coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ) AS vulnerability,
       v.cvss_score AS cvss,
       v.epss AS epss,
       v.fix_versions AS fix_versions
ORDER BY coalesce(v.cvss_score, 0.0) DESC, coalesce(v.epss, 0.0) DESC
LIMIT 100
""",
)


def _q8_recent(from_iso: str) -> QueryDef:
    return QueryDef(
        label="Recently modified vulnerabilities",
        cypher="""
MATCH (p:Project)
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE v.modified IS NOT NULL AND v.modified >= $from_iso
RETURN p.full_name AS project,
       c.name AS component,
       c.version AS version,
       coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ) AS vulnerability,
       v.modified AS modified,
       v.cvss_score AS cvss,
       v.kev AS kev
ORDER BY v.modified DESC
LIMIT 100
""",
        params={"from_iso": from_iso},
    )


def _q9_project_summary(project_name: str) -> QueryDef:
    return QueryDef(
        label="Project security overview",
        cypher="""
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WITH p, v, c
ORDER BY coalesce(v.kev, false) DESC, coalesce(v.cvss_score, 0.0) DESC
WITH p,
     collect({
       vulnerability: coalesce(
         head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
         v.id,
         head(coalesce(v.aliases, []))
       ),
       component: c.name,
       cvss: v.cvss_score,
       kev: v.kev
     })[..10] AS top_risks,
     count(DISTINCT v) AS total_vulns,
     count(DISTINCT c) AS total_components,
     sum(CASE WHEN coalesce(v.cvss_score, 0.0) >= 7.0 THEN 1 ELSE 0 END) AS critical_high_count
RETURN p.full_name AS project,
       total_vulns,
       total_components,
       critical_high_count,
       top_risks
""",
        params={"project_name": project_name},
    )


def _q10_project_alert_inventory(project_name: str) -> QueryDef:
    return QueryDef(
        label="Project alert inventory",
        cypher="""
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[hc:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN
  p.full_name AS project,
  coalesce(
    head([alias IN coalesce(v.aliases, []) WHERE alias STARTS WITH 'CVE-']),
    v.id,
    head(coalesce(v.aliases, []))
  ) AS vulnerability,
  v.id AS internal_id,
  c.name AS component,
  c.version AS version,
  c.component_id AS component_id,
  c.scope AS scope,
  hc.dependency_depth AS dependency_depth,
  v.cvss_score AS cvss,
  v.epss AS epss,
  v.kev AS kev,
  v.fix_versions AS fix_versions,
  v.detail_summary AS detail_summary,
  v.aliases AS aliases,
  v.cwe AS cwe,
  v.modified AS modified
ORDER BY coalesce(v.kev, false) DESC, coalesce(v.cvss_score, 0.0) DESC, c.name ASC
""",
        params={"project_name": project_name},
    )


def _q11_top_affected_components(project_name: str) -> QueryDef:
    return QueryDef(
        label="Top affected components",
        cypher="""
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN
  p.full_name AS project,
  c.name AS component,
  count(DISTINCT v) AS vulnerability_count,
  max(coalesce(v.cvss_score, 0.0)) AS max_cvss,
  sum(CASE WHEN coalesce(v.kev, false) THEN 1 ELSE 0 END) AS kev_hits
ORDER BY vulnerability_count DESC, max_cvss DESC, kev_hits DESC
LIMIT 20
""",
        params={"project_name": project_name},
    )


def _q12_latest_scan_metadata(project_name: str) -> QueryDef:
    return QueryDef(
        label="Latest scan metadata",
        cypher="""
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
""",
        params={"project_name": project_name},
    )


def _q13_vuln_dep_chains(project_name: str, vuln_id: str) -> QueryDef:
    return QueryDef(
        label="Dependency chains for vulnerability",
        cypher="""
MATCH (p:Project {full_name: $project_name})
CALL (p) {
  MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
  RETURN s
  ORDER BY s.generated_at DESC
  LIMIT 1
}
MATCH (s)-[target_rel:HAS_COMPONENT]->(target:Component)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE $vuln_id = v.id OR $vuln_id IN coalesce(v.aliases, [])
WITH p, s, target, target_rel
ORDER BY target_rel.dependency_depth ASC
WITH p, s, collect(target)[0..5] AS closest_targets
UNWIND closest_targets AS target
MATCH (p)-[:USES_DIRECT]->(root:Component)
WHERE (s)-[:HAS_COMPONENT]->(root)
MATCH path = shortestPath((root)-[:DEPENDS_ON*0..12]->(target))
WHERE all(rel IN relationships(path) WHERE rel.scan_id = s.scan_id)
RETURN
  p.full_name AS project,
  target.name AS component,
  target.version AS version,
  target.component_id AS component_id,
  [n IN nodes(path) | coalesce(n.component_id, n.name)] AS chain,
  length(path) AS depth
ORDER BY depth ASC, size(chain) ASC
LIMIT 15
""",
        params={"project_name": project_name, "vuln_id": vuln_id},
    )


def _q14_components_for_vuln(project_name: str, vuln_id: str) -> QueryDef:
    return QueryDef(
        label="Affected components for vulnerability",
        cypher="""
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
  p.full_name AS project,
  c.name AS component,
  c.version AS version,
  c.component_id AS component_id,
  hc.dependency_depth AS dependency_depth,
  hc.is_root AS is_root,
  hc.is_direct_dependency AS is_direct_dependency
ORDER BY dependency_depth ASC, component ASC
""",
        params={"project_name": project_name, "vuln_id": vuln_id},
    )


def stakeholder_report_queries(project_name: str) -> list[QueryDef]:
    """
    Report-driven query bundle for the Stakeholder Security Posture Report.
    """
    return [
        _q9_project_summary(project_name),
        _q10_project_alert_inventory(project_name),
        _q11_top_affected_components(project_name),
        _q12_latest_scan_metadata(project_name),
    ]


def developer_report_queries(
    project_name: str,
    vuln_id: str | None = None,
    component_id: str | None = None,
) -> list[QueryDef]:
    """
    Report-driven query bundle for the Developer Vulnerability Remediation Report.

    By default this returns full-project alert inventory. If ``vuln_id`` or
    ``component_id`` is provided, the bundle includes drill-down evidence.
    """
    queries: list[QueryDef] = [_q10_project_alert_inventory(project_name)]

    if vuln_id:
        queries.extend(
            [
                _q2_impact(project_name, vuln_id),
                _q14_components_for_vuln(project_name, vuln_id),
                _q13_vuln_dep_chains(project_name, vuln_id),
            ]
        )
    if component_id:
        queries.append(_q6_dep_chain(project_name, component_id))

    return queries


def get_scenario(name: str, overrides: dict[str, Any] | None = None) -> Scenario:
    ov = overrides or {}
    project_name = ov.get("project_name", config.DEMO_PROJECT_NAME)
    vuln_id = ov.get("vuln_id", config.DEMO_VULN_ID)
    component_id = ov.get("component_id", config.DEMO_COMPONENT_ID)
    from_iso = ov.get("from_iso", config.DEMO_FROM_ISO)

    scenarios: dict[str, Scenario] = {
        "dev_explain": Scenario(
            name="dev_explain",
            description=config.SCENARIOS["dev_explain"],
            queries=[_q2_impact(project_name, vuln_id), _q6_dep_chain(project_name, component_id)],
        ),
        "manager_brief": Scenario(
            name="manager_brief",
            description=config.SCENARIOS["manager_brief"],
            queries=[_Q1_TOP_RISKY, _Q7_KEV_QUEUE, _q8_recent(from_iso)],
        ),
        "triage_queue": Scenario(
            name="triage_queue",
            description=config.SCENARIOS["triage_queue"],
            queries=[_Q3_QUICK_WINS, _Q4_NO_FIX],
        ),
        "explainability_mode": Scenario(
            name="explainability_mode",
            description=config.SCENARIOS["explainability_mode"],
            queries=[_q2_impact(project_name, vuln_id), _q6_dep_chain(project_name, component_id)],
        ),
        "multi_audience": Scenario(
            name="multi_audience",
            description=config.SCENARIOS["multi_audience"],
            queries=[
                _q9_project_summary(str(project_name)),
                _q2_impact(project_name, vuln_id),
                _q6_dep_chain(project_name, component_id),
            ],
        ),
        "project_overview": Scenario(
            name="project_overview",
            description="Automated project-wide health summary.",
            queries=[_q9_project_summary(str(project_name))],
        ),
        "arch_impact": Scenario(
            name="arch_impact",
            description=config.SCENARIOS.get("arch_impact", "Blast Radius Analysis"),
            queries=[_q2_impact(project_name, vuln_id), _q6_dep_chain(project_name, component_id)],
        ),
    }

    if name not in scenarios:
        valid = ", ".join(scenarios.keys())
        raise ValueError(f"Unknown scenario '{name}'. Valid choices: {valid}")

    return scenarios[name]
