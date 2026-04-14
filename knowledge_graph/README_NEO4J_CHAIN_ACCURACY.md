# Neo4j Dependency Chain Accuracy (Old vs New)

This document explains the difference between the old graph model and the new graph model, and how to migrate from old Neo4j (bolt 7688) to new Neo4j (bolt 7689).

## 1) Problems in the old model

In the old model:
- `Component` is a global node shared by many projects/SBOMs.
- Depth was often taken from `Component.dependency_depth`.
- `Project-[:USES]->Component` connected too broadly to nearly all components.
- Dependency edges were not scoped per SBOM.

Impact:
- Depth values were mixed across projects.
- Chain visualization could show abnormal jumps (for example `1 -> 4`, `1 -> 10`).
- Dependency paths could be mixed across contexts.

## 2) New model

Nodes:
- `Project`
- `SBOM`
- `Component`
- `Vulnerability`
- `Location`

Main relationships:
- `(:Project)-[:GENERATED_SBOM]->(:SBOM)`
- `(:SBOM)-[r:HAS_COMPONENT]->(:Component)`
  - `r.dependency_depth`
  - `r.is_root`
  - `r.is_direct_dependency`
- `(:Component)-[:DEPENDS_ON {scan_id}]->(:Component)`
- `(:Project)-[:USES_DIRECT]->(:Component)`
- `(:Component)-[:AFFECTED_BY]->(:Vulnerability)`
- `(:Component)-[:DECLARED_IN]->(:Location)`

## 3) Key improvements

1. Depth is SBOM-scoped: use `HAS_COMPONENT.dependency_depth` instead of `Component.dependency_depth`.
2. Dependency edges are scoped: use `DEPENDS_ON {scan_id}`.
3. Direct dependencies are explicit: use `USES_DIRECT` instead of broad `USES`.
4. Recompute depth per SBOM to avoid inherited errors from old data.

## 4) Consolidated migration script

Single script:
- `scripts/migrate_neo4j_old_to_new.ps1`

This script will:
- Optionally reset the new DB.
- Copy core data from old DB to new DB.
- Build/merge `DEPENDS_ON {scan_id}`.
- Recompute `HAS_COMPONENT.dependency_depth` per SBOM.
- Rebuild `USES_DIRECT` from recomputed depth.
- Backfill missing `Vulnerability` properties.

## 5) How to run migration

```powershell
powershell -ExecutionPolicy Bypass -File "knowledge_graph/scripts/migrate_neo4j_old_to_new.ps1" -OldHttp "http://localhost:7475" -NewHttp "http://localhost:7476" -User "neo4j" -Password "password" -BatchSize 2000
```

Reset new DB first (optional):

```powershell
powershell -ExecutionPolicy Bypass -File "knowledge_graph/scripts/migrate_neo4j_old_to_new.ps1" -OldHttp "http://localhost:7475" -NewHttp "http://localhost:7476" -User "neo4j" -Password "password" -BatchSize 2000 -ResetNew
```

Skip vulnerability-property backfill (optional):

```powershell
powershell -ExecutionPolicy Bypass -File "knowledge_graph/scripts/migrate_neo4j_old_to_new.ps1" -OldHttp "http://localhost:7475" -NewHttp "http://localhost:7476" -User "neo4j" -Password "password" -BatchSize 2000 -SkipBackfillVulnerabilityProperties
```

Defaults:
- Old DB: `http://localhost:7475` (bolt `7688`)
- New DB: `http://localhost:7476` (bolt `7689`)
- User/Pass: `neo4j/password`

## 6) Validation queries

### 6.1 Check suspicious edges for one project

```cypher
MATCH (p:Project {repo_url:$repo_url})-[:GENERATED_SBOM]->(s:SBOM)
WITH s ORDER BY s.generated_at DESC LIMIT 1
MATCH (a:Component)-[:DEPENDS_ON {scan_id:s.scan_id}]->(b:Component)
MATCH (s)-[ha:HAS_COMPONENT]->(a)
MATCH (s)-[hb:HAS_COMPONENT]->(b)
RETURN
  sum(CASE WHEN ha.dependency_depth IS NULL OR hb.dependency_depth IS NULL THEN 1 ELSE 0 END) AS null_edges,
  sum(CASE WHEN hb.dependency_depth > ha.dependency_depth + 1 THEN 1 ELSE 0 END) AS jump_edges,
  sum(CASE WHEN hb.dependency_depth = ha.dependency_depth THEN 1 ELSE 0 END) AS same_level_edges,
  count(*) AS total_edges;
```

Expected after migration:
- `null_edges = 0`
- `jump_edges = 0`

### 6.2 Visualize latest-SBOM chain

```cypher
MATCH (p:Project {repo_url:$repo_url})-[:GENERATED_SBOM]->(s:SBOM)
WITH p, s ORDER BY s.generated_at DESC LIMIT 1
MATCH (p)-[:USES_DIRECT]->(start:Component)
WHERE (s)-[:HAS_COMPONENT]->(start)
MATCH path = (start)-[:DEPENDS_ON*0..8 {scan_id:s.scan_id}]->(dep:Component)
RETURN DISTINCT path
LIMIT 500;
```
