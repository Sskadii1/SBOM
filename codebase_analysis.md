# Codebase Analysis: Current State

This document describes the current state of the `SBOM_latest` repository.

- `knowledge_graph/` contains the vulnerable-ingestion and reachability pipeline.
- `gui_retrieval/` contains the Streamlit dashboard that reads Neo4j and reachability data.

---

## 1. Architecture Overview

The system currently has two main parts:

```text
knowledge_graph/
  |- pipeline.py       -> vulnerable repository ingestion into Neo4j
  |- pipeline_v2.py    -> reachability scanning with Semgrep + sink intelligence

gui_retrieval/
  |- main.py           -> Streamlit dashboard for Neo4j + reachability data
```

High-level data flow:

```text
Ground-truth file or GitHub repository link
  -> clone vulnerable-style repository
  -> SBOM generation
  -> vulnerability enrichment
  -> Neo4j import
  -> pipeline_v2.py loads vulnerabilities from Neo4j
  -> cve_sinks.db + Semgrep rules
  -> reachability JSON / SQLite
  -> GUI recomputes risk_score and displays results
```

---

## 2. knowledge_graph: Active Runtime Flow

### 2.1 Entry points

| File | Current role |
|------|--------------|
| `knowledge_graph/pipeline.py` | Vulnerable-only ingestion CLI. Supports `--groundtruth-file` or `--single-repo` |
| `knowledge_graph/pipeline_v2.py` | Reachability pipeline: loads project vulnerabilities from Neo4j, ensures sink data, runs Semgrep, writes `reachability/*.json` |
| `knowledge_graph/run_semgrep_sync_from_neo4j.py` | Batch runner: reads `Project.full_name` from Neo4j and calls `pipeline_v2.py` for each project |
| `knowledge_graph/re_enrich_neo4j_vulns.py` | Refresh script for metadata on existing `Vulnerability` nodes in Neo4j |

### 2.2 Core modules in use

| File / folder | Role |
|---------------|------|
| `knowledge_graph/modules/crawler/dependabot_vuln_crawler.py` | Clones vulnerable repositories from ground-truth, checks out vulnerable commits, saves metadata |
| `knowledge_graph/modules/sbom/sbom_generator.py` | Generates CycloneDX SBOMs for vulnerable repositories |
| `knowledge_graph/modules/vulnerability/osv_checker.py` | Queries OSV in batches and enriches results |
| `knowledge_graph/modules/vulnerability/enrichment.py` | Adds CVSS, EPSS, and KEV metadata |
| `knowledge_graph/modules/graph/neo4j_integration.py` | Imports data into Neo4j |
| `knowledge_graph/modules/utils/paths.py` | Path constants and path-rebasing helpers |
| `knowledge_graph/modules/utils/sbom_parser.py` | Parses CycloneDX JSON, dependency graph, and dependency depth |
| `knowledge_graph/modules/utils/purl_utils.py` | Parses and normalizes purl / ecosystem identifiers |

### 2.3 Agent modules used by reachability

| File | Role |
|------|------|
| `knowledge_graph/modules/agents/vuln_intel_agent.py` | Fetches OSV advisory data, prefers structured extraction, falls back to an LLM when needed |
| `knowledge_graph/modules/agents/semgrep_agent.py` | Generates rule YAML from sink data, runs Semgrep, parses findings into reachability verdicts |
| `knowledge_graph/modules/agents/sink_db.py` | SQLite layer for `cve_sinks.db` and `reachability_results` |
| `knowledge_graph/modules/agents/rate_limiter.py` | Rate limiting for external API calls |
| `knowledge_graph/modules/agents/config.py` | Agent, endpoint, model, and rate-limit configuration |
| `knowledge_graph/modules/agents/sink_enricher.py` | Offline sink enrichment from advisories and patch references |

---

## 3. pipeline.py: Current Ingestion Flow

`knowledge_graph/pipeline.py` has been simplified into a vulnerable-only pipeline.

### 3.1 Current CLI usage

There are two supported input modes:

- `--groundtruth-file`: run a batch from a Dependabot ground-truth file
- `--single-repo`: provide `owner/repo` or a GitHub URL directly

If `--stages` is omitted, the default full flow is:

- `crawl`
- `sbom`
- `vuln-check`
- `neo4j`

Custom stage lists are expected to stay in pipeline order and not repeat stages.

### 3.2 Important parameters

- `--groundtruth-file`
- `--single-repo`
- `--stages crawl sbom vuln-check neo4j`
- `--max-records`
- `--clear-neo4j`
- `--neo4j-uri`
- `--neo4j-user`
- `--neo4j-password`
- `--vulnerable-neo4j-database`

### 3.3 Compatibility behavior

To avoid breaking older callers, public method names are still preserved:

- `run_step_2_sbom()` delegates to `run_step_2b_vulnerable_sbom()`
- `run_step_3_vulnerability_check()` delegates to `run_step_3b_vulnerable_vulnerability_check()`
- `run_step_4_neo4j_import()` delegates to `run_step_4b_neo4j_import_vulnerable()`
- `run_full_pipeline()` now runs only the vulnerable flow and logs a warning if `flow=main|both` is requested
- `run_step_0_get_link()` and `run_step_1_crawl()` remain for compatibility but raise explicit errors

### 3.4 `--single-repo` flow

`--single-repo` does not use the ground-truth dataset. Instead it:

1. parses `owner/repo` or a GitHub URL
2. fetches repository metadata
3. resolves the current HEAD commit via `git ls-remote`
4. creates a metadata key in the form `owner/repo@<sha>`
5. clones the repository into `data/vulnerable_repos/`
6. continues through SBOM, vulnerability, and Neo4j stages like the vulnerable flow

Note: this is a vulnerable-style flow for one repository. It does not guarantee that the selected commit is a vulnerable ground-truth commit.

If `--single-repo` is combined with later stages such as `sbom`, `vuln-check`, or `neo4j`, the pipeline now keeps the stage inputs scoped to that repository instead of accidentally falling back to the entire vulnerable metadata set.

---

## 4. pipeline_v2.py: Current Reachability Flow

### 4.1 Goal

`pipeline_v2.py` determines whether a vulnerability in a project is:

- `confirmed_reachable`
- `likely_reachable`
- `likely_unreachable`
- or `no_sink_data`

### 4.2 Current execution flow

```text
pipeline_v2.py
  -> load_project_vulns() from Neo4j
  -> missing_vulns() checks which CVEs are missing sink data in SQLite
  -> if sink data is missing and --no-ai is not used:
       auto_extract_sinks()
         -> VulnIntelAgent
         -> structured OSV extraction first
         -> OpenRouter fallback if needed
         -> insert_sinks() into cve_sinks.db
  -> SemgrepAgent.scan()
       -> get_sinks_for_vulns()
       -> generate_rules()
       -> run_semgrep()
       -> parse_findings()
  -> agent.save(results)
       -> writes data/reachability/{project}_reachability.json
       -> writes SQLite reachability_results
```

### 4.3 Batch reachability around Neo4j

In addition to `pipeline_v2.py`, the repository currently includes:

- `knowledge_graph/run_semgrep_sync_from_neo4j.py`
  - reads the project list directly from Neo4j
  - uses metadata files to map project -> local repository path
  - calls `pipeline_v2.py` for each project

- `knowledge_graph/re_enrich_neo4j_vulns.py`
  - reads all `Vulnerability.id` values from Neo4j
  - reuses `OSVChecker` enrichment logic
  - refreshes aliases and metadata on existing vulnerability nodes

---

## 5. GUI: Important Notes

The single-repo ingest flow in `gui_retrieval/backend/services/repo_pipeline_service.py` is still a separate path.

It:

- does not call `knowledge_graph/pipeline.py` directly
- clones or updates a user-selected repository
- generates an SBOM, queries OSV, imports into Neo4j, and runs Semgrep
- refreshes dashboard data after completion

That means changing the CLI behavior in `pipeline.py` does not automatically change the GUI ingestion flow.

---

## 6. Important Data Artifacts

| Path | Meaning |
|------|---------|
| `knowledge_graph/data/cve_sinks.db` | SQLite database storing advisory data, sink metadata, and reachability results |
| `knowledge_graph/data/reachability/*.json` | Semgrep reachability results per project |
| `knowledge_graph/data/vulnerable_repos/` | Repository source code used by the vulnerable flow |
| `knowledge_graph/data/vulnerable_sboms/` | SBOM files for vulnerable repositories |
| `knowledge_graph/data/vulnerable_vulnerabilities/` | Vulnerability result files for vulnerable repositories |
| `knowledge_graph/data/metadata/vulnerable_repos_metadata.json` | Metadata for vulnerable repositories |
| `knowledge_graph/data/metadata/neo4j_imported_repos_*.json` | Neo4j import status by URI / database |
| `knowledge_graph/data/rules/*.yaml` | Generated Semgrep rule files |

---

## 7. Short Summary

If you need to quickly locate the code that most directly affects the current runtime behavior in `SBOM_latest`:

- Ingestion CLI: `knowledge_graph/pipeline.py`
- Reachability: `knowledge_graph/pipeline_v2.py`
- Batch reachability: `knowledge_graph/run_semgrep_sync_from_neo4j.py`
- Neo4j vulnerability refresh: `knowledge_graph/re_enrich_neo4j_vulns.py`
- Single-repo ingest from GUI: `gui_retrieval/backend/services/repo_pipeline_service.py`
- Sink intelligence: `knowledge_graph/modules/agents/vuln_intel_agent.py`
- Offline sink enrichment: `knowledge_graph/modules/agents/sink_enricher.py`
- Semgrep scan: `knowledge_graph/modules/agents/semgrep_agent.py`
- Risk score backend: `gui_retrieval/backend/repositories/graph_repository.py`
- Alerts UI: `gui_retrieval/frontend/views/alerts.py`
- LLM orchestration: `gui_retrieval/backend/services/llm_service.py`
