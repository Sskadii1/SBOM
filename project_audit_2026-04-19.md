# Project Audit Report

Date: 2026-04-19
Workspace: `d:\Capstone`
Status: Cleanup approved and executed after audit. This report now also reflects the applied changes.

## Audit Scope

Included in code audit:
- `gui_retrieval/**`
- `knowledge_graph/**`
- `tune_risk_weights.py`

Explicitly excluded from dead-code decisions:
- `knowledge_graph/data/**`
- `knowledge_graph/data/repos/**`
- `knowledge_graph/data/user_repos/**`
- `venv/**`
- `tmp/**`

Reason:
- these paths contain generated artifacts, cloned repositories, runtime caches, or environment dependencies
- deleting or refactoring them as if they were first-party source code would be unsafe

## Verified Runtime Flows

### 1. Dashboard runtime

Entrypoint:
- `gui_retrieval/main.py`

Observed flow:
- `main.py`
- `frontend/data_access.py`
- `backend/repositories/graph_repository.py`
- `backend/graph_service.py`
- Neo4j

Tabs currently wired in UI:
- Enterprise overview: `frontend/views/enterprise_overview.py`
- Repository alerts: `frontend/views/alerts.py`
- LLM analysis: `frontend/views/analysis.py`
- Upload/ingest: `frontend/views/upload_repository.py`

### 2. Single-repo ingest from UI

Entrypoint from UI:
- `frontend/views/upload_repository.py`

Observed flow:
- `backend/services/repo_pipeline_service.py`
- clone/update repo
- generate SBOM
- OSV check
- import into Neo4j
- load sink metadata / optional AI fallback
- Semgrep reachability

Important note:
- the Upload tab does not shell out to `knowledge_graph/pipeline.py`
- it reuses lower-level modules directly
- because of that, deleting `knowledge_graph` modules based only on CLI usage would be risky

### 3. Batch / CLI pipeline flow

Main CLI:
- `knowledge_graph/pipeline.py`
- `knowledge_graph/pipeline_v2.py`

Maintenance / operator scripts:
- `knowledge_graph/run_semgrep_sync_from_neo4j.py`
- `knowledge_graph/re_enrich_neo4j_vulns.py`

## Checks Performed

- call-site search across first-party code
- import and entrypoint tracing
- README / code consistency check
- dead-path / dormant-feature review
- unit test run: `python -m unittest gui_retrieval.tests.test_llm_service`

Test result:
- passed
- `3` tests run
- file: `gui_retrieval/tests/test_llm_service.py`

## Findings

### A. High-confidence dead / orphaned code

#### 1. `gui_retrieval/frontend/views/overview.py`

Status:
- removed after approval

Why:
- `main.py` does not import or render this file
- code search found no first-party call-site for `render_overview_tab`
- the current overview experience is provided by `frontend/views/enterprise_overview.py`

Risk if removed:
- low runtime risk for current UI
- medium documentation risk because internal docs still mention `overview.py`

Action taken:
- removed
- docs updated to reference `enterprise_overview.py` instead

References:
- `gui_retrieval/main.py`
- `gui_retrieval/frontend/views/overview.py`
- `gui_retrieval/frontend/views/enterprise_overview.py`

#### 2. `custom` branch in `gui_retrieval/backend/services/llm_service.py`

Status:
- removed after approval

Why:
- `run_pipeline()` contains a special branch for `scenario_name == "custom"`
- but `backend/retrieval_scenarios.py:get_scenario()` does not define `custom`
- `run_pipeline()` calls `get_scenario()` before the `custom` branch
- so the code returns an error before the `custom` branch can execute

Impact:
- current `custom` path is effectively unreachable through normal code flow
- README still documents `custom`, so docs and code are out of sync

Risk if removed or refactored:
- medium
- because there may have been an intended feature that was only partially removed

Action taken:
- removed unreachable branch from `llm_service.py`
- stale README references to `custom` were removed

References:
- `gui_retrieval/backend/services/llm_service.py`
- `gui_retrieval/backend/retrieval_scenarios.py`
- `gui_retrieval/README.md`

### B. Dormant but not safe to classify as dead yet

#### 3. Portfolio scenarios: `manager_brief`, `triage_queue`

Status:
- dormant / hidden, not dead

Why:
- scenario definitions still exist in:
  - `backend/config.py`
  - `backend/retrieval_scenarios.py`
  - `backend/services/llm_service.py`
  - `backend/services/prompt_service.py`
- UI currently hides them and shows project-only scenarios
- `analysis.py` explicitly says portfolio scenarios are temporarily hidden

Risk if removed:
- medium to high product risk
- they may be intentionally hidden for future re-enable

Recommendation:
- keep for now
- if you want to simplify the product, remove only after confirming you no longer need portfolio reporting

References:
- `gui_retrieval/frontend/views/analysis.py`
- `gui_retrieval/backend/retrieval_scenarios.py`
- `gui_retrieval/backend/services/llm_service.py`
- `gui_retrieval/backend/services/prompt_service.py`

#### 4. `gui_retrieval/export_llm_analysis_report.py`

Status:
- removed after approval

Why:
- not used by Streamlit UI
- but it is a valid offline export/review script
- useful for prompt review and reproducible analysis snapshots

Risk if removed:
- low runtime risk
- medium operations / evaluation workflow risk

Action taken:
- removed as requested

### C. Maintenance scripts that should be kept unless pipeline ownership says otherwise

#### 5. `knowledge_graph/run_semgrep_sync_from_neo4j.py`

Status:
- non-UI operator script

Why:
- batch-runs `pipeline_v2.py` for all projects currently present in Neo4j
- useful for re-syncing reachability after graph updates

Risk if removed:
- medium operational risk

Recommendation:
- keep

#### 6. `knowledge_graph/re_enrich_neo4j_vulns.py`

Status:
- maintenance / backfill script

Why:
- refreshes vulnerability metadata already stored in Neo4j
- relies on `run_custom_query()` from Neo4j integration

Risk if removed:
- medium operational risk

Recommendation:
- keep

#### 7. `tune_risk_weights.py`

Status:
- utility patch script, not runtime code

Why:
- it patches known locations in:
  - `graph_repository.py`
  - `alerts.py`
- useful if you tune your scoring model often

Risk if removed:
- low runtime risk
- low to medium operator convenience risk

Recommendation:
- keep unless you want to replace it with config-driven weights

## Documentation Drift

### 1. `codebase_analysis.md` is stale

Observed mismatches:
- still references `overview.py` as active view
- diagrams do not fully match current `main.py`

Recommendation:
- update after code cleanup

### 2. `gui_retrieval/README.md` is partially stale

Observed mismatches:
- documents `custom` scenario, but current code path is unreachable
- still lists scenarios not shown in current UI
- still mentions older layout in some places

Recommendation:
- update together with scenario decision

## Keep / Review / Remove Matrix

### Keep

- `knowledge_graph/pipeline.py`
- `knowledge_graph/pipeline_v2.py`
- `knowledge_graph/run_semgrep_sync_from_neo4j.py`
- `knowledge_graph/re_enrich_neo4j_vulns.py`
- `gui_retrieval/backend/services/repo_pipeline_service.py`
- `gui_retrieval/frontend/views/enterprise_overview.py`
- dormant portfolio scenario code for now
- `gui_retrieval/export_llm_analysis_report.py`
- `tune_risk_weights.py`

### Review first

- unreachable `custom` branch in `gui_retrieval/backend/services/llm_service.py`
- README and analysis docs mentioning removed or hidden features
- legacy import style (`import backend...`, `import frontend...`) because current runtime still depends on running from repo root

### Strong remove candidate

- completed: `gui_retrieval/frontend/views/overview.py`

## Proposed Safe Cleanup Plan

Executed cleanup:

1. Removed `gui_retrieval/frontend/views/overview.py`
2. Updated `codebase_analysis.md` and `gui_retrieval/README.md`
3. Removed unreachable `custom` branch and stale mentions
4. Removed `gui_retrieval/export_llm_analysis_report.py`
5. Re-ran unit tests

## Explicit Non-Actions In This Pass

Not done:
- no behavior change in ingestion pipeline
- no Semgrep rule changes
- no Neo4j schema changes
- no Docker changes
- no refactor of legacy imports
