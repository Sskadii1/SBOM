# GUI Retrieval - SBOM Vulnerability Dashboard

`gui_retrieval` is the Streamlit dashboard for browsing the Neo4j-backed SBOM
graph, viewing Dependabot-style alerts, and generating evidence-grounded LLM
analysis.

## Important Execution Note

This package still contains legacy imports such as `import backend.config` and
`import frontend.data_access`. To avoid `cwd`-dependent import failures, run the
dashboard from the repository root:

```bash
streamlit run gui_retrieval/main.py --server.port 8501
```

Do not `cd gui_retrieval` and then run files ad hoc from nested folders.

## Current Features

### Security Alerts tab

- repository selector
- severity / KEV / fix-available / free-text filters
- risk-score sorting
- alert detail view with reachability verdict and call locations
- dependency chain view and package/version breakdown

### LLM Analysis tab

Scenario-driven LLM output using graph evidence from Neo4j:

- `dev_explain`
- `manager_brief`
- `triage_queue`
- `explainability_mode`
- `multi_audience`
- `arch_impact`
- `project_overview`
- `custom`

### Overview tab

One-click project posture summary using the `project_overview` scenario.

### Ingest New Repository panel

The current UI can also kick off a full single-repository ingestion run through
`backend/services/repo_pipeline_service.py`:

```text
repo input
  -> clone / update
  -> SBOM generation
  -> OSV check
  -> Neo4j import
  -> Semgrep reachability
  -> dashboard refresh
```

This is newer than the original README and is now part of the normal UI flow.

## Architecture

```text
Streamlit UI
  -> frontend/data_access.py
  -> backend/repositories/graph_repository.py
  -> backend/graph_service.py
  -> Neo4j

Optional LLM path:
  -> backend/services/evidence_service.py
  -> backend/services/prompt_service.py
  -> backend/services/llm_service.py
  -> OpenRouter

Optional ingest path from UI:
  -> backend/services/repo_pipeline_service.py
  -> knowledge_graph pipeline components
```

## Reachability Integration

The GUI does not run Semgrep itself. It consumes reachability data produced by
`knowledge_graph`.

Current lookup order in `graph_repository.py`:

1. SQLite `knowledge_graph/data/cve_sinks.db`, table `reachability_results`
2. JSON fallback in `knowledge_graph/data/reachability/{project}_reachability.json`

That means the GUI is no longer JSON-only.

## Current Risk Score Implementation

The README previously documented an older six-factor formula. The current code
in `backend/repositories/graph_repository.py` recomputes risk in Python as:

```text
Risk = 100 * (
  0.25 * S_sev +
  0.25 * S_exp +
  0.15 * S_scope +
  0.35 * S_reach
)
```

Where:

- `S_sev = cvss / 10`
- `S_exp = 1.0 if KEV else EPSS`
- `S_scope = 1.0` for `required/runtime`, `0.3` for `optional/dev/test`, else `0.6`
- `S_reach = 1.0 / 0.7 / 0.5 / 0.3` from reachability verdict

The Cypher queries still return a placeholder score using `0.5` for
reachability, then Python overwrites it with the resolved verdict.

## Main Files

```text
gui_retrieval/
  main.py                              Streamlit entrypoint
  backend/
    config.py                          Environment/config values
    graph_service.py                   Neo4j connection wrapper
    retrieval_scenarios.py             Hardcoded Cypher scenario bundles
    repositories/graph_repository.py   Query layer + risk recomputation
    services/
      evidence_service.py              Neo4j rows -> evidence records
      prompt_service.py                Evidence formatting helpers
      llm_service.py                   OpenRouter integration
      repo_pipeline_service.py         Single-repository ingest path from UI
      semgrep_context_service.py       Reachability enrichment for evidence
  frontend/
    data_access.py                     Streamlit cache wrappers
    components/ui_components.py        Shared UI rendering helpers
    views/
      alerts.py
      analysis.py
      overview.py
    styles.py
```

## Requirements

- Python 3.11+
- Neo4j already populated by `knowledge_graph`
- OpenRouter API key only if using the LLM Analysis or Overview tabs

Install from the repository root:

```bash
pip install -r requirements.txt
```

## Environment Variables

`gui_retrieval/backend/config.py` loads `.env` from `gui_retrieval/.env`.

Example:

```env
NEO4J_URI=bolt://localhost:7688
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j

OPENROUTER_API_KEY=sk-or-...
LLM_MODEL=nvidia/nemotron-3-super-120b-a12b:free
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048

CVE_SINKS_DB=../knowledge_graph/data/cve_sinks.db
REACHABILITY_DIR=../knowledge_graph/data/reachability

DEMO_PROJECT_NAME=gulpjs/gulp
DEMO_VULN_ID=CVE-2021-44228
DEMO_COMPONENT_ID=pkg:npm/lodash@4.17.20
DEMO_FROM_ISO=2026-01-01T00:00:00Z
```

Notes:

- `OPENROUTER_API_KEY` is not required for the alert list itself.
- `REACHABILITY_DIR` is used for JSON fallback.
- `CVE_SINKS_DB` controls the SQLite path used for the primary reachability lookup.

## Local Run

From the repository root:

```bash
streamlit run gui_retrieval/main.py --server.port 8501
```

Then open:

```text
http://localhost:8501
```

## Docker

The root `docker-compose.yml` runs a single `app` container and exposes the UI
on port `8501`. Neo4j is expected on the host and accessed through
`host.docker.internal`.

```bash
docker compose up --build -d
```

## LLM Behavior

The LLM layer uses OpenRouter over `urllib.request`. Prompts are built from
evidence retrieved from Neo4j, and the system instruction explicitly tells the
model to stay within provided evidence.

The `custom` scenario is also evidence-bounded; it is not a general chatbot.

## Known Caveats

- The package still uses legacy import names internally. Running from the
  repository root is the supported path until imports are fully normalized to
  `gui_retrieval.*`.
- `manager_brief` and `triage_queue` are portfolio-oriented scenarios, not
  single-alert drill-downs.
- The repository ingest panel depends on the `knowledge_graph` runtime, Git,
  `cdxgen`, Neo4j, and optional OpenRouter configuration being available.
