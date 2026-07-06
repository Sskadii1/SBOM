# GUI Retrieval - Report-Centric SBOM Security Dashboard

`gui_retrieval` is the Streamlit dashboard for browsing Neo4j-backed SBOM
vulnerability data and producing two canonical outputs per project:

1. `Stakeholder Security Summary`
2. `Developer Remediation Report`

Legacy scenario-driven LLM analysis is retained as internal/debug tooling.

## Run

From repository root:

```bash
streamlit run gui_retrieval/main.py --server.port 8501
```

Do not `cd gui_retrieval` and run nested modules directly.

## Current UI Flow

### Repository analysis tabs

- `Security Alerts`
- `Stakeholder Report`
- `Developer Report`

### Enterprise tabs

- `Enterprise Security Overview`
- `Query Workbench`
- `Upload Repository`

### Internal/debug path

- Legacy `analysis.py` scenario mode is now shown under an expander in report
  views for troubleshooting only.

## Architecture

```text
Streamlit UI
  -> frontend/data_access.py
  -> backend/repositories/graph_repository.py
  -> backend/services/evidence_service.py
  -> backend/services/report_service.py
       -> stakeholder_report_builder.py
       -> developer_report_builder.py
  -> backend/services/case_state_service.py
  -> backend/services/verification_service.py
  -> Neo4j + SQLite (cve_sinks.db)

Optional narrative augmentation
  -> backend/services/llm_service.py (OpenRouter)
```

## Data/State Model

Canonical models are in `backend/models/`:

- `AlertCase`
- `StakeholderReport`
- `DeveloperReport`
- `VALID_CASE_STATUSES`
- `VALID_DECISION_TIERS`

SQLite persistence (`knowledge_graph/data/cve_sinks.db`) includes:

- `case_state` (status/decision tier overrides plus owner/notes/verification metadata)
- `report_run` (report lineage to scan snapshot)
- `report_case_snapshot` (baseline snapshots for verification delta)

Graph identity is split as:

- `Project` = logical repository identity
- `SBOM` = scan snapshot identity (`scan_id`, `generated_at`, `source_commit`)

## Verification Loop

The system supports lightweight verify-after-fix via:

- Developer report: `verification_steps`, `verification_delta`, `verification_targets`
- Stakeholder report: `current_action_snapshot`, `next_verification_checkpoint`

`build_verification_delta` compares:

- baseline scan vs current scan
- risk score old/new
- reachability verdict old/new
- fix availability old/new
- closure recommendation per case

## Environment Variables

`backend/config.py` tries to load from `gui_retrieval/.env`. If missing, normal
OS environment variables/defaults are used.

Common variables:

```env
NEO4J_URI=bolt://localhost:7689
NEO4J_USER=neo4j
NEO4J_PASSWORD=change_me
NEO4J_DATABASE=neo4j

LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=...
LLM_MODEL=claude-sonnet-4-6
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048
```

## Quick Checks

Syntax:

```bash
python -m compileall -f gui_retrieval/backend gui_retrieval/frontend gui_retrieval/main.py
```

Generate both reports without LLM:

```bash
NEO4J_URI=bolt://localhost:7689 NEO4J_USER=neo4j NEO4J_PASSWORD=change_me NEO4J_DATABASE=neo4j \
python -c "import sys; sys.path.insert(0,'gui_retrieval'); from backend.services.report_service import generate_report_bundle; b=generate_report_bundle('qws941/splunk', use_llm=False); print(b['stakeholder_report']['posture_summary']['total_cases'], b['developer_report']['triage_summary']['total_cases'])"
```

Run new unit tests:

```bash
python -m unittest \
  gui_retrieval.tests.test_decision_tiering \
  gui_retrieval.tests.test_case_state_service \
  gui_retrieval.tests.test_report_builders \
  gui_retrieval.tests.test_verification_delta
```
