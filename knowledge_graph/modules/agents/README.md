# Agent Utilities for Reachability Analysis

This directory contains the sink-extraction and Semgrep utilities used by
`knowledge_graph.pipeline_v2`. It is not a separate standalone pipeline anymore.

## What Is Current

Current files that are part of the active runtime:

```text
knowledge_graph/modules/agents/
  config.py
  rate_limiter.py
  semgrep_agent.py
  sink_db.py
  sink_enricher.py
  vuln_intel_agent.py
  prompts/vuln_sink_extraction.md
```

Historical references such as `run_agents.py`, `orchestrator.py`, and
`risk_scorer.py` are not part of the current workspace runtime.

## Agent Roles

### `vuln_intel_agent.py`

Purpose:

- extract vulnerable sink metadata for a vulnerability
- use OSV structured fields first when available
- optionally fall back to an LLM through OpenRouter

Typical output fields written to `cve_sinks.db`:

- `vuln_id`
- `package_name`
- `ecosystem`
- `function_name`
- `call_pattern`
- `sink_type`
- `confidence`
- `source`

### `semgrep_agent.py`

Purpose:

- load sinks from `cve_sinks.db`
- generate Semgrep rules per sink
- scan repository source code
- persist verdicts and call locations

Verdict mapping:

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed_reachable` | `1.0` | Direct sink usage was matched |
| `likely_reachable` | `0.7` | Import/package evidence exists without a direct sink call |
| `no_sink_data` | `0.5` | No sink metadata exists yet for that vulnerability |
| `likely_unreachable` | `0.3` | Scan completed with no supporting match |

## How This Is Used

The normal entrypoint is `pipeline_v2.py`, not a standalone agent runner.

From the repository root:

```bash
python -m knowledge_graph.pipeline_v2 --help
```

Examples:

```bash
# Import one AI output file into the sink database
python -m knowledge_graph.pipeline_v2 \
  --import-ai knowledge_graph/data/ai_output/batch_001.json

# Show how many project vulnerabilities still have no sink metadata
python -m knowledge_graph.pipeline_v2 \
  --project "owner/repo" \
  --check-coverage \
  --neo4j-uri bolt://localhost:7689

# Run a Semgrep reachability scan
python -m knowledge_graph.pipeline_v2 \
  --project "owner/repo" \
  --repo "knowledge_graph/data/vulnerable_repos/owner_repo" \
  --neo4j-uri bolt://localhost:7689 \
  --save
```

## Storage

Primary outputs:

```text
knowledge_graph/data/cve_sinks.db
  cve_sinks                sink metadata
  reachability_results     cached reachability verdicts

knowledge_graph/data/rules/
  {project}_rules.yaml     generated Semgrep rules

knowledge_graph/data/reachability/
  {project}_reachability.json
```

The GUI currently reads SQLite first and falls back to the JSON export.

## Configuration

Configuration is driven by environment variables read by `config.py` and the
calling process. Common values include:

| Variable | Description |
| --- | --- |
| `OPENROUTER_API_KEY` | Required only for LLM fallback in `VulnIntelAgent` |
| `AGENT_LLM_MODEL` | Model used for LLM-based sink extraction |
| `NEO4J_URI` | Neo4j connection URI |
| `NEO4J_USER` | Neo4j username |
| `NEO4J_PASSWORD` | Neo4j password |
| `NEO4J_DATABASE` | Neo4j database name |
| `OSV_RATE_LIMIT_RPS` | OSV request rate limit |
| `LLM_RATE_LIMIT_RPM` | LLM request rate limit |

## Notes

- This directory supplements the main ingestion pipeline; it does not replace it.
- `pipeline_v2.py` expects the target project to already exist in Neo4j.
- Manual batch import of AI output is still supported, but the preferred path is
  automatic sink extraction when coverage is missing.
- The supported execution style is from the repository root with
  `python -m knowledge_graph.pipeline_v2`.
