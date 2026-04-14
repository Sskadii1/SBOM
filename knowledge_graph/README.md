# Knowledge Graph - SBOM Vulnerability Pipeline

`knowledge_graph` is the ingestion and reachability side of this repository.
It discovers or clones repositories, generates CycloneDX SBOMs, checks
vulnerabilities through OSV, imports the result into Neo4j, and optionally runs
Semgrep-based reachability analysis for vulnerable sinks.

## Current Flow

```text
GitHub links or ground-truth file
  -> crawl / clone
  -> SBOM generation (cdxgen)
  -> OSV vulnerability check
  -> Neo4j import
  -> Semgrep reachability scan
  -> SQLite + JSON reachability artifacts
```

The vulnerable-repository dataset from Dependabot uses the parallel `1B/2B/3B/4B`
flow in `pipeline.py` and is typically imported into a separate Neo4j database.

## Important Execution Note

This codebase still contains legacy imports such as `from modules...`.
To avoid `cwd`-dependent import failures, run the entrypoints from the repository
root with module execution:

```bash
python -m knowledge_graph.pipeline --help
python -m knowledge_graph.pipeline_v2 --help
```

Running random files from inside nested directories is not a supported workflow.

## Main Files

```text
knowledge_graph/
  pipeline.py                         Full ingestion orchestrator
  pipeline_v2.py                      Semgrep reachability CLI
  modules/
    agents/
      vuln_intel_agent.py             Sink extraction from OSV and optional LLM fallback
      semgrep_agent.py                Rule generation, Semgrep execution, result persistence
      sink_db.py                      SQLite storage for sinks and reachability
      config.py                       Agent-related env/config values
    crawler/
      github_crawler.py               Standard repository crawl/clone flow
      dependabot_vuln_crawler.py      Ground-truth vulnerable repository crawl flow
    sbom/
      sbom_generator.py               cdxgen wrapper and SBOM summary handling
    vulnerability/
      osv_checker.py                  OSV batch checking plus enrichment hooks
      enrichment.py                   NVD / EPSS / KEV enrichment helpers
    graph/
      neo4j_integration.py            Neo4j import and graph setup
    utils/
      paths.py                        Project data paths and path rebasing helpers
  data/
    metadata/                         repo link lists and import metadata
    repos/                            standard cloned repositories
    vulnerable_repos/                 ground-truth cloned repositories
    sboms/                            generated SBOMs
    vulnerable_sboms/                 SBOMs for vulnerable flow
    vulnerabilities/                  OSV results
    vulnerable_vulnerabilities/       OSV results for vulnerable flow
    rules/                            generated Semgrep rule files
    reachability/                     Semgrep JSON reports
    cve_sinks.db                      sink metadata + cached reachability rows
```

## Prerequisites

- Python 3.11+
- Node.js with `cdxgen` available on `PATH`
- Neo4j 5.x reachable from the machine or container running the pipeline
- GitHub token for crawl steps
- OpenRouter API key only if you want AI fallback for missing sink metadata

Install local dependencies from the repository root:

```bash
pip install -r requirements.txt
npm install -g @cyclonedx/cdxgen
```

## Environment Variables

The runtime reads environment variables from the process environment. In this
repository, Docker uses the root `.env`, and some modules also read values from
`knowledge_graph/.env` or the inherited environment.

Common values:

```env
NEO4J_URI=bolt://localhost:7689
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j

GITHUB_TOKEN=ghp_...

NVD_API_KEY=...
NVD_API_KEYS=key1,key2
VULNCHECK_API_KEY=...

OPENROUTER_API_KEY=sk-or-...
LLM_MODEL=meta-llama/llama-3.3-70b-instruct:free
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048
```

## `pipeline.py`

`pipeline.py` orchestrates the main ingestion flow:

1. collect repository links
2. clone repositories
3. generate SBOMs
4. query OSV and enrich results
5. import into Neo4j
6. optionally run the parallel vulnerable-repo dataset flow

Show help:

```bash
python -m knowledge_graph.pipeline --help
```

Typical examples:

```bash
# Full main-flow run
python -m knowledge_graph.pipeline \
  --languages JavaScript Python \
  --max-per-language 25 \
  --neo4j-uri bolt://localhost:7689

# Incremental run using already-produced repo links / clones / SBOMs
python -m knowledge_graph.pipeline \
  --skip-get-link \
  --skip-crawl \
  --skip-sbom
```

Notes:

- The actual default languages in code are `Java` and `JavaScript`. Override
  `--languages` explicitly if you want `Python`.
- `--skip-*` flags are intended for incremental reruns, not first-time use.
- If you enable the vulnerable flow, you also need
  `--vulnerable-groundtruth-file`.

## `pipeline_v2.py`

`pipeline_v2.py` is the reachability entrypoint. It does not crawl repositories.
It expects:

- a project already imported into Neo4j
- a local path to the repository source code
- `cve_sinks.db` available

Show help:

```bash
python -m knowledge_graph.pipeline_v2 --help
```

Examples:

```bash
# Import one pre-generated AI output file
python -m knowledge_graph.pipeline_v2 \
  --import-ai knowledge_graph/data/ai_output/batch_001.json

# Check sink coverage for a project already present in Neo4j
python -m knowledge_graph.pipeline_v2 \
  --project "owner/repo" \
  --check-coverage \
  --neo4j-uri bolt://localhost:7689

# Full reachability scan
python -m knowledge_graph.pipeline_v2 \
  --project "owner/repo" \
  --repo "knowledge_graph/data/vulnerable_repos/owner_repo" \
  --neo4j-uri bolt://localhost:7689 \
  --save

# Show cached reachability rows from SQLite
python -m knowledge_graph.pipeline_v2 \
  --project "owner/repo" \
  --show-cached
```

## Reachability Storage

Reachability data is persisted in two places:

- `knowledge_graph/data/cve_sinks.db`
  - table `cve_sinks`: sink metadata
  - table `reachability_results`: cached reachability verdicts and call locations
- `knowledge_graph/data/reachability/{project}_reachability.json`
  - JSON export written by `SemgrepAgent.save()`

Verdict mapping used by both the pipeline and GUI:

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed_reachable` | `1.0` | Direct vulnerable sink usage was matched |
| `likely_reachable` | `0.7` | Import/package evidence exists without a direct sink call |
| `no_sink_data` | `0.5` | No sink metadata was available for that vulnerability |
| `likely_unreachable` | `0.3` | Scan completed and no supporting match was found |

## Neo4j Graph Model

Primary node labels:

- `Project`
- `SBOM`
- `Component`
- `Vulnerability`
- `Location`

Primary relationships:

- `GENERATED_SBOM`
- `HAS_COMPONENT`
- `DEPENDS_ON`
- `AFFECTED_BY`
- `HAS_VULNERABILITY`
- `DECLARED_IN`

## Docker

The root `docker-compose.yml` builds a single app container. Neo4j is expected
to run on the host.

```bash
docker compose up --build -d
```

Example reachability run inside the container:

```bash
docker compose exec app bash -c "
  cd /app && python -m knowledge_graph.pipeline_v2 \
    --project 'owner/repo' \
    --repo 'knowledge_graph/data/vulnerable_repos/owner_repo' \
    --neo4j-uri bolt://host.docker.internal:7689 \
    --save
"
```

## Known Caveats

- First-time users still need to understand which artifacts must already exist
  before using incremental flags.
- `pipeline_v2.py` will fail fast if the target project has not already been
  imported into Neo4j.
- The import style is still partly legacy internally; module execution from the
  repository root is the supported path until the imports are fully normalized
  to `knowledge_graph.*`.
