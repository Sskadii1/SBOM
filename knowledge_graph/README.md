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
cd knowledge_graph
python3 pipeline.py --help
```

Quick demo-oriented patterns:

```bash
cd knowledge_graph

# One small isolated demo run for exactly one repo
python3 pipeline.py \
  --demo-safe \
  --demo-label react_native_demo \
  --single-repo "DanBurbach/React-Native-Basic"

# Run only selected steps, in order
python3 pipeline.py \
  --demo-safe \
  --demo-label react_native_demo \
  --single-repo "DanBurbach/React-Native-Basic" \
  --steps crawl sbom vuln-check neo4j
```

Typical examples:

```bash
cd knowledge_graph

# Full vulnerable-flow run
python3 pipeline.py \
  --vulnerable-groundtruth-file data/metadata/dependabot_groundtruth.json \
  --neo4j-uri bolt://localhost:7689 \
  --vulnerable-neo4j-database vuln_repos
```

Notes:

- You must provide either `--vulnerable-groundtruth-file` or `--single-repo`.
- Preferred CLI usage revolves around `--steps`, `--single-repo`, and `--demo-safe`.

### Run Step By Step Via CLI

`pipeline.py` now supports step-oriented execution directly through `--steps`.
List the steps you want, in the order you want them to run.

All commands below should be run from the repository root.

#### Step 0: Collect repository links

This generates the repo-links file used by the main crawl flow.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps get-link
```

For a one-repo demo:

```bash
cd knowledge_graph
python3 pipeline.py \
  --single-repo "DanBurbach/React-Native-Basic" \
  --steps crawl
```

#### Step 1: Crawl and clone repositories

This consumes the links file and clones repos into `knowledge_graph/data/repos/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps crawl
```

#### Step 1B: Crawl vulnerable repositories from Dependabot ground truth

This is the separate vulnerable flow. Output goes to
`knowledge_graph/data/vulnerable_repos/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --vulnerable-groundtruth-file data/metadata/dependabot_groundtruth.json \
  --max-vulnerable-records 50 \
  --steps vuln-crawl
```

#### Step 2: Generate SBOMs for the main flow

This reads clone metadata and writes SBOMs to `knowledge_graph/data/sboms/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps sbom
```

#### Step 2B: Generate SBOMs for the vulnerable flow

This reads vulnerable clone metadata and writes SBOMs to
`knowledge_graph/data/vulnerable_sboms/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps vuln-sbom
```

#### Step 3: Run OSV vulnerability checking for the main flow

This reads `sbom_summary.json` and writes enriched vulnerability JSON into
`knowledge_graph/data/vulnerabilities/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps vuln-check
```

#### Step 3B: Run OSV vulnerability checking for the vulnerable flow

This reads `vulnerable_sbom_summary.json` and writes enriched vulnerability JSON
into `knowledge_graph/data/vulnerable_vulnerabilities/`.

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps vuln-vuln-check
```

#### Step 4: Import the main flow into Neo4j

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps neo4j \
  --neo4j-uri bolt://localhost:7689 \
  --neo4j-database neo4j
```

If you want to clear the target database before importing:

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps neo4j \
  --neo4j-uri bolt://localhost:7689 \
  --neo4j-database neo4j \
  --clear-neo4j
```

#### Step 4B: Import the vulnerable flow into Neo4j

```bash
cd knowledge_graph
python3 pipeline.py \
  --steps vuln-neo4j \
  --neo4j-uri bolt://localhost:7689 \
  --vulnerable-neo4j-database vuln_repos
```

#### Multi-step demo chain

This is usually the easiest small demo path for one repo:

```bash
cd knowledge_graph
python3 pipeline.py \
  --demo-safe \
  --demo-label react_native_demo \
  --single-repo "DanBurbach/React-Native-Basic" \
  --steps crawl sbom vuln-check neo4j \
  --neo4j-uri bolt://host.docker.internal:7689
```

#### Common artifact handoff between steps

- Step 0 writes `knowledge_graph/data/metadata/repos_link.txt`
- Step 1 writes `knowledge_graph/data/metadata/repos_metadata.json`
- Step 1B writes `knowledge_graph/data/metadata/vulnerable_repos_metadata.json`
- Step 2 writes `knowledge_graph/data/sboms/sbom_summary.json`
- Step 2B writes `knowledge_graph/data/vulnerable_sboms/vulnerable_sbom_summary.json`
- Step 3 writes `knowledge_graph/data/vulnerabilities/vulnerability_summary.json`
- Step 3B writes `knowledge_graph/data/vulnerable_vulnerabilities/vulnerable_vulnerability_summary.json`
- Step 4 and Step 4B import those summaries into Neo4j

## `pipeline_v2.py`

`pipeline_v2.py` is the reachability entrypoint. It does not crawl repositories.
It expects:

- a project already imported into Neo4j
- a local path to the repository source code
- `cve_sinks.db` available

Show help:

```bash
cd knowledge_graph
python3 pipeline_v2.py --help
```

Examples:

```bash
cd knowledge_graph

# Import one pre-generated AI output file
python3 pipeline_v2.py \
  --import-ai data/ai_output/batch_001.json

# Check sink coverage for a project already present in Neo4j
python3 pipeline_v2.py \
  --project "owner/repo" \
  --check-coverage \
  --neo4j-uri bolt://localhost:7689

# Full reachability scan
python3 pipeline_v2.py \
  --project "owner/repo" \
  --repo "data/vulnerable_repos/owner_repo" \
  --neo4j-uri bolt://localhost:7689 \
  --save

# Show cached reachability rows from SQLite
python3 pipeline_v2.py \
  --project "owner/repo" \
  --show-cached
```

### Run Step By Step Via CLI

`pipeline_v2.py` is already a focused CLI. In practice there are four useful
execution modes.

#### Mode 1: Import AI-generated sink data into SQLite

Use this if you already have a JSON batch produced elsewhere and only want to
load it into `knowledge_graph/data/cve_sinks.db`.

```bash
cd knowledge_graph
python3 pipeline_v2.py \
  --import-ai data/ai_output/batch_001.json
```

#### Mode 2: Check sink coverage for one imported project

This reads vulnerabilities for `--project` from Neo4j and reports how many CVEs
 already have sink metadata in SQLite.

```bash
cd knowledge_graph
python3 pipeline_v2.py \
  --project "DanBurbach/React-Native-Basic" \
  --neo4j-uri bolt://host.docker.internal:7689 \
  --check-coverage
```

#### Mode 3: Show cached reachability without re-running Semgrep

This reads previously saved rows from the SQLite cache.

```bash
cd knowledge_graph
python3 pipeline_v2.py \
  --project "DanBurbach/React-Native-Basic" \
  --show-cached
```

#### Mode 4: Run a full Semgrep reachability scan

This is the normal command after the project has already been imported into
Neo4j and the repository source is available locally.

```bash
cd knowledge_graph
python3 pipeline_v2.py \
  --project "DanBurbach/React-Native-Basic" \
  --repo "data/vulnerable_repos/DanBurbach_React-Native-Basic__1dd9339c46" \
  --neo4j-uri bolt://host.docker.internal:7689 \
  --save
```

That is effectively the minimal command shape you suggested:

```bash
python3 pipeline_v2.py \
  --project "DanBurbach/React-Native-Basic" \
  --repo "data/vulnerable_repos/DanBurbach_React-Native-Basic__1dd9339c46" \
  --neo4j-uri "bolt://host.docker.internal:7689" \
  --save
```

Use `--no-ai` if you want the run to skip `VulnIntelAgent` fallback for CVEs
missing sink metadata:

```bash
cd knowledge_graph
python3 pipeline_v2.py \
  --project "DanBurbach/React-Native-Basic" \
  --repo "data/vulnerable_repos/DanBurbach_React-Native-Basic__1dd9339c46" \
  --neo4j-uri bolt://host.docker.internal:7689 \
  --save \
  --no-ai
```

### What each CLI mode does internally

- `--import-ai`: loads sink JSON into `cve_sinks.db` and exits
- `--check-coverage`: reads project vulnerabilities from Neo4j and compares them against sink coverage in SQLite
- `--show-cached`: prints cached reachability rows from SQLite and exits
- `--project + --repo`: loads project vulnerabilities from Neo4j, optionally runs AI fallback for missing sinks, runs `SemgrepAgent.scan()`, prints a report, and optionally saves JSON with `--save`

### Important notes for `pipeline_v2.py`

- `--project` must match `Project.full_name` already imported into Neo4j.
- `--repo` must point to the local source tree for the same project.
- `--neo4j-uri` is exposed in CLI, but `NEO4J_USER`, `NEO4J_PASSWORD`, and optional `NEO4J_DATABASE` are still read from environment, not from CLI flags.
- `--save` writes JSON to `knowledge_graph/data/reachability/`.
- If the project is not already in Neo4j, the command fails fast with `No vulnerabilities found for project`.

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
  cd /app/knowledge_graph && python3 pipeline_v2.py \
    --project 'owner/repo' \
    --repo 'data/vulnerable_repos/owner_repo' \
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
