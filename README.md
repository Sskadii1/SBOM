# SBOM Security Dashboard

A research-oriented security dashboard for generating, enriching, analyzing, and visualizing Software Bill of Materials (SBOM) data, vulnerability intelligence, and reachability signals.

## Overview

SBOM Security Dashboard helps analyze open-source repositories through an end-to-end security research workflow:

- SBOM generation for repository dependencies.
- Vulnerability enrichment from external advisory and vulnerability intelligence sources.
- Advisory analysis and sink extraction for vulnerability context.
- Semgrep-based reachability analysis to estimate whether vulnerable APIs appear in project code.
- Neo4j knowledge graph import for repository, component, dependency, and vulnerability relationships.
- Streamlit dashboard visualization for security alerts, reports, and investigation workflows.

This project is a research and academic prototype. It is not a production vulnerability scanner, not a replacement for professional security review, and not an authoritative source of vulnerability reachability. Results should be manually validated before use in operational decisions.

## Features

- Repository ingestion from GitHub repository identifiers or URLs.
- CycloneDX SBOM generation using `cdxgen`.
- Vulnerability lookup and enrichment through OSV/NVD-style advisory data and related sources.
- Neo4j graph modeling for projects, SBOMs, components, dependencies, and vulnerabilities.
- Semgrep-based reachability analysis using generated rules from sink metadata.
- Streamlit dashboard for alert review, report generation, and repository-level analysis.
- Risk scoring and stakeholder/developer report views.
- Optional LLM-assisted advisory interpretation when an API key is configured.

## Architecture

```text
GitHub repository
  -> clone/update source locally
  -> generate CycloneDX SBOM with cdxgen
  -> query and enrich vulnerability data
  -> import project/component/vulnerability data into Neo4j
  -> extract or load vulnerable sink metadata
  -> run Semgrep reachability analysis
  -> store runtime outputs under knowledge_graph/data/
  -> visualize alerts and reports in Streamlit
```

Main components:

- `gui_retrieval/`: Streamlit dashboard, report views, query helpers, and repository ingestion UI.
- `gui_retrieval/backend/`: configuration, Neo4j access, report services, LLM integration, and ingestion orchestration.
- `knowledge_graph/`: CLI pipelines for SBOM generation, vulnerability enrichment, Neo4j import, and Semgrep reachability.
- `knowledge_graph/modules/`: reusable crawler, SBOM, vulnerability, graph, utility, and agent modules.
- Neo4j: graph database used to model projects, dependencies, SBOMs, and vulnerabilities.
- Semgrep: static-analysis engine used for reachability signals.
- External data sources: OSV, NVD-style enrichment, VulnCheck-style enrichment, GitHub APIs, and optional LLM APIs when configured.

## Repository Structure

```text
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── gui_retrieval/
│   ├── main.py
│   ├── backend/
│   ├── frontend/
│   └── tests/
├── knowledge_graph/
│   ├── pipeline.py
│   ├── pipeline_v2.py
│   ├── run_semgrep_sync_from_neo4j.py
│   ├── re_enrich_neo4j_vulns.py
│   ├── modules/
│   └── data/
│       ├── .gitkeep
│       └── sample/
└── tune_risk_weights.py
```

`knowledge_graph/data/` is generated at runtime and intentionally excluded from source control. It may contain cloned repositories, generated SBOMs, vulnerability caches, SQLite databases, LLM outputs, Semgrep rules, and reachability artifacts. Public releases should include only reviewed, sanitized samples under `knowledge_graph/data/sample/`.

## Security and Data Notice

Do not commit `.env` files, API keys, Neo4j credentials, cloned repositories, generated SBOMs, vulnerability caches, SQLite databases, LLM outputs, or Semgrep reachability results.

`knowledge_graph/data/` is runtime/generated data and is intentionally excluded from source control. Public releases should include only small sanitized samples under `knowledge_graph/data/sample/`, with dataset attribution and license notes where applicable.

This project is intended for local research and academic use. Do not expose Streamlit, Neo4j, or internal APIs directly to the Internet without authentication, network controls, TLS, and rotated credentials.

## Requirements

Recommended local environment:

- Python 3.11 or newer.
- Git.
- Node.js and npm.
- Docker and Docker Compose, if using the containerized workflow.
- Neo4j 5.x, either local, Docker-hosted, or reachable through a configured Bolt URI.
- Semgrep for reachability analysis.
- `@cyclonedx/cdxgen` for SBOM generation.

Optional API keys:

- `GITHUB_TOKEN` for GitHub API rate limits and repository metadata calls.
- `NVD_API_KEY` or `NVD_API_KEYS` for NVD enrichment.
- `VULNCHECK_API_KEY` for additional vulnerability intelligence, if supported by the pipeline configuration.
- `ANTHROPIC_API_KEY` or `OPENROUTER_API_KEY` for optional LLM-assisted report/advisory interpretation.

## Environment Setup

Copy `.env.example` to `.env` and fill in local values:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Never commit `.env`. The example file must contain placeholders only.

Important variables:

| Variable | Purpose |
| --- | --- |
| `NEO4J_URI` | Neo4j Bolt URI. |
| `NEO4J_USER` | Neo4j username. |
| `NEO4J_PASSWORD` | Neo4j password. Use a real local value in `.env`, not in Git. |
| `NEO4J_DATABASE` | Neo4j database name. |
| `GITHUB_TOKEN` | Optional GitHub API token. |
| `NVD_API_KEY` / `NVD_API_KEYS` | Optional NVD enrichment keys. |
| `VULNCHECK_API_KEY` | Optional VulnCheck enrichment key. |
| `LLM_PROVIDER` | `anthropic` or `openrouter`. |
| `ANTHROPIC_API_KEY` | Optional Anthropic key. |
| `OPENROUTER_API_KEY` | Optional OpenRouter key. |
| `USER_REPO_CLONE_DIR` | Runtime directory for repositories cloned through the dashboard. |
| `ALLOW_UNTRUSTED_DEPENDENCY_INSTALL` | Set to `true` only if you explicitly accept the risk of installing dependencies from cloned repositories. Defaults to disabled. |

## Installation

```bash
git clone <repo-url>
cd SBOM
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Windows PowerShell:

```powershell
git clone <repo-url>
cd SBOM
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Install `cdxgen` if you plan to generate SBOMs locally:

```bash
npm install -g @cyclonedx/cdxgen
```

## Running with Docker

```bash
docker compose up -d --build
```

The dashboard is exposed locally on port `8501` by default. Docker Compose is intended for local development and research use. Do not expose the Streamlit app or Neo4j directly to the Internet without authentication, reverse proxy controls, TLS, and network restrictions.

`docker-compose.yml` mounts `knowledge_graph/data/` as runtime storage. That directory is intentionally ignored by Git.

## Running the Dashboard

From the repository root:

```bash
streamlit run gui_retrieval/main.py --server.port 8501
```

Then open:

```text
http://localhost:8501
```

The dashboard can ingest a GitHub repository, generate an SBOM, query vulnerability data, import results into Neo4j, run reachability analysis, and display alerts/reports.

## Data Generation

The public repository does not include the full generated research dataset. Users must generate their own runtime data by running the ingestion and analysis workflows.

Runtime outputs are written under `knowledge_graph/data/`, including:

- cloned repositories;
- generated SBOM JSON files;
- vulnerability enrichment JSON files;
- Semgrep rule files;
- reachability result JSON files;
- SQLite databases and caches;
- optional LLM outputs.

These files are intentionally excluded from source control. If you publish a separate dataset or release artifact, review it for secrets, local paths, third-party licensing, exploit/PoC content, and attribution requirements.

## Testing and Validation

Compile-check the Python source:

```bash
python -m compileall knowledge_graph gui_retrieval tune_risk_weights.py
```

If your environment has the test dependencies installed, run the unit test suite:

```bash
python -m unittest discover -s gui_retrieval/tests
```

Optional security and quality tools, when installed:

```bash
bandit -r .
semgrep scan --config auto .
pip-audit
ruff check .
```

## Limitations

- This is a research prototype, not a production-grade scanner.
- SBOM and vulnerability results depend on third-party tools and external data sources.
- Reachability analysis can produce false positives and false negatives.
- Generated Semgrep rules are heuristic and should be reviewed.
- LLM-assisted interpretation is optional and should not be treated as authoritative.
- Results require manual validation before remediation, reporting, or compliance use.
- External vulnerability sources and APIs may change over time.

## Security Review Notes for Operators

- Repository ingestion is restricted to GitHub-style `owner/repo` inputs in the dashboard flow.
- Cloned repositories are untrusted input. Do not run this system with privileged credentials.
- Dependency installation from cloned repositories is disabled by default for safety. Set `ALLOW_UNTRUSTED_DEPENDENCY_INSTALL=true` only in an isolated environment.
- Advisory and patch fetching should be treated as outbound network access. Keep the system on a controlled network when processing untrusted data.

## License

This project is released under the MIT License. See `LICENSE` for details.

## Citation / Academic Use

If you use this project in academic or research work, cite the repository name, commit hash, and the date you accessed it. If you publish derived datasets or benchmark results, include the data source, generation process, and license/attribution notes.

## Contributing

Contributions are welcome through pull requests. Please keep generated data, credentials, local databases, and runtime artifacts out of Git. For security-sensitive reports, follow `SECURITY.md` instead of opening a public issue with sensitive details.
