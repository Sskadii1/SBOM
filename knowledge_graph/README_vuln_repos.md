# Vulnerable Repos Flow (Quick Guide)

This guide describes the **vulnerable repositories** flow only. It assumes you already generated the Dependabot ground-truth JSON and cloned the vulnerable repos.

## Prerequisites

- Docker running
- Neo4j old instance on ports `7475/7688` (for reference/migration)
- Neo4j new instance on ports `7476/7689` (for new architecture)

Example container:

```bash
docker run -d --name vuln_repos_neo4j -p 7475:7474 -p 7688:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest
```

## Four Steps (Vuln Flow)

Run these from the `knowledge_graph` folder.

### 1) Crawl vulnerable repos from ground-truth

```bash
cd knowledge_graph
python3 github_crawler.py --vuln-repos --vuln-language javascript
```

Outputs:
- `data/vulnerable_repos/`
- `data/metadata/vulnerable_repos_metadata.json`

### 2) Generate SBOMs for vulnerable repos

```bash
cd knowledge_graph
python3 sbom_generator.py --vuln-repos
```

Outputs:
- `data/vulnerable_sboms/`
- `data/vulnerable_sboms/vulnerable_sbom_summary.json`

### 3) Check vulnerabilities (OSV)

```bash
cd knowledge_graph
python3 osv_checker.py --vuln-repos
```

Outputs:
- `data/vulnerable_vulnerabilities/`
- `data/vulnerable_vulnerabilities/vulnerable_vulnerability_summary.json`

### 4) Import into Neo4j (new architecture on 7689)

```bash
cd knowledge_graph
python3 neo4j_integration.py --vuln-repos
```

Metadata log:
- `data/metadata/neo4j_imported_vuln_repos.json`

Neo4j Browser:
- `http://localhost:7476`
- Connect with `bolt://localhost:7689`

## Notes

- `--vuln-language` supports `javascript` or `python`.
- `--vuln-repos` uses default vuln paths and now imports to Neo4j port `7689`.
