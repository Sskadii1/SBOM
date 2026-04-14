# Pipeline End-to-End Diagram (Current Implementation)

## 1) Main Batch Pipeline (`knowledge_graph/pipeline.py`)

```mermaid
flowchart TD
    A["run_full_pipeline()"] --> B["Step 0: run_step_0_get_link()"]
    B --> C["modules/get_link/get_link_github.py\nBuild repos_link.txt"]
    A --> D["Step 1: run_step_1_crawl()"]
    D --> E["modules/crawler/github_crawler.py\ncrawl_from_file()"]
    E --> E1["GitHub REST API\nGET /repos/{owner}/{repo}"]
    E --> E2["git clone --depth 1"]
    E --> E3["data/metadata/repos_metadata.json"]

    A --> F["Step 2: run_step_2_sbom()"]
    F --> G["modules/sbom/sbom_generator.py\ngenerate_batch()"]
    G --> G1["cdxgen (CycloneDX SBOM)"]
    G --> G2["data/sboms/*_sbom.json\n+ sbom_summary.json"]

    A --> H["Step 3: run_step_3_vulnerability_check()"]
    H --> I["modules/vulnerability/osv_checker.py\nprocess_sbom_results()"]
    I --> I1["OSV API\nPOST /v1/querybatch"]
    I --> I2["OSV API\nGET /v1/vulns/{id}"]
    I --> J["modules/vulnerability/enrichment.py\nVulnerabilityEnricher"]
    J --> J1["NVD API\nGET /rest/json/cves/2.0?cveId=..."]
    J --> J2["FIRST EPSS API\nGET /data/v1/epss?cve=..."]
    J --> J3["CISA KEV JSON feed"]
    I --> I3["data/vulnerabilities/*_vulnerabilities.json\n+ vulnerability_summary.json"]

    A --> K["Step 4: run_step_4_neo4j_import()"]
    K --> L["modules/graph/neo4j_integration.py\nimport_batch()"]
    L --> L1["Neo4j\nProject/SBOM/Component/Vulnerability/Location nodes\n+ relationships"]
    L --> L2["data/metadata/neo4j_imported_repos*.json"]
```

## 2) Reachability Pipeline (`knowledge_graph/pipeline_v2.py`)

```mermaid
flowchart TD
    P["pipeline_v2.py main()"] --> P1["load_project_vulns() from Neo4j"]
    P1 --> P1a["Canonical vuln id in query:\ncoalesce(CVE alias, v.id, any alias)"]
    P --> P2["missing_vulns() from sink_db"]
    P2 --> P3{"Missing sink data?"}
    P3 -- Yes --> P4["auto_extract_sinks()\nVulnIntelAgent (OSV + LLM fallback)"]
    P4 --> P5["insert_sinks() into cve_sinks.db"]
    P3 -- No --> P6["SemgrepAgent.scan(vuln_ids)"]
    P5 --> P6

    P6 --> P7["generate_rules() from sink metadata"]
    P7 --> P8["run_semgrep() on repo"]
    P8 --> P9["parse_findings() => verdicts\nconfirmed/likely/unreachable/no_sink_data"]
    P9 --> P10["save_reachability() to SQLite"]
    P9 --> P11["save() to data/reachability/{project}_reachability.json"]
```

## 3) GUI Read/LLM Flow (`gui_retrieval`)

```mermaid
flowchart TD
    U["Streamlit GUI"] --> U1["backend/repositories/graph_repository.py\nget_alerts/get_vuln_detail/..."]
    U1 --> U2["Read Neo4j graph data"]
    U1 --> U3["Load reachability JSON/DB\nmerge by vuln_id"]
    U --> U4["backend/services/llm_service.py\nrun_pipeline()"]
    U4 --> U5["KnowledgeRetriever (retrieval_scenarios.py Cypher)"]
    U5 --> U2
    U4 --> U6["semgrep_context_service.py\nenrich_evidence_with_semgrep()"]
    U6 --> U7["cve_sinks.db + reachability json"]
    U4 --> U8["OpenRouter Chat Completions API"]
```

## 4) CVE Mapping Logic (Where IDs Become “CVE” vs “GHSA”)

### A. During OSV ingest (`osv_checker.py`)
- Vulnerability object identity is stored as `vuln.id` from OSV detail.
- If OSV detail `id` is `GHSA-...`, then Neo4j node `Vulnerability.id` is GHSA.
- CVE aliases are taken from `vuln.aliases` (if present) and stored into `v.aliases`.
- Enrichment (`EPSS/CVSS/KEV`) is only attempted when at least one CVE is available in aliases.

### B. During query/render (`graph_repository.py`, `pipeline_v2.py`, `retrieval_scenarios.py`)
- Canonical vuln id is resolved with:
  - `head(alias STARTS WITH 'CVE-')`
  - fallback `v.id`
  - fallback `head(v.aliases)`
- Therefore:
  - If a CVE alias exists, UI/pipeline tends to show CVE.
  - If no CVE alias exists, system shows GHSA id.

## 5) External APIs / Tools Used

- GitHub REST API: `https://api.github.com/repos/{owner}/{repo}`
- Git (clone/fetch)
- cdxgen (CycloneDX SBOM generator)
- OSV querybatch: `https://api.osv.dev/v1/querybatch`
- OSV vuln detail: `https://api.osv.dev/v1/vulns/{id}`
- NVD CVE API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- CISA KEV feed:
  - `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`
  - fallback `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Semgrep CLI
- OpenRouter Chat Completions (LLM layer)

## 6) Persisted Artifacts by Stage

- Crawl metadata: `data/metadata/repos_metadata.json`
- SBOM: `data/sboms/*_sbom.json` + `sbom_summary.json`
- Vulnerability cache: `data/vulnerabilities/*_vulnerabilities.json` + `vulnerability_summary.json`
- Graph import ledger: `data/metadata/neo4j_imported_repos*.json`
- Sink/reachability DB: `data/cve_sinks.db`
- Semgrep rules: `data/rules/*_rules.yaml`
- Reachability results: `data/reachability/*_reachability.json`
