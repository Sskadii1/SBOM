# SBOM Vulnerability Analysis Pipeline

Incremental pipeline for scanning dependency vulnerabilities:
- Clone repos from `repos_link.txt`
- Generate SBOM for new repos
- Check OSV for new repos
- Import into Neo4j for new repos

All steps support **skip if already processed**.

## 1) Data Flow

1. `modules/crawler/github_crawler.py`
2. `modules/sbom/sbom_generator.py`
3. `modules/vulnerability/osv_checker.py`
4. `modules/graph/neo4j_integration.py`

## 2) Incremental Files

- `data/metadata/repos_link.txt`
  - Source repo list (one per line: `owner/repo` or GitHub URL)
- `data/metadata/repos_metadata.json`
  - Repo metadata and clone status
- `data/sboms/*.json`
  - SBOM output per repo
- `data/sboms/sbom_summary.json`
  - Merged SBOM summary (incremental)
- `data/vulnerabilities/*_vulnerabilities.json`
  - Vulnerability results per repo
- `data/vulnerabilities/vulnerability_summary.json`
  - Merged vulnerability summary (incremental)
- `data/metadata/neo4j_imported_repos.json`
  - List of repos already imported into graph (used to skip on re-run)

## 3) Setup

### Requirements

- Python 3.8+
- Node.js + npm
- Docker + Docker Compose
- Git

### Install Python deps

```bash
pip install -r requirements.txt
```

### Install cdxgen

```bash
npm install -g @cyclonedx/cdxgen
```

### Start Neo4j

```bash
docker-compose up -d
```

Neo4j defaults:
- UI: `http://localhost:7474`
- Bolt: `bolt://localhost:7687`
- User: `neo4j`
- Password: `password`

### Environment variables

Create a `.env` file at the project root:

```env
GITHUB_TOKEN=your_github_token
NVD_API_KEY=your_nvd_key_1,your_nvd_key_2
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
```

> **NVD API Key:** Without a key, OSV enrichment will be rate-limited by the NVD API.
> Multiple keys separated by commas are supported for load balancing.
> The `.env` file must be placed at the **project root** (same directory as `pipeline.py`).

## 4) Usage

### Full pipeline

```bash
python pipeline.py
```

### Step by step

```bash
python github_crawler.py
python sbom_generator.py
python osv_checker.py
python neo4j_integration.py
```

### Get Link

Chạy bước này để tìm ngẫu nhiên repo trên GitHub trước khi chạy crawler (pipeline từ số 0).

```bash
python get_link_github.py -js      # JavaScript only
python get_link_github.py -py      # Python only
python get_link_github.py -js -py  # both
```
#### Cơ chế chọn repository mặc định

Theo mặc định, hệ thống sẽ **tìm và chọn ngẫu nhiên 20 repository** trên GitHub thỏa mãn các điều kiện lọc đã định nghĩa.

#### Danh sách từ khóa loại trừ (Blacklist)

Các repository có chứa một trong các từ khóa sau trong **tên hoặc mô tả** sẽ bị loại bỏ khỏi quá trình thu thập dữ liệu:

- awesome
- tutorial
- example
- demo
- boilerplate
- starter
- template
- learning
- course
- sample

#### Phân loại theo ngôn ngữ

Các repository sau khi được thu thập sẽ được phân loại theo ngôn ngữ lập trình như sau:

| Ngôn ngữ | Tiêu đề section |
|----------|----------------|
| JavaScript / TypeScript | `# NodeJS - JavaScript, TypeScript` |
| Python | `# Python` |

Output file: `data/metadata/repos-link.txt`.
The script appends by language section and skips duplicate repo URLs.

## 5) Module Logic

### Crawler

- Reads `repos_link.txt`
- Already cloned repo → `clone_status=already_exists`
- New repo → clone
- Updates `repos_metadata.json`

### SBOM Generator

- Repo already has SBOM file → skip `cdxgen`
- New repo → run `cdxgen`
- Merges results into `sbom_summary.json`

#### cdxgen — NodeJS (default)

```bash
python sbom_generator.py
# hoặc
python sbom_generator.py -p nodejs
```

Command được chạy:
```
cdxgen <repo_path> -o <output_file> --no-install
```

- `--no-install`: ngăn cdxgen tự chạy `npm install` / `yarn install`.  
  cdxgen đọc trực tiếp từ **lock file** (`package-lock.json`, `yarn.lock`) thay vì quét `node_modules`.  
  → Tránh timeout do cài và quét toàn bộ dependencies.

#### cdxgen — Python

```bash
python sbom_generator.py -p python
```

Command được chạy:
```
cdxgen <repo_path> -o <output_file> -t python --deep
```

Trước khi chạy cdxgen, pipeline sẽ tự động:
1. Tạo **virtual environment** (`.venv`) trong thư mục repo
2. Cài dependencies từ `requirements.txt` (hoặc `requirements-dev.txt`, `requirements-prod.txt`) vào venv
3. Chạy `cdxgen` với `-t python --deep` để phân tích đầy đủ dependency tree

> **Lưu ý:** Nếu không tìm thấy file `requirements*.txt`, bước `pip install` bị bỏ qua và cdxgen vẫn chạy.


### OSV Checker

- Repo already has vulnerability file → skip
- New repo → check via:
  - `POST /v1/querybatch` in batches of `500–700` PURLs (default 600)
  - `GET /v1/vulns/{id}` for details
- Merges results into `vulnerability_summary.json`

### Neo4j Integration

- Repo already in `neo4j_imported_repos.json` → skip
- New repo → import into graph
- On success → write to `neo4j_imported_repos.json`
- `clear_graph()` resets both the graph and the import metadata file

## 6) Useful Commands

```bash
# Skip some steps
python pipeline.py --repo-links-file data/metadata/repos_link.txt --skip-crawl --skip-sbom

# Clear Neo4j before import
python pipeline.py --repo-links-file data/metadata/repos_link.txt --clear-neo4j

# Custom Neo4j credentials
python pipeline.py --repo-links-file data/metadata/repos_link.txt \
  --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password yourpass
```

## 7) Graph Schema

Nodes:
- `Project`
- `SBOM`
- `Component`
- `Location`
- `Vulnerability`

Relationships:
- `(Project)-[:GENERATED_SBOM]->(SBOM)`
- `(SBOM)-[:HAS_COMPONENT]->(Component)`
- `(Project)-[:USES]->(Component)`
- `(Component)-[:DEPENDS_ON]->(Component)`
- `(Component)-[:AFFECTED_BY]->(Vulnerability)`
- `(Project)-[:HAS_VULNERABILITY]->(Vulnerability)`
- `(Component)-[:DECLARED_IN]->(Location)`

> **Note:** `Location.key` is scoped per SBOM (`{scan_id}::{path}:{line}`), so locations from different projects are always distinct even if they share the same file path.

## 8) Logging

All modules log to **stdout** only — no log files are created.

## License

MIT

