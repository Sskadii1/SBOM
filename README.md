# SBOM Security Dashboard

Hệ thống phân tích bảo mật phụ thuộc phần mềm dựa trên SBOM, Neo4j, Semgrep và Streamlit. Repo này kết hợp 2 phần chính:

- `knowledge_graph/`: pipeline thu thập source, sinh SBOM, truy vấn lỗ hổng, import vào Neo4j và chạy reachability scan.
- `gui_retrieval/`: dashboard Streamlit để xem alert, báo cáo cho stakeholder/developer, query workbench và ingest nhanh một repo GitHub.

## Mục lục

- [1. Tổng quan](#1-tổng-quan)
- [2. Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
- [3. Tính năng chính](#3-tính-năng-chính)
- [4. Cấu trúc thư mục](#4-cấu-trúc-thư-mục)
- [5. Yêu cầu môi trường](#5-yêu-cầu-môi-trường)
- [6. Cài đặt local](#6-cài-đặt-local)
- [7. Cấu hình biến môi trường](#7-cấu-hình-biến-môi-trường)
- [8. Chạy ứng dụng](#8-chạy-ứng-dụng)
- [9. Quy trình sử dụng điển hình](#9-quy-trình-sử-dụng-điển-hình)
- [10. CLI tham khảo](#10-cli-tham-khảo)
- [11. Dữ liệu sinh ra](#11-dữ-liệu-sinh-ra)
- [12. Testing và kiểm tra nhanh](#12-testing-và-kiểm-tra-nhanh)
- [13. Vận hành và mở rộng](#13-vận-hành-và-mở-rộng)

## 1. Tổng quan

Repo này phục vụ bài toán phân tích rủi ro thư viện/phụ thuộc của source code theo luồng:

1. Clone hoặc cập nhật repository.
2. Sinh SBOM bằng `cdxgen`.
3. Truy vấn lỗ hổng qua OSV, enrich thêm CVSS/EPSS/KEV.
4. Import dữ liệu vào Neo4j theo graph model `Project -> SBOM -> Component -> Vulnerability`.
5. Dùng Semgrep để đánh giá reachability của sink liên quan tới CVE.
6. Hiển thị kết quả trên dashboard và sinh báo cáo kỹ thuật/quản trị.

Repo hỗ trợ 2 cách dùng chính:

- Dùng GUI để ingest nhanh 1 repository GitHub và xem kết quả ngay.
- Dùng CLI trong `knowledge_graph` để chạy batch ingest theo ground-truth hoặc batch reachability scan.

## 2. Kiến trúc hệ thống

```text
GitHub repo / ground-truth dataset
  -> clone / update source code
  -> cdxgen sinh CycloneDX SBOM
  -> OSV + enrichment (CVSS / EPSS / KEV)
  -> import Neo4j knowledge graph
  -> sink intelligence (SQLite)
  -> Semgrep reachability scan
  -> JSON + SQLite reachability cache
  -> Streamlit dashboard / reports / query workbench
```

Các entrypoint quan trọng:

| Thành phần | File chính | Vai trò |
| --- | --- | --- |
| Ingestion pipeline | `knowledge_graph/pipeline.py` | Chạy crawl, SBOM, vulnerability check và import Neo4j |
| Reachability pipeline | `knowledge_graph/pipeline_v2.py` | Tải CVE từ Neo4j, lấy sink data, chạy Semgrep |
| Batch Semgrep | `knowledge_graph/run_semgrep_sync_from_neo4j.py` | Quét reachability cho toàn bộ project đang có trong Neo4j |
| Re-enrichment | `knowledge_graph/re_enrich_neo4j_vulns.py` | Làm giàu lại node `Vulnerability` trong Neo4j |
| GUI app | `gui_retrieval/main.py` | Dashboard Streamlit |
| One-click repo ingest trong GUI | `gui_retrieval/backend/services/repo_pipeline_service.py` | Pipeline đầy đủ cho 1 repo GitHub |

## 3. Tính năng chính

- Dashboard theo repository với các tab `Security Alerts`, `Stakeholder Report`, `Developer Report`.
- Dashboard enterprise để xem tổng quan toàn danh mục repository.
- Query Workbench hỗ trợ filter bằng query text hoặc expression builder.
- Upload/ingest một GitHub repository trực tiếp từ UI.
- Sinh báo cáo stakeholder và developer với fallback deterministic hoặc narrative qua LLM.
- Export PDF cho report bằng WeasyPrint hoặc headless Chrome/Edge.
- Reachability scoring với các verdict:
  - `confirmed_reachable`
  - `likely_reachable`
  - `no_sink_data`
  - `likely_unreachable`
- Lưu trạng thái xử lý case và verification delta giữa các lần scan.

## 4. Cấu trúc thư mục

```text
.
|- Dockerfile
|- docker-compose.yml
|- requirements.txt
|- .env.example
|- knowledge_graph/
|  |- pipeline.py
|  |- pipeline_v2.py
|  |- run_semgrep_sync_from_neo4j.py
|  |- re_enrich_neo4j_vulns.py
|  |- modules/
|  |  |- crawler/
|  |  |- sbom/
|  |  |- vulnerability/
|  |  |- graph/
|  |  |- agents/
|  |  |- utils/
|  |- data/
|     |- metadata/
|     |- vulnerable_repos/
|     |- vulnerable_sboms/
|     |- vulnerable_vulnerabilities/
|     |- reachability/
|     |- rules/
|     |- cve_sinks.db
|- gui_retrieval/
|  |- main.py
|  |- backend/
|  |  |- config.py
|  |  |- repositories/
|  |  |- services/
|  |  |- templates/
|  |- frontend/
|  |  |- views/
|  |  |- components/
|  |- tests/
```

## 5. Yêu cầu môi trường

Tối thiểu nên có:

- Python `3.11+`
- Git
- Node.js + npm
- Neo4j `5.x`
- `@cyclonedx/cdxgen` cài global qua npm
- Semgrep

Nếu muốn dùng đầy đủ report/PDF:

- `weasyprint` và các thư viện hệ thống tương ứng
- Hoặc Chrome/Edge headless để fallback export PDF

Nếu muốn dùng AI narrative hoặc AI sink fallback:

- Anthropic API key hoặc OpenRouter API key

## 6. Cài đặt local

### 6.1. Clone repo và tạo môi trường Python

```bash
git clone <your-repo-url>
cd SBOM
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

### 6.2. Cài dependency Python

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 6.3. Cài `cdxgen`

```bash
npm install -g @cyclonedx/cdxgen
```

### 6.4. Chuẩn bị Neo4j

Khởi động Neo4j ở local hoặc máy host khác, sau đó bảo đảm truy cập được qua `bolt://localhost:7689` hoặc URI bạn cấu hình trong `.env`.

## 7. Cấu hình biến môi trường

Tạo file `.env` từ mẫu:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Biến quan trọng:

| Biến | Ý nghĩa |
| --- | --- |
| `NEO4J_URI` | URI kết nối Neo4j |
| `NEO4J_USER` | User Neo4j |
| `NEO4J_PASSWORD` | Password Neo4j |
| `NEO4J_DATABASE` | Database Neo4j đang dùng |
| `GITHUB_TOKEN` | Token để gọi GitHub API / clone flow |
| `NVD_API_KEY` hoặc `NVD_API_KEYS` | Key enrich NVD |
| `VULNCHECK_API_KEY` | Key bổ sung cho enrichment |
| `LLM_PROVIDER` | `anthropic` hoặc `openrouter` |
| `ANTHROPIC_API_KEY` | Key Anthropic |
| `OPENROUTER_API_KEY` | Key OpenRouter |
| `LLM_MODEL` | Model mặc định cho narrative / AI fallback |
| `CVE_SINKS_DB` | Đường dẫn SQLite cache sink/reachability |
| `USER_REPO_CLONE_DIR` | Thư mục clone repo từ UI upload |

Lưu ý:

- `gui_retrieval/backend/config.py` sẽ load root `.env` trước, rồi mới ưu tiên `gui_retrieval/.env` nếu có.
- Trong Docker, nếu app chạy trong container và `NEO4J_URI` đang trỏ tới `localhost`, code sẽ tự rewrite sang `host.docker.internal` để dễ kết nối host Neo4j hơn.

## 8. Chạy ứng dụng

### 8.1. Chạy dashboard local

Từ root repo:

```bash
streamlit run gui_retrieval/main.py --server.port 8501
```

Truy cập:

```text
http://localhost:8501
```

### 8.2. Chạy bằng Docker Compose

Repo hiện build một container `app`, phù hợp cho cách chạy gọn nhẹ của dashboard và pipeline ứng dụng.

```bash
docker compose up --build
```

Port mặc định của dashboard:

```text
http://localhost:8501
```

### 8.3. Chạy pipeline qua UI

Trong tab `Upload Repository`, hệ thống hỗ trợ:

- `GitHub Repository (Latest Commit)`
- `GitHub Repository (Custom Commit)`
- Tùy chọn `Use parent commit`
- Tùy chọn `Enable AI fallback for missing sink data`

Luồng này sẽ:

1. Clone hoặc update repo.
2. Sinh SBOM.
3. Query OSV.
4. Import Neo4j.
5. Chạy Semgrep reachability.
6. Refresh cache UI và chuyển về tab `Security Alerts`.

## 9. Quy trình sử dụng điển hình

### 9.1. Trường hợp nhanh nhất cho demo

1. Khởi động Neo4j.
2. Cấu hình `.env`.
3. Chạy Streamlit.
4. Vào tab `Upload Repository`.
5. Nhập `owner/repo` hoặc URL GitHub.
6. Đợi pipeline hoàn tất.
7. Xem:
   - `Security Alerts`
   - `Stakeholder Report`
   - `Developer Report`
   - `Enterprise Security Overview`

### 9.2. Trường hợp batch qua CLI

1. Chuẩn bị ground-truth JSON hoặc metadata repo.
2. Chạy `knowledge_graph/pipeline.py`.
3. Chạy `knowledge_graph/pipeline_v2.py` hoặc batch Semgrep.
4. Mở GUI để xem kết quả.

## 10. CLI tham khảo

### 10.1. `knowledge_graph/pipeline.py`

File này điều phối ingest. Các `--steps` hợp lệ hiện tại:

- `get-link`
- `crawl`
- `vuln-crawl`
- `sbom`
- `vuln-sbom`
- `vuln-check`
- `vuln-vuln-check`
- `neo4j`
- `vuln-neo4j`

#### Chạy full vulnerable flow bằng ground-truth

```bash
cd knowledge_graph
python pipeline.py \
  --vulnerable-groundtruth-file dependabot_groundtruth_javascript.json \
  --max-vulnerable-records 20 \
  --neo4j-uri bolt://localhost:7689
```

Ghi chú:

- Khi không truyền `--steps`, `pipeline.py` hiện đi theo vulnerable flow dùng ground-truth.
- Đây là CLI riêng của `knowledge_graph`; UI upload không gọi trực tiếp file này mà đi qua `repo_pipeline_service.py`.

### 10.2. `knowledge_graph/pipeline_v2.py`

Dùng để đánh giá reachability sau khi project đã có trong Neo4j.

#### Scan đầy đủ cho 1 project

```bash
cd knowledge_graph
python pipeline_v2.py \
  --project "owner/repo" \
  --repo "data/user_repos/owner_repo" \
  --neo4j-uri bolt://localhost:7688 \
  --save
```

#### Scan không dùng AI fallback

```bash
cd knowledge_graph
python pipeline_v2.py \
  --project "owner/repo" \
  --repo "data/user_repos/owner_repo" \
  --neo4j-uri bolt://localhost:7688 \
  --save \
  --no-ai
```

#### Kiểm tra coverage sink data

```bash
cd knowledge_graph
python pipeline_v2.py \
  --project "owner/repo" \
  --check-coverage \
  --neo4j-uri bolt://localhost:7688
```

#### Xem cached reachability

```bash
cd knowledge_graph
python pipeline_v2.py \
  --project "owner/repo" \
  --show-cached
```

#### Import JSON sink data thủ công

```bash
cd knowledge_graph
python pipeline_v2.py \
  --import-ai data/ai_output/batch_001.json
```

### 10.3. Batch Semgrep cho toàn bộ project trong Neo4j

```bash
cd knowledge_graph
python run_semgrep_sync_from_neo4j.py \
  --neo4j-uri bolt://localhost:7688 \
  --neo4j-user neo4j \
  --neo4j-password password \
  --neo4j-database neo4j
```

Tùy chọn hữu ích:

- `--limit`
- `--no-ai`
- `--dry-run`

### 10.4. Re-enrich toàn bộ vulnerability node trong Neo4j

```bash
cd knowledge_graph
python re_enrich_neo4j_vulns.py \
  --neo4j-uri bolt://localhost:7688 \
  --neo4j-user neo4j \
  --neo4j-password password
```

## 11. Dữ liệu sinh ra

Các artifact quan trọng:

| Đường dẫn | Ý nghĩa |
| --- | --- |
| `knowledge_graph/data/cve_sinks.db` | SQLite lưu advisory cache, sink metadata, reachability results, case/report state |
| `knowledge_graph/data/reachability/*.json` | Kết quả Semgrep reachability theo project |
| `knowledge_graph/data/rules/*.yaml` | Rule Semgrep sinh tự động |
| `knowledge_graph/data/metadata/repos_metadata.json` | Metadata repo của flow thường |
| `knowledge_graph/data/metadata/vulnerable_repos_metadata.json` | Metadata repo của vulnerable flow |
| `knowledge_graph/data/sboms/` | SBOM của flow thường |
| `knowledge_graph/data/vulnerabilities/` | Kết quả lỗ hổng của flow thường |
| `knowledge_graph/data/vulnerable_sboms/` | SBOM của vulnerable flow |
| `knowledge_graph/data/vulnerable_vulnerabilities/` | Kết quả vulnerability của vulnerable flow |
| `knowledge_graph/data/user_repos/` | Repo clone chủ yếu từ flow upload trong GUI |
| `.report_export_tmp/` | File tạm phục vụ export PDF |

Graph model chính trong Neo4j:

- Node:
  - `Project`
  - `SBOM`
  - `Component`
  - `Vulnerability`
  - `Location`
- Relationship:
  - `GENERATED_SBOM`
  - `HAS_COMPONENT`
  - `DEPENDS_ON`
  - `AFFECTED_BY`
  - `HAS_VULNERABILITY`
  - `DECLARED_IN`
  - `USES_DIRECT`

## 12. Testing và kiểm tra nhanh

### 12.1. Unit test GUI/report/query

```bash
python -m unittest \
  gui_retrieval.tests.test_decision_tiering \
  gui_retrieval.tests.test_case_state_service \
  gui_retrieval.tests.test_report_builders \
  gui_retrieval.tests.test_report_export \
  gui_retrieval.tests.test_repo_pipeline_service \
  gui_retrieval.tests.test_query_workbench \
  gui_retrieval.tests.test_verification_delta
```

### 12.2. Compile check

```bash
python -m compileall -f gui_retrieval/backend gui_retrieval/frontend gui_retrieval/main.py
```

### 12.3. Sinh thử report bundle không cần LLM

```bash
python -c "import sys; sys.path.insert(0,'gui_retrieval'); from backend.services.report_service import generate_report_bundle; bundle=generate_report_bundle('qws941/splunk', use_llm=False); print(bundle['stakeholder_report']['posture_summary']['total_cases'], bundle['developer_report']['triage_summary']['total_cases'])"
```

## 13. Vận hành và mở rộng

Repo được tổ chức theo hướng dễ demo, dễ vận hành và cũng thuận tiện để mở rộng tiếp:

- Có thể chạy nhanh qua Streamlit cho demo và review nghiệp vụ.
- Có thể chạy theo từng bước bằng CLI để phục vụ batch ingest hoặc automation.
- Dữ liệu trung gian được lưu rõ ràng trong `knowledge_graph/data`, thuận tiện cho việc kiểm tra và tái sử dụng.
- Report layer, graph layer, query layer và ingestion layer đã được tách module khá rõ, giúp bảo trì và nâng cấp dễ hơn.
- Phần narrative/report vẫn hoạt động tốt cả khi bật hoặc không bật LLM, phù hợp cho nhiều môi trường triển khai.

## Gợi ý bắt đầu nhanh

Nếu mục tiêu là chạy được end-to-end nhanh nhất:

1. Cấu hình `.env`.
2. Chạy Neo4j.
3. Cài Python dependencies + `cdxgen`.
4. Chạy `streamlit run gui_retrieval/main.py --server.port 8501`.
5. Vào `Upload Repository` và ingest một repo GitHub.
6. Kiểm tra `Security Alerts`, `Stakeholder Report`, `Developer Report`.
