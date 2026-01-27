1.Reg
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

2. concept
python scripts/parse_any_spdx.py path/to/sbom.json
python scripts/export_packages_from_dataset.py path/to/sbom.json ./packages.csv
python scripts/osv_enrich_smart.py ./packages.csv ./findings.json
python scripts/report_md.py ./findings.json ./report.md

3. phan llm
python scripts/build_corpus.py path/to/sbom.json ./findings.json ./corpus.jsonl
python scripts/index_chroma.py ./corpus.jsonl ./chroma_store
python scripts/rag_retrieve.py ./chroma_store "SBOM này có rủi ro gì?"
python scripts/rag_answer_ollama.py ./chroma_store llama3 "SBOM này có rủi ro gì?"
