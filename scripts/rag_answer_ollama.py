import sys, subprocess, chromadb

persist_dir = sys.argv[1]
model_name = sys.argv[2]
question = " ".join(sys.argv[3:])

client = chromadb.PersistentClient(path=persist_dir)
col = client.get_collection("sbom_kb")

res = col.query(query_texts=[question], n_results=8)

hits = []
for doc, meta, _id in zip(res["documents"][0], res["metadatas"][0], res["ids"][0]):
    hits.append((doc, meta, _id))

context = "\n\n".join(
    [f"[{i+1}] id={_id} type={meta.get('type')} purl={meta.get('purl','')}\n{doc}"
     for i, (doc, meta, _id) in enumerate(hits)]
)

system = """Bạn là trợ lý an ninh phần mềm. Nhiệm vụ: giải thích SBOM + kết quả truy xuất từ KB cho người không chuyên (PM/QA/Manager).

Quy tắc:
- Chỉ dựa vào CONTEXT. Nếu thiếu dữ liệu vuln thì nói rõ "chưa thấy vuln theo OSV trong dữ liệu hiện có".
- Không bịa CVE/OSV IDs. Không kết luận "an toàn tuyệt đối".
- Viết tiếng Việt dễ hiểu, ngắn gọn, ưu tiên bullet.

Output bắt buộc theo cấu trúc:
1) Tóm tắt 5 dòng
2) Điều đáng chú ý (top 3)
3) Rủi ro & tác động (business)
4) Khuyến nghị hành động (cụ thể, ưu tiên)
5) Độ tin cậy (High/Medium/Low) + lý do
"""

user = f"""CÂU HỎI:
{question}

CONTEXT:
{context}
"""

prompt = system + "\n\n" + user

p = subprocess.run(
    ["ollama", "run", model_name],
    input=prompt.encode("utf-8"),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

if p.returncode != 0:
    print("ERROR calling ollama:")
    print(p.stderr.decode("utf-8", errors="ignore"))
    sys.exit(1)

print(p.stdout.decode("utf-8", errors="ignore"))
