import sys, chromadb
from sentence_transformers import SentenceTransformer

persist_dir = sys.argv[1]
question = " ".join(sys.argv[2:])

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path=persist_dir)
col = client.get_collection("sbom_kb")

qemb = model.encode([question]).tolist()
res = col.query(query_embeddings=qemb, n_results=6)

for i, (doc, meta, _id) in enumerate(zip(res["documents"][0], res["metadatas"][0], res["ids"][0]), 1):
    print(f"\n--- HIT {i} | id={_id} | type={meta.get('type')} | purl={meta.get('purl','')}")
    print(doc[:800])
