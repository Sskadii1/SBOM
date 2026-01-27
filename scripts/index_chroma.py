import json, sys
import chromadb
from sentence_transformers import SentenceTransformer

corpus_path = sys.argv[1]
persist_dir = sys.argv[2]

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

client = chromadb.PersistentClient(path=persist_dir)
col = client.get_or_create_collection("sbom_kb")

ids, docs, metas = [], [], []
with open(corpus_path, "r", encoding="utf-8") as f:
    for line in f:
        c = json.loads(line)
        ids.append(c["id"])
        docs.append(c["text"])
        metas.append({
            "type": c["type"],
            "repo": c["repo"],
            "purl": c.get("purl",""),
            "ecosystem": c.get("ecosystem",""),
            **(c.get("meta") or {})
        })

emb = model.encode(docs, show_progress_bar=True).tolist()
col.upsert(ids=ids, documents=docs, metadatas=metas, embeddings=emb)

print("indexed", len(ids), "chunks into", persist_dir)
