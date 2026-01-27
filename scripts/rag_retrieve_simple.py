import sys, chromadb

persist_dir = sys.argv[1]
question = " ".join(sys.argv[2:])

client = chromadb.PersistentClient(path=persist_dir)
col = client.get_collection("sbom_kb")

res = col.query(query_texts=[question], n_results=6)

for i, (doc, meta, _id) in enumerate(zip(res["documents"][0], res["metadatas"][0], res["ids"][0]), 1):
    print(f"\n--- HIT {i} | id={_id} | type={meta.get('type')} | purl={meta.get('purl','')}")
    print(doc[:800])
