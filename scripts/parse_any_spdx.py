import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

def find_spdx_docs(obj, out, depth=0, max_depth=6):
    if depth > max_depth:
        return
    if isinstance(obj, dict):
        if "spdxVersion" in obj and ("packages" in obj or "relationships" in obj):
            out.append(obj)
            return
        for v in obj.values():
            find_spdx_docs(v, out, depth+1, max_depth)
    elif isinstance(obj, list):
        for it in obj[:5000]:  # tránh quá nặng
            find_spdx_docs(it, out, depth+1, max_depth)

docs = []
find_spdx_docs(data, docs)

print("file:", path)
print("top_type:", type(data).__name__)
print("found_spdx_docs:", len(docs))

if not docs:
    if isinstance(data, dict):
        print("top_keys_sample:", list(data.keys())[:40])
    elif isinstance(data, list):
        print("array_length:", len(data))
        print("first_elem_type:", type(data[0]).__name__ if data else None)
    sys.exit(1)

doc = docs[0]
print("spdxVersion:", doc.get("spdxVersion"))
print("name:", doc.get("name"))
print("packages:", len(doc.get("packages", []) or []))
print("relationships:", len(doc.get("relationships", []) or []))

pkgs = doc.get("packages", []) or []
def get_purl(pkg):
    for r in (pkg.get("externalRefs") or []):
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator")
    return None

sample = []
for p in pkgs[:3]:
    sample.append({
        "name": p.get("name"),
        "versionInfo": p.get("versionInfo"),
        "purl": get_purl(p),
        "SPDXID": p.get("SPDXID")
    })
print("sample_packages:", sample)
