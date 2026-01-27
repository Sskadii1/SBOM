import json, sys, csv

in_path = sys.argv[1]
out_path = sys.argv[2]

with open(in_path, "r", encoding="utf-8") as f:
    root = json.load(f)

doc = root.get("sbom") if isinstance(root, dict) and "sbom" in root else root
pkgs = doc.get("packages", []) or []

def get_purl(pkg):
    for r in (pkg.get("externalRefs") or []):
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator")
    return ""

rows = []
for p in pkgs:
    rows.append({
        "spdxid": p.get("SPDXID",""),
        "name": p.get("name",""),
        "version": p.get("versionInfo",""),
        "purl": get_purl(p),
    })

with open(out_path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["spdxid","name","version","purl"])
    w.writeheader()
    w.writerows(rows)

print("wrote", out_path, "rows", len(rows))
