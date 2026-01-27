import csv, json, sys
import requests

csv_path = sys.argv[1]
out_path = sys.argv[2]

items = []
with open(csv_path, newline="", encoding="utf-8") as f:
    r = csv.DictReader(f)
    for row in r:
        if row["purl"]:
            items.append(row)

queries = [{"package": {"purl": it["purl"]}} for it in items]
payload = {"queries": queries}

resp = requests.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=60)
resp.raise_for_status()
data = resp.json()

results = []
for it, res in zip(items, data.get("results", [])):
    vulns = res.get("vulns") or []
    results.append({
        "purl": it["purl"],
        "name": it["name"],
        "version": it["version"],
        "vuln_count": len(vulns),
        "vuln_ids": [v.get("id") for v in vulns],
    })

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("wrote", out_path, "items", len(results))
print(json.dumps(results[:3], ensure_ascii=False, indent=2))
