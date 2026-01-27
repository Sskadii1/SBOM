import csv, json, sys, re
import requests

csv_path = sys.argv[1]
out_path = sys.argv[2]

def parse_purl(purl: str):
    # purl format (basic): pkg:type/name@version
    # e.g. pkg:npm/lodash@4.17.21
    m = re.match(r"^pkg:([^/]+)/([^@]+)(?:@(.+))?$", purl)
    if not m:
        return None
    ptype, name, version = m.group(1), m.group(2), m.group(3)
    return ptype, name, version


ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "crates": "crates.io",
    "composer": "Packagist",
}

items = []
with open(csv_path, newline="", encoding="utf-8") as f:
    r = csv.DictReader(f)
    for row in r:
        if row.get("purl"):
            items.append(row)

queries = []
meta = []
for it in items:
    p = parse_purl(it["purl"])
    if not p:
        continue
    ptype, name, version = p
    eco = ECOSYSTEM_MAP.get(ptype)
    if eco and version:
        queries.append({"package": {"ecosystem": eco, "name": name}, "version": version})
        meta.append(it)
    else:
        # fallback: query by purl anyway
        queries.append({"package": {"purl": it["purl"]}})
        meta.append(it)

payload = {"queries": queries}
resp = requests.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=60)
resp.raise_for_status()
data = resp.json()

results = []
for it, res in zip(meta, data.get("results", [])):
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
print("top_hits:", sorted(results, key=lambda x: x["vuln_count"], reverse=True)[:5])
