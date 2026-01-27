import json, sys, re

sbom_path = sys.argv[1]
findings_path = sys.argv[2]
out_path = sys.argv[3]

def load_sbom(path):
    with open(path, "r", encoding="utf-8") as f:
        root = json.load(f)
    return root.get("sbom") if isinstance(root, dict) and "sbom" in root else root

def load_findings(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def purl_ecosystem(purl: str):
    m = re.match(r"^pkg:([^/]+)/", purl or "")
    return m.group(1) if m else ""

sbom = load_sbom(sbom_path)
findings = load_findings(findings_path)

repo_name = sbom.get("name") or sbom.get("documentName") or "unknown-repo"
packages = sbom.get("packages", []) or []

def get_purl(pkg):
    for r in (pkg.get("externalRefs") or []):
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator")
    return ""

find_by_purl = {x["purl"]: x for x in findings if x.get("purl")}

chunks = []

total_vulns = sum(x.get("vuln_count", 0) for x in findings)
repo_text = (
    f"Repository/SBOM: {repo_name}\n"
    f"Total packages: {len(packages)}\n"
    f"Total vulnerabilities found (OSV): {total_vulns}\n"
    f"SBOM file: {sbom_path}\n"
)
chunks.append({
    "id": f"{repo_name}::repo_summary",
    "type": "repo",
    "repo": repo_name,
    "purl": "",
    "ecosystem": "",
    "text": repo_text,
    "meta": {"sbom_file": sbom_path}
})

for p in packages:
    name = p.get("name","")
    version = p.get("versionInfo","")
    spdxid = p.get("SPDXID","")
    purl = get_purl(p)
    eco = purl_ecosystem(purl)

    fnd = find_by_purl.get(purl) if purl else None
    vuln_count = fnd.get("vuln_count", 0) if fnd else 0
    vuln_ids = fnd.get("vuln_ids", []) if fnd else []

    text = (
        f"Package: {name}\n"
        f"Version: {version}\n"
        f"PURL: {purl}\n"
        f"SPDXID: {spdxid}\n"
        f"OSV vulnerabilities: {vuln_count}\n"
    )
    if vuln_ids:
        text += "Vulnerability IDs:\n" + "\n".join([f"- {vid}" for vid in vuln_ids[:30]]) + "\n"

    chunks.append({
        "id": f"{repo_name}::pkg::{purl or spdxid}",
        "type": "package",
        "repo": repo_name,
        "purl": purl,
        "ecosystem": eco,
        "text": text,
        "meta": {"spdxid": spdxid, "name": name, "version": version, "sbom_file": sbom_path}
    })

for x in findings:
    if not x.get("vuln_ids"):
        continue
    for vid in x["vuln_ids"][:50]:
        chunks.append({
            "id": f"{repo_name}::vuln::{vid}::{x.get('purl','')}",
            "type": "vuln",
            "repo": repo_name,
            "purl": x.get("purl",""),
            "ecosystem": purl_ecosystem(x.get("purl","")),
            "text": f"Vulnerability ID: {vid}\nAffected package: {x.get('purl','')}\n",
            "meta": {"vuln_id": vid, "sbom_file": sbom_path}
        })

with open(out_path, "w", encoding="utf-8") as f:
    for c in chunks:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

print("wrote", out_path, "chunks", len(chunks))
