import json, sys

findings_path = sys.argv[1]
out_md = sys.argv[2]

with open(findings_path, "r", encoding="utf-8") as f:
    items = json.load(f)

lines = []
lines.append("# SBOM Vulnerability Summary\n")
for it in items:
    lines.append(f"## {it['name']} ({it['purl']})")
    lines.append(f"- Version: `{it.get('version','')}`")
    lines.append(f"- Vulns found: **{it['vuln_count']}**")
    if it["vuln_ids"]:
        lines.append("- IDs:")
        for vid in it["vuln_ids"][:20]:
            lines.append(f"  - {vid}")
    lines.append("")

with open(out_md, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print("wrote", out_md)
