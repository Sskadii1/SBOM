"""
Backfill vulnerability aliases + enrichment fields in Neo4j using existing pipeline code.

Uses:
- modules.vulnerability.osv_checker.OSVChecker
- modules.graph.neo4j_integration.Neo4jKnowledgeGraph.create_vulnerability()
"""

import argparse
import os
from typing import List

from dotenv import load_dotenv

from modules.graph.neo4j_integration import Neo4jKnowledgeGraph
from modules.vulnerability.osv_checker import OSVChecker


def load_vuln_ids(kg: Neo4jKnowledgeGraph) -> List[str]:
    rows = kg.run_custom_query("MATCH (v:Vulnerability) RETURN DISTINCT v.id AS id ORDER BY id")
    return [str(r["id"]) for r in rows if r.get("id")]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Re-enrich all Neo4j Vulnerability nodes from OSV/NVD/EPSS and refresh aliases."
    )
    parser.add_argument("--neo4j-uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7688"))
    parser.add_argument("--neo4j-user", default=os.getenv("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", "change_me"))
    parser.add_argument("--neo4j-database", default=os.getenv("NEO4J_DATABASE"))
    parser.add_argument("--limit", type=int, default=0, help="0 means all vulnerabilities")
    args = parser.parse_args()

    # Load env from both common locations:
    # - repo root: d:\Capstone\.env
    # - KG root:   d:\Capstone\knowledge_graph\.env
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root_env = os.path.join(os.path.dirname(script_dir), ".env")
    kg_root_env = os.path.join(script_dir, ".env")
    load_dotenv(repo_root_env, override=False)
    load_dotenv(kg_root_env, override=False)

    keys_inline = os.getenv("NVD_API_KEYS", "")
    key_single = os.getenv("NVD_API_KEY", "")
    key_count = len([k for k in keys_inline.split(",") if k.strip()]) if keys_inline else (1 if key_single else 0)
    print(f"NVD keys detected from env: {key_count}")

    kg = Neo4jKnowledgeGraph(
        uri=args.neo4j_uri,
        user=args.neo4j_user,
        password=args.neo4j_password,
        database=args.neo4j_database,
    )
    checker = OSVChecker(enable_enrichment=True)

    try:
        vuln_ids = load_vuln_ids(kg)
        if args.limit and args.limit > 0:
            vuln_ids = vuln_ids[: args.limit]

        print(f"Total vuln ids to refresh: {len(vuln_ids)}")
        ok = 0
        miss_osv = 0
        failed = 0

        for idx, vid in enumerate(vuln_ids, start=1):
            try:
                osv = checker._fetch_vuln_detail(vid)
                if not osv:
                    miss_osv += 1
                    print(f"[{idx}/{len(vuln_ids)}] MISS_OSV {vid}")
                    continue

                details = checker.extract_vulnerability_details(osv)
                saved_id = kg.create_vulnerability(details)
                if saved_id:
                    ok += 1
                    print(f"[{idx}/{len(vuln_ids)}] OK {vid} -> {saved_id}")
                else:
                    failed += 1
                    print(f"[{idx}/{len(vuln_ids)}] FAIL_SAVE {vid}")
            except Exception as exc:
                failed += 1
                print(f"[{idx}/{len(vuln_ids)}] ERROR {vid}: {exc}")

        print("\n=== Summary ===")
        print(f"Refreshed: {ok}")
        print(f"OSV missing: {miss_osv}")
        print(f"Failed: {failed}")

    finally:
        kg.close()


if __name__ == "__main__":
    main()
