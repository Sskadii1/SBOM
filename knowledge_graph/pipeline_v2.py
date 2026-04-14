"""
pipeline_v2.py — SBOM Reachability Pipeline (Semgrep edition).

Phase 1:  Load sink data from cve_sinks.db (auto-populated via VulnIntelAgent if missing)
Phase 2:  Run Semgrep on repo source code
Phase 3:  Save results → data/reachability/{project}_reachability.json

Usage:
    # Full scan (with AI fallback for missing CVEs)
    python pipeline_v2.py \\
        --project "DanBurbach/React-Native-Basic" \\
        --repo    "/mnt/d/repos/DanBurbach_React-Native-Basic"

    # Full scan WITHOUT AI fallback
    python pipeline_v2.py --project "owner/repo" --repo "/path/repo" --no-ai

    # Import AI output manually (run once per AI batch)
    python pipeline_v2.py --import-ai data/ai_output/batch_001.json

    # Check DB coverage for a project
    python pipeline_v2.py --project "owner/repo" --check-coverage
"""
import argparse
import json
import logging
import sys
from pathlib import Path

KG_ROOT = Path(__file__).resolve().parent
if str(KG_ROOT) not in sys.path:
    sys.path.insert(0, str(KG_ROOT))

from modules.agents.sink_db import (
    init_db, get_sinks_for_vulns, missing_vulns, load_ai_json_output,
    get_reachability, insert_sinks,
)
from modules.agents.semgrep_agent import SemgrepAgent, VERDICT_SCORES
from modules.agents.vuln_intel_agent import VulnIntelAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline_v2")


# ---------------------------------------------------------------------------
# Neo4j helpers
# ---------------------------------------------------------------------------

def load_project_vulns(project_name: str, neo4j_uri: str, neo4j_database: str | None = None) -> list:
    """Load unique (vuln_id, package_name) for a project from Neo4j."""
    from neo4j import GraphDatabase
    import os

    uri = neo4j_uri or os.environ.get("NEO4J_URI", "bolt://localhost:7688")
    user = os.environ.get("NEO4J_USER", "neo4j")
    pwd = os.environ.get("NEO4J_PASSWORD", "password")

    database = neo4j_database or os.environ.get("NEO4J_DATABASE")
    if database and str(database).strip().lower() == "neo4j":
        database = None

    driver = GraphDatabase.driver(uri, auth=(user, pwd))
    try:
        with driver.session(database=database) as s:
            rows = list(s.run("""
            MATCH (p:Project {full_name: $proj})
            CALL (p) {
              MATCH (p)-[:GENERATED_SBOM]->(s:SBOM)
              RETURN s ORDER BY s.generated_at DESC LIMIT 1
            }
            MATCH (s)-[:HAS_COMPONENT]->(c:Component)-[:AFFECTED_BY]->(v:Vulnerability)
            WITH c, v,
                 coalesce(
                   head([a IN coalesce(v.aliases,[]) WHERE a STARTS WITH 'CVE-']),
                   v.id, head(coalesce(v.aliases,[]))
                 ) AS vuln_id,
                 CASE WHEN c.component_id STARTS WITH 'pkg:npm'   THEN 'npm'
                      WHEN c.component_id STARTS WITH 'pkg:pypi'  THEN 'pypi'
                      WHEN c.component_id STARTS WITH 'pkg:cargo' THEN 'cargo'
                      ELSE 'other' END AS eco
            RETURN DISTINCT vuln_id, c.name AS package_name, eco
            ORDER BY vuln_id
            """, proj=project_name))
            return [dict(r) for r in rows]
    finally:
        driver.close()


# ---------------------------------------------------------------------------
# AI sink extraction fallback
# ---------------------------------------------------------------------------

def auto_extract_sinks(missing_vuln_ids: list, vuln_rows: list) -> int:
    """
    Use VulnIntelAgent to extract sinks for CVEs missing from cve_sinks.db.
    Tries OSV structured fields first; falls back to LLM (OpenRouter) if needed.
    Returns number of sinks inserted into DB.
    """
    # Build lookup: vuln_id -> (package_name, ecosystem)
    pkg_map = {r["vuln_id"]: (r.get("package_name", ""), r.get("eco", ""))
               for r in vuln_rows}

    vuln_list = []
    for vid in missing_vuln_ids:
        pkg, _ = pkg_map.get(vid, ("", ""))
        vuln_list.append({"vuln_id": vid, "package_name": pkg})

    logger.info(f"[AI Fallback] Extracting sinks for {len(vuln_list)} CVEs "
                f"via VulnIntelAgent (OSV + LLM)...")

    agent = VulnIntelAgent()
    results = agent.analyze_vulnerabilities(vuln_list)

    all_sinks = []
    for result in results:
        if not result.sinks:
            continue
        _, eco = pkg_map.get(result.vuln_id, ("", ""))
        for sink in result.sinks:
            all_sinks.append({
                "vuln_id": sink.vuln_id,
                "package_name": sink.package_name,
                "ecosystem": eco,
                "function_name": sink.function_name,
                "class_name": getattr(sink, "class_name", None),
                "call_pattern": getattr(sink, "call_pattern", None),
                "sink_type": getattr(sink, "sink_type", "function_call"),
                "vuln_type": getattr(sink, "vulnerability_type", None),
                "confidence": sink.confidence,
                "source": sink.source,
                "raw_evidence": getattr(sink, "raw_evidence", None)
                                or getattr(sink, "sink_description", None),
            })

    if not all_sinks:
        logger.warning("[AI Fallback] No sinks extracted by AI.")
        return 0

    inserted = insert_sinks(all_sinks)
    logger.info(f"[AI Fallback] Inserted {inserted} new sinks into DB.")
    return inserted


# ---------------------------------------------------------------------------
# Coverage check
# ---------------------------------------------------------------------------

def print_coverage(project_name: str, neo4j_uri: str) -> None:
    """Show how many CVEs have sink data in the DB."""
    rows = load_project_vulns(project_name, neo4j_uri)
    vuln_ids = list({r["vuln_id"] for r in rows})
    missing = missing_vulns(vuln_ids)

    print(f"\nProject : {project_name}")
    print(f"Total unique CVEs : {len(vuln_ids)}")
    print(f"CVEs with sink data in DB : {len(vuln_ids) - len(missing)}")
    print(f"CVEs missing from DB      : {len(missing)}")
    if missing:
        print("\nMissing CVEs (need AI extraction):")
        for v in sorted(missing):
            print(f"  {v}")


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------
 
def print_report(results, project_name: str) -> None:
    line = "=" * 70
    print(f"\n{line}")
    print(f"  SEMGREP REACHABILITY REPORT  --  {project_name}")
    print(line)

    reachable = [r for r in results if r.verdict == "confirmed_reachable"]
    if reachable:
        print(f"\n  REACHABLE SINKS ({len(reachable)}):")
        for r in reachable:
            print(f"\n  {r.vuln_id} / {r.package_name}.{r.sink_function or '?'}")
            for loc in r.call_locations[:5]:
                print(f"    -> {loc}")
            if len(r.call_locations) > 5:
                print(f"    ... +{len(r.call_locations)-5} more")

    print(f"\n{'-' * 70}")
    summary: dict = {}
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    for verdict, cnt in sorted(summary.items(), key=lambda x: -VERDICT_SCORES.get(x[0], 0)):
        print(f"  {verdict:25s}: {cnt}")
    print(line)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="SBOM Reachability Pipeline v2 (Semgrep)")
    parser.add_argument("--project",  help="Neo4j project full_name (e.g. owner/repo)")
    parser.add_argument("--repo",     help="Local path to cloned repo for Semgrep scan")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7688",
                        help="Neo4j bolt URI")
    parser.add_argument("--import-ai", metavar="JSON_FILE",
                        help="Import AI-extracted sinks JSON into DB and exit")
    parser.add_argument("--check-coverage", action="store_true",
                        help="Show DB coverage for --project and exit")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI fallback: do not call VulnIntelAgent for missing CVEs")
    parser.add_argument("--save", action="store_true",
                        help="Save JSON report to data/reachability/")
    parser.add_argument("--show-cached", action="store_true",
                        help="Show cached reachability results from DB without re-scanning")
    args = parser.parse_args()

    # Ensure DB schema exists
    init_db()

    # ── Import AI output ──────────────────────────────────────────────────────
    if args.import_ai:
        path = Path(args.import_ai)
        if not path.exists():
            logger.error(f"File not found: {path}")
            sys.exit(1)
        stats = load_ai_json_output(path)
        print(f"Imported: {stats['inserted']} new sinks, "
              f"{stats['skipped']} already existed "
              f"(total in file: {stats['total']})")
        return

    # ── Require --project for other operations ────────────────────────────────
    if not args.project:
        parser.print_help()
        sys.exit(1)

    # ── Coverage check ────────────────────────────────────────────────────────
    if args.check_coverage:
        print_coverage(args.project, args.neo4j_uri)
        return

    # ── Show cached results ───────────────────────────────────────────────────
    if args.show_cached:
        cached = get_reachability(args.project)
        if not cached:
            print(f"No cached results for '{args.project}'")
        else:
            print(f"\nCached results for '{args.project}' ({len(cached)} entries):")
            for r in cached:
                locs = r.get("call_locations", [])
                print(f"  {r['vuln_id']:30s} {r['verdict']:25s} "
                      f"score={r.get('reach_score','?'):.1f}  "
                      f"locs={len(locs) if isinstance(locs, list) else '?'}")
        return

    # ── Full scan ─────────────────────────────────────────────────────────────
    if not args.repo:
        logger.error("--repo is required for scanning")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  PROJECT : {args.project}")
    print(f"  REPO    : {args.repo}")
    print(f"  MODE    : Semgrep")
    print(f"{'='*70}\n")

    # Load vulns from Neo4j
    logger.info("Loading vulnerabilities from Neo4j...")
    vuln_rows = load_project_vulns(args.project, args.neo4j_uri)
    if not vuln_rows:
        logger.error(f"No vulnerabilities found for project: {args.project}")
        sys.exit(1)

    vuln_ids = list({r["vuln_id"] for r in vuln_rows})
    logger.info(f"Found {len(vuln_ids)} unique CVEs")

    # Check DB coverage — fallback to AI extraction if needed
    missing = missing_vulns(vuln_ids)
    if missing:
        logger.warning(f"{len(missing)}/{len(vuln_ids)} CVEs have no sink data in DB")
        if args.no_ai:
            logger.warning("  --no-ai set: skipping AI extraction. "
                           "These CVEs will return no_sink_data (score 0.3).")
            logger.warning(f"  Missing: {', '.join(sorted(missing)[:5])}"
                           + (f" ... +{len(missing)-5} more" if len(missing) > 5 else ""))
        else:
            logger.info("  Triggering AI fallback (use --no-ai to skip)...")
            inserted = auto_extract_sinks(list(missing), vuln_rows)
            if inserted:
                # Refresh missing list after extraction
                missing = missing_vulns(vuln_ids)
                if missing:
                    logger.warning(f"  {len(missing)} CVEs still have no sinks after AI extraction.")
                else:
                    logger.info("  All CVEs now have sink data. Proceeding with scan.")

    # Run Semgrep
    agent = SemgrepAgent(project_name=args.project, repo_path=args.repo)
    results = agent.scan(vuln_ids)

    # Print report
    print_report(results, args.project)

    # Save
    if args.save:
        agent.save(results)


if __name__ == "__main__":
    main()
