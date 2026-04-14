"""
Run pipeline_v2 Semgrep scans for every Project currently present in Neo4j.

Default behavior is aligned with the current dataset shape in this workspace:
- Project list source: Neo4j (Project.full_name)
- Local repo path source: metadata JSON files
  - data/metadata/vulnerable_repos_metadata.json
  - data/metadata/repos_metadata.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from neo4j import GraphDatabase


ROOT = Path(__file__).resolve().parent
META_DIR = ROOT / "data" / "metadata"
SUMMARY_FILE = ROOT / "data" / "reachability" / "semgrep_sync_summary.json"


def _load_json(path: Path) -> List[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _list_projects_from_neo4j(uri: str, user: str, password: str, database: str) -> List[str]:
    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        with driver.session(database=database) as session:
            rows = session.run("MATCH (p:Project) RETURN p.full_name AS p ORDER BY p")
            return [r["p"] for r in rows if r["p"]]


def _build_local_path_index() -> Dict[str, Path]:
    index: Dict[str, Path] = {}
    for file_name in ("vulnerable_repos_metadata.json", "repos_metadata.json"):
        for item in _load_json(META_DIR / file_name):
            full_name = item.get("full_name")
            local_path = item.get("local_path")
            if not full_name or not local_path:
                continue
            abs_path = ROOT / str(local_path)
            if full_name not in index:
                index[full_name] = abs_path
    return index


def _run_one(project: str, repo_path: Path, neo4j_uri: str, no_ai: bool) -> Tuple[bool, str]:
    cmd = [
        sys.executable,
        str(ROOT / "pipeline_v2.py"),
        "--project",
        project,
        "--repo",
        str(repo_path),
        "--neo4j-uri",
        neo4j_uri,
        "--save",
    ]
    if no_ai:
        cmd.append("--no-ai")

    proc = subprocess.run(cmd, capture_output=True, text=True)
    ok = proc.returncode == 0
    tail = (proc.stdout or "")[-1000:] + "\n" + (proc.stderr or "")[-1000:]
    return ok, tail.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-run pipeline_v2 for all Neo4j projects")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7688")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="password")
    parser.add_argument("--neo4j-database", default="neo4j")
    parser.add_argument("--limit", type=int, default=0, help="0 means no limit")
    parser.add_argument("--no-ai", action="store_true", help="Pass --no-ai to pipeline_v2")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    projects = _list_projects_from_neo4j(
        uri=args.neo4j_uri,
        user=args.neo4j_user,
        password=args.neo4j_password,
        database=args.neo4j_database,
    )
    path_index = _build_local_path_index()

    if args.limit and args.limit > 0:
        projects = projects[: args.limit]

    summary = {
        "neo4j_project_count": len(projects),
        "scanned": [],
        "missing_repo_path": [],
        "failed": [],
    }

    for i, project in enumerate(projects, start=1):
        repo_path = path_index.get(project)
        if not repo_path:
            summary["missing_repo_path"].append({"project": project, "reason": "not_found_in_metadata"})
            print(f"[{i}/{len(projects)}] MISSING metadata path: {project}")
            continue
        if not repo_path.exists():
            summary["missing_repo_path"].append({"project": project, "reason": "path_not_exists", "path": str(repo_path)})
            print(f"[{i}/{len(projects)}] MISSING local repo: {project} -> {repo_path}")
            continue

        if args.dry_run:
            summary["scanned"].append({"project": project, "path": str(repo_path), "status": "dry_run"})
            print(f"[{i}/{len(projects)}] DRY-RUN {project}")
            continue

        ok, tail = _run_one(project, repo_path, args.neo4j_uri, args.no_ai)
        if ok:
            summary["scanned"].append({"project": project, "path": str(repo_path), "status": "ok"})
            print(f"[{i}/{len(projects)}] OK {project}")
        else:
            summary["failed"].append({"project": project, "path": str(repo_path), "status": "failed", "log_tail": tail})
            print(f"[{i}/{len(projects)}] FAIL {project}")

    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSummary written to: {SUMMARY_FILE}")
    print(
        f"Scanned={len(summary['scanned'])} "
        f"MissingRepo={len(summary['missing_repo_path'])} "
        f"Failed={len(summary['failed'])}"
    )


if __name__ == "__main__":
    main()

