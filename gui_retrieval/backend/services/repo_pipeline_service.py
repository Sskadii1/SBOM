"""
backend/services/repo_pipeline_service.py

End-to-end ingestion pipeline for a single GitHub repository:
repo link -> clone/update -> SBOM -> OSV -> Neo4j import -> Semgrep reachability.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import backend.config as config


ROOT = Path(__file__).resolve().parents[3]
KG_ROOT = ROOT / "knowledge_graph"
USER_REPOS_DIR = Path(
    os.environ.get("USER_REPO_CLONE_DIR", str(KG_ROOT / "data" / "user_repos"))
)

if str(KG_ROOT) not in sys.path:
    sys.path.insert(0, str(KG_ROOT))


_VERDICT_ORDER = {
    "confirmed_reachable": 4,
    "likely_reachable": 3,
    "no_sink_data": 2,
    "likely_unreachable": 1,
}

_SOURCE_MODES = {
    "github_latest",
    "github_commit",
}


def _emit(log: Callable[[str], None] | None, message: str) -> None:
    if log:
        log(message)


def _run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    log: Callable[[str], None] | None = None,
) -> str:
    _emit(log, f"$ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        if proc.stderr:
            _emit(log, proc.stderr.strip())
        raise RuntimeError((proc.stderr or proc.stdout or "").strip() or f"Command failed: {' '.join(cmd)}")
    if proc.stdout:
        line = proc.stdout.strip().splitlines()[-1]
        if line:
            _emit(log, line)
    return (proc.stdout or "").strip()


def _normalize_source_mode(source_mode: str | None) -> str:
    normalized = str(source_mode or "github_latest").strip().lower()
    if normalized not in _SOURCE_MODES:
        allowed = ", ".join(sorted(_SOURCE_MODES))
        raise ValueError(f"Unsupported source mode '{source_mode}'. Expected one of: {allowed}")
    return normalized


def _normalize_commit_hash(commit_hash: str | None) -> str | None:
    if commit_hash is None:
        return None
    normalized = str(commit_hash).strip()
    return normalized or None


def _resolve_target_commit(
    repo_path: Path,
    normalized_commit: str,
    *,
    use_parent_commit: bool = False,
    log: Callable[[str], None] | None = None,
) -> str:
    try:
        resolved_commit = _run_cmd(
            ["git", "rev-parse", "--verify", f"{normalized_commit}^{{commit}}"],
            cwd=repo_path,
            log=log,
        )
    except RuntimeError as exc:
        raise RuntimeError(f"Requested commit could not be resolved: {normalized_commit}") from exc

    if not use_parent_commit:
        return resolved_commit

    try:
        parent_commit = _run_cmd(
            ["git", "rev-parse", "--verify", f"{resolved_commit}^"],
            cwd=repo_path,
            log=log,
        )
    except RuntimeError as exc:
        raise RuntimeError(
            f"Requested commit has no parent commit to check out: {resolved_commit}"
        ) from exc
    _emit(log, f"[Clone] Using parent commit before fix: {parent_commit}")
    return parent_commit


def _parse_repo_input(repo_input: str) -> tuple[str, str]:
    text = (repo_input or "").strip()
    if not text:
        raise ValueError("Repository link is empty.")

    if text.endswith(".git"):
        text = text[:-4]

    m = re.match(r"^https?://github\.com/([^/\s]+)/([^/\s]+?)/?$", text, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)

    m = re.match(r"^([^/\s]+)/([^/\s]+)$", text)
    if m:
        return m.group(1), m.group(2)

    raise ValueError("Invalid repository format. Use owner/repo or https://github.com/owner/repo")


def _detect_repo_language(repo_path: Path) -> str:
    if (repo_path / "package.json").exists():
        return "JavaScript"
    if (repo_path / "pyproject.toml").exists() or (repo_path / "requirements.txt").exists():
        return "Python"
    return "Unknown"


def _fetch_github_repo_metadata(
    owner: str,
    repo: str,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any] | None:
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sbom-repo-pipeline",
    }
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    try:
        with urlopen(Request(api_url, headers=headers), timeout=15) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except HTTPError as exc:
        _emit(log, f"[GitHub] Metadata lookup failed ({exc.code}) for {owner}/{repo}; using local fallback")
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        _emit(log, f"[GitHub] Metadata lookup failed ({exc}); using local fallback")
    return None


def _detect_repo_language_from_metadata(
    owner: str,
    repo: str,
    repo_path: Path,
    log: Callable[[str], None] | None = None,
) -> str:
    metadata = _fetch_github_repo_metadata(owner, repo, log=log)
    language = (metadata or {}).get("language")
    if language:
        return str(language)
    return _detect_repo_language(repo_path)


def _default_branch_for_repo(
    repo_path: Path,
    log: Callable[[str], None] | None = None,
) -> str:
    try:
        head_ref = _run_cmd(["git", "symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_path, log=log)
        return head_ref.rsplit("/", 1)[-1]
    except Exception:
        return "main"


def _ensure_git_safe_directory(
    repo_path: Path,
    log: Callable[[str], None] | None = None,
) -> None:
    # Some containerized runs mount repos with a different owner. Register both
    # the parent clone root and the concrete repo path so git fetch/pull works.
    try:
        existing = _run_cmd(
            ["git", "config", "--global", "--get-all", "safe.directory"],
            log=log,
        )
    except RuntimeError:
        existing = ""
    configured_paths = {line.strip() for line in existing.splitlines() if line.strip()}

    for safe_path in (USER_REPOS_DIR, repo_path):
        if str(safe_path) not in configured_paths:
            _run_cmd(
                ["git", "config", "--global", "--add", "safe.directory", str(safe_path)],
                log=log,
            )
            configured_paths.add(str(safe_path))


def _build_repo_metadata(
    owner: str,
    repo: str,
    *,
    local_path: Path,
    clone_url: str,
    clone_status: str,
    default_branch: str,
    commit: str,
    checked_out_branch: str,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    from modules.utils.paths import to_project_relative

    full_name = f"{owner}/{repo}"
    language = _detect_repo_language_from_metadata(owner, repo, local_path, log=log)
    branch_label = checked_out_branch or default_branch
    _emit(log, f"[Clone] Ready at commit {commit[:10]} on branch {branch_label} (language={language})")

    return {
        "owner": owner,
        "name": repo,
        "full_name": full_name,
        "metadata_key": f"{full_name}@{commit}",
        "url": f"https://github.com/{full_name}",
        "clone_url": clone_url,
        "clone_status": clone_status,
        "local_path": to_project_relative(str(local_path)),
        "default_branch": default_branch,
        "vulnerable_commit": commit,
        "language": language,
    }


def _resolve_github_latest_repo(
    owner: str,
    repo: str,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    USER_REPOS_DIR.mkdir(parents=True, exist_ok=True)
    full_name = f"{owner}/{repo}"
    repo_url = f"https://github.com/{full_name}.git"
    local_path = USER_REPOS_DIR / f"{owner}_{repo}"

    _ensure_git_safe_directory(local_path, log=log)
    _emit(log, "[Clone] Resolving latest commit on default branch")

    if (local_path / ".git").exists():
        _emit(log, f"[Clone] Existing repo found, updating: {local_path}")
        _run_cmd(["git", "fetch", "origin", "--prune"], cwd=local_path, log=log)
        default_branch = _default_branch_for_repo(local_path, log=log)
        _run_cmd(["git", "checkout", default_branch], cwd=local_path, log=log)
        _run_cmd(["git", "pull", "--ff-only", "origin", default_branch], cwd=local_path, log=log)
        clone_status = "updated"
    else:
        _emit(log, f"[Clone] Cloning {full_name} into {local_path}")
        _run_cmd(["git", "clone", "--depth", "1", repo_url, str(local_path)], log=log)
        default_branch = _default_branch_for_repo(local_path, log=log)
        clone_status = "success"

    if not (local_path / ".git").exists():
        raise RuntimeError(
            "Repository folder was not found after clone/update. "
            "This may be caused by antivirus quarantine/removal. "
            f"Please add an exclusion for: {local_path}"
        )

    commit = _run_cmd(["git", "rev-parse", "HEAD"], cwd=local_path, log=log)
    branch = _run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=local_path, log=log)
    return _build_repo_metadata(
        owner,
        repo,
        local_path=local_path,
        clone_url=repo_url,
        clone_status=clone_status,
        default_branch=default_branch,
        commit=commit,
        checked_out_branch=branch,
        log=log,
    )


def _resolve_github_commit_repo(
    owner: str,
    repo: str,
    commit_hash: str,
    *,
    use_parent_commit: bool = False,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    normalized_commit = _normalize_commit_hash(commit_hash)
    if not normalized_commit:
        raise ValueError("Commit hash is required for custom commit mode.")

    USER_REPOS_DIR.mkdir(parents=True, exist_ok=True)
    full_name = f"{owner}/{repo}"
    repo_url = f"https://github.com/{full_name}.git"
    local_path = USER_REPOS_DIR / f"{owner}_{repo}"

    _ensure_git_safe_directory(local_path, log=log)
    _emit(log, f"[Clone] Resolving requested commit: {normalized_commit}")
    if use_parent_commit:
        _emit(log, "[Clone] Parent commit mode enabled")

    if (local_path / ".git").exists():
        _emit(log, f"[Clone] Existing repo found, fetching requested commit in: {local_path}")
        _run_cmd(["git", "fetch", "origin", "--prune"], cwd=local_path, log=log)
        clone_status = "updated"
    else:
        _emit(log, f"[Clone] Cloning {full_name} into {local_path}")
        _run_cmd(["git", "clone", repo_url, str(local_path)], log=log)
        clone_status = "success"

    if not (local_path / ".git").exists():
        raise RuntimeError(
            "Repository folder was not found after clone/update. "
            "This may be caused by antivirus quarantine/removal. "
            f"Please add an exclusion for: {local_path}"
        )

    default_branch = _default_branch_for_repo(local_path, log=log)
    _run_cmd(["git", "fetch", "origin", normalized_commit], cwd=local_path, log=log)
    resolved_commit = _resolve_target_commit(
        local_path,
        normalized_commit,
        use_parent_commit=use_parent_commit,
        log=log,
    )

    _run_cmd(["git", "checkout", "--detach", resolved_commit], cwd=local_path, log=log)
    checked_out_branch = _run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=local_path, log=log)
    return _build_repo_metadata(
        owner,
        repo,
        local_path=local_path,
        clone_url=repo_url,
        clone_status=clone_status,
        default_branch=default_branch,
        commit=resolved_commit,
        checked_out_branch=checked_out_branch,
        log=log,
    )


def _upsert_repo_metadata(repo_meta: dict[str, Any]) -> None:
    from modules.utils.paths import REPOS_METADATA_FILE, ensure_data_dirs

    ensure_data_dirs()
    metadata_file = Path(REPOS_METADATA_FILE)
    existing: list[dict[str, Any]] = []
    if metadata_file.exists():
        try:
            payload = json.loads(metadata_file.read_text(encoding="utf-8-sig"))
            if isinstance(payload, list):
                existing = [item for item in payload if isinstance(item, dict)]
        except Exception:
            existing = []

    updated = False
    for index, item in enumerate(existing):
        if item.get("full_name") == repo_meta.get("full_name"):
            existing[index] = {**item, **repo_meta}
            updated = True
            break
    if not updated:
        existing.append(repo_meta)

    metadata_file.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def run_full_repo_pipeline(
    repo_input: str,
    enable_ai_sink_fallback: bool = True,
    log: Callable[[str], None] | None = None,
    source_mode: str = "github_latest",
    commit_hash: str | None = None,
    use_parent_commit: bool = False,
) -> dict[str, Any]:
    from modules.agents.sink_db import init_db, missing_vulns
    from modules.agents.semgrep_agent import SemgrepAgent
    from modules.graph.neo4j_integration import Neo4jKnowledgeGraph
    from modules.sbom.sbom_generator import SBOMGenerator
    from modules.utils.paths import SBOMS_DIR, VULNS_DIR
    from modules.vulnerability.osv_checker import OSVChecker
    from pipeline_v2 import auto_extract_sinks, load_project_vulns

    started = time.time()
    normalized_mode = _normalize_source_mode(source_mode)
    normalized_commit = _normalize_commit_hash(commit_hash)
    _emit(log, "[Pipeline] Starting full ingestion pipeline")
    _emit(log, f"[Pipeline] Source mode: {normalized_mode}")
    owner, repo = _parse_repo_input(repo_input)
    _emit(log, f"[Pipeline] Repository input parsed: {owner}/{repo}")
    if normalized_mode == "github_commit":
        repo_meta = _resolve_github_commit_repo(
            owner,
            repo,
            normalized_commit or "",
            use_parent_commit=use_parent_commit,
            log=log,
        )
    else:
        repo_meta = _resolve_github_latest_repo(owner, repo, log=log)
    _upsert_repo_metadata(repo_meta)
    full_name = repo_meta["full_name"]
    local_repo_abs = ROOT / repo_meta["local_path"]

    _emit(log, "[SBOM] Generating SBOM")
    sbom_generator = SBOMGenerator(output_dir=str(SBOMS_DIR))
    sbom_payload = sbom_generator.generate_sbom(str(local_repo_abs), repo_meta["metadata_key"])
    if not sbom_payload:
        raise RuntimeError("SBOM generation failed.")

    sbom_result = {
        "repo": repo_meta,
        "sbom": sbom_payload,
        "sbom_file": sbom_payload.get("_metadata", {}).get("output_file"),
        "status": "success",
    }
    sbom_generator.save_summary([sbom_result])
    _emit(log, "[SBOM] SBOM generated and summary updated")

    _emit(log, "[OSV] Checking vulnerabilities via OSV")
    osv_checker = OSVChecker(output_dir=str(VULNS_DIR))
    enriched = osv_checker.process_sbom_results([sbom_result])
    osv_checker.save_summary(enriched)
    vuln_count = enriched[0].get("vulnerability_data", {}).get("total_vulnerabilities", 0) if enriched else 0
    _emit(log, f"[OSV] Done. Vulnerabilities found: {vuln_count}")

    db_name = (config.NEO4J_DATABASE or "").strip()
    if db_name.lower() == "neo4j":
        db_name = None

    _emit(log, "[Neo4j] Importing SBOM+vulnerability data into graph")
    kg = Neo4jKnowledgeGraph(
        uri=config.NEO4J_URI,
        user=config.NEO4J_USER,
        password=config.NEO4J_PASSWORD,
        database=db_name,
    )
    try:
        repo_key = repo_meta.get("metadata_key")
        if repo_key and repo_key in kg.imported_repo_keys:
            _emit(log, "[Neo4j] Repo already marked imported; forcing refresh for current run")
            kg.imported_repo_keys.discard(repo_key)
        kg.import_batch(enriched)
        graph_stats = kg.get_statistics()
    finally:
        kg.close()
    _emit(log, f"[Neo4j] Import complete. Projects in graph: {graph_stats.get('projects', 0)}")

    init_db()
    _emit(log, "[Semgrep] Loading project vulnerabilities from Neo4j")
    vuln_rows = load_project_vulns(full_name, config.NEO4J_URI, db_name)
    vuln_ids = sorted({r["vuln_id"] for r in vuln_rows if r.get("vuln_id")})
    _emit(log, f"[Semgrep] Unique CVEs to scan: {len(vuln_ids)}")

    missing = missing_vulns(vuln_ids)
    if missing and enable_ai_sink_fallback:
        _emit(log, f"[Semgrep] Missing sink metadata for {len(missing)} CVE(s), running AI fallback")
        auto_extract_sinks(list(missing), vuln_rows)
        missing = missing_vulns(vuln_ids)
        _emit(log, f"[Semgrep] Remaining missing sink metadata: {len(missing)}")

    semgrep_results_summary: dict[str, int] = {}
    semgrep_entries = 0
    if vuln_ids:
        _emit(log, "[Semgrep] Running reachability scan")
        agent = SemgrepAgent(project_name=full_name, repo_path=str(local_repo_abs))
        semgrep_results = agent.scan(vuln_ids)
        agent.save(semgrep_results)
        semgrep_entries = len(semgrep_results)
        for item in semgrep_results:
            verdict = item.verdict or "no_sink_data"
            semgrep_results_summary[verdict] = semgrep_results_summary.get(verdict, 0) + 1
        _emit(log, f"[Semgrep] Completed. Result entries: {semgrep_entries}")

    best_verdict = "no_sink_data"
    if semgrep_results_summary:
        best_verdict = max(semgrep_results_summary, key=lambda v: _VERDICT_ORDER.get(v, -1))
    _emit(log, f"[Pipeline] Finished. Best Semgrep verdict: {best_verdict}")

    return {
        "project_name": full_name,
        "source_mode": normalized_mode,
        "use_parent_commit": bool(use_parent_commit),
        "repo_local_path": str(local_repo_abs),
        "commit": repo_meta.get("vulnerable_commit"),
        "branch": repo_meta.get("default_branch"),
        "vulnerability_count": enriched[0].get("vulnerability_data", {}).get("total_vulnerabilities", 0) if enriched else 0,
        "semgrep_entry_count": semgrep_entries,
        "semgrep_verdict_summary": semgrep_results_summary,
        "semgrep_best_verdict": best_verdict,
        "missing_sink_count": len(missing),
        "neo4j_stats": graph_stats,
        "duration_seconds": round(time.time() - started, 2),
    }
