"""
Dependabot Vulnerable Repo Crawler
Clone repositories at vulnerable commits defined in Dependabot ground-truth JSON.
Stores metadata in a separate file without overwriting the existing crawler outputs.
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

import requests

try:
    from modules.utils.paths import (
        DATA_DIR,
        VULNERABLE_REPOS_DIR,
        VULNERABLE_REPOS_METADATA_FILE,
        ensure_data_dirs,
        to_project_relative,
    )
except ModuleNotFoundError:
    # Allow direct execution from this file path.
    KG_ROOT = Path(__file__).resolve().parents[2]
    if str(KG_ROOT) not in sys.path:
        sys.path.insert(0, str(KG_ROOT))
    from modules.utils.paths import (
        DATA_DIR,
        VULNERABLE_REPOS_DIR,
        VULNERABLE_REPOS_METADATA_FILE,
        ensure_data_dirs,
        to_project_relative,
    )


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


DEFAULT_INPUT_FILE = os.path.join(str(DATA_DIR.parent), "dependabot_groundtruth_javascript.json")
DEFAULT_OUTPUT_DIR = str(VULNERABLE_REPOS_DIR)
DEFAULT_METADATA_FILE = str(VULNERABLE_REPOS_METADATA_FILE)


class DependabotVulnerableCrawler:
    """Clone repositories at vulnerable commits from Dependabot ground-truth data."""

    def __init__(
        self,
        github_token: Optional[str] = None,
        output_dir: Optional[str] = None,
        metadata_file: Optional[str] = None,
    ):
        ensure_data_dirs()
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.metadata_file = metadata_file or DEFAULT_METADATA_FILE
        self.base_url = "https://api.github.com"

        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.metadata_file), exist_ok=True)

        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            self.headers["Authorization"] = f"token {self.github_token}"

    @staticmethod
    def _parse_repo_full_name(full_name: str) -> Optional[Tuple[str, str]]:
        if not full_name or "/" not in full_name:
            return None
        owner, repo = full_name.split("/", 1)
        owner = owner.strip()
        repo = repo.strip()
        if owner and repo:
            return owner, repo
        return None

    @staticmethod
    def _safe_repo_dir_name(full_name: str, vulnerable_commit: str) -> str:
        short_sha = (vulnerable_commit or "").strip()[:10] or "unknown"
        return f"{full_name.replace('/', '_')}__{short_sha}"

    def _repo_local_path(self, full_name: str, vulnerable_commit: str) -> str:
        return os.path.join(self.output_dir, self._safe_repo_dir_name(full_name, vulnerable_commit))

    def _build_fallback_metadata(self, owner: str, repo: str) -> Dict:
        full_name = f"{owner}/{repo}"
        return {
            "id": None,
            "name": repo,
            "full_name": full_name,
            "owner": owner,
            "url": f"https://github.com/{full_name}",
            "clone_url": f"https://github.com/{full_name}.git",
            "language": None,
            "size_kb": None,
            "stars": None,
            "forks": None,
            "description": "",
            "created_at": None,
            "updated_at": None,
            "default_branch": None,
        }

    def _fetch_repo_metadata(self, owner: str, repo: str) -> Optional[Dict]:
        url = f"{self.base_url}/repos/{owner}/{repo}"
        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            response.raise_for_status()
            item = response.json()
            return {
                "id": item.get("id"),
                "name": item.get("name") or repo,
                "full_name": item.get("full_name") or f"{owner}/{repo}",
                "owner": item.get("owner", {}).get("login", owner),
                "url": item.get("html_url") or f"https://github.com/{owner}/{repo}",
                "clone_url": item.get("clone_url") or f"https://github.com/{owner}/{repo}.git",
                "language": item.get("language"),
                "size_kb": item.get("size"),
                "stars": item.get("stargazers_count"),
                "forks": item.get("forks_count"),
                "description": item.get("description") or "",
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "default_branch": item.get("default_branch"),
            }
        except requests.exceptions.RequestException as exc:
            logger.warning(f"Cannot fetch API metadata for {owner}/{repo}: {exc}")
            return None

    @staticmethod
    def _run_git(cmd: List[str], cwd: Optional[str] = None, timeout: int = 600) -> Tuple[int, str]:
        try:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or "") + (result.stderr or "")
            return result.returncode, output.strip()
        except subprocess.TimeoutExpired:
            return 124, "command timeout"
        except Exception as exc:
            return 1, str(exc)

    def _current_head(self, repo_path: str) -> Optional[str]:
        code, output = self._run_git(["git", "rev-parse", "HEAD"], cwd=repo_path, timeout=30)
        if code == 0 and output:
            return output.strip()
        return None

    def _checkout_commit(self, repo_path: str, commit_sha: str) -> Tuple[bool, str]:
        if not commit_sha:
            return False, "missing vulnerable commit SHA"

        code, output = self._run_git(["git", "checkout", commit_sha], cwd=repo_path, timeout=120)
        if code == 0:
            return True, "checked out"

        # Try fetch commit if checkout failed (likely missing commit in history)
        fetch_code, fetch_out = self._run_git(
            ["git", "fetch", "origin", commit_sha, "--depth", "1"],
            cwd=repo_path,
            timeout=300,
        )
        if fetch_code == 0:
            code, output = self._run_git(["git", "checkout", commit_sha], cwd=repo_path, timeout=120)
            if code == 0:
                return True, "fetched and checked out"

        # Fallback: full fetch
        full_code, full_out = self._run_git(["git", "fetch", "origin"], cwd=repo_path, timeout=600)
        if full_code == 0:
            code, output = self._run_git(["git", "checkout", commit_sha], cwd=repo_path, timeout=120)
            if code == 0:
                return True, "full fetch and checked out"

        error_msg = " | ".join(part for part in [output, fetch_out, full_out] if part)
        return False, error_msg or "checkout failed"

    def clone_vulnerable_repo(self, repo_data: Dict, vulnerable_commit: str) -> bool:
        repo_path = self._repo_local_path(repo_data["full_name"], vulnerable_commit)

        if os.path.exists(repo_path):
            repo_data["local_path"] = to_project_relative(repo_path)
            current = self._current_head(repo_path)
            if current and vulnerable_commit and current.startswith(vulnerable_commit[:7]):
                repo_data["clone_status"] = "already_exists"
                return True

            ok, msg = self._checkout_commit(repo_path, vulnerable_commit)
            repo_data["clone_status"] = "updated" if ok else "failed"
            if not ok:
                repo_data["clone_error"] = msg
            return ok

        cmd = [
            "git",
            "clone",
            "--no-checkout",
            "--depth",
            "1",
            repo_data["clone_url"],
            repo_path,
        ]
        code, output = self._run_git(cmd, timeout=600)
        if code != 0:
            repo_data["clone_status"] = "failed"
            repo_data["clone_error"] = output
            return False

        ok, msg = self._checkout_commit(repo_path, vulnerable_commit)
        repo_data["local_path"] = to_project_relative(repo_path)
        repo_data["clone_status"] = "success" if ok else "failed"
        if not ok:
            repo_data["clone_error"] = msg
        return ok

    def load_metadata(self) -> List[Dict]:
        if not os.path.exists(self.metadata_file):
            return []
        try:
            with open(self.metadata_file, "r", encoding="utf-8-sig") as f:
                return json.load(f)
        except Exception as exc:
            logger.error(f"Error loading metadata: {exc}")
            return []

    def save_metadata(self, records: List[Dict]):
        existing = self.load_metadata()
        merged: Dict[str, Dict] = {}

        for item in existing:
            if not isinstance(item, dict):
                continue
            key = item.get("metadata_key")
            if key:
                merged[key] = item

        for record in records:
            key = record.get("metadata_key")
            if not key:
                continue
            if record.get("local_path"):
                record["local_path"] = to_project_relative(record.get("local_path"))
            merged[key] = record

        output = list(merged.values())
        with open(self.metadata_file, "w", encoding="utf-8-sig") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    def _load_groundtruth(self, input_file: str) -> List[Dict]:
        if not os.path.exists(input_file):
            logger.error(f"Ground-truth file not found: {input_file}")
            return []
        try:
            with open(input_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception as exc:
            logger.error(f"Error reading ground-truth file: {exc}")
        return []

    def crawl_from_groundtruth(self, input_file: str, max_records: Optional[int] = None) -> List[Dict]:
        records = self._load_groundtruth(input_file)
        if not records:
            return []

        existing_metadata = self.load_metadata()
        existing_keys = {
            item.get("metadata_key")
            for item in existing_metadata
            if isinstance(item, dict) and item.get("metadata_key")
        }

        updates: List[Dict] = []

        for idx, record in enumerate(records):
            if max_records is not None and idx >= max_records:
                break

            full_name = record.get("repo_full_name")
            vulnerable_commit = record.get("vulnerable_commit") or ""
            parsed = self._parse_repo_full_name(full_name)
            if not parsed or not vulnerable_commit:
                continue

            owner, repo = parsed
            metadata_key = f"{full_name}@{vulnerable_commit}"
            if metadata_key in existing_keys:
                logger.info(f"Skip existing vulnerable repo in metadata: {metadata_key}")
                continue

            api_data = self._fetch_repo_metadata(owner, repo)
            repo_data = api_data or self._build_fallback_metadata(owner, repo)
            repo_data["full_name"] = full_name
            repo_data["owner"] = owner
            repo_data["name"] = repo_data.get("name") or repo
            repo_data["url"] = repo_data.get("url") or f"https://github.com/{full_name}"
            repo_data["clone_url"] = repo_data.get("clone_url") or f"https://github.com/{full_name}.git"
            repo_data["crawled_at"] = datetime.now().isoformat()

            # Keep ground-truth fields
            repo_data["vulnerable_commit"] = vulnerable_commit
            repo_data["patched_commit"] = record.get("patched_commit")
            repo_data["cves"] = record.get("cves", [])
            repo_data["ground_truth_label"] = record.get("ground_truth_label")
            repo_data["pr_url"] = record.get("pr_url")
            repo_data["closed_at"] = record.get("closed_at")
            repo_data["merged_at"] = record.get("merged_at")
            repo_data["metadata_key"] = metadata_key

            logger.info(f"Cloning vulnerable repo: {full_name} @ {vulnerable_commit[:10]}")
            self.clone_vulnerable_repo(repo_data, vulnerable_commit)

            updates.append(repo_data)
            existing_keys.add(metadata_key)
            time.sleep(1.0)

        self.save_metadata(updates)
        logger.info(f"Processed {len(updates)} vulnerable repos from {input_file}")
        return updates


def main():
    parser = argparse.ArgumentParser(description="Clone vulnerable repos from Dependabot ground-truth data")
    parser.add_argument(
        "--input-file",
        default=DEFAULT_INPUT_FILE,
        help="Path to dependabot_groundtruth_*.json",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to store vulnerable repo clones",
    )
    parser.add_argument(
        "--metadata-file",
        default=DEFAULT_METADATA_FILE,
        help="Metadata output file (JSON)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Limit number of records to process",
    )
    args = parser.parse_args()

    crawler = DependabotVulnerableCrawler(
        github_token=os.getenv("GITHUB_TOKEN"),
        output_dir=args.output_dir,
        metadata_file=args.metadata_file,
    )

    results = crawler.crawl_from_groundtruth(args.input_file, max_records=args.max_records)
    print(f"\nProcessed {len(results)} vulnerable repositories.")


if __name__ == "__main__":
    main()
