"""
GitHub Repository Crawler
Reads repos_link.txt, clones missing repositories, and updates metadata incrementally.
"""

import os
import json
import logging
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

import requests

from modules.utils.paths import (
    REPOS_DIR,
    REPOS_METADATA_FILE,
    ensure_data_dirs,
    to_project_relative,
)
from modules.crawler.dependabot_vuln_crawler import DependabotVulnerableCrawler


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class GitHubCrawler:
    """Clone repositories from a links file and keep metadata in sync."""

    def __init__(self, github_token: Optional[str] = None, output_dir: str = None):
        ensure_data_dirs()
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.output_dir = output_dir or str(REPOS_DIR)
        self.metadata_file = str(REPOS_METADATA_FILE)
        self.base_url = "https://api.github.com"

        os.makedirs(self.output_dir, exist_ok=True)

        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            self.headers["Authorization"] = f"token {self.github_token}"

    @staticmethod
    def _parse_repo_identifier(repo_input: str) -> Optional[Tuple[str, str]]:
        if not repo_input:
            return None

        text = repo_input.strip()
        if not text or text.startswith("#"):
            return None

        if text.endswith(".git"):
            text = text[:-4]

        if text.startswith("https://github.com/") or text.startswith("http://github.com/"):
            parts = text.rstrip("/").split("/")
            if len(parts) >= 5:
                return parts[3], parts[4]
            return None

        if "/" in text:
            owner, repo = text.split("/", 1)
            owner = owner.strip()
            repo = repo.strip().rstrip("/")
            if owner and repo:
                return owner, repo

        return None

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

    def _repo_local_path(self, full_name: str) -> str:
        return os.path.join(self.output_dir, full_name.replace("/", "_"))

    def clone_repository(self, repo_data: Dict) -> bool:
        repo_path = self._repo_local_path(repo_data["full_name"])

        if os.path.exists(repo_path):
            repo_data["local_path"] = to_project_relative(repo_path)
            repo_data["clone_status"] = "already_exists"
            return True

        cmd = ["git", "clone", "--depth", "1", repo_data["clone_url"], repo_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            repo_data["clone_status"] = "timeout"
            repo_data["clone_error"] = "clone timeout"
            return False
        except Exception as exc:
            repo_data["clone_status"] = "error"
            repo_data["clone_error"] = str(exc)
            return False

        if result.returncode == 0:
            repo_data["local_path"] = to_project_relative(repo_path)
            repo_data["clone_status"] = "success"
            return True

        repo_data["clone_status"] = "failed"
        repo_data["clone_error"] = (result.stderr or "").strip()
        return False

    def load_metadata(self) -> List[Dict]:
        if not os.path.exists(self.metadata_file):
            return []
        try:
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error(f"Error loading metadata: {exc}")
            return []

    def save_metadata(self, repos: List[Dict]):
        existing = self.load_metadata()
        for item in existing:
            if isinstance(item, dict) and item.get("local_path"):
                item["local_path"] = to_project_relative(item.get("local_path"))
        merged: Dict[str, Dict] = {
            r.get("full_name"): r
            for r in existing
            if isinstance(r, dict) and r.get("full_name")
        }

        for repo in repos:
            full_name = repo.get("full_name")
            if not full_name:
                continue
            if repo.get("local_path"):
                repo["local_path"] = to_project_relative(repo.get("local_path"))
            merged[full_name] = repo

        output = list(merged.values())
        os.makedirs(os.path.dirname(self.metadata_file), exist_ok=True)
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    def crawl_from_file(self, repo_links_file: str) -> List[Dict]:
        if not os.path.exists(repo_links_file):
            logger.error(f"Repository list file not found: {repo_links_file}")
            return []

        with open(repo_links_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]

        existing_metadata = self.load_metadata()
        existing_by_full_name = {
            r.get("full_name"): r
            for r in existing_metadata
            if isinstance(r, dict) and r.get("full_name")
        }

        updates: List[Dict] = []

        for raw in lines:
            parsed = self._parse_repo_identifier(raw)
            if not parsed:
                continue

            owner, repo = parsed
            full_name = f"{owner}/{repo}"
            if full_name in existing_by_full_name:
                logger.info(f"Skip existing repo in metadata (no API call): {full_name}")
                continue

            api_data = self._fetch_repo_metadata(owner, repo)
            repo_data = api_data or self._build_fallback_metadata(owner, repo)
            repo_data["full_name"] = full_name
            repo_data["owner"] = owner
            repo_data["name"] = repo_data.get("name") or repo
            repo_data["url"] = repo_data.get("url") or f"https://github.com/{full_name}"
            repo_data["clone_url"] = repo_data.get("clone_url") or f"https://github.com/{full_name}.git"
            repo_data["crawled_at"] = datetime.now().isoformat()

            local_path = self._repo_local_path(full_name)
            if os.path.exists(local_path):
                repo_data["local_path"] = to_project_relative(local_path)
                repo_data["clone_status"] = "already_exists"
            else:
                self.clone_repository(repo_data)

            updates.append(repo_data)
            existing_by_full_name[full_name] = repo_data

        self.save_metadata(updates)
        logger.info(f"Processed {len(updates)} repositories from {repo_links_file}")
        return updates

    def crawl(self, repo_links_file: str = "data/metadata/repos_link.txt", **_: Dict) -> List[Dict]:
        """Backward-compatible wrapper."""
        return self.crawl_from_file(repo_links_file)


def main():
    parser = argparse.ArgumentParser(description="GitHub repository crawler")
    parser.add_argument(
        "--repo-links-file",
        default="data/metadata/repos_link.txt",
        help="Text file with one repo link (or owner/repo) per line",
    )
    parser.add_argument(
        "--vuln-repos",
        action="store_true",
        help="Use vulnerable repo flow (Dependabot ground-truth)",
    )
    parser.add_argument(
        "--vuln-language",
        choices=["javascript", "python"],
        default="javascript",
        help="Language for Dependabot ground-truth (javascript or python)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Limit number of vulnerable records to process",
    )
    args = parser.parse_args()

    if args.vuln_repos:
        kg_root = Path(__file__).resolve().parents[2]
        groundtruth_file = str(kg_root / f"dependabot_groundtruth_{args.vuln_language}.json")
        crawler = DependabotVulnerableCrawler(
            github_token=os.getenv("GITHUB_TOKEN"),
        )
        repos = crawler.crawl_from_groundtruth(
            groundtruth_file,
            max_records=args.max_records,
        )
        print(f"\nProcessed {len(repos)} vulnerable repositories.")
        return

    crawler = GitHubCrawler(
        github_token=os.getenv("GITHUB_TOKEN"),
        output_dir=str(REPOS_DIR),
    )

    repos = crawler.crawl_from_file(args.repo_links_file)

    print(f"\nProcessed {len(repos)} repositories:")
    for repo in repos:
        print(f"  - {repo.get('full_name')}: {repo.get('clone_status', 'unknown')}")


if __name__ == "__main__":
    main()
