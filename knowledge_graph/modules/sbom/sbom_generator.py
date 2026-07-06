"""
SBOM Generator
Generate SBOM for cloned repositories and skip repositories that already have SBOM files.
"""

import os
import sys
import json
import logging
import shutil
import subprocess
import argparse
from datetime import datetime
from typing import Dict, List, Optional

from pathlib import Path

try:
    from modules.utils.paths import (
        SBOMS_DIR,
        REPOS_METADATA_FILE,
        ensure_data_dirs,
        resolve_project_path,
        to_project_relative,
    )
except ModuleNotFoundError:
    # Allow direct execution from this file path.
    KG_ROOT = Path(__file__).resolve().parents[2]
    if str(KG_ROOT) not in sys.path:
        sys.path.insert(0, str(KG_ROOT))
    from modules.utils.paths import (
        SBOMS_DIR,
        REPOS_METADATA_FILE,
        ensure_data_dirs,
        resolve_project_path,
        to_project_relative,
    )


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class SBOMGenerator:
    def __init__(self, output_dir: str = None, project_language: str = "nodejs"):
        ensure_data_dirs()
        self.output_dir = output_dir or str(SBOMS_DIR)
        os.makedirs(self.output_dir, exist_ok=True)
        self._cdxgen_available: Optional[bool] = None
        self.project_language = (project_language or "nodejs").lower()

    def _check_cdxgen(self) -> bool:
        try:
            result = subprocess.run(
                ["cdxgen", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _ensure_cdxgen(self) -> bool:
        if self._cdxgen_available is None:
            self._cdxgen_available = self._check_cdxgen()
            if not self._cdxgen_available:
                logger.error("cdxgen is not installed. Install: npm install -g @cyclonedx/cdxgen")
        return bool(self._cdxgen_available)

    @staticmethod
    def _safe_repo_name(repo_name: str) -> str:
        return repo_name.replace("/", "_").replace("\\", "_")

    def _sbom_output_file(self, repo_name: str) -> str:
        return os.path.join(self.output_dir, f"{self._safe_repo_name(repo_name)}_sbom.json")

    @staticmethod
    def _venv_python_path(repo_path: str) -> str:
        if os.name == "nt":
            return os.path.join(repo_path, ".venv", "Scripts", "python.exe")
        return os.path.join(repo_path, ".venv", "bin", "python")

    @staticmethod
    def _find_requirements_file(repo_path: str) -> Optional[str]:
        candidates = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "requirements_test.txt",
        ]
        for name in candidates:
            req_path = os.path.join(repo_path, name)
            if os.path.isfile(req_path):
                return req_path
        return None

    @staticmethod
    def _allow_untrusted_dependency_install() -> bool:
        return os.getenv("ALLOW_UNTRUSTED_DEPENDENCY_INSTALL", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _repo_matches_project_language(self, repo_language: str) -> bool:
        normalized = (repo_language or "").strip().lower()

        if self.project_language == "python":
            return normalized in {"python", "py"}

        # nodejs flow can safely cover JavaScript/TypeScript repositories.
        return normalized in {"javascript", "js", "typescript", "ts"}

    def _prepare_python_env(self, repo_path: str, repo_name: str) -> bool:
        try:
            venv_cmd = ["python3", "-m", "venv", ".venv"]
            venv_result = subprocess.run(
                venv_cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if venv_result.returncode != 0:
                logger.error(f"Failed to create venv for {repo_name}: {venv_result.stderr}")
                return False

            venv_python = self._venv_python_path(repo_path)
            if not os.path.exists(venv_python):
                logger.error(f"Venv python executable not found for {repo_name}: {venv_python}")
                return False

            venv_dir = os.path.join(repo_path, ".venv")
            venv_bin_dir = os.path.dirname(venv_python)
            pip_env = os.environ.copy()
            pip_env["VIRTUAL_ENV"] = venv_dir
            pip_env["PIP_REQUIRE_VIRTUALENV"] = "1"
            pip_env["PYTHONNOUSERSITE"] = "1"
            pip_env["PATH"] = (
                f"{venv_bin_dir}{os.pathsep}{pip_env.get('PATH', '')}"
                if pip_env.get("PATH")
                else venv_bin_dir
            )

            req_file = self._find_requirements_file(repo_path)
            if req_file:
                if not self._allow_untrusted_dependency_install():
                    logger.warning(
                        "Skipping dependency installation for %s. Set "
                        "ALLOW_UNTRUSTED_DEPENDENCY_INSTALL=true only in an isolated "
                        "environment if installing dependencies from cloned repositories "
                        "is required.",
                        repo_name,
                    )
                    return True
                pip_cmd = [venv_python, "-m", "pip", "install", "-r", req_file]
                pip_result = subprocess.run(
                    pip_cmd,
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=900,
                    env=pip_env,
                )
                if pip_result.returncode != 0:
                    logger.error(f"Failed to install requirements for {repo_name}: {pip_result.stderr}")
                    return False
            else:
                logger.info(f"No requirements file found for {repo_name}, skip pip install")

            return True
        except Exception as exc:
            logger.error(f"Error preparing python env for {repo_name}: {exc}")
            return False

    def _load_existing_sbom(self, repo_name: str, repo_path: str) -> Optional[Dict]:
        sbom_file = self._sbom_output_file(repo_name)
        if not os.path.exists(sbom_file):
            return None

        try:
            with open(sbom_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["_metadata"] = {
                "repo_name": repo_name,
                "repo_path": to_project_relative(repo_path),
                "generated_at": data.get("_metadata", {}).get("generated_at") or datetime.now().isoformat(),
                "generation_duration_seconds": data.get("_metadata", {}).get("generation_duration_seconds", 0),
                "cdxgen_return_code": data.get("_metadata", {}).get("cdxgen_return_code", 0),
                "output_file": to_project_relative(sbom_file),
                "reused_existing": True,
            }
            return data
        except Exception as exc:
            logger.warning(f"Invalid existing SBOM for {repo_name}, regenerate: {exc}")
            return None

    def generate_sbom(self, repo_path: str, repo_name: str) -> Optional[Dict]:
        if not self._ensure_cdxgen():
            return None

        repo_path = resolve_project_path(repo_path)
        if not repo_path or not os.path.exists(repo_path):
            logger.error(f"Repository path does not exist for {repo_name}: {repo_path}")
            return None

        output_file = self._sbom_output_file(repo_name)
        if self.project_language == "python":
            if not self._prepare_python_env(repo_path=repo_path, repo_name=repo_name):
                return None
            cmd = ["cdxgen", repo_path, "-o", output_file, "-t", "python", "--deep"]
        else:
            # --no-install: ngăn cdxgen tự chạy npm/yarn install
            # Không cần install; cdxgen đọc package-lock.json / yarn.lock trực tiếp
            cmd = ["cdxgen", repo_path, "-o", output_file, "--no-install"]


        try:
            start = datetime.now()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            duration = (datetime.now() - start).total_seconds()

            if result.returncode != 0 and not os.path.exists(output_file):
                logger.error(f"Failed to generate SBOM for {repo_name}: {result.stderr}")
                return None

            if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
                logger.error(f"Failed to generate SBOM for {repo_name}: output file is empty")
                return None

            if result.returncode != 0 and os.path.exists(output_file):
                logger.warning(
                    "cdxgen returned non-zero for %s, but SBOM exists. Using output anyway. stderr=%s",
                    repo_name,
                    (result.stderr or "").strip(),
                )

            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            data["_metadata"] = {
                "repo_name": repo_name,
                "repo_path": to_project_relative(repo_path),
                "generated_at": datetime.now().isoformat(),
                "generation_duration_seconds": duration,
                "cdxgen_return_code": result.returncode,
                "cdxgen_error": (result.stderr or "").strip() if result.returncode != 0 else None,
                "output_file": to_project_relative(output_file),
            }
            return data
        except Exception as exc:
            logger.error(f"Error generating SBOM for {repo_name}: {exc}")
            return None

    def generate_batch(
        self,
        repos_metadata: List[Dict],
        summary_file: Optional[str] = None,
        save_after_each: bool = False,
    ) -> List[Dict]:
        results: List[Dict] = []

        for repo in repos_metadata:
            repo_name = repo.get("metadata_key") or repo.get("full_name")
            repo_path = resolve_project_path(repo.get("local_path"))
            repo_lang = repo.get("language")

            if not self._repo_matches_project_language(repo_lang):
                logger.info(
                    "Skip repo with mismatched language for %s flow: %s (language=%s)",
                    self.project_language,
                    repo_name,
                    repo_lang,
                )
                continue

            if not repo_name or not repo_path or not os.path.exists(repo_path):
                logger.warning(f"Skip repo without local path: {repo.get('full_name', 'unknown')}")
                continue

            sbom = self._load_existing_sbom(repo_name, repo_path)
            if sbom:
                logger.info(f"SBOM exists, skip cdxgen: {repo_name}")
            else:
                sbom = self.generate_sbom(repo_path=repo_path, repo_name=repo_name)

            if sbom:
                results.append(
                    {
                        "repo": repo,
                        "sbom": sbom,
                        "sbom_file": to_project_relative(sbom.get("_metadata", {}).get("output_file")),
                        "status": "success",
                    }
                )
            else:
                results.append(
                    {
                        "repo": repo,
                        "sbom": None,
                        "sbom_file": None,
                        "status": "failed",
                    }
                )

            if save_after_each and summary_file:
                self.save_summary(results, output_file=summary_file)

        logger.info(
            f"SBOM summary: total={len(repos_metadata)} success={sum(1 for r in results if r['status'] == 'success')} failed={sum(1 for r in results if r['status'] == 'failed')}"
        )
        return results

    def save_summary(self, results: List[Dict], output_file: str = "sbom_summary.json"):
        output_path = os.path.join(self.output_dir, output_file)

        existing_summary = {}
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    existing_summary = json.load(f)
            except Exception:
                existing_summary = {}

        merged_by_repo = {
            item.get("repo_name"): item
            for item in existing_summary.get("results", [])
            if isinstance(item, dict) and item.get("repo_name")
        }

        for r in results:
            repo_name = r.get("repo", {}).get("full_name")
            if not repo_name:
                continue
            merged_by_repo[repo_name] = {
                "repo_name": repo_name,
                "status": r.get("status"),
                "sbom_file": to_project_relative(r.get("sbom_file")) if r.get("sbom_file") else None,
                "component_count": len((r.get("sbom") or {}).get("components", [])),
            }

        merged_results = list(merged_by_repo.values())
        summary = {
            "generated_at": datetime.now().isoformat(),
            "total_repos": len(merged_results),
            "successful": sum(1 for r in merged_results if r.get("status") == "success"),
            "failed": sum(1 for r in merged_results if r.get("status") == "failed"),
            "results": merged_results,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="Generate SBOM for cloned repositories")
    parser.add_argument(
        "--vuln-repos",
        action="store_true",
        help="Use vulnerable repo flow defaults for inputs/outputs",
    )
    parser.add_argument(
        "-p",
        "--project-language",
        choices=["nodejs", "python"],
        default="nodejs",
        help="Project language to choose SBOM generation flow (default: nodejs)",
    )
    args = parser.parse_args()

    if args.vuln_repos:
        kg_root = Path(__file__).resolve().parents[2]
        metadata_file = str(kg_root / "data" / "metadata" / "vulnerable_repos_metadata.json")
        output_dir = str(kg_root / "data" / "vulnerable_sboms")
        summary_file = "vulnerable_sbom_summary.json"
    else:
        metadata_file = str(REPOS_METADATA_FILE)
        output_dir = str(SBOMS_DIR)
        summary_file = "sbom_summary.json"

    if not os.path.exists(metadata_file):
        logger.error(f"Metadata file not found: {metadata_file}")
        return

    with open(metadata_file, "r", encoding="utf-8-sig") as f:
        repos = json.load(f)

    cloned_repos = [r for r in repos if r.get("clone_status") in {"success", "already_exists"}]
    if not cloned_repos:
        logger.error("No cloned repositories found")
        return

    generator = SBOMGenerator(output_dir=output_dir, project_language=args.project_language)
    results = generator.generate_batch(
        cloned_repos,
        summary_file=summary_file,
        save_after_each=True,
    )
    generator.save_summary(results, output_file=summary_file)

    print(f"Generated {sum(1 for r in results if r['status'] == 'success')} SBOMs")


if __name__ == "__main__":
    main()
