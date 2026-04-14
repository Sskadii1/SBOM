"""
Main Orchestrator
Runs the complete pipeline: crawl -> SBOM -> vulnerability check -> Neo4j import
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import List, Dict, Set, Optional

from modules.crawler.github_crawler import GitHubCrawler
from modules.crawler.dependabot_vuln_crawler import DependabotVulnerableCrawler
from modules.get_link import get_link_github
from modules.sbom.sbom_generator import SBOMGenerator
from modules.vulnerability.osv_checker import OSVChecker
from modules.graph.neo4j_integration import Neo4jKnowledgeGraph
from modules.utils.paths import (
    METADATA_DIR,
    REPOS_METADATA_FILE,
    SBOMS_DIR,
    VULNS_DIR,
    VULNERABLE_REPOS_METADATA_FILE,
    VULNERABLE_REPOS_DIR,
    VULNERABLE_SBOMS_DIR,
    VULNERABLE_VULNS_DIR,
    ensure_data_dirs,
    resolve_project_path,
    to_project_relative,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class Pipeline:
    """Main pipeline orchestrator"""

    def __init__(
        self,
        github_token: str = None,
        neo4j_uri: str = "bolt://localhost:7689",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password"
    ):
        """
        Initialize pipeline

        Args:
            github_token: GitHub API token
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password

        ensure_data_dirs()

        # Initialize components
        self.crawler = None
        self.sbom_generator = None
        self.osv_checker = None
        self.knowledge_graph = None

    @staticmethod
    def _load_json_file(path: str) -> Dict:
        if not os.path.exists(path):
            return {}
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def _successful_sbom_repos() -> Set[str]:
        sbom_summary_file = os.path.join(str(SBOMS_DIR), "sbom_summary.json")
        if not os.path.exists(sbom_summary_file):
            return set()

        summary = Pipeline._load_json_file(sbom_summary_file)
        results = summary.get("results", []) if isinstance(summary, dict) else []
        return {
            r.get("repo_name")
            for r in results
            if r.get("repo_name") and r.get("status") == "success" and r.get("sbom_file")
        }

    @staticmethod
    def _successful_vuln_repos() -> Set[str]:
        vuln_summary_file = os.path.join(str(VULNS_DIR), "vulnerability_summary.json")
        if not os.path.exists(vuln_summary_file):
            return set()

        summary = Pipeline._load_json_file(vuln_summary_file)
        results = summary.get("results", []) if isinstance(summary, dict) else []
        return {
            r.get("repo_name")
            for r in results
            if r.get("repo_name") and r.get("vulnerability_file")
        }

    def run_step_0_get_link(self) -> str:
        """Step 0: Build repository links file for both JavaScript and Python."""
        logger.info("\n" + "="*80)
        logger.info("STEP 0: COLLECTING REPOSITORY LINKS")
        logger.info("="*80 + "\n")

        output_file = get_link_github(crawl_js=True, crawl_py=True)
        logger.info(f"\nStep 0 completed: Repository links saved to {output_file}")
        return str(output_file)

    def run_step_1_crawl(
        self,
        languages: List[str] = ["Java", "JavaScript"],
        min_size: int = 10000,
        max_per_language: int = 25,
        clone: bool = True,
        repo_links_file: Optional[str] = None
    ) -> List[Dict]:
        """
        Step 1: Crawl GitHub repositories

        Args:
            languages: Programming languages to search for
            min_size: Minimum repository size in KB
            max_per_language: Maximum repos per language
            clone: Whether to clone repositories
            repo_links_file: File containing all repository links (incremental mode)

        Returns:
            List of newly added repository metadata
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 1: CRAWLING GITHUB REPOSITORIES")
        logger.info("="*80 + "\n")

        self.crawler = GitHubCrawler(
            github_token=self.github_token
        )

        if repo_links_file:
            repos = self.crawler.crawl_from_file(repo_links_file)
        else:
            repos = self.crawler.crawl(
                languages=languages,
                min_size=min_size,
                max_per_language=max_per_language,
                clone=clone
            )

        logger.info(f"\nStep 1 completed: Crawled {len(repos)} new repositories")
        return repos

    def run_step_1b_vulnerable_crawl(
        self,
        groundtruth_file: str,
        max_records: Optional[int] = None,
        output_dir: Optional[str] = None,
        metadata_file: Optional[str] = None,
    ) -> List[Dict]:
        """
        Step 1B: Crawl vulnerable repositories from Dependabot ground-truth data.
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 1B: CRAWLING VULNERABLE REPOSITORIES")
        logger.info("="*80 + "\n")

        crawler = DependabotVulnerableCrawler(
            github_token=self.github_token,
            output_dir=output_dir,
            metadata_file=metadata_file,
        )

        repos = crawler.crawl_from_groundtruth(groundtruth_file, max_records=max_records)
        logger.info(f"\nStep 1B completed: Crawled {len(repos)} vulnerable repositories")
        return repos

    def run_step_2_sbom(self, repos_metadata: List[Dict] = None) -> List[Dict]:
        """
        Step 2: Generate SBOMs using cdxgen (incremental)

        Args:
            repos_metadata: Repository metadata (if None, load from file)

        Returns:
            List of SBOM results
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 2: GENERATING SBOMS")
        logger.info("="*80 + "\n")

        # Load repos if not provided
        if repos_metadata is None:
            if not os.path.exists(REPOS_METADATA_FILE):
                logger.error(f"Metadata file not found: {REPOS_METADATA_FILE}")
                return []

            with open(REPOS_METADATA_FILE, 'r', encoding='utf-8') as f:
                repos_metadata = json.load(f)

        successful_sbom_repos = self._successful_sbom_repos()

        # Filter cloned repos and skip repos that already have SBOM
        cloned_statuses = {"success", "already_exists"}
        cloned_repos = [
            r for r in repos_metadata
            if r.get("clone_status") in cloned_statuses
            and r.get("full_name")
            and r.get("full_name") not in successful_sbom_repos
        ]
        logger.info(f"Found {len(cloned_repos)} repositories pending SBOM generation")

        if not cloned_repos:
            logger.info("No new repositories need SBOM generation")
            return []

        # Generate SBOM
        self.sbom_generator = SBOMGenerator(output_dir=str(SBOMS_DIR))
        results = self.sbom_generator.generate_batch(cloned_repos)

        # Save summary
        self.sbom_generator.save_summary(results)

        logger.info(f"\nStep 2 completed: Generated {sum(1 for r in results if r['status'] == 'success')} SBOMs")
        return results

    def run_step_2b_vulnerable_sbom(self, repos_metadata: List[Dict] = None) -> List[Dict]:
        """
        Step 2B: Generate SBOMs for vulnerable repositories (separate output dir)
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 2B: GENERATING SBOMS FOR VULNERABLE REPOS")
        logger.info("="*80 + "\n")

        if repos_metadata is None:
            if not os.path.exists(VULNERABLE_REPOS_METADATA_FILE):
                logger.error(f"Metadata file not found: {VULNERABLE_REPOS_METADATA_FILE}")
                return []

            with open(VULNERABLE_REPOS_METADATA_FILE, "r", encoding="utf-8") as f:
                repos_metadata = json.load(f)

        cloned_statuses = {"success", "already_exists", "updated"}
        cloned_repos = [
            r for r in repos_metadata
            if r.get("clone_status") in cloned_statuses
            and r.get("full_name")
        ]
        logger.info(f"Found {len(cloned_repos)} vulnerable repos pending SBOM generation")

        if not cloned_repos:
            logger.info("No vulnerable repositories need SBOM generation")
            return []

        self.sbom_generator = SBOMGenerator(output_dir=str(VULNERABLE_SBOMS_DIR))
        results = self.sbom_generator.generate_batch(cloned_repos)
        self.sbom_generator.save_summary(results, output_file="vulnerable_sbom_summary.json")

        logger.info(
            f"\nStep 2B completed: Generated {sum(1 for r in results if r['status'] == 'success')} SBOMs"
        )
        return results

    def run_step_3_vulnerability_check(self, sbom_results: List[Dict] = None) -> List[Dict]:
        """
        Step 3: Check vulnerabilities using OSV.dev (incremental)

        Args:
            sbom_results: SBOM generation results (if None, load from files)

        Returns:
            List of enriched results with vulnerability data
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 3: CHECKING VULNERABILITIES")
        logger.info("="*80 + "\n")

        processed_vuln_repos = self._successful_vuln_repos()

        # Load SBOM results if not provided
        if sbom_results is None:
            sbom_summary_file = os.path.join(str(SBOMS_DIR), "sbom_summary.json")
            if not os.path.exists(sbom_summary_file):
                logger.error(f"SBOM summary not found: {sbom_summary_file}")
                return []

            sbom_results = []
            with open(sbom_summary_file, 'r', encoding='utf-8') as f:
                summary = json.load(f)

            all_repos = []
            if os.path.exists(REPOS_METADATA_FILE):
                with open(REPOS_METADATA_FILE, 'r', encoding='utf-8') as f:
                    all_repos = json.load(f)

            for result in summary.get("results", []):
                repo_name = result.get("repo_name")
                sbom_file = resolve_project_path(result.get("sbom_file"))
                if not repo_name or repo_name in processed_vuln_repos:
                    continue
                if result.get("status") != "success" or not sbom_file or not os.path.exists(sbom_file):
                    continue

                with open(sbom_file, 'r', encoding='utf-8') as f:
                    sbom_data = json.load(f)

                repo = next((r for r in all_repos if r.get("full_name") == repo_name), None)
                if repo:
                    sbom_results.append({
                        "repo": repo,
                        "sbom": sbom_data,
                        "sbom_file": to_project_relative(sbom_file),
                        "status": "success"
                    })
        else:
            sbom_results = [
                r for r in sbom_results
                if r.get("repo", {}).get("full_name") not in processed_vuln_repos
            ]

        logger.info(f"Loaded {len(sbom_results)} SBOM results pending vulnerability check")

        if not sbom_results:
            logger.info("No new repositories need vulnerability checking")
            return []

        # Check vulnerabilities
        self.osv_checker = OSVChecker(output_dir=str(VULNS_DIR))
        enriched_results = self.osv_checker.process_sbom_results(sbom_results)

        # Save summary
        self.osv_checker.save_summary(enriched_results)

        total_vulns = sum(
            r.get("vulnerability_data", {}).get("total_vulnerabilities", 0)
            for r in enriched_results
        )

        logger.info(f"\nStep 3 completed: Found {total_vulns} total vulnerabilities")
        return enriched_results

    def run_step_3b_vulnerable_vulnerability_check(self, sbom_results: List[Dict] = None) -> List[Dict]:
        """
        Step 3B: Check vulnerabilities for vulnerable repos (separate output dir)
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 3B: CHECKING VULNERABILITIES FOR VULNERABLE REPOS")
        logger.info("="*80 + "\n")

        if sbom_results is None:
            sbom_summary_file = os.path.join(str(VULNERABLE_SBOMS_DIR), "vulnerable_sbom_summary.json")
            if not os.path.exists(sbom_summary_file):
                logger.error(f"SBOM summary not found: {sbom_summary_file}")
                return []

            sbom_results = []
            with open(sbom_summary_file, "r", encoding="utf-8") as f:
                summary = json.load(f)

            all_repos = []
            if os.path.exists(VULNERABLE_REPOS_METADATA_FILE):
                with open(VULNERABLE_REPOS_METADATA_FILE, "r", encoding="utf-8") as f:
                    all_repos = json.load(f)
            repos_by_key = {
                r.get("metadata_key"): r
                for r in all_repos
                if isinstance(r, dict) and r.get("metadata_key")
            }
            repos_by_full_name = {
                r.get("full_name"): r
                for r in all_repos
                if isinstance(r, dict) and r.get("full_name")
            }

            for result in summary.get("results", []):
                repo_name = result.get("repo_name")
                sbom_file = resolve_project_path(result.get("sbom_file"))
                if not repo_name or result.get("status") != "success" or not sbom_file or not os.path.exists(sbom_file):
                    continue

                with open(sbom_file, "r", encoding="utf-8") as f:
                    sbom_data = json.load(f)

                repo = repos_by_key.get(repo_name) or repos_by_full_name.get(repo_name)
                if repo:
                    sbom_results.append(
                        {
                            "repo": repo,
                            "sbom": sbom_data,
                            "sbom_file": to_project_relative(sbom_file),
                            "status": "success",
                        }
                    )

        logger.info(f"Loaded {len(sbom_results)} SBOM results pending vulnerability check (vulnerable repos)")

        if not sbom_results:
            logger.info("No vulnerable repositories need vulnerability checking")
            return []

        self.osv_checker = OSVChecker(output_dir=str(VULNERABLE_VULNS_DIR))
        enriched_results = self.osv_checker.process_sbom_results(sbom_results)
        self.osv_checker.save_summary(enriched_results, output_file="vulnerable_vulnerability_summary.json")

        total_vulns = sum(
            r.get("vulnerability_data", {}).get("total_vulnerabilities", 0)
            for r in enriched_results
        )
        logger.info(f"\nStep 3B completed: Found {total_vulns} total vulnerabilities")
        return enriched_results

    def run_step_4_neo4j_import(
        self,
        enriched_results: List[Dict] = None,
        database: Optional[str] = None,
    ):
        """
        Step 4: Import data into Neo4j Knowledge Graph

        Args:
            enriched_results: Enriched results (if None, load from files)
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 4: IMPORTING TO NEO4J KNOWLEDGE GRAPH")
        logger.info("="*80 + "\n")

        # Load enriched results if not provided
        if enriched_results is None:
            vuln_summary_file = os.path.join(str(VULNS_DIR), "vulnerability_summary.json")
            if not os.path.exists(vuln_summary_file):
                logger.error(f"Vulnerability summary not found: {vuln_summary_file}")
                return

            enriched_results = []
            with open(vuln_summary_file, "r", encoding="utf-8") as f:
                summary = json.load(f)

            for result in summary.get("results", []):
                vuln_file = resolve_project_path(result.get("vulnerability_file"))
                if vuln_file and os.path.exists(vuln_file):
                    with open(vuln_file, "r", encoding="utf-8") as f:
                        vuln_data = json.load(f)

                    enriched_results.append(
                        {
                            "repo": vuln_data.get("repo"),
                            "vulnerability_data": vuln_data,
                            "sbom_file": to_project_relative(vuln_data.get("sbom_file")),
                        }
                    )

        logger.info(f"Loaded {len(enriched_results)} enriched results")

        # Initialize Knowledge Graph
        self.knowledge_graph = Neo4jKnowledgeGraph(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            database=database,
        )

        try:
            # Import data
            self.knowledge_graph.import_batch(enriched_results)

            # Get statistics
            stats = self.knowledge_graph.get_statistics()

            logger.info("\nStep 4 completed: Data imported to Neo4j")
            logger.info("\nKnowledge Graph Statistics:")
            logger.info(f"  - Projects: {stats['projects']}")
            logger.info(f"  - Components: {stats['components']}")
            logger.info(f"  - Vulnerabilities: {stats['vulnerabilities']}")
            logger.info(f"  - SBOMs: {stats['sboms']}")
            logger.info(f"  - Vulnerable Components: {stats['vulnerable_components']}")

        finally:
            self.knowledge_graph.close()

    def run_step_4b_neo4j_import_vulnerable(
        self,
        enriched_results: List[Dict] = None,
        database: Optional[str] = None,
    ):
        """
        Step 4B: Import vulnerable flow data into Neo4j (separate database).
        """
        logger.info("\n" + "="*80)
        logger.info("STEP 4B: IMPORTING VULNERABLE DATA TO NEO4J")
        logger.info("="*80 + "\n")

        if enriched_results is None:
            vuln_summary_file = os.path.join(str(VULNERABLE_VULNS_DIR), "vulnerable_vulnerability_summary.json")
            if not os.path.exists(vuln_summary_file):
                logger.error(f"Vulnerability summary not found: {vuln_summary_file}")
                return

            enriched_results = []
            with open(vuln_summary_file, "r", encoding="utf-8") as f:
                summary = json.load(f)

            for result in summary.get("results", []):
                vuln_file = resolve_project_path(result.get("vulnerability_file"))
                if vuln_file and os.path.exists(vuln_file):
                    with open(vuln_file, "r", encoding="utf-8") as f:
                        vuln_data = json.load(f)

                    enriched_results.append(
                        {
                            "repo": vuln_data.get("repo"),
                            "vulnerability_data": vuln_data,
                            "sbom_file": to_project_relative(vuln_data.get("sbom_file")),
                        }
                    )

        logger.info(f"Loaded {len(enriched_results)} vulnerable enriched results")

        if not enriched_results:
            logger.info("No vulnerable results to import")
            return

        self.knowledge_graph = Neo4jKnowledgeGraph(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            database=database,
        )

        try:
            self.knowledge_graph.import_batch(enriched_results)
            stats = self.knowledge_graph.get_statistics()
            logger.info("\nStep 4B completed: Data imported to Neo4j (vulnerable)")
            logger.info("\nKnowledge Graph Statistics (vulnerable):")
            logger.info(f"  - Projects: {stats['projects']}")
            logger.info(f"  - Components: {stats['components']}")
            logger.info(f"  - Vulnerabilities: {stats['vulnerabilities']}")
            logger.info(f"  - SBOMs: {stats['sboms']}")
            logger.info(f"  - Vulnerable Components: {stats['vulnerable_components']}")

        finally:
            self.knowledge_graph.close()

    def run_full_pipeline(
        self,
        languages: List[str] = ["Java", "JavaScript"],
        min_size: int = 10000,
        max_per_language: int = 25,
        repo_links_file: Optional[str] = None,
        vulnerable_groundtruth_file: Optional[str] = None,
        max_vulnerable_records: Optional[int] = None,
        neo4j_database: Optional[str] = None,
        vulnerable_neo4j_database: Optional[str] = "vuln_repos",
        skip_get_link: bool = False,
        skip_crawl: bool = False,
        skip_vulnerable_crawl: bool = True,
        skip_sbom: bool = False,
        skip_vulnerable_sbom: bool = True,
        skip_vuln_check: bool = False,
        skip_vulnerable_vuln_check: bool = True,
        skip_neo4j: bool = False,
        skip_vulnerable_neo4j: bool = False,
        clear_neo4j: bool = False
    ):
        """
        Run the complete pipeline

        Args:
            languages: Programming languages to crawl
            min_size: Minimum repository size
            max_per_language: Max repos per language
            vulnerable_groundtruth_file: Dependabot ground-truth file for vulnerable repo flow
            max_vulnerable_records: Limit vulnerable records to process
            skip_get_link: Skip repo link collection step
            skip_crawl: Skip crawling step
            skip_vulnerable_crawl: Skip vulnerable repo crawling step
            skip_sbom: Skip SBOM generation step
            skip_vulnerable_sbom: Skip vulnerable SBOM generation step
            skip_vuln_check: Skip vulnerability check step
            skip_vulnerable_vuln_check: Skip vulnerable vulnerability check step
            skip_neo4j: Skip Neo4j import step
            skip_vulnerable_neo4j: Skip Neo4j import for vulnerable flow
            clear_neo4j: Clear Neo4j before import
        """
        start_time = datetime.now()

        logger.info("\n" + "#"*80)
        logger.info("STARTING FULL PIPELINE")
        logger.info(f"Start time: {start_time}")
        logger.info("#"*80 + "\n")

        try:
            # Step 0 + Step 1: Get links then crawl
            if not skip_crawl:
                if repo_links_file:
                    logger.info(f"Using provided repo links file: {repo_links_file}")
                elif skip_get_link:
                    repo_links_file = os.path.join(str(METADATA_DIR), "repos_link.txt")
                    logger.info(f"Skipping Step 0: Get Link (using {repo_links_file})")
                else:
                    repo_links_file = self.run_step_0_get_link()

                repos = self.run_step_1_crawl(languages, min_size, max_per_language, repo_links_file=repo_links_file)
            else:
                logger.info("Skipping Step 1: Crawl")
                repos = None

            # Step 1B: Vulnerable Crawl
            vuln_repos = None
            if not skip_vulnerable_crawl:
                if not vulnerable_groundtruth_file:
                    logger.error("Missing vulnerable_groundtruth_file for Step 1B")
                else:
                    vuln_repos = self.run_step_1b_vulnerable_crawl(
                        vulnerable_groundtruth_file,
                        max_records=max_vulnerable_records,
                        metadata_file=str(VULNERABLE_REPOS_METADATA_FILE),
                        output_dir=str(VULNERABLE_REPOS_DIR),
                    )
            else:
                logger.info("Skipping Step 1B: Vulnerable Crawl")

            # Step 2: SBOM
            if not skip_sbom:
                sbom_results = self.run_step_2_sbom(repos)
            else:
                logger.info("Skipping Step 2: SBOM Generation")
                sbom_results = None

            if not skip_vulnerable_sbom:
                vuln_sbom_results = self.run_step_2b_vulnerable_sbom(vuln_repos)
            else:
                logger.info("Skipping Step 2B: Vulnerable SBOM Generation")
                vuln_sbom_results = None

            # Step 3: Vulnerability Check
            if not skip_vuln_check:
                enriched_results = self.run_step_3_vulnerability_check(sbom_results)
            else:
                logger.info("Skipping Step 3: Vulnerability Check")
                enriched_results = None

            if not skip_vulnerable_vuln_check:
                vuln_enriched_results = self.run_step_3b_vulnerable_vulnerability_check(vuln_sbom_results)
            else:
                logger.info("Skipping Step 3B: Vulnerable Vulnerability Check")
                vuln_enriched_results = None

            # Step 4: Neo4j Import
            if not skip_neo4j:
                # Clear if requested
                if clear_neo4j:
                    logger.info("Clearing Neo4j database...")
                    kg = Neo4jKnowledgeGraph(
                        uri=self.neo4j_uri,
                        user=self.neo4j_user,
                        password=self.neo4j_password,
                        database=neo4j_database,
                    )
                    kg.clear_graph()
                    kg.close()

                self.run_step_4_neo4j_import(enriched_results, database=neo4j_database)
            else:
                logger.info("Skipping Step 4: Neo4j Import")

            if not skip_vulnerable_neo4j:
                if not vulnerable_neo4j_database:
                    logger.error("Missing vulnerable_neo4j_database for Step 4B")
                else:
                    self.run_step_4b_neo4j_import_vulnerable(
                        vuln_enriched_results,
                        database=vulnerable_neo4j_database,
                    )
            else:
                logger.info("Skipping Step 4B: Vulnerable Neo4j Import")

        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            raise

        finally:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            logger.info("\n" + "#"*80)
            logger.info("PIPELINE COMPLETED")
            logger.info(f"End time: {end_time}")
            logger.info(f"Total duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")
            logger.info("#"*80 + "\n")


def main():
    """Main entry point with CLI"""
    parser = argparse.ArgumentParser(
        description="SBOM and Vulnerability Analysis Pipeline"
    )

    parser.add_argument(
        "--languages",
        nargs="+",
        default=["Java", "JavaScript"],
        help="Programming languages to crawl"
    )

    parser.add_argument(
        "--min-size",
        type=int,
        default=10000,
        help="Minimum repository size in KB"
    )

    parser.add_argument(
        "--max-per-language",
        type=int,
        default=25,
        help="Maximum repositories per language"
    )

    parser.add_argument(
        "--repo-links-file",
        default=None,
        help="Path to text file containing repository links (owner/repo or GitHub URL)"
    )
    parser.add_argument(
        "--vulnerable-groundtruth-file",
        default=None,
        help="Path to dependabot_groundtruth_*.json for vulnerable repo flow"
    )
    parser.add_argument(
        "--max-vulnerable-records",
        type=int,
        default=None,
        help="Limit number of vulnerable records to process"
    )

    parser.add_argument(
        "--skip-get-link",
        action="store_true",
        help="Skip repository link collection step (Step 0)"
    )

    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip GitHub crawling step"
    )
    parser.add_argument(
        "--skip-vulnerable-crawl",
        action="store_true",
        help="Skip vulnerable repo crawling step"
    )

    parser.add_argument(
        "--skip-sbom",
        action="store_true",
        help="Skip SBOM generation step"
    )
    parser.add_argument(
        "--skip-vulnerable-sbom",
        action="store_true",
        help="Skip vulnerable SBOM generation step"
    )

    parser.add_argument(
        "--skip-vuln-check",
        action="store_true",
        help="Skip vulnerability check step"
    )
    parser.add_argument(
        "--skip-vulnerable-vuln-check",
        action="store_true",
        help="Skip vulnerable vulnerability check step"
    )

    parser.add_argument(
        "--skip-neo4j",
        action="store_true",
        help="Skip Neo4j import step"
    )

    parser.add_argument(
        "--clear-neo4j",
        action="store_true",
        help="Clear Neo4j database before import"
    )

    parser.add_argument(
        "--neo4j-uri",
        default="bolt://localhost:7689",
        help="Neo4j connection URI"
    )

    parser.add_argument(
        "--neo4j-user",
        default="neo4j",
        help="Neo4j username"
    )

    parser.add_argument(
        "--neo4j-password",
        default="password",
        help="Neo4j password"
    )
    parser.add_argument(
        "--neo4j-database",
        default=None,
        help="Neo4j database name for main flow (default: server default)",
    )
    parser.add_argument(
        "--vulnerable-neo4j-database",
        default="vuln_repos",
        help="Neo4j database name for vulnerable flow",
    )
    parser.add_argument(
        "--skip-vulnerable-neo4j",
        action="store_true",
        help="Skip Neo4j import for vulnerable flow",
    )

    args = parser.parse_args()

    # Initialize pipeline
    pipeline = Pipeline(
        github_token=os.getenv("GITHUB_TOKEN"),
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password
    )

    # Run pipeline
    pipeline.run_full_pipeline(
        languages=args.languages,
        min_size=args.min_size,
        max_per_language=args.max_per_language,
        repo_links_file=args.repo_links_file,
        vulnerable_groundtruth_file=args.vulnerable_groundtruth_file,
        max_vulnerable_records=args.max_vulnerable_records,
        neo4j_database=args.neo4j_database,
        vulnerable_neo4j_database=args.vulnerable_neo4j_database,
        skip_get_link=args.skip_get_link,
        skip_crawl=args.skip_crawl,
        skip_vulnerable_crawl=args.skip_vulnerable_crawl,
        skip_sbom=args.skip_sbom,
        skip_vulnerable_sbom=args.skip_vulnerable_sbom,
        skip_vuln_check=args.skip_vuln_check,
        skip_vulnerable_vuln_check=args.skip_vulnerable_vuln_check,
        skip_neo4j=args.skip_neo4j,
        skip_vulnerable_neo4j=args.skip_vulnerable_neo4j,
        clear_neo4j=args.clear_neo4j
    )


if __name__ == "__main__":
    main()
