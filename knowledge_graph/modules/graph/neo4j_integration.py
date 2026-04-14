"""
Neo4j Knowledge Graph Integration
Import SBOM + vulnerability data into Neo4j with incremental metadata tracking.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Any, Set

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError, Neo4jError, SessionExpired
from dotenv import load_dotenv

from pathlib import Path

try:
    from modules.utils.sbom_parser import (
        get_sbom_metadata,
        extract_components,
        extract_dependencies,
        compute_dependency_depths,
        extract_direct_dependency_refs,
        extract_occurrences,
    )
    from modules.utils.purl_utils import infer_ecosystem, infer_package_manager
    from modules.utils.paths import (
        VULNS_DIR,
        VULNERABLE_VULNS_DIR,
        METADATA_DIR,
        resolve_project_path,
        to_project_relative,
        PROJECT_ROOT,
    )
except ModuleNotFoundError:
    # Allow direct execution from this file path.
    KG_ROOT = Path(__file__).resolve().parents[2]
    if str(KG_ROOT) not in sys.path:
        sys.path.insert(0, str(KG_ROOT))
    from modules.utils.sbom_parser import (
        get_sbom_metadata,
        extract_components,
        extract_dependencies,
        compute_dependency_depths,
        extract_direct_dependency_refs,
        extract_occurrences,
    )
    from modules.utils.purl_utils import infer_ecosystem, infer_package_manager
    from modules.utils.paths import (
        VULNS_DIR,
        VULNERABLE_VULNS_DIR,
        METADATA_DIR,
        resolve_project_path,
        to_project_relative,
        PROJECT_ROOT,
    )


load_dotenv(PROJECT_ROOT / ".env")


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


class Neo4jKnowledgeGraph:
    """Manage Neo4j Knowledge Graph for SBOM and vulnerability data."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7689",
        user: str = "neo4j",
        password: str = "password",
        database: Optional[str] = None,
        import_metadata_file: Optional[str] = None,
    ):
        self.uri = uri
        self.user = user
        self.database = database
        self.driver = None

        METADATA_DIR.mkdir(parents=True, exist_ok=True)
        self.import_metadata_file = import_metadata_file or self._import_metadata_path(database, uri)
        self.imported_repo_keys = self._load_imported_repo_keys()

        try:
            logger.info(f"Connecting to Neo4j at {uri}")
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            self._ensure_database()
            self._create_constraints()
            logger.info("Successfully connected to Neo4j")
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(
                f"Cannot connect to Neo4j at {uri}. "
                f"Ensure Neo4j is running and reachable (Docker/container/network). Error: {exc}"
            )
            raise
        except AuthError as exc:
            logger.error(f"Neo4j authentication failed for user '{user}': {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j server error during initialization: {exc}")
            raise
        except Exception as exc:
            logger.error(f"Unexpected Neo4j initialization error: {exc}", exc_info=True)
            raise

    def close(self):
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")

    @staticmethod
    def _import_metadata_path(database: Optional[str], uri: Optional[str]) -> str:
        safe_db = str(database).replace("/", "_").replace("\\", "_") if database else "default"
        safe_uri = str(uri or "neo4j").replace("://", "_").replace("/", "_").replace("\\", "_").replace(":", "_")
        return str(METADATA_DIR / f"neo4j_imported_repos_{safe_uri}_{safe_db}.json")

    @staticmethod
    def _repo_key(repo_data: Dict) -> Optional[str]:
        if not isinstance(repo_data, dict):
            return None
        return (
            repo_data.get("metadata_key")
            or repo_data.get("full_name")
            or repo_data.get("url")
            or repo_data.get("name")
        )

    @staticmethod
    def _project_repo_url(repo_data: Dict) -> Optional[str]:
        if not isinstance(repo_data, dict):
            return None
        base_url = repo_data.get("url")
        vulnerable_commit = repo_data.get("vulnerable_commit")
        if base_url and vulnerable_commit:
            return f"{base_url}@{vulnerable_commit}"
        return base_url

    def _load_imported_repo_keys(self) -> Set[str]:
        if not os.path.exists(self.import_metadata_file):
            return set()

        try:
            with open(self.import_metadata_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            repos = data.get("imported_repos", []) if isinstance(data, dict) else []
            return {r for r in repos if isinstance(r, str) and r}
        except Exception as exc:
            logger.warning(f"Failed to read import metadata file: {exc}")
            return set()

    def _save_imported_repo_keys(self):
        payload = {
            "updated_at": datetime.now().isoformat(),
            "imported_repos": sorted(self.imported_repo_keys),
        }
        try:
            with open(self.import_metadata_file, "w", encoding="utf-8-sig") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning(f"Failed to save import metadata file: {exc}")

    def _mark_repo_imported(self, repo_data: Dict):
        key = self._repo_key(repo_data)
        if key:
            self.imported_repo_keys.add(key)

    def _is_repo_imported(self, repo_data: Dict) -> bool:
        key = self._repo_key(repo_data)
        return bool(key and key in self.imported_repo_keys)

    def _create_constraints(self):
        queries = [
            "CREATE CONSTRAINT project_url IF NOT EXISTS FOR (p:Project) REQUIRE p.repo_url IS UNIQUE",
            "CREATE CONSTRAINT sbom_scan_id IF NOT EXISTS FOR (s:SBOM) REQUIRE s.scan_id IS UNIQUE",
            "CREATE CONSTRAINT component_id IF NOT EXISTS FOR (c:Component) REQUIRE c.component_id IS UNIQUE",
            "CREATE INDEX component_package_id IF NOT EXISTS FOR (c:Component) ON (c.package_id)",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT location_key IF NOT EXISTS FOR (l:Location) REQUIRE l.key IS UNIQUE",
            "CREATE INDEX project_name IF NOT EXISTS FOR (p:Project) ON (p.name)",
            "CREATE INDEX component_name IF NOT EXISTS FOR (c:Component) ON (c.name)",
            "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss_score)",
            "CREATE INDEX has_component_depth IF NOT EXISTS FOR ()-[r:HAS_COMPONENT]-() ON (r.dependency_depth)",
            "CREATE INDEX depends_on_scan IF NOT EXISTS FOR ()-[r:DEPENDS_ON]-() ON (r.scan_id)",
        ]
        with self.driver.session(database=self.database) as session:
            for q in queries:
                try:
                    session.run(q)
                except Neo4jError as exc:
                    logger.warning(f"Cannot apply schema statement, continuing: {exc}")
                except (ServiceUnavailable, SessionExpired, OSError) as exc:
                    logger.error(f"Connection lost while creating constraints/indexes: {exc}")
                    raise

    def _ensure_database(self):
        if not self.database:
            return
        # Neo4j Community does not support CREATE DATABASE.
        # Also skip admin command for the default database name.
        if str(self.database).strip().lower() == "neo4j":
            return
        try:
            with self.driver.session(database="system") as session:
                session.run(f"CREATE DATABASE {self.database} IF NOT EXISTS")
                logger.info(f"Ensured Neo4j database exists: {self.database}")
        except Neo4jError as exc:
            msg = str(exc)
            if "Unsupported administration command" in msg or "not supported in this edition" in msg:
                logger.warning(
                    "Skipping CREATE DATABASE for '%s' because this Neo4j edition does not support it.",
                    self.database,
                )
                return
            logger.error(f"Failed to create/verify database '{self.database}': {exc}")
            raise
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Neo4j unavailable while creating database '{self.database}': {exc}")
            raise

    def clear_graph(self):
        logger.warning("Clearing all data from Neo4j graph")
        try:
            with self.driver.session(database=self.database) as session:
                session.run("MATCH (n) DETACH DELETE n")
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Cannot clear graph because Neo4j is unavailable: {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j error while clearing graph: {exc}")
            raise

        self.imported_repo_keys = set()
        self._save_imported_repo_keys()
        logger.info("Graph cleared and import metadata reset")

    def _run_write(self, query: str, params: Dict) -> Optional[Dict]:
        try:
            with self.driver.session(database=self.database) as session:
                record = session.run(query, params).single()
                return dict(record) if record else None
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Neo4j unavailable during write query: {exc}")
            raise
        except AuthError as exc:
            logger.error(f"Neo4j authentication failed during write query: {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j write query error: {exc}")
            raise

    @staticmethod
    def _to_str_list(value: Any) -> List[str]:
        if not value:
            return []
        if isinstance(value, list):
            return [str(v) for v in value if v is not None]
        return [str(value)]

    @staticmethod
    def _normalize_severity(severity: Any) -> List[str]:
        if not isinstance(severity, list):
            return []
        vectors: List[str] = []
        for item in severity:
            if isinstance(item, dict) and item.get("score") is not None:
                vectors.append(str(item.get("score")))
        return vectors

    def create_project(self, repo_data: Dict, sbom_metadata: Dict) -> Optional[str]:
        root_component = sbom_metadata.get("component", {}) if sbom_metadata else {}
        package_manager = infer_package_manager(root_component.get("purl"))
        repo_url = self._project_repo_url(repo_data)

        record = self._run_write(
            """
            MERGE (p:Project {repo_url: $repo_url})
            SET p.name = $name,
                p.full_name = $full_name,
                p.language = $language,
                p.package_manager = $package_manager,
                p.description = $description,
                p.vulnerable_commit = $vulnerable_commit,
                p.patched_commit = $patched_commit,
                p.ground_truth_label = $ground_truth_label
            RETURN p.repo_url as repo_url
            """,
            {
                "repo_url": repo_url,
                "name": repo_data.get("name") or root_component.get("name"),
                "full_name": repo_data.get("full_name"),
                "language": repo_data.get("language"),
                "package_manager": package_manager,
                "description": repo_data.get("description"),
                "vulnerable_commit": repo_data.get("vulnerable_commit"),
                "patched_commit": repo_data.get("patched_commit"),
                "ground_truth_label": repo_data.get("ground_truth_label"),
            },
        )
        return record.get("repo_url") if record else None

    def create_sbom(self, sbom_metadata: Dict, repo_url: str) -> Optional[str]:
        scan_id = sbom_metadata.get("serialNumber") or f"{repo_url}::{sbom_metadata.get('timestamp')}"
        record = self._run_write(
            """
            MERGE (s:SBOM {scan_id: $scan_id})
            SET s.generated_at = $generated_at,
                s.branch = $branch
            RETURN s.scan_id as scan_id
            """,
            {
                "scan_id": scan_id,
                "generated_at": sbom_metadata.get("timestamp"),
                "branch": sbom_metadata.get("branch"),
            },
        )
        return record.get("scan_id") if record else None

    def create_component(self, component_data: Dict) -> Optional[str]:
        record = self._run_write(
            """
            MERGE (c:Component {component_id: $component_id})
            SET c.name = $name,
                c.version = $version,
                c.purl = $purl,
                c.package_id = $package_id,
                c.package_component_id = $package_component_id,
                c.type = $type,
                c.bom_ref = $bom_ref,
                c.group = $group,
                c.description = $description,
                c.scope = $scope,
                c.ecosystem = $ecosystem,
                c.dependency_depth = $dependency_depth
            RETURN c.component_id as component_id
            """,
            {
                "component_id": component_data.get("component_id"),
                "package_id": component_data.get("package_id"),
                "package_component_id": component_data.get("package_component_id"),
                "name": component_data.get("name"),
                "version": component_data.get("version"),
                "purl": component_data.get("purl"),
                "type": component_data.get("type"),
                "bom_ref": component_data.get("bom-ref"),
                "group": component_data.get("group"),
                "description": component_data.get("description"),
                "scope": component_data.get("scope"),
                "ecosystem": component_data.get("ecosystem"),
                "dependency_depth": component_data.get("dependency_depth"),
            },
        )
        return record.get("component_id") if record else None

    def create_location(
        self,
        path_value: Optional[str],
        line_number: Optional[int],
        scan_id: Optional[str] = None,
    ) -> Optional[str]:
        if not path_value:
            return None

        # Include scan_id in key so each Location is scoped to its SBOM/Project.
        # Without this, two projects sharing the same path/line merge into one node.
        prefix = scan_id if scan_id else "global"
        key = f"{prefix}::{path_value}:{line_number if line_number is not None else 'unknown'}"
        record = self._run_write(
            """
            MERGE (l:Location {key: $key})
            SET l.path = $path,
                l.line = $line,
                l.scan_id = $scan_id
            RETURN l.key as key
            """,
            {"key": key, "path": path_value, "line": line_number, "scan_id": scan_id},
        )
        return record.get("key") if record else None

    def create_vulnerability(self, vuln_data: Dict) -> Optional[str]:
        epss = vuln_data.get("epss") or {}
        record = self._run_write(
            """
            MERGE (v:Vulnerability {id: $id})
            SET v.detail_summary = $detail_summary,
                v.published = $published,
                v.modified = $modified,
                v.withdrawn = $withdrawn,
                v.severity_vectors = $severity_vectors,
                v.cvss_score = $cvss_score,
                v.cvss_severity = $cvss_severity,
                v.cwe = $cwe,
                v.aliases = $aliases,
                v.epss = $epss,
                v.epss_percentile = $epss_percentile,
                v.kev = $kev,
                v.fix_versions = $fix_versions
            RETURN v.id as id
            """,
            {
                "id": vuln_data.get("id"),
                "detail_summary": vuln_data.get("details"),
                "published": vuln_data.get("published"),
                "modified": vuln_data.get("modified"),
                "withdrawn": vuln_data.get("withdrawn"),
                "severity_vectors": self._normalize_severity(vuln_data.get("severity")),
                "cvss_score": vuln_data.get("cvss_score"),
                "cvss_severity": vuln_data.get("cvss_severity"),
                "cwe": self._to_str_list(vuln_data.get("cwe")),
                "aliases": self._to_str_list(vuln_data.get("aliases")),
                "epss": float(epss.get("epss")) if epss and epss.get("epss") is not None else None,
                "epss_percentile": float(epss.get("percentile")) if epss and epss.get("percentile") is not None else None,
                "kev": bool(vuln_data.get("kev")),
                "fix_versions": self._to_str_list(vuln_data.get("fix_versions")),
            },
        )
        return record.get("id") if record else None

    def create_relationship(self, query: str, params: Dict):
        try:
            with self.driver.session(database=self.database) as session:
                session.run(query, params)
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Neo4j unavailable during relationship write: {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j relationship write error: {exc}")
            raise

    def import_repository_data(self, enriched_result: Dict, checker=None) -> bool:
        repo_data = enriched_result.get("repo")
        vuln_data = enriched_result.get("vulnerability_data")
        sbom_data = enriched_result.get("sbom")

        if not repo_data:
            return False

        if not sbom_data:
            sbom_file = resolve_project_path(enriched_result.get("sbom_file") or (vuln_data or {}).get("sbom_file"))
            if sbom_file and os.path.exists(sbom_file):
                with open(sbom_file, "r", encoding="utf-8-sig") as f:
                    sbom_data = json.load(f)

        if not sbom_data:
            logger.warning(f"No SBOM found for {repo_data.get('full_name')}, skipping")
            return False

        sbom_metadata = get_sbom_metadata(sbom_data)
        components = extract_components(sbom_data)
        dependencies = extract_dependencies(sbom_data)
        root_ref = sbom_metadata.get("component", {}).get("bom-ref")
        dependency_depths = compute_dependency_depths(dependencies, root_ref)
        direct_dependency_refs = extract_direct_dependency_refs(dependencies, root_ref)

        vuln_by_purl: Dict[str, Dict] = {}
        for comp in (vuln_data or {}).get("components", []):
            purl = comp.get("purl")
            if purl:
                vuln_by_purl[purl] = comp

        if checker is None:
            from modules.vulnerability.osv_checker import OSVChecker
            checker = OSVChecker(enable_enrichment=False)

        project_url = self.create_project(repo_data, sbom_metadata)
        sbom_id = self.create_sbom(sbom_metadata, project_url)

        if project_url and sbom_id:
            self.create_relationship(
                """
                MATCH (p:Project {repo_url: $repo_url})
                MATCH (s:SBOM {scan_id: $scan_id})
                MERGE (p)-[:GENERATED_SBOM]->(s)
                """,
                {"repo_url": project_url, "scan_id": sbom_id},
            )

        component_id_by_ref: Dict[str, str] = {}

        for comp in components:
            purl = comp.get("purl")
            bom_ref = comp.get("bom-ref")
            package_component_id = purl or bom_ref or f"{comp.get('name')}@{comp.get('version')}"
            component_id = package_component_id

            component_data = {
                **comp,
                "component_id": component_id,
                "package_component_id": package_component_id,
                "package_id": purl or f"{comp.get('name')}@{comp.get('version')}",
                "ecosystem": infer_ecosystem(purl),
                "dependency_depth": dependency_depths.get(bom_ref),
            }
            created_component_id = self.create_component(component_data)
            if not created_component_id:
                continue

            if bom_ref:
                component_id_by_ref[bom_ref] = created_component_id

            if project_url and bom_ref in direct_dependency_refs:
                self.create_relationship(
                    """
                    MATCH (p:Project {repo_url: $repo_url})
                    MATCH (c:Component {component_id: $component_id})
                    MERGE (p)-[:USES_DIRECT]->(c)
                    """,
                    {"repo_url": project_url, "component_id": created_component_id},
                )

            if sbom_id:
                self.create_relationship(
                    """
                    MATCH (s:SBOM {scan_id: $scan_id})
                    MATCH (c:Component {component_id: $component_id})
                    MERGE (s)-[r:HAS_COMPONENT]->(c)
                    SET r.dependency_depth = $dependency_depth,
                        r.is_direct_dependency = $is_direct_dependency,
                        r.is_root = $is_root
                    """,
                    {
                        "scan_id": sbom_id,
                        "component_id": created_component_id,
                        "dependency_depth": dependency_depths.get(bom_ref),
                        "is_direct_dependency": bom_ref in direct_dependency_refs,
                        "is_root": bool(root_ref and bom_ref == root_ref),
                    },
                )

            for occ in extract_occurrences(comp):
                location_key = self.create_location(occ.get("path"), occ.get("line"), scan_id=sbom_id)
                if location_key:
                    self.create_relationship(
                        """
                        MATCH (c:Component {component_id: $component_id})
                        MATCH (l:Location {key: $location_key})
                        MERGE (c)-[:DECLARED_IN]->(l)
                        """,
                        {"component_id": created_component_id, "location_key": location_key},
                    )

            vuln_info = vuln_by_purl.get(purl, {})
            for vuln in vuln_info.get("vulnerabilities", []):
                vuln_details = checker.extract_vulnerability_details(vuln)
                vuln_id = self.create_vulnerability(vuln_details)
                if not vuln_id:
                    continue

                self.create_relationship(
                    """
                    MATCH (c:Component {component_id: $component_id})
                    MATCH (v:Vulnerability {id: $vuln_id})
                    MERGE (c)-[:AFFECTED_BY]->(v)
                    """,
                    {"component_id": created_component_id, "vuln_id": vuln_id},
                )

                if project_url:
                    self.create_relationship(
                        """
                        MATCH (p:Project {repo_url: $repo_url})
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MERGE (p)-[:HAS_VULNERABILITY]->(v)
                        """,
                        {"repo_url": project_url, "vuln_id": vuln_id},
                    )

        for parent_ref, child_refs in dependencies.items():
            parent_id = component_id_by_ref.get(parent_ref)
            if not parent_id:
                continue
            for child_ref in child_refs:
                child_id = component_id_by_ref.get(child_ref)
                if not child_id:
                    continue
                self.create_relationship(
                    """
                    MATCH (c1:Component {component_id: $parent_id})
                    MATCH (c2:Component {component_id: $child_id})
                    MERGE (c1)-[:DEPENDS_ON {scan_id: $scan_id}]->(c2)
                    """,
                    {"parent_id": parent_id, "child_id": child_id, "scan_id": sbom_id},
                )

        return True

    def import_batch(self, enriched_results: List[Dict], enable_enrichment: bool = True):
        success = 0
        failed = 0
        skipped = 0

        logger.info(f"Starting batch import of {len(enriched_results)} repositories")

        from modules.vulnerability.osv_checker import OSVChecker
        checker = OSVChecker(enable_enrichment=enable_enrichment)

        for item in enriched_results:
            repo = item.get("repo", {})
            repo_name = self._repo_key(repo) or "unknown"

            if self._is_repo_imported(repo):
                skipped += 1
                logger.info(f"Skip already imported repository: {repo_name}")
                continue

            try:
                imported = self.import_repository_data(item, checker=checker)
                if imported:
                    self._mark_repo_imported(repo)
                    success += 1
                    logger.info(f"Imported repository: {repo_name}")
                else:
                    failed += 1
                    logger.warning(f"Failed to import repository: {repo_name}")
            except Exception as exc:
                failed += 1
                logger.error(f"Error importing repository {repo_name}: {exc}")

        self._save_imported_repo_keys()

        logger.info(f"Batch import summary: total={len(enriched_results)} success={success} skipped={skipped} failed={failed}")

    def get_statistics(self) -> Dict:
        queries = {
            "projects": "MATCH (p:Project) RETURN count(p) as count",
            "sboms": "MATCH (s:SBOM) RETURN count(s) as count",
            "components": "MATCH (c:Component) RETURN count(c) as count",
            "vulnerabilities": "MATCH (v:Vulnerability) RETURN count(v) as count",
            "locations": "MATCH (l:Location) RETURN count(l) as count",
            "vulnerable_components": "MATCH (c:Component)-[:AFFECTED_BY]->(:Vulnerability) RETURN count(DISTINCT c) as count",
        }

        stats: Dict[str, int] = {}
        try:
            with self.driver.session(database=self.database) as session:
                for key, query in queries.items():
                    record = session.run(query).single()
                    stats[key] = record["count"] if record else 0
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Neo4j unavailable while collecting statistics: {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j error while collecting statistics: {exc}")
            raise
        return stats

    def run_custom_query(self, query: str, params: Dict = None) -> List[Dict]:
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, params or {})
                return [dict(record) for record in result]
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            logger.error(f"Neo4j unavailable while running custom query: {exc}")
            raise
        except Neo4jError as exc:
            logger.error(f"Neo4j custom query error: {exc}")
            raise


def main():
    parser = argparse.ArgumentParser(description="Import vulnerability data into Neo4j")
    parser.add_argument(
        "--vuln-repos",
        action="store_true",
        help="Use vulnerable repo flow defaults (summary file, ports, and import metadata)",
    )
    args = parser.parse_args()

    env_uri = os.getenv("NEO4J_URI")
    if args.vuln_repos:
        neo4j_uri = "bolt://localhost:7689"
        if env_uri and env_uri != neo4j_uri:
            logger.info(f"Ignoring NEO4J_URI={env_uri} because --vuln-repos is set")
    else:
        neo4j_uri = env_uri or "bolt://localhost:7689"
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "password")

    if args.vuln_repos:
        summary_file = os.path.join(
            str(VULNERABLE_VULNS_DIR),
            "vulnerable_vulnerability_summary.json",
        )
    else:
        summary_file = os.path.join(str(VULNS_DIR), "vulnerability_summary.json")

    import_metadata_file = None
    if args.vuln_repos:
        import_metadata_file = str(METADATA_DIR / "neo4j_imported_vuln_repos.json")

    try:
        kg = Neo4jKnowledgeGraph(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            import_metadata_file=import_metadata_file,
        )
    except Exception:
        return

    try:
        enriched_results: List[Dict] = []
        if summary_file and os.path.exists(summary_file):
            with open(summary_file, "r", encoding="utf-8-sig") as f:
                summary = json.load(f)

            for result in summary.get("results", []):
                vuln_file = resolve_project_path(result.get("vulnerability_file"))
                if not vuln_file or not os.path.exists(vuln_file):
                    continue

                with open(vuln_file, "r", encoding="utf-8-sig") as f:
                    vuln_data = json.load(f)

                enriched_results.append(
                    {
                        "repo": vuln_data.get("repo"),
                        "vulnerability_data": vuln_data,
                        "sbom_file": to_project_relative(vuln_data.get("sbom_file")),
                    }
                )

        if enriched_results:
            enable_enrichment = os.getenv("NEO4J_ENRICHMENT", "1").lower() not in {"0", "false", "no"}
            kg.import_batch(enriched_results, enable_enrichment=enable_enrichment)
            stats = kg.get_statistics()
            label = "vulnerable" if args.vuln_repos else "primary"
            print(f"Knowledge Graph Statistics ({label}):")
            for k, v in stats.items():
                print(f"  - {k}: {v}")
        else:
            logger.warning("No vulnerability data found to import.")

    finally:
        kg.close()


if __name__ == "__main__":
    main()



