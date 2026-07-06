from __future__ import annotations

import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services import repo_pipeline_service  # noqa: E402


class RepoPipelineServiceTests(unittest.TestCase):
    def test_normalize_source_mode_defaults_to_latest(self) -> None:
        self.assertEqual(repo_pipeline_service._normalize_source_mode(None), "github_latest")
        self.assertEqual(repo_pipeline_service._normalize_source_mode("github_commit"), "github_commit")

    def test_normalize_source_mode_rejects_unknown_value(self) -> None:
        with self.assertRaises(ValueError):
            repo_pipeline_service._normalize_source_mode("zip_upload")

    def test_resolve_github_commit_repo_requires_commit_hash(self) -> None:
        with self.assertRaises(ValueError):
            repo_pipeline_service._resolve_github_commit_repo("owner", "repo", "", log=None)

    def test_resolve_github_commit_repo_uses_requested_commit(self) -> None:
        original_dir = repo_pipeline_service.USER_REPOS_DIR
        with tempfile.TemporaryDirectory(prefix=f"repo_pipeline_{uuid.uuid4().hex}_") as tmp_dir:
            tmp_root = Path(tmp_dir)
            local_repo = tmp_root / "owner_repo_deadbeef"
            git_dir = local_repo / ".git"
            git_dir.mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def _fake_run(cmd: list[str], cwd: Path | None = None, log=None) -> str:
                calls.append(cmd)
                if cmd[:4] == ["git", "rev-parse", "--verify", "deadbeef^{commit}"]:
                    return "deadbeefcafebabefeedface1234567890abcd"
                if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"]:
                    return "HEAD"
                return ""

            try:
                repo_pipeline_service.USER_REPOS_DIR = tmp_root
                with mock.patch.object(repo_pipeline_service, "_ensure_git_safe_directory"), \
                     mock.patch.object(repo_pipeline_service, "_default_branch_for_repo", return_value="main"), \
                     mock.patch.object(repo_pipeline_service, "_run_cmd", side_effect=_fake_run), \
                     mock.patch.object(
                         repo_pipeline_service,
                         "_build_repo_metadata",
                         return_value={"metadata_key": "owner/repo@deadbeefcafebabefeedface1234567890abcd"},
                     ) as build_meta:
                    result = repo_pipeline_service._resolve_github_commit_repo(
                        "owner",
                        "repo",
                        "deadbeef",
                    )
            finally:
                repo_pipeline_service.USER_REPOS_DIR = original_dir

        self.assertEqual(result["metadata_key"], "owner/repo@deadbeefcafebabefeedface1234567890abcd")
        self.assertIn(["git", "fetch", "origin", "--prune"], calls)
        self.assertIn(["git", "fetch", "origin", "deadbeef"], calls)
        self.assertIn(["git", "checkout", "--detach", "deadbeefcafebabefeedface1234567890abcd"], calls)
        build_meta.assert_called_once()
        self.assertEqual(
            build_meta.call_args.kwargs["commit"],
            "deadbeefcafebabefeedface1234567890abcd",
        )

    def test_resolve_github_commit_repo_can_use_parent_commit(self) -> None:
        original_dir = repo_pipeline_service.USER_REPOS_DIR
        with tempfile.TemporaryDirectory(prefix=f"repo_pipeline_{uuid.uuid4().hex}_") as tmp_dir:
            tmp_root = Path(tmp_dir)
            (tmp_root / "owner_repo_feedface" / ".git").mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def _fake_run(cmd: list[str], cwd: Path | None = None, log=None) -> str:
                calls.append(cmd)
                if cmd[:4] == ["git", "rev-parse", "--verify", "feedface^{commit}"]:
                    return "feedfacecafebabefeedface1234567890abcd"
                if cmd[:4] == ["git", "rev-parse", "--verify", "feedfacecafebabefeedface1234567890abcd^"]:
                    return "parent1234567890abcdef1234567890abcdef12"
                if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"]:
                    return "HEAD"
                return ""

            try:
                repo_pipeline_service.USER_REPOS_DIR = tmp_root
                with mock.patch.object(repo_pipeline_service, "_ensure_git_safe_directory"), \
                     mock.patch.object(repo_pipeline_service, "_default_branch_for_repo", return_value="main"), \
                     mock.patch.object(repo_pipeline_service, "_run_cmd", side_effect=_fake_run), \
                     mock.patch.object(
                         repo_pipeline_service,
                         "_build_repo_metadata",
                         return_value={"metadata_key": "owner/repo@parent1234567890abcdef1234567890abcdef12"},
                     ) as build_meta:
                    result = repo_pipeline_service._resolve_github_commit_repo(
                        "owner",
                        "repo",
                        "feedface",
                        use_parent_commit=True,
                    )
            finally:
                repo_pipeline_service.USER_REPOS_DIR = original_dir

        self.assertEqual(result["metadata_key"], "owner/repo@parent1234567890abcdef1234567890abcdef12")
        self.assertIn(
            ["git", "checkout", "--detach", "parent1234567890abcdef1234567890abcdef12"],
            calls,
        )
        self.assertEqual(
            build_meta.call_args.kwargs["commit"],
            "parent1234567890abcdef1234567890abcdef12",
        )

    def test_resolve_target_commit_raises_when_parent_missing(self) -> None:
        with mock.patch.object(
            repo_pipeline_service,
            "_run_cmd",
            side_effect=[
                "feedfacecafebabefeedface1234567890abcd",
                RuntimeError("bad revision"),
            ],
        ):
            with self.assertRaises(RuntimeError) as ctx:
                repo_pipeline_service._resolve_target_commit(
                    Path("."),
                    "feedface",
                    use_parent_commit=True,
                )

        self.assertIn("has no parent commit", str(ctx.exception))

    def test_run_full_repo_pipeline_dispatches_latest_mode(self) -> None:
        fake_modules = self._fake_pipeline_modules()
        with mock.patch.dict(sys.modules, fake_modules, clear=False):
            with mock.patch.object(
                repo_pipeline_service,
                "_resolve_github_latest_repo",
                return_value=self._repo_meta("owner/repo", "abc123"),
            ) as latest_resolver, \
                 mock.patch.object(repo_pipeline_service, "_resolve_github_commit_repo") as commit_resolver, \
                 mock.patch.object(repo_pipeline_service, "_upsert_repo_metadata") as upsert_meta:
                result = repo_pipeline_service.run_full_repo_pipeline(
                    repo_input="owner/repo",
                    source_mode="github_latest",
                    enable_ai_sink_fallback=False,
                )

        latest_resolver.assert_called_once_with("owner", "repo", log=None)
        commit_resolver.assert_not_called()
        upsert_meta.assert_called_once()
        self.assertEqual(result["source_mode"], "github_latest")
        self.assertEqual(result["commit"], "abc123")

    def test_run_full_repo_pipeline_dispatches_commit_mode(self) -> None:
        fake_modules = self._fake_pipeline_modules()
        with mock.patch.dict(sys.modules, fake_modules, clear=False):
            with mock.patch.object(
                repo_pipeline_service,
                "_resolve_github_commit_repo",
                return_value=self._repo_meta("owner/repo", "deadbeef"),
            ) as commit_resolver, \
                 mock.patch.object(repo_pipeline_service, "_resolve_github_latest_repo") as latest_resolver, \
                 mock.patch.object(repo_pipeline_service, "_upsert_repo_metadata") as upsert_meta:
                result = repo_pipeline_service.run_full_repo_pipeline(
                    repo_input="owner/repo",
                    source_mode="github_commit",
                    commit_hash="deadbeef",
                    use_parent_commit=True,
                    enable_ai_sink_fallback=False,
                )

        commit_resolver.assert_called_once_with(
            "owner",
            "repo",
            "deadbeef",
            use_parent_commit=True,
            log=None,
        )
        latest_resolver.assert_not_called()
        upsert_meta.assert_called_once()
        self.assertEqual(result["source_mode"], "github_commit")
        self.assertEqual(result["commit"], "deadbeef")

    @staticmethod
    def _repo_meta(full_name: str, commit: str) -> dict[str, str]:
        owner, repo = full_name.split("/", 1)
        return {
            "owner": owner,
            "name": repo,
            "full_name": full_name,
            "metadata_key": f"{full_name}@{commit}",
            "url": f"https://github.com/{full_name}",
            "clone_url": f"https://github.com/{full_name}.git",
            "clone_status": "success",
            "local_path": "knowledge_graph/data/user_repos/owner_repo",
            "default_branch": "main",
            "vulnerable_commit": commit,
            "language": "JavaScript",
        }

    @staticmethod
    def _fake_pipeline_modules() -> dict[str, types.ModuleType]:
        sink_db = types.ModuleType("modules.agents.sink_db")
        sink_db.init_db = mock.Mock()
        sink_db.missing_vulns = mock.Mock(return_value=[])

        semgrep_agent = types.ModuleType("modules.agents.semgrep_agent")

        class _FakeResult:
            def __init__(self, verdict: str = "confirmed_reachable") -> None:
                self.verdict = verdict

        class _FakeSemgrepAgent:
            def __init__(self, project_name: str, repo_path: str) -> None:
                self.project_name = project_name
                self.repo_path = repo_path

            def scan(self, vuln_ids: list[str]) -> list[_FakeResult]:
                return [_FakeResult() for _ in vuln_ids]

            def save(self, semgrep_results: list[_FakeResult]) -> None:
                return None

        semgrep_agent.SemgrepAgent = _FakeSemgrepAgent

        neo4j = types.ModuleType("modules.graph.neo4j_integration")

        class _FakeNeo4jKnowledgeGraph:
            def __init__(self, uri: str, user: str, password: str, database=None) -> None:
                self.imported_repo_keys: set[str] = set()

            def import_batch(self, enriched, enable_enrichment: bool = True) -> None:
                return None

            def get_statistics(self) -> dict[str, int]:
                return {"projects": 1}

            def close(self) -> None:
                return None

        neo4j.Neo4jKnowledgeGraph = _FakeNeo4jKnowledgeGraph

        sbom = types.ModuleType("modules.sbom.sbom_generator")

        class _FakeSBOMGenerator:
            def __init__(self, output_dir: str) -> None:
                self.output_dir = output_dir

            def generate_sbom(self, repo_path: str, repo_name: str) -> dict:
                return {
                    "_metadata": {
                        "output_file": "knowledge_graph/data/sboms/demo_sbom.json",
                    }
                }

            def save_summary(self, results) -> None:
                return None

        sbom.SBOMGenerator = _FakeSBOMGenerator

        paths = types.ModuleType("modules.utils.paths")
        paths.SBOMS_DIR = Path("knowledge_graph/data/sboms")
        paths.VULNS_DIR = Path("knowledge_graph/data/vulnerabilities")
        paths.REPOS_METADATA_FILE = Path("knowledge_graph/data/metadata/repos_metadata.json")
        paths.ensure_data_dirs = mock.Mock()

        osv = types.ModuleType("modules.vulnerability.osv_checker")

        class _FakeOSVChecker:
            def __init__(self, output_dir: str) -> None:
                self.output_dir = output_dir

            def process_sbom_results(self, sbom_results: list[dict]) -> list[dict]:
                return [
                    {
                        **sbom_results[0],
                        "vulnerability_data": {
                            "total_vulnerabilities": 2,
                        },
                    }
                ]

            def save_summary(self, enriched) -> None:
                return None

        osv.OSVChecker = _FakeOSVChecker

        pipeline_v2 = types.ModuleType("pipeline_v2")
        pipeline_v2.auto_extract_sinks = mock.Mock(return_value=0)
        pipeline_v2.load_project_vulns = mock.Mock(
            return_value=[
                {"vuln_id": "CVE-1"},
                {"vuln_id": "CVE-2"},
            ]
        )

        return {
            "modules.agents.sink_db": sink_db,
            "modules.agents.semgrep_agent": semgrep_agent,
            "modules.graph.neo4j_integration": neo4j,
            "modules.sbom.sbom_generator": sbom,
            "modules.utils.paths": paths,
            "modules.vulnerability.osv_checker": osv,
            "pipeline_v2": pipeline_v2,
        }


if __name__ == "__main__":
    unittest.main()
