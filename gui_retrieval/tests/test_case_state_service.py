from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backend.config as config  # noqa: E402
from backend.services.case_state_service import (  # noqa: E402
    bootstrap_default_states,
    get_case_state,
    get_case_states,
    get_report_case_snapshot,
    get_recent_report_runs,
    record_report_case_snapshot,
    record_report_run,
    upsert_case_state,
)
from backend.services.evidence_service import recompute_and_overwrite_case_state_tiers  # noqa: E402
from backend.services.verification_service import sync_case_status_with_previous_snapshot  # noqa: E402


def _sample_case(vuln_id: str, component_id: str | None) -> dict:
    return {
        "project": "demo/project",
        "vuln_id": vuln_id,
        "component_name": "pkg",
        "component_version": "1.0.0",
        "component_id": component_id,
        "cvss": 8.1,
        "epss": 0.2,
        "kev": False,
        "severity": "high",
        "fix_versions": ["1.0.1"],
        "dependency_depth": 1,
        "scope": "runtime",
        "reachability_verdict": "likely_reachable",
        "call_locations": [],
        "risk_score": 75.0,
        "decision_tier": "plan_remediation",
        "status": "new",
        "summary_note": "sample",
    }


class CaseStateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_db = config.CVE_SINKS_DB
        self._tmp_dir = Path("gui_retrieval/tests/.tmp")
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        self._tmp_db = self._tmp_dir / f"test_case_state_{uuid.uuid4().hex}.db"
        config.CVE_SINKS_DB = self._tmp_db

    def tearDown(self) -> None:
        config.CVE_SINKS_DB = self._original_db
        if self._tmp_db.exists():
            try:
                self._tmp_db.unlink()
            except PermissionError:
                pass

    def test_upsert_and_get_case_state(self) -> None:
        saved = upsert_case_state(
            "demo/project",
            "CVE-2024-0001",
            None,
            status="under_review",
            owner="alice",
            notes="tracking",
        )
        self.assertEqual(saved["status"], "under_review")
        loaded = get_case_state("demo/project", "CVE-2024-0001", None)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["owner"], "alice")
        self.assertEqual(loaded["notes"], "tracking")

    def test_bootstrap_and_snapshot_roundtrip(self) -> None:
        cases = [
            _sample_case("CVE-2024-0001", "pkg:npm/a@1.0.0"),
            _sample_case("CVE-2024-0002", None),
        ]
        inserted = bootstrap_default_states("demo/project", cases)
        self.assertEqual(inserted, 2)

        all_states = get_case_states("demo/project")
        self.assertEqual(len(all_states), 2)

        run_id = record_report_run("demo/project", report_version="test")
        snap_count = record_report_case_snapshot("demo/project", run_id, cases)
        self.assertEqual(snap_count, 2)

        snapshot = get_report_case_snapshot(run_id)
        self.assertEqual(len(snapshot), 2)
        recent_runs = get_recent_report_runs("demo/project", limit=5)
        self.assertTrue(any(run["run_id"] == run_id for run in recent_runs))

    def test_recompute_overwrites_legacy_decision_tier(self) -> None:
        upsert_case_state(
            "demo/project",
            "CVE-2024-0009",
            "pkg:npm/legacy@1.0.0",
            decision_tier="monitor",
            status="under_review",
        )

        rows = [
            {
                "project": "demo/project",
                "vuln_id": "CVE-2024-0009",
                "component": "legacy",
                "version": "1.0.0",
                "component_id": "pkg:npm/legacy@1.0.0",
                "cvss": 5.0,
                "epss": 0.05,
                "kev": False,
                "fix_versions": [],
                "dependency_depth": 1,
                "scope": "runtime",
                "reachability_verdict": "confirmed_reachable",
                "call_locations": ["app.py:10"],
                "risk_score": 50.0,
            }
        ]

        summary = recompute_and_overwrite_case_state_tiers("demo/project", rows)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["changed"], 1)

        state = get_case_state("demo/project", "CVE-2024-0009", "pkg:npm/legacy@1.0.0")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state["decision_tier"], "fix_now")
        self.assertEqual(state["status"], "under_review")

    def test_sync_status_with_previous_snapshot(self) -> None:
        project = "demo/project"
        baseline_cases = [
            _sample_case("CVE-2024-0101", "pkg:npm/a@1.0.0"),
            _sample_case("CVE-2024-0102", "pkg:npm/b@1.0.0"),
        ]
        baseline_cases[0]["status"] = "resolved_pending_verify"
        baseline_cases[1]["status"] = "in_progress"

        run_id = record_report_run(project, report_version="stakeholder-v1")
        record_report_case_snapshot(project, run_id, baseline_cases)

        upsert_case_state(
            project,
            "CVE-2024-0101",
            "pkg:npm/a@1.0.0",
            status="resolved_pending_verify",
            decision_tier="fix_now",
        )
        upsert_case_state(
            project,
            "CVE-2024-0102",
            "pkg:npm/b@1.0.0",
            status="in_progress",
            decision_tier="plan_remediation",
        )

        current_cases = [
            _sample_case("CVE-2024-0101", "pkg:npm/a@1.0.0"),  # still present -> reopen
            _sample_case("CVE-2024-0103", "pkg:npm/c@1.0.0"),  # new case
        ]

        summary = sync_case_status_with_previous_snapshot(project, current_cases)
        self.assertEqual(summary["new_cases"], 1)
        self.assertEqual(summary["reopened_cases"], 1)
        self.assertEqual(summary["resolved_cases"], 1)
        self.assertTrue(summary["status_updates"] >= 3)

        reopened = get_case_state(project, "CVE-2024-0101", "pkg:npm/a@1.0.0")
        self.assertIsNotNone(reopened)
        assert reopened is not None
        self.assertEqual(reopened["status"], "under_review")

        resolved = get_case_state(project, "CVE-2024-0102", "pkg:npm/b@1.0.0")
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved["status"], "resolved_pending_verify")

        new_case = get_case_state(project, "CVE-2024-0103", "pkg:npm/c@1.0.0")
        self.assertIsNotNone(new_case)
        assert new_case is not None
        self.assertEqual(new_case["status"], "new")


if __name__ == "__main__":
    unittest.main()
